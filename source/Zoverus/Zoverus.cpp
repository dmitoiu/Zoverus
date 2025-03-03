/**
*
*  Copyright [2025] [Darie-Dragos Mitoiu]
*
* Licensed under the Zoverus License, Version 1.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.dmitoiu.ro/licenses/LICENSE-1.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/


#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <Windows.h>
#include <shlobj.h>
#include <direct.h>

constexpr size_t SEGMENT_SIZE = 1024;

void show_usage(const char* program_name) {
    std::cerr << "Usage:\n"
        << "  " << program_name << " <port> <file_path>\n"
        << "Options:\n"
        << "  server    Start in server mode and send the specified file.\n"
        << "Examples:\n"
        << "  " << program_name << " 5000 sample.txt\n";
}

// Generate a SHA-256 hash using OpenSSL 3.0 EVP interface
std::vector<unsigned char> compute_sha256(const std::vector<char>& data, size_t length) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* sha256 = EVP_sha256();

    if (ctx == nullptr) {
        std::cerr << "[ERROR] Failed to create EVP_MD_CTX" << std::endl;
        return {};
    }

    if (EVP_DigestInit_ex(ctx, sha256, nullptr) != 1) {
        std::cerr << "[ERROR] Failed to initialize SHA256 digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    if (EVP_DigestUpdate(ctx, data.data(), length) != 1) {
        std::cerr << "[ERROR] Failed to update SHA256 digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> hash(EVP_MD_size(sha256));

    if (EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        std::cerr << "[ERROR] Failed to finalize SHA256 digest" << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

void print_hash(const std::vector<unsigned char>& hash) {
    for (unsigned char byte : hash) {
        printf("%02x", byte);
    }
    printf("\n");
}

bool initialize_winsock() {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

bool send_all(SOCKET socket, const char* buffer, size_t length) {
    size_t total_sent = 0;
    while (total_sent < length) {
        int sent = send(socket, buffer + total_sent, length - total_sent, 0);
        if (sent == SOCKET_ERROR) return false;
        total_sent += sent;
    }
    return true;
}

bool receive_all(SOCKET socket, char* buffer, size_t length) {
    size_t total_received = 0;
    while (total_received < length) {
        int received = recv(socket, buffer + total_received, length - total_received, 0);
        if (received == SOCKET_ERROR) return false;
        total_received += received;
    }
    return true;
}

void start_server(unsigned short port, const std::string& file_path) {
    if (!initialize_winsock()) {
        std::cout << "[ERROR] Winsock initialization failed!\n";
        return;
    }

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        std::cout << "[ERROR] Failed to create server socket.\n";
        WSACleanup();
        return;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cout << "[ERROR] Bind failed.\n";
        closesocket(server_socket);
        WSACleanup();
        return;
    }

    if (listen(server_socket, 1) == SOCKET_ERROR) {
        std::cout << "[ERROR] Listen failed.\n";
        closesocket(server_socket);
        WSACleanup();
        return;
    }

    std::cout << "[Server] Waiting for a connection on port " << port << "...\n";
    SOCKET client_socket = accept(server_socket, nullptr, nullptr);
    if (client_socket == INVALID_SOCKET) {
        std::cout << "[ERROR] Accept failed.\n";
        closesocket(server_socket);
        WSACleanup();
        return;
    }
    std::cout << "[Server] Connection established.\n";

    // Send the filename first
    std::string filename = file_path.substr(file_path.find_last_of("/\\") + 1);
    send(client_socket, filename.c_str(), filename.size() + 1, 0);
    std::cout << "[Server] Sending file: " << filename << "\n";

    std::ifstream input_file(file_path, std::ios_base::binary);
    std::vector<char> buffer(SEGMENT_SIZE);
    int segment_index = 0;

    while (input_file.read(buffer.data(), buffer.size()) || input_file.gcount() > 0) {
        size_t bytes_read = input_file.gcount();
        std::vector<unsigned char> hash = compute_sha256(buffer, bytes_read);
        // Send the segment data
        if (!send_all(client_socket, buffer.data(), bytes_read)) break;

        // Wait for the client to send back the hash of the received segment
        std::vector<unsigned char> client_hash(SHA256_DIGEST_LENGTH);
        if (!receive_all(client_socket, (char*)client_hash.data(), client_hash.size())) break;

        std::cout << "[Server] Segment " << segment_index++ << " sent with hash: ";

        // Check if the received hash matches the original hash
        if (client_hash == hash) {
            std::cout << "[Server] Segment " << segment_index++ << " sent and confirmed with hash: ";
            print_hash(hash);
        }
        else {
            std::cout << "[Server] Hash mismatch for segment " << segment_index << "! Re-sending segment...\n";
            // Re-send the segment if hash doesn't match
            send_all(client_socket, buffer.data(), bytes_read);
        }
    }

    std::cout << "[Server] File transfer complete.\n";
    closesocket(client_socket);
    closesocket(server_socket);
    WSACleanup();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_usage(argv[0]);
        return 1;
    }
    if (argc != 3) {
        std::cerr << "[ERROR] Invalid arguments for server mode.\n";
        show_usage(argv[0]);
        return 1;
    }
    unsigned short port = static_cast<unsigned short>(std::stoi(argv[1]));
    start_server(port, argv[2]);
    return 1;
}

