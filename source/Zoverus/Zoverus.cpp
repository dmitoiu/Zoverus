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
    input_file.seekg(0, std::ios_base::end);
    size_t total_file_size = input_file.tellg();
    input_file.seekg(0, std::ios_base::beg);

    // Determine segment size dynamically (uTorrent logic)
    size_t SEGMENT_SIZE = 32 * 1024; // Default 32 KB
    if (total_file_size > 128 * 1024 * 1024) SEGMENT_SIZE = 64 * 1024;
    if (total_file_size > 256 * 1024 * 1024) SEGMENT_SIZE = 128 * 1024;
    if (total_file_size > 512 * 1024 * 1024) SEGMENT_SIZE = 256 * 1024;
    if (total_file_size > 1 * 1024 * 1024 * 1024) SEGMENT_SIZE = 512 * 1024;
    if (total_file_size > 2 * 1024 * 1024 * 1024) SEGMENT_SIZE = 1 * 1024 * 1024;
    if (total_file_size > 4 * 1024 * 1024 * 1024) SEGMENT_SIZE = 2 * 1024 * 1024;
    if (total_file_size > 8 * 1024 * 1024 * 1024) SEGMENT_SIZE = 4 * 1024 * 1024;

    std::cout << "[Server] Segment size: " << (SEGMENT_SIZE / 1024) << " KB\n";

    // Send segment size to client
    send(client_socket, reinterpret_cast<char*>(&SEGMENT_SIZE), sizeof(SEGMENT_SIZE), 0);

    // Send segment size to client
    send(client_socket, reinterpret_cast<char*>(&total_file_size), sizeof(total_file_size), 0);

    std::vector<char> buffer(SEGMENT_SIZE);
    int segment_index = 0;
    size_t total_bytes_sent = 0;

    while (input_file.read(buffer.data(), buffer.size()) || input_file.gcount() > 0) {
        size_t bytes_read = input_file.gcount();
        std::vector<unsigned char> hash = compute_sha256(buffer, bytes_read);

        while (true) { // Loop until the segment is acknowledged
            // Send the segment index first
            if (!send_all(client_socket, reinterpret_cast<char*>(&segment_index), sizeof(segment_index))) {
                std::cout << "[ERROR] Failed to send segment index.\n";
                return;
            }

            // Send the segment data
            if (!send_all(client_socket, buffer.data(), bytes_read)) {
                std::cout << "[ERROR] Failed to send segment data.\n";
                return;
            }

            // Wait for the client acknowledgment
            char ack[6] = { 0 }; // "OK" or "RETRY"
            if (!receive_all(client_socket, ack, sizeof(ack))) {
                std::cout << "[ERROR] Failed to receive acknowledgment.\n";
                return;
            }

            if (std::string(ack) == "OK") {
                total_bytes_sent += bytes_read;
                double progress = (double)total_bytes_sent / total_file_size * 100;
                std::cout << "[Server] Segment " << segment_index << " confirmed with hash: " << std::endl;
                std::cout << "\r[Server] Progress: " << progress << "% (" << total_bytes_sent << " / " << total_file_size << " bytes)   " << std::endl;
                std::cout.flush();
                print_hash(hash);
                break; // Move to the next segment
            }
            else {
                std::cout << "[Server] Segment " << segment_index << " failed hash check. Retrying...\n";
            }
        }
        segment_index++; // Move to the next segment
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

