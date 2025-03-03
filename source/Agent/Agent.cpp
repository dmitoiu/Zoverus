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
        << "  " << program_name << " <host> <port> <save_folder>\n\n"
        << "Options:\n"
        << "  client    Start in client mode and download the file to the given folder.\n\n"
        << "Examples:\n"
        << "  " << program_name << " 127.0.0.1 5000 C:\\Downloads\\\n";
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

void start_client(const std::string& host, unsigned short port, const std::string& folder_name) {
    if (!initialize_winsock()) {
        std::cout << "[ERROR] Winsock initialization failed!\n";
        return;
    }

    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        std::cout << "[ERROR] Failed to create client socket.\n";
        WSACleanup();
        return;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr);
    server_addr.sin_port = htons(port);

    std::cout << "[Client] Connecting to " << host << " on port " << port << "...\n";
    if (connect(client_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Connection failed.\n";
        closesocket(client_socket);
        WSACleanup();
        return;
    }
    std::cout << "[Client] Connection established.\n";

    // Receive the filename first
    char filename[256];
    recv(client_socket, filename, sizeof(filename), 0);
    std::cout << "[Client] Receiving file: " << filename << "\n";

    // Get user's home directory
    char user_home[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, user_home) != S_OK) {
        std::cerr << "[ERROR] Failed to get user home directory!\n";
        closesocket(client_socket);
        WSACleanup();
        return;
    }

    // Create the custom folder inside home directory
    std::string download_dir = std::string(user_home) + "\\" + folder_name;
    _mkdir(download_dir.c_str());  // Ensure directory exists

    // Save file in the custom folder
    std::string output_path = download_dir + "\\" + filename;
    std::ofstream output_file(output_path, std::ios_base::binary);
    if (!output_file.is_open()) {
        std::cerr << "[ERROR] Failed to open output file: " << output_path << "\n";
        closesocket(client_socket);
        WSACleanup();
        return;
    }

    // Receive file data
    std::vector<char> buffer(SEGMENT_SIZE);
    int bytes_received, segment_index = 0;

    while ((bytes_received = recv(client_socket, buffer.data(), buffer.size(), 0)) > 0) {
        if (bytes_received == 0) break;
        std::vector<unsigned char> hash = compute_sha256(buffer, bytes_received);
        // Send back the hash to confirm receipt
        send_all(client_socket, (char*)hash.data(), hash.size());
        output_file.write(buffer.data(), bytes_received);
        std::cout << "[Client] Segment " << segment_index++ << " received with hash: ";
        print_hash(hash);
    }

    std::cout << "[Client] File saved to: " << output_path << "\n";
    std::cout << "[Client] File transfer complete.\n";

    closesocket(client_socket);
    WSACleanup();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_usage(argv[0]);
        return 1;
    }
    if (argc != 4) {
        std::cerr << "[ERROR] Invalid arguments for client mode.\n";
        show_usage(argv[0]);
        return 1;
    }
    std::string host = argv[1];
    unsigned short port = static_cast<unsigned short>(std::stoi(argv[2]));
    std::string save_folder = argv[3];
    start_client(host, port, save_folder);
    return 1;
}

