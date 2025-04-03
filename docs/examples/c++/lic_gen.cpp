/*
 * Copyright (c) 2015 Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <termios.h>
#include <unistd.h>
#include <vector>
#include <themis/themis.h>

// For cxxopts, either:
// 1. Install system-wide and use #include <cxxopts.hpp>
// 2. Or place in local directory and use:
#include "cxxopts.hpp"

#define MAX_KEY_SIZE 4096

// Secure string clearing
void secure_clear(std::string& str)
{
    if (!str.empty()) {
        volatile char* p = const_cast<volatile char*>(str.c_str());
        while (*p)
            *p++ = '\0';
    }
}

// Disable terminal echo for password input
std::string get_password(const std::string& prompt)
{
    std::cout << prompt;

    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string password;
    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;

    return password;
}

// Encrypt and save master key
void save_master_key(const std::string& filename,
                     const std::vector<uint8_t>& master_key,
                     const std::string& password)
{
    // First call to get buffer size
    size_t encrypted_len = 0;
    themis_status_t res = themis_secure_cell_encrypt_seal(reinterpret_cast<const uint8_t*>(
                                                              password.data()),
                                                          password.size(),
                                                          nullptr,
                                                          0, // No context
                                                          master_key.data(),
                                                          master_key.size(),
                                                          nullptr,
                                                          &encrypted_len);

    if (res != THEMIS_BUFFER_TOO_SMALL) {
        throw std::runtime_error("Failed to get encrypted data size");
    }

    // Allocate buffer
    std::vector<uint8_t> encrypted_data(encrypted_len);

    // Second call to actually encrypt
    res = themis_secure_cell_encrypt_seal(reinterpret_cast<const uint8_t*>(password.data()),
                                          password.size(),
                                          nullptr,
                                          0, // No context
                                          master_key.data(),
                                          master_key.size(),
                                          encrypted_data.data(),
                                          &encrypted_len);

    if (res != THEMIS_SUCCESS) {
        throw std::runtime_error("Failed to encrypt master key");
    }

    // Save to file
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_len);
}

// Decrypt master key
std::vector<uint8_t> load_master_key(const std::string& filename, const std::string& password)
{
    // Read encrypted data
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open master key file: " + filename);
    }

    std::vector<uint8_t> encrypted_data((std::istreambuf_iterator<char>(file)),
                                        std::istreambuf_iterator<char>());
    file.close();

    // First call to get buffer size
    size_t decrypted_len = 0;
    themis_status_t res = themis_secure_cell_decrypt_seal(reinterpret_cast<const uint8_t*>(
                                                              password.data()),
                                                          password.size(),
                                                          nullptr,
                                                          0, // No context
                                                          encrypted_data.data(),
                                                          encrypted_data.size(),
                                                          nullptr,
                                                          &decrypted_len);

    if (res != THEMIS_BUFFER_TOO_SMALL) {
        throw std::runtime_error("Failed to get decrypted data size");
    }

    // Allocate buffer
    std::vector<uint8_t> decrypted_data(decrypted_len);

    // Second call to actually decrypt
    res = themis_secure_cell_decrypt_seal(reinterpret_cast<const uint8_t*>(password.data()),
                                          password.size(),
                                          nullptr,
                                          0, // No context
                                          encrypted_data.data(),
                                          encrypted_data.size(),
                                          decrypted_data.data(),
                                          &decrypted_len);

    if (res != THEMIS_SUCCESS) {
        throw std::runtime_error("Failed to decrypt master key - wrong password?");
    }

    return decrypted_data;
}

// License feature definition
struct LicenseFeatures {
    uint32_t feature_flags;
    uint64_t valid_from;
    uint64_t expiry_time;
    uint32_t use_count;
    std::string client_id;
};

// Client key pair
struct ClientKeyPair {
    std::vector<uint8_t> private_key;
    std::vector<uint8_t> public_key;
};

// Generate random master key
std::vector<uint8_t> generate_master_key(size_t length = 32)
{
    std::vector<uint8_t> key(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto& byte : key) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    return key;
}

// Generate client key pair
ClientKeyPair generate_client_keys()
{
    ClientKeyPair keys;
    uint8_t private_key[MAX_KEY_SIZE] = {0};
    uint8_t public_key[MAX_KEY_SIZE] = {0};
    size_t private_key_length = sizeof(private_key);
    size_t public_key_length = sizeof(public_key);

    themis_status_t res =
        themis_gen_rsa_key_pair(private_key, &private_key_length, public_key, &public_key_length);
    if (res != THEMIS_SUCCESS) {
        throw std::runtime_error("Failed to generate client keys");
    }

    // Copy the generated keys into our vector
    keys.private_key.assign(private_key, private_key + private_key_length);
    keys.public_key.assign(public_key, public_key + public_key_length);

    return keys;
}

// Serialize license features
std::vector<uint8_t> serialize_license_features(const LicenseFeatures& features)
{
    std::vector<uint8_t> data;

    // Serialize feature flags
    auto flags_ptr = reinterpret_cast<const uint8_t*>(&features.feature_flags);
    data.insert(data.end(), flags_ptr, flags_ptr + sizeof(features.feature_flags));

    // Serialize timestamps
    auto valid_ptr = reinterpret_cast<const uint8_t*>(&features.valid_from);
    data.insert(data.end(), valid_ptr, valid_ptr + sizeof(features.valid_from));

    auto expiry_ptr = reinterpret_cast<const uint8_t*>(&features.expiry_time);
    data.insert(data.end(), expiry_ptr, expiry_ptr + sizeof(features.expiry_time));

    // Serialize use count
    auto count_ptr = reinterpret_cast<const uint8_t*>(&features.use_count);
    data.insert(data.end(), count_ptr, count_ptr + sizeof(features.use_count));

    // Serialize client ID
    data.insert(data.end(), features.client_id.begin(), features.client_id.end());
    data.push_back('\0'); // null terminator

    return data;
}

// Generate feature license
std::vector<uint8_t> generate_feature_license(const std::vector<uint8_t>& master_key,
                                              const ClientKeyPair& client_keys,
                                              const LicenseFeatures& features)
{
    // Serialize features
    auto features_data = serialize_license_features(features);

    // First call to get buffer size
    size_t encrypted_len = 0;
    themis_status_t res = themis_secure_cell_encrypt_seal(master_key.data(),
                                                          master_key.size(),
                                                          client_keys.public_key.data(),
                                                          client_keys.public_key.size(),
                                                          features_data.data(),
                                                          features_data.size(),
                                                          nullptr,
                                                          &encrypted_len);

    if (res != THEMIS_BUFFER_TOO_SMALL) {
        throw std::runtime_error("Failed to get license data size");
    }

    // Allocate buffer
    std::vector<uint8_t> license_data(encrypted_len);

    // Second call to actually encrypt
    res = themis_secure_cell_encrypt_seal(master_key.data(),
                                          master_key.size(),
                                          client_keys.public_key.data(),
                                          client_keys.public_key.size(),
                                          features_data.data(),
                                          features_data.size(),
                                          license_data.data(),
                                          &encrypted_len);

    if (res != THEMIS_SUCCESS) {
        throw std::runtime_error("Failed to generate feature license");
    }

    return license_data;
}

// Save data to file
void save_to_file(const std::string& filename, const std::vector<uint8_t>& data)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Convert timestamp to string
std::string time_to_string(time_t timestamp)
{
    std::tm tm = *std::localtime(&timestamp);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

int main(int argc, char** argv)
{
    try {
        cxxopts::Options options("lic_gen", "Password-protected License Generator using Themis");

        options.add_options()("g,generate-master",
                              "Generate new password-protected master key",
                              cxxopts::value<bool>()->default_value(
                                  "false"))("m,master-key",
                                            "Master key file",
                                            cxxopts::value<std::string>())("p,password",
                                                                           "Password (leave empty to prompt)",
                                                                           cxxopts::value<std::string>()
                                                                               ->default_value(""))(
            "o,output",
            "Output directory",
            cxxopts::value<std::string>()->default_value(
                "."))("c,client-id",
                      "Client ID",
                      cxxopts::value<std::string>()->default_value(
                          "default-client"))("f,features",
                                             "Feature flags (hex)",
                                             cxxopts::value<std::string>()->default_value(
                                                 "0x0001"))("d,duration",
                                                            "License duration in days",
                                                            cxxopts::value<int>()->default_value(
                                                                "30"))("n,count",
                                                                       "Usage count (0=unlimited)",
                                                                       cxxopts::value<int>()->default_value(
                                                                           "0"))("h,help",
                                                                                 "Print usage");

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        std::string password = result["password"].as<std::string>();
        std::vector<uint8_t> master_key;

        // Generate master key mode
        if (result["generate-master"].as<bool>()) {
            if (password.empty()) {
                password = get_password("Enter password for new master key: ");
                std::string confirm = get_password("Confirm password: ");

                if (password != confirm) {
                    std::cerr << "Error: Passwords do not match" << std::endl;
                    return 1;
                }
            }

            master_key = generate_master_key();
            std::string master_key_file = result["output"].as<std::string>() + "/master.key";
            save_master_key(master_key_file, master_key, password);

            // Securely clear sensitive data
            secure_clear(password);
            master_key.assign(master_key.size(), 0);

            std::cout << "Generated new password-protected master key saved to: " << master_key_file
                      << std::endl;
            return 0;
        }

        // Normal license generation mode
        if (!result.count("master-key")) {
            std::cerr << "Error: Master key file is required" << std::endl;
            std::cerr << options.help() << std::endl;
            return 1;
        }

        // Get password
        if (password.empty()) {
            password = get_password("Enter password for master key: ");
        }

        // Load master key
        std::string master_key_file = result["master-key"].as<std::string>();
        master_key = load_master_key(master_key_file, password);

        // Generate client keys
        std::cout << "Generating client keys..." << std::endl;
        ClientKeyPair client_keys = generate_client_keys();

        // Save client keys
        std::string output_dir = result["output"].as<std::string>();
        save_to_file(output_dir + "/client_private.key", client_keys.private_key);
        save_to_file(output_dir + "/client_public.key", client_keys.public_key);

        std::cout << "Client keys saved to:\n"
                  << "  Private: " << output_dir << "/client_private.key\n"
                  << "  Public:  " << output_dir << "/client_public.key" << std::endl;

        // Prepare license features
        LicenseFeatures features;
        features.client_id = result["client-id"].as<std::string>();

        // Parse feature flags
        std::string features_str = result["features"].as<std::string>();
        features.feature_flags = std::stoul(features_str, nullptr, 16);

        // Set timestamps
        time_t now = time(nullptr);
        features.valid_from = now;
        features.expiry_time = now + result["duration"].as<int>() * 24 * 3600;
        features.use_count = result["count"].as<int>();

        std::cout << "\nLicense features:\n"
                  << "  Client ID:  " << features.client_id << "\n"
                  << "  Features:   0x" << std::hex << features.feature_flags << std::dec << "\n"
                  << "  Valid from: " << time_to_string(features.valid_from) << "\n"
                  << "  Expires:    " << time_to_string(features.expiry_time) << "\n"
                  << "  Use count:  " << features.use_count
                  << (features.use_count == 0 ? " (unlimited)" : "") << std::endl;

        // Generate license
        std::cout << "\nGenerating license..." << std::endl;
        auto license = generate_feature_license(master_key, client_keys, features);

        // Save license
        std::string license_file = output_dir + "/" + features.client_id + ".lic";
        save_to_file(license_file, license);
        std::cout << "License saved to: " << license_file << std::endl;

        // Securely clear sensitive data
        secure_clear(password);
        master_key.assign(master_key.size(), 0);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}