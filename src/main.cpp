// ============================================================================
// Secura - Main Entry Point
// ============================================================================
// A demonstration of the Secura encryption library.
// ============================================================================

#include "secura/crypto.hpp"

#include <iostream>
#include <format>
#include <string>

using namespace secura;

/// Print a byte buffer as hexadecimal
void print_hex(std::string_view label, ByteSpan data, std::size_t max_bytes = 32) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (std::size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
        std::cout << std::format("{:02x}", data[i]);
    }
    if (data.size() > max_bytes) {
        std::cout << "...";
    }
    std::cout << "\n";
}

int main() {
    std::cout << std::format("=== Secura v{} ===\n\n", VERSION_STRING);
    std::cout << "A lightweight encryption tool built with modern C++23\n\n";

    // ========================================================================
    // Demo 1: Key Generation
    // ========================================================================
    std::cout << "--- Demo 1: Key Generation ---\n";
    
    auto key_result = KeyManager::generate_key();
    if (!key_result) {
        std::cerr << "Failed to generate key: " << error_to_string(key_result.error()) << "\n";
        return 1;
    }
    
    print_hex("Generated AES-256 key", key_result->span());
    std::cout << "\n";
    
    // ========================================================================
    // Demo 2: Text Encryption with Key
    // ========================================================================
    std::cout << "--- Demo 2: Text Encryption ---\n";
    
    const std::string plaintext = "Hello, Secura! This is a secret message.";
    std::cout << "Plaintext: \"" << plaintext << "\"\n";
    
    // Encrypt
    auto encrypted_result = Encryptor::encrypt_text(plaintext, key_result->span());
    if (!encrypted_result) {
        std::cerr << "Encryption failed: " << error_to_string(encrypted_result.error()) << "\n";
        return 1;
    }
    
    print_hex("Ciphertext", *encrypted_result);
    
    // Decrypt
    auto decrypted_result = Decryptor::decrypt_text(*encrypted_result, key_result->span());
    if (!decrypted_result) {
        std::cerr << "Decryption failed: " << error_to_string(decrypted_result.error()) << "\n";
        return 1;
    }
    
    std::cout << "Decrypted: \"" << *decrypted_result << "\"\n";
    std::cout << "Round-trip successful: " << (plaintext == *decrypted_result ? "YES" : "NO") << "\n\n";
    
    // ========================================================================
    // Demo 3: Password-based Encryption
    // ========================================================================
    std::cout << "--- Demo 3: Password-based Encryption ---\n";
    
    const std::string password = "MySecurePassword123!";
    const std::string secret = "This message is protected by a password.";
    
    std::cout << "Password: \"" << password << "\"\n";
    std::cout << "Plaintext: \"" << secret << "\"\n";
    
    // Encrypt with password
    auto pw_encrypted = Encryptor::encrypt_text_with_password(secret, password);
    if (!pw_encrypted) {
        std::cerr << "Password encryption failed: " << error_to_string(pw_encrypted.error()) << "\n";
        return 1;
    }
    
    print_hex("Ciphertext (includes salt)", *pw_encrypted);
    
    // Decrypt with password
    auto pw_decrypted = Decryptor::decrypt_text_with_password(*pw_encrypted, password);
    if (!pw_decrypted) {
        std::cerr << "Password decryption failed: " << error_to_string(pw_decrypted.error()) << "\n";
        return 1;
    }
    
    std::cout << "Decrypted: \"" << *pw_decrypted << "\"\n\n";
    
    // ========================================================================
    // Demo 4: Tampering Detection
    // ========================================================================
    std::cout << "--- Demo 4: Tampering Detection ---\n";
    
    // Try to decrypt with wrong password
    auto wrong_password_result = Decryptor::decrypt_text_with_password(*pw_encrypted, "WrongPassword!");
    if (!wrong_password_result) {
        std::cout << "Decryption with wrong password failed as expected: " 
                  << error_to_string(wrong_password_result.error()) << "\n";
    }
    
    // Tamper with ciphertext
    ByteBuffer tampered = *pw_encrypted;
    if (tampered.size() > 20) {
        tampered[20] ^= 0xFF;  // Flip bits
    }
    
    auto tampered_result = Decryptor::decrypt_text_with_password(tampered, password);
    if (!tampered_result) {
        std::cout << "Tampered data detection: " 
                  << error_to_string(tampered_result.error()) << "\n";
    }
    
    std::cout << "\n=== All demos completed successfully! ===\n";
    
    return 0;
}
