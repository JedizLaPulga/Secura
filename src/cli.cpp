// ============================================================================
// Secura - Command Line Interface Implementation
// ============================================================================

#include "secura/cli.hpp"
#include "secura/crypto.hpp"

#include <iostream>
#include <fstream>
#include <format>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace secura::cli {

// ============================================================================
// Terminal Utilities
// ============================================================================

void print_error(std::string_view message) {
    std::cerr << "[ERROR] " << message << "\n";
}

void print_success(std::string_view message) {
    std::cout << "[OK] " << message << "\n";
}

void print_info(std::string_view message) {
    std::cout << "[INFO] " << message << "\n";
}

std::string read_password(std::string_view prompt) {
    std::cout << prompt << std::flush;
    std::string password;
    
#ifdef _WIN32
    // Windows: Use _getch() to read without echo
    char ch;
    while ((ch = static_cast<char>(_getch())) != '\r') {
        if (ch == '\b') {  // Backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";  // Erase character
            }
        } else if (ch >= 32) {  // Printable characters
            password += ch;
            std::cout << '*';
        }
    }
    std::cout << "\n";
#else
    // Unix: Disable terminal echo
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    
    std::getline(std::cin, password);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    std::cout << "\n";
#endif
    
    return password;
}

std::optional<std::string> read_password_confirmed(std::string_view prompt) {
    std::string password1 = read_password(std::format("{}: ", prompt));
    std::string password2 = read_password("Confirm password: ");
    
    if (password1 != password2) {
        print_error("Passwords do not match");
        return std::nullopt;
    }
    
    // Validate password
    if (auto result = KeyManager::validate_password(password1); !result) {
        print_error(std::string(error_to_string(result.error())));
        return std::nullopt;
    }
    
    return password1;
}

// ============================================================================
// Argument Parsing
// ============================================================================

ParsedArgs parse_args(std::span<char*> args) {
    ParsedArgs result;
    
    for (std::size_t i = 1; i < args.size(); ++i) {
        std::string_view arg = args[i];
        
        // Check for options
        if (arg.starts_with("--")) {
            std::string_view option = arg.substr(2);
            
            if (option == "help") {
                result.help = true;
            } else if (option == "verbose" || option == "v") {
                result.verbose = true;
            } else if (option == "password" || option == "p") {
                result.use_password = true;
            } else if (option == "text" || option == "t") {
                result.text_mode = true;
            } else if (option.starts_with("output=")) {
                result.output = std::string(option.substr(7));
            } else if (option.starts_with("key=")) {
                result.key_file = std::string(option.substr(4));
            } else if (option.starts_with("public-key=")) {
                result.public_key = std::string(option.substr(11));
            } else if (option.starts_with("private-key=")) {
                result.private_key = std::string(option.substr(12));
            } else if (option.starts_with("type=")) {
                result.key_type = std::string(option.substr(5));
            } else if (option.starts_with("size=")) {
                try {
                    result.key_size = std::stoi(std::string(option.substr(5)));
                } catch (...) {
                    // Invalid size, will be caught during validation
                }
            }
        } else if (arg.starts_with("-")) {
            // Short options
            for (std::size_t j = 1; j < arg.size(); ++j) {
                switch (arg[j]) {
                    case 'h': result.help = true; break;
                    case 'v': result.verbose = true; break;
                    case 'p': result.use_password = true; break;
                    case 't': result.text_mode = true; break;
                    case 'o':
                        if (i + 1 < args.size()) {
                            result.output = args[++i];
                        }
                        break;
                    case 'k':
                        if (i + 1 < args.size()) {
                            result.key_file = args[++i];
                        }
                        break;
                    default:
                        break;
                }
            }
        } else {
            // Positional argument
            if (result.command.empty()) {
                result.command = std::string(arg);
            } else {
                result.positional.push_back(std::string(arg));
            }
        }
    }
    
    return result;
}

// ============================================================================
// Help Command
// ============================================================================

ExitCode cmd_help(const ParsedArgs& args) {
    if (args.positional.empty()) {
        // General help
        std::cout << R"(
Secura - A lightweight encryption tool built with modern C++23

USAGE:
    secura <command> [options] [arguments]

COMMANDS:
    keygen      Generate encryption keys (AES or RSA)
    encrypt     Encrypt a file or text
    decrypt     Decrypt a file or text
    version     Show version information
    help        Show this help message

EXAMPLES:
    secura keygen --type=aes --output=secret.key
    secura keygen --type=rsa --size=2048 --output=mykey
    secura encrypt file.txt --key=secret.key --output=file.enc
    secura encrypt file.txt --password --output=file.enc
    secura decrypt file.enc --key=secret.key --output=file.txt
    secura encrypt --text "Hello World" --password

Use 'secura help <command>' for more information about a command.
)";
    } else if (args.positional[0] == "keygen") {
        std::cout << R"(
secura keygen - Generate encryption keys

USAGE:
    secura keygen [options]

OPTIONS:
    --type=<aes|rsa>    Key type (default: aes)
    --size=<bits>       Key size for RSA: 2048 or 4096 (default: 2048)
    --output=<file>     Output file (required)
    --password, -p      Protect RSA private key with password

EXAMPLES:
    secura keygen --type=aes --output=secret.key
    secura keygen --type=rsa --size=4096 --output=mykey
    secura keygen --type=rsa --output=mykey --password

For RSA keys, two files will be created:
    <output>.pub     Public key (share this)
    <output>.pem     Private key (keep secret!)
)";
    } else if (args.positional[0] == "encrypt") {
        std::cout << R"(
secura encrypt - Encrypt a file or text

USAGE:
    secura encrypt <input> [options]
    secura encrypt --text "message" [options]

OPTIONS:
    --output=<file>, -o   Output file (default: <input>.enc)
    --key=<file>, -k      AES key file for symmetric encryption
    --public-key=<file>   RSA public key for hybrid encryption
    --password, -p        Use password-based encryption
    --text, -t            Encrypt text (input is the message)

EXAMPLES:
    secura encrypt secret.txt --key=secret.key
    secura encrypt secret.txt --password
    secura encrypt secret.txt --public-key=recipient.pub
    secura encrypt --text "Hello" --password
)";
    } else if (args.positional[0] == "decrypt") {
        std::cout << R"(
secura decrypt - Decrypt a file or text

USAGE:
    secura decrypt <input> [options]

OPTIONS:
    --output=<file>, -o    Output file (default: stdout for text, <input>.dec for files)
    --key=<file>, -k       AES key file for symmetric decryption
    --private-key=<file>   RSA private key for hybrid decryption
    --password, -p         Use password-based decryption
    --text, -t             Output as text to stdout

EXAMPLES:
    secura decrypt secret.enc --key=secret.key
    secura decrypt secret.enc --password
    secura decrypt secret.enc --private-key=mykey.pem
    secura decrypt secret.enc --password --text
)";
    }
    
    return ExitCode::Success;
}

// ============================================================================
// Version Command
// ============================================================================

ExitCode cmd_version() {
    std::cout << std::format("Secura v{}\n", VERSION_STRING);
    std::cout << "A lightweight encryption tool built with modern C++23\n";
    std::cout << "Copyright (c) 2026 Joel Emeka\n";
    std::cout << "\nEncryption: AES-256-GCM, RSA-2048/4096 (OAEP-SHA256)\n";
    std::cout << "Key derivation: PBKDF2-HMAC-SHA256 (600,000 iterations)\n";
    return ExitCode::Success;
}

// ============================================================================
// Keygen Command
// ============================================================================

ExitCode cmd_keygen(const ParsedArgs& args) {
    // Validate output
    if (!args.output) {
        print_error("Missing --output option. Use --output=<file> to specify output file.");
        return ExitCode::InvalidArguments;
    }
    
    std::string key_type = args.key_type.value_or("aes");
    std::transform(key_type.begin(), key_type.end(), key_type.begin(), ::tolower);
    
    if (key_type == "aes") {
        // Generate AES-256 key
        auto key_result = KeyManager::generate_key();
        if (!key_result) {
            print_error(std::format("Failed to generate key: {}", 
                        error_to_string(key_result.error())));
            return ExitCode::CryptoError;
        }
        
        // Write to file
        std::ofstream file(*args.output, std::ios::binary);
        if (!file) {
            print_error(std::format("Cannot write to file: {}", *args.output));
            return ExitCode::FileError;
        }
        
        file.write(reinterpret_cast<const char*>(key_result->data()), 
                   static_cast<std::streamsize>(key_result->size()));
        
        print_success(std::format("Generated AES-256 key: {}", *args.output));
        print_info("Keep this file secret! Anyone with it can decrypt your data.");
        
    } else if (key_type == "rsa") {
        // Determine key size
        int key_bits = args.key_size.value_or(2048);
        RsaKeySize key_size;
        
        if (key_bits == 2048) {
            key_size = RsaKeySize::Bits2048;
        } else if (key_bits == 4096) {
            key_size = RsaKeySize::Bits4096;
        } else {
            print_error("Invalid RSA key size. Use 2048 or 4096.");
            return ExitCode::InvalidArguments;
        }
        
        print_info(std::format("Generating RSA-{} key pair (this may take a moment)...", key_bits));
        
        // Generate RSA key pair
        auto keypair_result = RsaKeyPair::generate(key_size);
        if (!keypair_result) {
            print_error(std::format("Failed to generate RSA key pair: {}",
                        error_to_string(keypair_result.error())));
            return ExitCode::CryptoError;
        }
        
        // Save public key
        std::string public_key_path = *args.output + ".pub";
        auto pub_result = keypair_result->save_public_key(public_key_path);
        if (!pub_result) {
            print_error(std::format("Failed to save public key: {}",
                        error_to_string(pub_result.error())));
            return ExitCode::FileError;
        }
        
        // Save private key
        std::string private_key_path = *args.output + ".pem";
        VoidResult priv_result;
        
        if (args.use_password) {
            auto password = read_password_confirmed("Enter password for private key");
            if (!password) {
                return ExitCode::InvalidArguments;
            }
            priv_result = keypair_result->save_private_key_encrypted(private_key_path, *password);
        } else {
            priv_result = keypair_result->save_private_key(private_key_path);
        }
        
        if (!priv_result) {
            print_error(std::format("Failed to save private key: {}",
                        error_to_string(priv_result.error())));
            return ExitCode::FileError;
        }
        
        print_success(std::format("Generated RSA-{} key pair", key_bits));
        print_info(std::format("Public key:  {} (share this)", public_key_path));
        print_info(std::format("Private key: {} (KEEP SECRET!)", private_key_path));
        
    } else {
        print_error(std::format("Unknown key type: '{}'. Use 'aes' or 'rsa'.", key_type));
        return ExitCode::InvalidArguments;
    }
    
    return ExitCode::Success;
}

// ============================================================================
// Encrypt Command
// ============================================================================

ExitCode cmd_encrypt(const ParsedArgs& args) {
    // Get input
    if (args.positional.empty() && !args.text_mode) {
        print_error("Missing input file. Use: secura encrypt <file>");
        return ExitCode::InvalidArguments;
    }
    
    ByteBuffer plaintext;
    std::string default_output;
    
    if (args.text_mode) {
        // Text mode: positional args are the message
        std::string message;
        for (const auto& part : args.positional) {
            if (!message.empty()) message += " ";
            message += part;
        }
        if (message.empty()) {
            print_error("No text provided. Use: secura encrypt --text \"message\"");
            return ExitCode::InvalidArguments;
        }
        plaintext.assign(reinterpret_cast<const Byte*>(message.data()),
                        reinterpret_cast<const Byte*>(message.data() + message.size()));
        default_output = "encrypted.bin";
    } else {
        // File mode
        std::string input_file = args.positional[0];
        default_output = input_file + ".enc";
        
        // Read input file
        std::ifstream file(input_file, std::ios::binary | std::ios::ate);
        if (!file) {
            print_error(std::format("Cannot open file: {}", input_file));
            return ExitCode::FileError;
        }
        
        auto size = file.tellg();
        if (size > static_cast<std::streamsize>(constants::MAX_FILE_SIZE)) {
            print_error("File too large (max 100MB)");
            return ExitCode::FileError;
        }
        
        file.seekg(0);
        plaintext.resize(static_cast<std::size_t>(size));
        file.read(reinterpret_cast<char*>(plaintext.data()), size);
    }
    
    std::string output_file = args.output.value_or(default_output);
    ByteBuffer ciphertext;
    
    // Determine encryption method
    if (args.public_key) {
        // RSA hybrid encryption
        auto keypair = RsaKeyPair::load_public_key(*args.public_key);
        if (!keypair) {
            print_error(std::format("Failed to load public key: {}",
                        error_to_string(keypair.error())));
            return ExitCode::KeyError;
        }
        
        auto result = RsaEncryptor::hybrid_encrypt(plaintext, *keypair);
        if (!result) {
            print_error(std::format("Encryption failed: {}", 
                        error_to_string(result.error())));
            return ExitCode::CryptoError;
        }
        
        ciphertext = RsaEncryptor::serialize_hybrid_data(*result);
        
    } else if (args.use_password) {
        // Password-based encryption
        std::string password = read_password("Enter password: ");
        
        if (auto validation = KeyManager::validate_password(password); !validation) {
            print_error(std::string(error_to_string(validation.error())));
            return ExitCode::InvalidArguments;
        }
        
        auto result = Encryptor::encrypt_with_password(plaintext, password);
        if (!result) {
            print_error(std::format("Encryption failed: {}",
                        error_to_string(result.error())));
            return ExitCode::CryptoError;
        }
        
        ciphertext = std::move(*result);
        
    } else if (args.key_file) {
        // AES key file encryption
        std::ifstream key_file(*args.key_file, std::ios::binary);
        if (!key_file) {
            print_error(std::format("Cannot open key file: {}", *args.key_file));
            return ExitCode::KeyError;
        }
        
        ByteBuffer key(constants::AES_KEY_SIZE);
        key_file.read(reinterpret_cast<char*>(key.data()), 
                      static_cast<std::streamsize>(key.size()));
        
        if (key_file.gcount() != static_cast<std::streamsize>(constants::AES_KEY_SIZE)) {
            print_error("Invalid key file (must be 32 bytes)");
            return ExitCode::KeyError;
        }
        
        auto result = Encryptor::encrypt(plaintext, key);
        if (!result) {
            print_error(std::format("Encryption failed: {}",
                        error_to_string(result.error())));
            return ExitCode::CryptoError;
        }
        
        ciphertext = std::move(*result);
        
    } else {
        print_error("No encryption method specified. Use --key, --password, or --public-key");
        return ExitCode::InvalidArguments;
    }
    
    // Write output
    std::ofstream out_file(output_file, std::ios::binary);
    if (!out_file) {
        print_error(std::format("Cannot write to: {}", output_file));
        return ExitCode::FileError;
    }
    
    out_file.write(reinterpret_cast<const char*>(ciphertext.data()),
                   static_cast<std::streamsize>(ciphertext.size()));
    
    print_success(std::format("Encrypted {} bytes -> {}", plaintext.size(), output_file));
    
    return ExitCode::Success;
}

// ============================================================================
// Decrypt Command
// ============================================================================

ExitCode cmd_decrypt(const ParsedArgs& args) {
    if (args.positional.empty()) {
        print_error("Missing input file. Use: secura decrypt <file>");
        return ExitCode::InvalidArguments;
    }
    
    std::string input_file = args.positional[0];
    
    // Read input file
    std::ifstream file(input_file, std::ios::binary | std::ios::ate);
    if (!file) {
        print_error(std::format("Cannot open file: {}", input_file));
        return ExitCode::FileError;
    }
    
    auto size = file.tellg();
    file.seekg(0);
    ByteBuffer ciphertext(static_cast<std::size_t>(size));
    file.read(reinterpret_cast<char*>(ciphertext.data()), size);
    file.close();
    
    ByteBuffer plaintext;
    
    // Determine decryption method
    if (args.private_key) {
        // RSA hybrid decryption
        Result<RsaKeyPair> keypair;
        
        // Check if key is encrypted
        std::ifstream key_check(*args.private_key);
        std::string first_line;
        std::getline(key_check, first_line);
        key_check.close();
        
        if (first_line.find("ENCRYPTED") != std::string::npos) {
            std::string password = read_password("Enter private key password: ");
            keypair = RsaKeyPair::load_private_key_encrypted(*args.private_key, password);
        } else {
            keypair = RsaKeyPair::load_private_key(*args.private_key);
        }
        
        if (!keypair) {
            print_error(std::format("Failed to load private key: {}",
                        error_to_string(keypair.error())));
            return ExitCode::KeyError;
        }
        
        auto result = RsaDecryptor::hybrid_decrypt_serialized(ciphertext, *keypair);
        if (!result) {
            print_error(std::format("Decryption failed: {}",
                        error_to_string(result.error())));
            return ExitCode::CryptoError;
        }
        
        plaintext = std::move(*result);
        
    } else if (args.use_password) {
        // Password-based decryption
        std::string password = read_password("Enter password: ");
        
        auto result = Decryptor::decrypt_with_password(ciphertext, password);
        if (!result) {
            print_error(std::format("Decryption failed: {}",
                        error_to_string(result.error())));
            return ExitCode::CryptoError;
        }
        
        plaintext = std::move(*result);
        
    } else if (args.key_file) {
        // AES key file decryption
        std::ifstream key_file(*args.key_file, std::ios::binary);
        if (!key_file) {
            print_error(std::format("Cannot open key file: {}", *args.key_file));
            return ExitCode::KeyError;
        }
        
        ByteBuffer key(constants::AES_KEY_SIZE);
        key_file.read(reinterpret_cast<char*>(key.data()),
                      static_cast<std::streamsize>(key.size()));
        
        if (key_file.gcount() != static_cast<std::streamsize>(constants::AES_KEY_SIZE)) {
            print_error("Invalid key file (must be 32 bytes)");
            return ExitCode::KeyError;
        }
        
        auto result = Decryptor::decrypt(ciphertext, key);
        if (!result) {
            print_error(std::format("Decryption failed: {}",
                        error_to_string(result.error())));
            return ExitCode::CryptoError;
        }
        
        plaintext = std::move(*result);
        
    } else {
        print_error("No decryption method specified. Use --key, --password, or --private-key");
        return ExitCode::InvalidArguments;
    }
    
    // Output result
    if (args.text_mode || !args.output) {
        // Output to stdout as text
        std::string text(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        
        if (args.output) {
            std::ofstream out(*args.output);
            out << text;
            print_success(std::format("Decrypted to: {}", *args.output));
        } else if (args.text_mode) {
            std::cout << text << "\n";
        } else {
            // Default: write to .dec file
            std::string out_file = input_file;
            if (out_file.ends_with(".enc")) {
                out_file = out_file.substr(0, out_file.size() - 4);
            } else {
                out_file += ".dec";
            }
            
            std::ofstream out(out_file, std::ios::binary);
            out.write(reinterpret_cast<const char*>(plaintext.data()),
                      static_cast<std::streamsize>(plaintext.size()));
            print_success(std::format("Decrypted {} bytes -> {}", plaintext.size(), out_file));
        }
    } else {
        std::ofstream out(*args.output, std::ios::binary);
        if (!out) {
            print_error(std::format("Cannot write to: {}", *args.output));
            return ExitCode::FileError;
        }
        
        out.write(reinterpret_cast<const char*>(plaintext.data()),
                  static_cast<std::streamsize>(plaintext.size()));
        print_success(std::format("Decrypted {} bytes -> {}", plaintext.size(), *args.output));
    }
    
    return ExitCode::Success;
}

// ============================================================================
// Main Entry Point
// ============================================================================

ExitCode run(std::span<char*> args) {
    if (args.size() < 2) {
        cmd_help({});
        return ExitCode::InvalidArguments;
    }
    
    ParsedArgs parsed = parse_args(args);
    
    // Handle help flag on any command
    if (parsed.help) {
        return cmd_help(parsed);
    }
    
    // Dispatch to command handlers
    if (parsed.command == "help") {
        return cmd_help(parsed);
    } else if (parsed.command == "version" || parsed.command == "--version" || parsed.command == "-V") {
        return cmd_version();
    } else if (parsed.command == "keygen") {
        return cmd_keygen(parsed);
    } else if (parsed.command == "encrypt") {
        return cmd_encrypt(parsed);
    } else if (parsed.command == "decrypt") {
        return cmd_decrypt(parsed);
    } else {
        print_error(std::format("Unknown command: '{}'. Use 'secura help' for usage.", 
                    parsed.command));
        return ExitCode::InvalidArguments;
    }
}

} // namespace secura::cli
