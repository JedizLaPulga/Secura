// ============================================================================
// Secura - Command Line Interface
// ============================================================================
// A command-line tool for encryption and decryption operations.
//
// Usage:
//   secura <command> [options]
//
// Commands:
//   keygen      Generate encryption keys (AES or RSA)
//   encrypt     Encrypt a file or text
//   decrypt     Decrypt a file or text
//   help        Show help information
//   version     Show version information
// ============================================================================

#ifndef SECURA_CLI_HPP
#define SECURA_CLI_HPP

#include "secura/types.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <optional>

namespace secura::cli {

/// Exit codes for the CLI
enum class ExitCode : int {
    Success = 0,
    InvalidArguments = 1,
    FileError = 2,
    CryptoError = 3,
    KeyError = 4,
    InternalError = 5
};

/// CLI argument parser result
struct ParsedArgs {
    std::string command;
    std::vector<std::string> positional;
    
    // Flags
    bool help = false;
    bool verbose = false;
    
    // Options with values
    std::optional<std::string> output;
    std::optional<std::string> key_file;
    std::optional<std::string> password;
    std::optional<std::string> public_key;
    std::optional<std::string> private_key;
    std::optional<std::string> key_type;  // "aes" or "rsa"
    std::optional<int> key_size;          // 2048 or 4096 for RSA
    bool use_password = false;            // Use password-based encryption
    bool text_mode = false;               // Encrypt/decrypt text instead of file
};

/// Parse command line arguments
[[nodiscard]] ParsedArgs parse_args(std::span<char*> args);

/// Main CLI entry point
[[nodiscard]] ExitCode run(std::span<char*> args);

// Command handlers
[[nodiscard]] ExitCode cmd_help(const ParsedArgs& args);
[[nodiscard]] ExitCode cmd_version();
[[nodiscard]] ExitCode cmd_keygen(const ParsedArgs& args);
[[nodiscard]] ExitCode cmd_encrypt(const ParsedArgs& args);
[[nodiscard]] ExitCode cmd_decrypt(const ParsedArgs& args);

// Utility functions
void print_error(std::string_view message);
void print_success(std::string_view message);
void print_info(std::string_view message);

/// Securely read a password from the terminal (hides input)
[[nodiscard]] std::string read_password(std::string_view prompt);

/// Confirm password by reading it twice
[[nodiscard]] std::optional<std::string> read_password_confirmed(std::string_view prompt);

} // namespace secura::cli

#endif // SECURA_CLI_HPP
