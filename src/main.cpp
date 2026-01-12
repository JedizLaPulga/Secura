// ============================================================================
// Secura - Main Entry Point
// ============================================================================
// A lightweight encryption tool built with modern C++23.
//
// Usage:
//   secura <command> [options]
//
// Run 'secura help' for more information.
// ============================================================================

#include "secura/cli.hpp"
#include <span>

int main(int argc, char* argv[]) {
    auto result = secura::cli::run(std::span(argv, static_cast<std::size_t>(argc)));
    return static_cast<int>(result);
}
