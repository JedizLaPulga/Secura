// ============================================================================
// Secura - GUI Application (Dear ImGui)
// ============================================================================
// A graphical interface for the Secura encryption tool.
// Uses Dear ImGui with Win32 + DirectX 11 backend.
// ============================================================================

#ifndef SECURA_GUI_HPP
#define SECURA_GUI_HPP

#include "secura/types.hpp"
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace secura::gui {

/// GUI application state
enum class AppState {
    Home,
    KeyGeneration,
    Encryption,
    Decryption,
    Settings
};

/// Message/notification type
enum class MessageType {
    Info,
    Success,
    Warning,
    Error
};

/// Application configuration
struct AppConfig {
    bool dark_mode = true;
    float font_scale = 1.0f;
    bool show_hex_view = false;
};

/// Run the GUI application
/// @return Exit code
int run_gui();

} // namespace secura::gui

#endif // SECURA_GUI_HPP
