// ============================================================================
// Secura - GUI Application Implementation
// ============================================================================

#include "secura/gui.hpp"
#include "secura/crypto.hpp"

// Dear ImGui
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

// DirectX
#include <d3d11.h>
#include <tchar.h>

// Windows
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>

// Standard library
#include <fstream>
#include <format>
#include <filesystem>
#include <algorithm>

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace secura::gui {

// ============================================================================
// DirectX 11 Globals
// ============================================================================

static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

// Forward declarations
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ============================================================================
// Application State
// ============================================================================

struct AppData {
    AppState current_state = AppState::Home;
    AppConfig config;
    
    // Status message
    std::string status_message;
    MessageType status_type = MessageType::Info;
    float status_timer = 0.0f;
    
    // Key Generation
    int keygen_type = 0;  // 0 = AES, 1 = RSA
    int rsa_key_size = 0; // 0 = 2048, 1 = 4096
    char keygen_output[256] = "";
    char keygen_password[256] = "";
    bool keygen_use_password = false;
    
    // Encryption
    char encrypt_input_file[512] = "";
    char encrypt_output_file[512] = "";
    char encrypt_key_file[512] = "";
    char encrypt_password[256] = "";
    int encrypt_method = 0;  // 0 = AES Key, 1 = Password, 2 = RSA
    
    // Decryption
    char decrypt_input_file[512] = "";
    char decrypt_output_file[512] = "";
    char decrypt_key_file[512] = "";
    char decrypt_password[256] = "";
    int decrypt_method = 0;
    
    // Text mode
    char text_input[4096] = "";
    char text_output[4096] = "";
    bool text_mode = false;
};

static AppData g_app;

// ============================================================================
// Utility Functions
// ============================================================================

void SetStatus(const std::string& message, MessageType type) {
    g_app.status_message = message;
    g_app.status_type = type;
    g_app.status_timer = 5.0f;
}

std::string OpenFileDialog(const char* filter, const char* title) {
    char filename[MAX_PATH] = "";
    
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    
    if (GetOpenFileNameA(&ofn)) {
        return std::string(filename);
    }
    return "";
}

std::string SaveFileDialog(const char* filter, const char* title, const char* default_ext) {
    char filename[MAX_PATH] = "";
    
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.lpstrDefExt = default_ext;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    
    if (GetSaveFileNameA(&ofn)) {
        return std::string(filename);
    }
    return "";
}

// ============================================================================
// Styling
// ============================================================================

void SetupStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    
    // Modern rounded look
    style.WindowRounding = 8.0f;
    style.FrameRounding = 6.0f;
    style.PopupRounding = 6.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 6.0f;
    
    style.WindowPadding = ImVec2(16, 16);
    style.FramePadding = ImVec2(12, 8);
    style.ItemSpacing = ImVec2(12, 8);
    style.ItemInnerSpacing = ImVec2(8, 6);
    
    style.WindowBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;
    style.PopupBorderSize = 1.0f;
    
    // Dark theme with accent colors
    ImVec4* colors = style.Colors;
    
    // Background
    colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.10f, 0.12f, 1.00f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.12f, 0.12f, 0.14f, 0.98f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
    
    // Headers
    colors[ImGuiCol_Header] = ImVec4(0.20f, 0.45f, 0.70f, 0.55f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.25f, 0.55f, 0.85f, 0.80f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.30f, 0.60f, 0.90f, 1.00f);
    
    // Buttons - Teal/Cyan accent
    colors[ImGuiCol_Button] = ImVec4(0.15f, 0.50f, 0.55f, 0.80f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.20f, 0.60f, 0.65f, 1.00f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.25f, 0.70f, 0.75f, 1.00f);
    
    // Frame
    colors[ImGuiCol_FrameBg] = ImVec4(0.15f, 0.15f, 0.18f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.20f, 0.25f, 1.00f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.25f, 0.25f, 0.30f, 1.00f);
    
    // Title
    colors[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
    colors[ImGuiCol_TitleBgActive] = ImVec4(0.12f, 0.35f, 0.50f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.08f, 0.08f, 0.10f, 0.75f);
    
    // Tabs
    colors[ImGuiCol_Tab] = ImVec4(0.15f, 0.15f, 0.18f, 1.00f);
    colors[ImGuiCol_TabHovered] = ImVec4(0.25f, 0.55f, 0.65f, 0.80f);
    colors[ImGuiCol_TabActive] = ImVec4(0.20f, 0.50f, 0.60f, 1.00f);
    colors[ImGuiCol_TabUnfocused] = ImVec4(0.12f, 0.12f, 0.14f, 1.00f);
    colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.18f, 0.40f, 0.50f, 1.00f);
    
    // Scrollbar
    colors[ImGuiCol_ScrollbarBg] = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
    colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.25f, 0.25f, 0.30f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.35f, 0.35f, 0.40f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.45f, 0.45f, 0.50f, 1.00f);
    
    // Separator
    colors[ImGuiCol_Separator] = ImVec4(0.30f, 0.30f, 0.35f, 0.50f);
    colors[ImGuiCol_SeparatorHovered] = ImVec4(0.40f, 0.60f, 0.70f, 0.78f);
    colors[ImGuiCol_SeparatorActive] = ImVec4(0.40f, 0.60f, 0.70f, 1.00f);
    
    // Text
    colors[ImGuiCol_Text] = ImVec4(0.95f, 0.95f, 0.95f, 1.00f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.55f, 1.00f);
    
    // Border
    colors[ImGuiCol_Border] = ImVec4(0.30f, 0.30f, 0.35f, 0.50f);
    colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    
    // Check/Radio
    colors[ImGuiCol_CheckMark] = ImVec4(0.35f, 0.80f, 0.85f, 1.00f);
    
    // Slider
    colors[ImGuiCol_SliderGrab] = ImVec4(0.30f, 0.65f, 0.75f, 1.00f);
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.40f, 0.75f, 0.85f, 1.00f);
}

// ============================================================================
// UI Panels
// ============================================================================

void RenderStatusBar() {
    if (g_app.status_timer > 0) {
        ImVec4 color;
        switch (g_app.status_type) {
            case MessageType::Success:
                color = ImVec4(0.2f, 0.8f, 0.4f, 1.0f);
                break;
            case MessageType::Warning:
                color = ImVec4(0.9f, 0.7f, 0.2f, 1.0f);
                break;
            case MessageType::Error:
                color = ImVec4(0.9f, 0.3f, 0.3f, 1.0f);
                break;
            default:
                color = ImVec4(0.5f, 0.7f, 0.9f, 1.0f);
        }
        
        ImGui::PushStyleColor(ImGuiCol_Text, color);
        ImGui::Text("%s", g_app.status_message.c_str());
        ImGui::PopStyleColor();
        
        g_app.status_timer -= ImGui::GetIO().DeltaTime;
    }
}

void RenderSidebar() {
    ImGui::BeginChild("Sidebar", ImVec2(200, 0), true);
    
    // Logo/Title
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);
    ImGui::TextColored(ImVec4(0.35f, 0.80f, 0.85f, 1.0f), "SECURA");
    ImGui::PopFont();
    ImGui::TextDisabled("v%s", VERSION_STRING);
    
    ImGui::Separator();
    ImGui::Spacing();
    
    // Navigation
    ImGui::TextDisabled("NAVIGATION");
    ImGui::Spacing();
    
    if (ImGui::Selectable("  Home", g_app.current_state == AppState::Home)) {
        g_app.current_state = AppState::Home;
    }
    
    if (ImGui::Selectable("  Key Generation", g_app.current_state == AppState::KeyGeneration)) {
        g_app.current_state = AppState::KeyGeneration;
    }
    
    if (ImGui::Selectable("  Encrypt", g_app.current_state == AppState::Encryption)) {
        g_app.current_state = AppState::Encryption;
    }
    
    if (ImGui::Selectable("  Decrypt", g_app.current_state == AppState::Decryption)) {
        g_app.current_state = AppState::Decryption;
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Quick stats
    ImGui::TextDisabled("ALGORITHMS");
    ImGui::Spacing();
    ImGui::BulletText("AES-256-GCM");
    ImGui::BulletText("RSA-2048/4096");
    ImGui::BulletText("PBKDF2-SHA256");
    
    ImGui::EndChild();
}

void RenderHomePanel() {
    ImGui::TextColored(ImVec4(0.35f, 0.80f, 0.85f, 1.0f), "Welcome to Secura");
    ImGui::Spacing();
    ImGui::TextWrapped(
        "A lightweight encryption tool built with modern C++23. "
        "Secura provides military-grade encryption using AES-256-GCM and RSA."
    );
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Quick actions
    ImGui::Text("Quick Actions:");
    ImGui::Spacing();
    
    if (ImGui::Button("Generate AES Key", ImVec2(180, 40))) {
        g_app.current_state = AppState::KeyGeneration;
        g_app.keygen_type = 0;
    }
    
    ImGui::SameLine();
    
    if (ImGui::Button("Generate RSA Keys", ImVec2(180, 40))) {
        g_app.current_state = AppState::KeyGeneration;
        g_app.keygen_type = 1;
    }
    
    ImGui::SameLine();
    
    if (ImGui::Button("Encrypt File", ImVec2(180, 40))) {
        g_app.current_state = AppState::Encryption;
    }
    
    ImGui::SameLine();
    
    if (ImGui::Button("Decrypt File", ImVec2(180, 40))) {
        g_app.current_state = AppState::Decryption;
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Features
    ImGui::Text("Features:");
    ImGui::Spacing();
    
    ImGui::BeginChild("Features", ImVec2(0, 200), true);
    
    ImGui::BulletText("AES-256-GCM authenticated encryption");
    ImGui::BulletText("RSA-2048/4096 with OAEP-SHA256 padding");
    ImGui::BulletText("Password-based key derivation (PBKDF2, 600,000 iterations)");
    ImGui::BulletText("Secure memory handling (keys zeroed on destruction)");
    ImGui::BulletText("Tampering detection (authentication tags)");
    ImGui::BulletText("Hybrid encryption (RSA + AES for large files)");
    ImGui::BulletText("PEM key import/export");
    ImGui::BulletText("Password-protected private keys");
    
    ImGui::EndChild();
}

void RenderKeyGenPanel() {
    ImGui::TextColored(ImVec4(0.35f, 0.80f, 0.85f, 1.0f), "Key Generation");
    ImGui::Spacing();
    ImGui::TextWrapped("Generate cryptographic keys for encryption.");
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Key type selection
    ImGui::Text("Key Type:");
    ImGui::RadioButton("AES-256 (Symmetric)", &g_app.keygen_type, 0);
    ImGui::SameLine();
    ImGui::RadioButton("RSA (Asymmetric)", &g_app.keygen_type, 1);
    
    ImGui::Spacing();
    
    if (g_app.keygen_type == 1) {
        // RSA options
        ImGui::Text("RSA Key Size:");
        ImGui::RadioButton("2048 bits (faster)", &g_app.rsa_key_size, 0);
        ImGui::SameLine();
        ImGui::RadioButton("4096 bits (more secure)", &g_app.rsa_key_size, 1);
        
        ImGui::Spacing();
        
        ImGui::Checkbox("Password-protect private key", &g_app.keygen_use_password);
        
        if (g_app.keygen_use_password) {
            ImGui::InputText("Password##keygen", g_app.keygen_password, 
                           sizeof(g_app.keygen_password), ImGuiInputTextFlags_Password);
        }
    }
    
    ImGui::Spacing();
    
    // Output file
    ImGui::Text("Output File:");
    ImGui::InputText("##keygen_output", g_app.keygen_output, sizeof(g_app.keygen_output));
    ImGui::SameLine();
    if (ImGui::Button("Browse##keygen")) {
        std::string ext = (g_app.keygen_type == 0) ? "key" : "";
        std::string filter = (g_app.keygen_type == 0) 
            ? "Key Files (*.key)\0*.key\0All Files (*.*)\0*.*\0"
            : "All Files (*.*)\0*.*\0";
        std::string path = SaveFileDialog(filter.c_str(), "Save Key", ext.c_str());
        if (!path.empty()) {
            strncpy_s(g_app.keygen_output, path.c_str(), sizeof(g_app.keygen_output) - 1);
        }
    }
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // Generate button
    if (ImGui::Button("Generate Key", ImVec2(200, 45))) {
        if (strlen(g_app.keygen_output) == 0) {
            SetStatus("Please specify an output file", MessageType::Error);
        } else if (g_app.keygen_type == 0) {
            // Generate AES key
            auto result = KeyManager::generate_key();
            if (result) {
                std::ofstream file(g_app.keygen_output, std::ios::binary);
                if (file) {
                    file.write(reinterpret_cast<const char*>(result->data()), 
                              static_cast<std::streamsize>(result->size()));
                    SetStatus("AES-256 key generated successfully!", MessageType::Success);
                } else {
                    SetStatus("Failed to write key file", MessageType::Error);
                }
            } else {
                SetStatus("Key generation failed", MessageType::Error);
            }
        } else {
            // Generate RSA key pair
            RsaKeySize size = (g_app.rsa_key_size == 0) ? RsaKeySize::Bits2048 : RsaKeySize::Bits4096;
            SetStatus("Generating RSA key pair...", MessageType::Info);
            
            auto result = RsaKeyPair::generate(size);
            if (result) {
                std::string base_path = g_app.keygen_output;
                
                // Save public key
                auto pub_result = result->save_public_key(base_path + ".pub");
                
                // Save private key
                VoidResult priv_result;
                if (g_app.keygen_use_password && strlen(g_app.keygen_password) > 0) {
                    priv_result = result->save_private_key_encrypted(
                        base_path + ".pem", g_app.keygen_password);
                } else {
                    priv_result = result->save_private_key(base_path + ".pem");
                }
                
                if (pub_result && priv_result) {
                    SetStatus("RSA key pair generated successfully!", MessageType::Success);
                } else {
                    SetStatus("Failed to save key files", MessageType::Error);
                }
            } else {
                SetStatus("RSA key generation failed", MessageType::Error);
            }
        }
    }
    
    ImGui::Spacing();
    
    // Help text
    if (g_app.keygen_type == 0) {
        ImGui::TextWrapped(
            "AES-256 generates a 32-byte symmetric key. "
            "Keep this key secret - anyone with it can encrypt and decrypt your data."
        );
    } else {
        ImGui::TextWrapped(
            "RSA generates a public/private key pair. "
            "Share the .pub file with others. Keep the .pem file secret!"
        );
    }
}

void RenderEncryptPanel() {
    ImGui::TextColored(ImVec4(0.35f, 0.80f, 0.85f, 1.0f), "Encrypt");
    ImGui::Spacing();
    ImGui::TextWrapped("Encrypt files or text using AES-256-GCM or RSA hybrid encryption.");
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Method selection
    ImGui::Text("Encryption Method:");
    ImGui::RadioButton("AES Key File", &g_app.encrypt_method, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Password", &g_app.encrypt_method, 1);
    ImGui::SameLine();
    ImGui::RadioButton("RSA Public Key", &g_app.encrypt_method, 2);
    
    ImGui::Spacing();
    
    // Mode toggle
    ImGui::Checkbox("Text Mode", &g_app.text_mode);
    
    ImGui::Spacing();
    
    if (g_app.text_mode) {
        // Text input
        ImGui::Text("Text to Encrypt:");
        ImGui::InputTextMultiline("##text_input", g_app.text_input, sizeof(g_app.text_input),
                                  ImVec2(-1, 150));
    } else {
        // File input
        ImGui::Text("Input File:");
        ImGui::InputText("##encrypt_input", g_app.encrypt_input_file, sizeof(g_app.encrypt_input_file));
        ImGui::SameLine();
        if (ImGui::Button("Browse##enc_in")) {
            std::string path = OpenFileDialog("All Files (*.*)\0*.*\0", "Select File to Encrypt");
            if (!path.empty()) {
                strncpy_s(g_app.encrypt_input_file, path.c_str(), sizeof(g_app.encrypt_input_file) - 1);
                // Auto-fill output
                std::string out = path + ".enc";
                strncpy_s(g_app.encrypt_output_file, out.c_str(), sizeof(g_app.encrypt_output_file) - 1);
            }
        }
        
        ImGui::Text("Output File:");
        ImGui::InputText("##encrypt_output", g_app.encrypt_output_file, sizeof(g_app.encrypt_output_file));
        ImGui::SameLine();
        if (ImGui::Button("Browse##enc_out")) {
            std::string path = SaveFileDialog("Encrypted Files (*.enc)\0*.enc\0All Files (*.*)\0*.*\0", 
                                             "Save Encrypted File", "enc");
            if (!path.empty()) {
                strncpy_s(g_app.encrypt_output_file, path.c_str(), sizeof(g_app.encrypt_output_file) - 1);
            }
        }
    }
    
    ImGui::Spacing();
    
    // Key/Password input based on method
    if (g_app.encrypt_method == 0) {
        ImGui::Text("AES Key File:");
        ImGui::InputText("##encrypt_key", g_app.encrypt_key_file, sizeof(g_app.encrypt_key_file));
        ImGui::SameLine();
        if (ImGui::Button("Browse##enc_key")) {
            std::string path = OpenFileDialog("Key Files (*.key)\0*.key\0All Files (*.*)\0*.*\0", 
                                             "Select Key File");
            if (!path.empty()) {
                strncpy_s(g_app.encrypt_key_file, path.c_str(), sizeof(g_app.encrypt_key_file) - 1);
            }
        }
    } else if (g_app.encrypt_method == 1) {
        ImGui::Text("Password:");
        ImGui::InputText("##encrypt_password", g_app.encrypt_password, sizeof(g_app.encrypt_password),
                        ImGuiInputTextFlags_Password);
    } else {
        ImGui::Text("RSA Public Key:");
        ImGui::InputText("##encrypt_pubkey", g_app.encrypt_key_file, sizeof(g_app.encrypt_key_file));
        ImGui::SameLine();
        if (ImGui::Button("Browse##enc_pub")) {
            std::string path = OpenFileDialog("Public Key (*.pub)\0*.pub\0PEM Files (*.pem)\0*.pem\0All Files (*.*)\0*.*\0", 
                                             "Select Public Key");
            if (!path.empty()) {
                strncpy_s(g_app.encrypt_key_file, path.c_str(), sizeof(g_app.encrypt_key_file) - 1);
            }
        }
    }
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // Encrypt button
    if (ImGui::Button("Encrypt", ImVec2(200, 45))) {
        ByteBuffer plaintext;
        
        if (g_app.text_mode) {
            std::string text = g_app.text_input;
            plaintext.assign(reinterpret_cast<const Byte*>(text.data()),
                           reinterpret_cast<const Byte*>(text.data() + text.size()));
        } else {
            if (strlen(g_app.encrypt_input_file) == 0) {
                SetStatus("Please select an input file", MessageType::Error);
                return;
            }
            std::ifstream file(g_app.encrypt_input_file, std::ios::binary | std::ios::ate);
            if (!file) {
                SetStatus("Cannot open input file", MessageType::Error);
                return;
            }
            auto size = file.tellg();
            file.seekg(0);
            plaintext.resize(static_cast<std::size_t>(size));
            file.read(reinterpret_cast<char*>(plaintext.data()), size);
        }
        
        if (plaintext.empty()) {
            SetStatus("No data to encrypt", MessageType::Error);
            return;
        }
        
        Result<ByteBuffer> result = std::unexpected(ErrorCode::InternalError);
        
        if (g_app.encrypt_method == 0) {
            // AES key file
            std::ifstream key_file(g_app.encrypt_key_file, std::ios::binary);
            if (!key_file) {
                SetStatus("Cannot open key file", MessageType::Error);
                return;
            }
            ByteBuffer key(constants::AES_KEY_SIZE);
            key_file.read(reinterpret_cast<char*>(key.data()), 
                         static_cast<std::streamsize>(key.size()));
            result = Encryptor::encrypt(plaintext, key);
            
        } else if (g_app.encrypt_method == 1) {
            // Password
            result = Encryptor::encrypt_with_password(plaintext, g_app.encrypt_password);
            
        } else {
            // RSA hybrid
            auto keypair = RsaKeyPair::load_public_key(g_app.encrypt_key_file);
            if (!keypair) {
                SetStatus("Cannot load public key", MessageType::Error);
                return;
            }
            auto hybrid = RsaEncryptor::hybrid_encrypt(plaintext, *keypair);
            if (hybrid) {
                result = RsaEncryptor::serialize_hybrid_data(*hybrid);
            }
        }
        
        if (result) {
            if (g_app.text_mode) {
                // Show as hex for text mode
                std::string hex;
                for (auto b : *result) {
                    hex += std::format("{:02x}", b);
                }
                strncpy_s(g_app.text_output, hex.c_str(), sizeof(g_app.text_output) - 1);
                SetStatus("Text encrypted successfully!", MessageType::Success);
            } else {
                std::ofstream out(g_app.encrypt_output_file, std::ios::binary);
                if (out) {
                    out.write(reinterpret_cast<const char*>(result->data()),
                             static_cast<std::streamsize>(result->size()));
                    SetStatus(std::format("Encrypted {} bytes", plaintext.size()), MessageType::Success);
                } else {
                    SetStatus("Cannot write output file", MessageType::Error);
                }
            }
        } else {
            SetStatus(std::string(error_to_string(result.error())), MessageType::Error);
        }
    }
    
    // Text output for text mode
    if (g_app.text_mode && strlen(g_app.text_output) > 0) {
        ImGui::Spacing();
        ImGui::Text("Encrypted (Hex):");
        ImGui::InputTextMultiline("##text_output", g_app.text_output, sizeof(g_app.text_output),
                                  ImVec2(-1, 100), ImGuiInputTextFlags_ReadOnly);
    }
}

void RenderDecryptPanel() {
    ImGui::TextColored(ImVec4(0.35f, 0.80f, 0.85f, 1.0f), "Decrypt");
    ImGui::Spacing();
    ImGui::TextWrapped("Decrypt files encrypted with Secura.");
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Method selection
    ImGui::Text("Decryption Method:");
    ImGui::RadioButton("AES Key File##dec", &g_app.decrypt_method, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Password##dec", &g_app.decrypt_method, 1);
    ImGui::SameLine();
    ImGui::RadioButton("RSA Private Key##dec", &g_app.decrypt_method, 2);
    
    ImGui::Spacing();
    
    // Input file
    ImGui::Text("Encrypted File:");
    ImGui::InputText("##decrypt_input", g_app.decrypt_input_file, sizeof(g_app.decrypt_input_file));
    ImGui::SameLine();
    if (ImGui::Button("Browse##dec_in")) {
        std::string path = OpenFileDialog("Encrypted Files (*.enc)\0*.enc\0All Files (*.*)\0*.*\0", 
                                         "Select File to Decrypt");
        if (!path.empty()) {
            strncpy_s(g_app.decrypt_input_file, path.c_str(), sizeof(g_app.decrypt_input_file) - 1);
            // Auto-fill output
            std::string out = path;
            if (out.ends_with(".enc")) {
                out = out.substr(0, out.size() - 4);
            } else {
                out += ".dec";
            }
            strncpy_s(g_app.decrypt_output_file, out.c_str(), sizeof(g_app.decrypt_output_file) - 1);
        }
    }
    
    ImGui::Text("Output File:");
    ImGui::InputText("##decrypt_output", g_app.decrypt_output_file, sizeof(g_app.decrypt_output_file));
    ImGui::SameLine();
    if (ImGui::Button("Browse##dec_out")) {
        std::string path = SaveFileDialog("All Files (*.*)\0*.*\0", "Save Decrypted File", "");
        if (!path.empty()) {
            strncpy_s(g_app.decrypt_output_file, path.c_str(), sizeof(g_app.decrypt_output_file) - 1);
        }
    }
    
    ImGui::Spacing();
    
    // Key/Password input based on method
    if (g_app.decrypt_method == 0) {
        ImGui::Text("AES Key File:");
        ImGui::InputText("##decrypt_key", g_app.decrypt_key_file, sizeof(g_app.decrypt_key_file));
        ImGui::SameLine();
        if (ImGui::Button("Browse##dec_key")) {
            std::string path = OpenFileDialog("Key Files (*.key)\0*.key\0All Files (*.*)\0*.*\0", 
                                             "Select Key File");
            if (!path.empty()) {
                strncpy_s(g_app.decrypt_key_file, path.c_str(), sizeof(g_app.decrypt_key_file) - 1);
            }
        }
    } else if (g_app.decrypt_method == 1) {
        ImGui::Text("Password:");
        ImGui::InputText("##decrypt_password", g_app.decrypt_password, sizeof(g_app.decrypt_password),
                        ImGuiInputTextFlags_Password);
    } else {
        ImGui::Text("RSA Private Key:");
        ImGui::InputText("##decrypt_privkey", g_app.decrypt_key_file, sizeof(g_app.decrypt_key_file));
        ImGui::SameLine();
        if (ImGui::Button("Browse##dec_priv")) {
            std::string path = OpenFileDialog("PEM Files (*.pem)\0*.pem\0All Files (*.*)\0*.*\0", 
                                             "Select Private Key");
            if (!path.empty()) {
                strncpy_s(g_app.decrypt_key_file, path.c_str(), sizeof(g_app.decrypt_key_file) - 1);
            }
        }
    }
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // Decrypt button
    if (ImGui::Button("Decrypt", ImVec2(200, 45))) {
        if (strlen(g_app.decrypt_input_file) == 0) {
            SetStatus("Please select an input file", MessageType::Error);
            return;
        }
        
        // Read input file
        std::ifstream file(g_app.decrypt_input_file, std::ios::binary | std::ios::ate);
        if (!file) {
            SetStatus("Cannot open input file", MessageType::Error);
            return;
        }
        
        auto size = file.tellg();
        file.seekg(0);
        ByteBuffer ciphertext(static_cast<std::size_t>(size));
        file.read(reinterpret_cast<char*>(ciphertext.data()), size);
        file.close();
        
        Result<ByteBuffer> result = std::unexpected(ErrorCode::InternalError);
        
        if (g_app.decrypt_method == 0) {
            // AES key file
            std::ifstream key_file(g_app.decrypt_key_file, std::ios::binary);
            if (!key_file) {
                SetStatus("Cannot open key file", MessageType::Error);
                return;
            }
            ByteBuffer key(constants::AES_KEY_SIZE);
            key_file.read(reinterpret_cast<char*>(key.data()),
                         static_cast<std::streamsize>(key.size()));
            result = Decryptor::decrypt(ciphertext, key);
            
        } else if (g_app.decrypt_method == 1) {
            // Password
            result = Decryptor::decrypt_with_password(ciphertext, g_app.decrypt_password);
            
        } else {
            // RSA hybrid
            auto keypair = RsaKeyPair::load_private_key(g_app.decrypt_key_file);
            if (!keypair) {
                SetStatus("Cannot load private key", MessageType::Error);
                return;
            }
            result = RsaDecryptor::hybrid_decrypt_serialized(ciphertext, *keypair);
        }
        
        if (result) {
            std::ofstream out(g_app.decrypt_output_file, std::ios::binary);
            if (out) {
                out.write(reinterpret_cast<const char*>(result->data()),
                         static_cast<std::streamsize>(result->size()));
                SetStatus(std::format("Decrypted {} bytes", result->size()), MessageType::Success);
            } else {
                SetStatus("Cannot write output file", MessageType::Error);
            }
        } else {
            SetStatus(std::string(error_to_string(result.error())), MessageType::Error);
        }
    }
}

// ============================================================================
// Main Render
// ============================================================================

void RenderUI() {
    // Main window
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    
    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                                    ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                                    ImGuiWindowFlags_NoBringToFrontOnFocus;
    
    ImGui::Begin("Secura", nullptr, window_flags);
    
    // Sidebar
    RenderSidebar();
    
    ImGui::SameLine();
    
    // Main content
    ImGui::BeginChild("Content", ImVec2(0, -30), true);
    
    switch (g_app.current_state) {
        case AppState::Home:
            RenderHomePanel();
            break;
        case AppState::KeyGeneration:
            RenderKeyGenPanel();
            break;
        case AppState::Encryption:
            RenderEncryptPanel();
            break;
        case AppState::Decryption:
            RenderDecryptPanel();
            break;
        default:
            RenderHomePanel();
            break;
    }
    
    ImGui::EndChild();
    
    // Status bar
    RenderStatusBar();
    
    ImGui::End();
}

// ============================================================================
// DirectX 11 Functions
// ============================================================================

bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 
                                                 createDeviceFlags, featureLevelArray, 2, 
                                                 D3D11_SDK_VERSION, &sd, &g_pSwapChain, 
                                                 &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED) {
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 
                                            createDeviceFlags, featureLevelArray, 2,
                                            D3D11_SDK_VERSION, &sd, &g_pSwapChain, 
                                            &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    }
    if (res != S_OK) return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED)
                return 0;
            g_ResizeWidth = (UINT)LOWORD(lParam);
            g_ResizeHeight = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU)
                return 0;
            break;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================================
// Main Entry Point
// ============================================================================

int run_gui() {
    // Create window class
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, 
                       GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, 
                       L"SecuraWindow", nullptr };
    ::RegisterClassExW(&wc);
    
    // Create window
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Secura - Encryption Tool",
                                WS_OVERLAPPEDWINDOW, 100, 100, 1200, 800,
                                nullptr, nullptr, wc.hInstance, nullptr);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // Setup style
    SetupStyle();
    
    // Load font (larger for better readability)
    io.Fonts->AddFontDefault();
    
    ImVec4 clear_color = ImVec4(0.06f, 0.06f, 0.08f, 1.00f);

    // Main loop
    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done) break;

        // Handle window resize
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Render our UI
        RenderUI();

        // Rendering
        ImGui::Render();
        const float clear_color_with_alpha[4] = { 
            clear_color.x * clear_color.w, clear_color.y * clear_color.w, 
            clear_color.z * clear_color.w, clear_color.w 
        };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

} // namespace secura::gui
