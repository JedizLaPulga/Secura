# 🔐 Secura

**Secura** is a lightweight encryption tool built with **modern C++23**, featuring both a robust CLI and a modern GUI. It uses trusted cryptographic libraries like **AES** and **RSA** to protect files and text, combining speed, reliability, and ease of use.

> *With Secura, privacy becomes effortless—your personal vault for the digital age.*

---

## ✨ Features

- 🔒 **AES-256-GCM** symmetric encryption for files and text
- 🔑 **RSA-2048/4096** asymmetric encryption for key exchange
- 📁 **File encryption/decryption** with secure key management
- 📝 **Text encryption/decryption** for quick secure messaging
- 🖥️ **Modern GUI** with dark mode (built with Dear ImGui)
- 💻 **Command-line Interface (CLI)** for automation
- 🛡️ **Modern C++23** with strict type safety and memory safety
- ⚡ **Zero-allocation secure buffers** for sensitive data

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Language** | C++23 |
| **Build System** | CMake 3.25+ |
| **Package Manager** | vcpkg (manifest mode) |
| **Crypto Library** | OpenSSL 3.x |
| **GUI Library** | Dear ImGui + DirectX 11 |
| **Testing** | GoogleTest |
| **Formatting** | fmt library |
| **Compiler** | MSVC (VS 2022/2026) |

---

## 📦 Prerequisites

Before building Secura, ensure you have:

1. **Visual Studio 2022/2026** with C++ desktop development workload
2. **CMake 3.25+**
3. **Git**
4. **vcpkg** set up and integrated

---

## 🚀 Getting Started

### 1. Build the Project

```powershell
# Clone
git clone https://github.com/yourusername/Secura.git
cd Secura

# Configure (automatically installs dependencies via vcpkg)
cmake --preset default

# Build
cmake --build build/debug
```

### 2. Run the GUI

```powershell
.\build\debug\Debug\secura_gui.exe
```

### 3. Run the CLI

```powershell
# Help
.\build\debug\Debug\secura.exe help

# Generate Key
.\build\debug\Debug\secura.exe keygen --type=aes --output=my.key

# Encrypt
.\build\debug\Debug\secura.exe encrypt file.txt --key=my.key
```

---

## 📁 Project Structure

```
Secura/
├── CMakeLists.txt          # Main build configuration
├── vcpkg.json              # Dependencies manifest
├── src/
│   ├── main.cpp            # CLI entry point
│   ├── cli.cpp             # CLI implementation
│   ├── gui_main.cpp        # GUI entry point
│   ├── gui.cpp             # GUI implementation
│   ├── key_manager.cpp     # Key generation logic
│   ├── encryptor.cpp       # AES encryption
│   └── rsa_*.cpp           # RSA implementation
├── include/secura/         # Header files
├── tests/                  # Unit tests (GoogleTest)
└── assets/                 # Resources
```

---

## 🤝 Contributing

Contributions are welcome! Please follow the code style (Modern C++23) and ensure all tests pass before submitting a PR.

```powershell
# Run tests
ctest --preset default --output-on-failure
```

---

## 📄 License

This project is licensed under the **MIT License**.

---

## 👤 Author

**Joel Emeka**

<p align="center">
  <i>Built with ❤️ using Modern C++23</i>
</p>
