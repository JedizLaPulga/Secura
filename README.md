# 🔐 Secura

**Secura** is a lightweight encryption tool built with **modern C++23** and a simple GUI. It uses trusted cryptographic libraries like **AES** and **RSA** to protect files and text, combining speed, reliability, and ease of use.

> *With Secura, privacy becomes effortless—your personal vault for the digital age.*

---

## ✨ Features

- 🔒 **AES-256-GCM** symmetric encryption for files and text
- 🔑 **RSA-2048/4096** asymmetric encryption for key exchange
- 📁 **File encryption/decryption** with secure key management
- 📝 **Text encryption/decryption** for quick secure messaging
- 🖥️ **Simple GUI** (coming soon)
- 🛡️ **Modern C++23** with strict type safety and memory safety

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Language** | C++23 |
| **Build System** | CMake 3.25+ |
| **Package Manager** | vcpkg (manifest mode) |
| **Crypto Library** | OpenSSL 3.x |
| **Testing** | GoogleTest |
| **Formatting** | fmt library |
| **Compiler** | MSVC (Visual Studio 2026) |

---

## 📦 Prerequisites

Before building Secura, ensure you have:

1. **Visual Studio 2022/2026** with C++ desktop development workload
2. **CMake 3.25+** (bundled with Visual Studio or [download here](https://cmake.org/download/))
3. **Git** ([download here](https://git-scm.com/))
4. **vcpkg** (see setup below)

---

## 🚀 Getting Started

### 1. Clone the Repository

```powershell
git clone https://github.com/yourusername/Secura.git
cd Secura
```

### 2. Set Up vcpkg (One-time)

```powershell
# Clone vcpkg
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg

# Bootstrap vcpkg
C:\vcpkg\bootstrap-vcpkg.bat

# Set environment variable (run as Administrator, then restart terminal)
[Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\vcpkg", "User")
```

### 3. Configure and Build

```powershell
# Configure with CMake (downloads dependencies automatically)
cmake --preset default

# Build
cmake --build build/debug

# Run tests
ctest --preset default
```

### 4. Run Secura

```powershell
.\build\debug\Debug\secura.exe
```

---

## 📁 Project Structure

```
Secura/
├── CMakeLists.txt          # Main build configuration
├── CMakePresets.json       # CMake presets (debug/release)
├── vcpkg.json              # Dependencies manifest
├── src/                    # Source files (.cpp)
│   ├── main.cpp            # Entry point
│   └── ...
├── include/                # Header files (.hpp)
│   └── secura/
│       └── version.hpp
├── tests/                  # Unit tests
├── assets/                 # GUI resources
├── docs/                   # Documentation
└── libs/                   # Third-party libraries (if any)
```

---

## 🔧 Development

### Build Presets

| Preset | Description |
|--------|-------------|
| `default` | Debug build (for development) |
| `debug` | Debug build with symbols |
| `release` | Optimized release build |

```powershell
# Debug build
cmake --preset debug
cmake --build build/debug

# Release build
cmake --preset release
cmake --build build/release --config Release
```

### Running Tests

```powershell
ctest --preset default --output-on-failure
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Joel Emeka**

---

<p align="center">
  <i>Built with ❤️ using Modern C++23</i>
</p>
