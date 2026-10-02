# seedmix - Combine multiple BIP39 mnemonics statelessly

**LVGL-based touchscreen application**  
Prototype on Linux (SDL2) -> deploy to ESP32.

## Quick Start (Linux)

### 1. Install system dependencies
```bash
sudo apt install build-essential cmake libsdl2-dev zlib1g-dev autoconf automake libtool libtool-bin
```

### 2. Clone and build
```bash
# Clone the project with submodules (lvgl, libwally-core)
git clone --recurse-submodules <this-repo>
cd seedmix

# Build
chmod +x scripts/build.sh
./scripts/build.sh
```

### 3. Run
```bash
./build_linux/seedmix
```

A 480×320 window opens with a "Generate" button that creates a BIP39 mnemonic.

## Web (Emscripten)

Build the app for the browser.  The page uses the SDL2 backend for the LVGL
display, Web Crypto (`crypto.getRandomValues`) for entropy, and `getUserMedia`
for camera when a webcam is available.

```bash
# Build (first run auto-installs the pinned Emscripten SDK into external/emsdk)
./scripts/build_web.sh

# Serve and open http://localhost:8000/seedmix.html
./scripts/build_web.sh serve
```

On first run the script downloads the Emscripten toolchain (~500 MB) into
`external/emsdk` and installs version 6.0.9.  Set `EMSDK=/path/to/emsdk` to
reuse an SDK you've already installed.

Camera access requires a secure context (https:// or http://localhost).

## ESP32 Deployment

See [platform/esp32/README.md](platform/esp32/README.md) for:
- Required ESP-IDF components
- Touchscreen wiring
- libwally cross-compilation

## Architecture

| Layer          | Description                                      |
|----------------|--------------------------------------------------|
| `main/ui/`     | LVGL screens, platform-agnostic                  |
| `main/crypto/` | Wallet operations, wraps libwally                |
| `platform/`    | Platform entry points (SDL2 / FreeRTOS)          |
| `cmake/`       | Reusable CMake modules                           |

Platform code is only the entry point, tick provider, and display/input driver
setup.  All business logic and UI lives in `main/`.
