#!/usr/bin/env bash
set -euo pipefail

# ci-syntax-check.sh
# End-to-end real QEMU build verification for iPhone 4S (n94 / S5L8940) emulation
# Clones qemu_ios_repo, links n94 device models, configures with Meson/Ninja, and builds target objects.

echo "=== [1/5] Installing host build dependencies ==="
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        git ninja-build pkg-config python3-venv python3-pip \
        libglib2.0-dev libpixman-1-dev flex bison
fi

QEMU_SRC="qemu_ios_repo"
if [ ! -d "$QEMU_SRC" ]; then
    echo "=== [2/5] Cloning samhenrigold/qemu-ios (main) ==="
    git clone --depth 1 https://github.com/samhenrigold/qemu-ios.git "$QEMU_SRC"
fi

echo "=== [3/5] Installing n94 and s5l8940 source files into $QEMU_SRC/hw/arm/ ==="
cp -v hw/arm/n94_board.c "$QEMU_SRC/hw/arm/"
cp -v hw/arm/n94_display.c "$QEMU_SRC/hw/arm/"
cp -v hw/arm/n94_uart.c "$QEMU_SRC/hw/arm/"
cp -v hw/arm/s5l8940_soc.c "$QEMU_SRC/hw/arm/"
cp -v hw/arm/s5l8940_soc.h "$QEMU_SRC/hw/arm/"
cp -v hw/arm/s5l8940_aic.c "$QEMU_SRC/hw/arm/"
cp -v hw/arm/s5l8940_pmgr.c "$QEMU_SRC/hw/arm/"

# Add n94 sources to hw/arm/meson.build if not already present
if ! grep -q "n94_board.c" "$QEMU_SRC/hw/arm/meson.build"; then
    echo "Registering n94 sources in hw/arm/meson.build..."
    cat << 'EOF' >> "$QEMU_SRC/hw/arm/meson.build"

# Apple iPhone 4S (n94) Emulation Model
arm_ss.add(files(
  'n94_board.c',
  'n94_display.c',
  'n94_uart.c',
  's5l8940_soc.c',
  's5l8940_aic.c',
  's5l8940_pmgr.c',
))
EOF
fi

echo "=== [4/5] Configuring QEMU for arm-softmmu ==="
cd "$QEMU_SRC"
if [ ! -f "build/build.ninja" ]; then
    ./configure --target-list=arm-softmmu --disable-werror --enable-debug-info
fi

echo "=== [5/5] Compiling n94 and s5l8940 objects with ninja ==="
ninja -C build \
    hw/arm/n94_display.c.o \
    hw/arm/n94_uart.c.o \
    hw/arm/s5l8940_soc.c.o \
    hw/arm/s5l8940_aic.c.o \
    hw/arm/s5l8940_pmgr.c.o \
    hw/arm/n94_board.c.o

echo "=== [SUCCESS] All 6 iPhone 4S emulation objects compiled cleanly against real QEMU headers! ==="
