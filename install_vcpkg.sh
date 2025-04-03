#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define the vcpkg installation directory
VCPKG_DIR="$HOME/vcpkg"

# Check if vcpkg is already installed
if [ -d "$VCPKG_DIR" ]; then
    echo "vcpkg is already installed in $VCPKG_DIR"
    exit 0
fi

# Update and install required dependencies
echo "Installing required dependencies..."
sudo apt update
sudo apt install -y git cmake build-essential curl unzip

# Clone the vcpkg repository
echo "Cloning vcpkg repository..."
git clone https://github.com/microsoft/vcpkg.git "$VCPKG_DIR"

# Navigate to the vcpkg directory
cd "$VCPKG_DIR"

# Bootstrap vcpkg
echo "Bootstrapping vcpkg..."
./bootstrap-vcpkg.sh

# Add vcpkg to the PATH (optional)
if ! grep -q "vcpkg" ~/.bashrc; then
    echo "Adding vcpkg to PATH..."
    echo "export PATH=\$PATH:$VCPKG_DIR" >> ~/.bashrc
    echo "export VCPKG_ROOT=$VCPKG_DIR" >> ~/.bashrc
    echo "Run 'source ~/.bashrc' to update your shell."
fi

# Display success message
echo "vcpkg installation completed successfully!"
echo "To use vcpkg, run: source ~/.bashrc"