#!/bin/bash

# Get the version from argument or use v0.1.0 as default
VERSION=${1:-v0.1.0}
BINARY_NAME="go-generator"
BUILD_DIR="dist"

# Create dist directory if it doesn't exist
mkdir -p $BUILD_DIR

# Build for different platforms
echo "Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -o $BUILD_DIR/${BINARY_NAME}_${VERSION}_darwin_amd64 ./cmd/go-generator

echo "Building for macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -o $BUILD_DIR/${BINARY_NAME}_${VERSION}_darwin_arm64 ./cmd/go-generator

echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -o $BUILD_DIR/${BINARY_NAME}_${VERSION}_linux_amd64 ./cmd/go-generator

echo "Building for Linux (arm64)..."
GOOS=linux GOARCH=arm64 go build -o $BUILD_DIR/${BINARY_NAME}_${VERSION}_linux_arm64 ./cmd/go-generator

echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -o $BUILD_DIR/${BINARY_NAME}_${VERSION}_windows_amd64.exe ./cmd/go-generator

# Create ZIP archives
cd $BUILD_DIR
echo "Creating ZIP archives..."
for file in *; do
    if [ -f "$file" ]; then
        zip "${file}.zip" "$file"
        rm "$file"  # Remove the original binary after zipping
    fi
done

# Create checksums
echo "Generating checksums..."
sha256sum *.zip > checksums.txt

echo "Build complete! Binaries and checksums are in the $BUILD_DIR directory"
ls -l 