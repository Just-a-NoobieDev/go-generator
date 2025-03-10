#!/bin/bash

# Build the binary
echo "Building go-generator..."
go build -o bin/go-generator cmd/go-generator/main.go

# Create installation directory if it doesn't exist
sudo mkdir -p /usr/local/bin

# Copy binary to installation directory
sudo cp bin/go-generator /usr/local/bin/

echo "Installation complete! You can now use 'go-generator' command from anywhere." 