# Makefile for ArchGuardian

# Default Go command
GO := go

# Binary name for local builds
BINARY_NAME := archguardian

.PHONY: all build run test clean cross-compile

all: cross-compile

# Build the application for the current OS and architecture
build:
	@echo "Building ArchGuardian for local development..."
	@$(GO) build -o $(BINARY_NAME) .
	@echo "✅ Build complete: ./$(BINARY_NAME)"

# Run the application
run:
	@echo "Running ArchGuardian..."
	@$(GO) run main.go

# Run tests
test:
	@echo "Running tests..."
	@$(GO) test ./...

# Clean up build artifacts
clean:
	@echo "Cleaning up build artifacts..."
	@rm -f $(BINARY_NAME)
	@rm -rf build/
	@echo "✅ Cleanup complete."

# Cross-compile for all target platforms
cross-compile:
	@echo "Cross-compiling for all platforms..."
	@bash scripts/cross-compile.sh

# Build and release all binaries to cloud storage
release: cross-compile
	@echo "Uploading release binaries..."
	@bash scripts/release.sh