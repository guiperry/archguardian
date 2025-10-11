# Makefile for ArchGuardian

# Default Go command
GO=go

# Binary name for local builds
BINARY_NAME=archguardian

# Main package path
CMD_PATH=./cmd/archguardian

# Node.js parameters for the website frontend
NPM_CMD=npm
WEBSITE_DIR=website

.PHONY: all build run test clean cross-compile install-frontend build-frontend

all: cross-compile

# Build the application for the current OS and architecture
build: build-frontend
	@echo "Building ArchGuardian go backend for local development..."
	@$(GO) build -o $(BINARY_NAME) $(CMD_PATH)
	@echo "✅ Build complete: ./$(BINARY_NAME)"

# Run the application
run:
	@echo "Running ArchGuardian..."
	@$(GO) run $(CMD_PATH)

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


# Install frontend dependencies
install-frontend:
	@echo "Installing website dependencies..."
	@cd $(WEBSITE_DIR) && $(NPM_CMD) install

# Build the website frontend
build-frontend: install-frontend
	@echo "Building website frontend..."
	@cd $(WEBSITE_DIR) && $(NPM_CMD) run build