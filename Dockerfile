# --- Stage 1: Build ---
# Use the official Go image as a builder.
FROM golang:1.23.3-alpine AS builder

# Install build dependencies.
RUN apk add --no-cache git build-base

# Set working directory
WORKDIR /app

# Copy and download dependencies first to leverage Docker layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code.
COPY . .

# Build the application binary.
# The output is a static binary that can be run in a minimal container.
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-s -w' -installsuffix cgo -o /archguardian ./cmd/archguardian


# --- Stage 2: Final Image ---
# Use a minimal base image for a small and secure final image.
FROM alpine:latest

# Set working directory in the final image.
WORKDIR /root/

# Copy the built binary from the builder stage.
COPY --from=builder /archguardian .

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["./archguardian"]
