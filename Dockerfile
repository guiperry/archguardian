# Simple single-stage Dockerfile for ArchGuardian
FROM golang:1.23.3-alpine

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o archguardian *.go

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["./archguardian"]
