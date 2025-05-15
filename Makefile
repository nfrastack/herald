.PHONY: clean deps build run test all

# Default target
all: clean deps build

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -rf bin/

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod tidy

# Build the application
build:
	@echo "Building application..."
	go build -o bin/container-dns-companion ./cmd/container-dns-companion

# Run the application
run: build
	@echo "Running application..."
	./bin/container-dns-companion $(ARGS)

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...