# Stage 1: Build the Go application
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o paseto_web .

# Stage 2: Create minimal runtime image
FROM scratch

WORKDIR /app

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/paseto_web .

# Copy static files
COPY static/ ./static/

# Expose port
EXPOSE 8080

# Set environment variables
ENV PORT=8080
ENV CORS_ORIGIN=https://paseto.getgud.boo

# Run the application
ENTRYPOINT ["/app/paseto_web"]
