# ----------- Build Stage -----------
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install git and tzdata
RUN apk add --no-cache git tzdata

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY internal/ ./internal/
COPY cmd/myiradat-backend-auth/ ./cmd/myiradat-backend-auth/

# Build the binary from the correct main.go
RUN go build -o auth-service ./cmd/myiradat-backend-auth/main.go

# ----------- Final Stage -----------
FROM alpine:latest

WORKDIR /app

# Install timezone support
RUN apk add --no-cache tzdata

# Copy the binary
COPY --from=builder /app/auth-service .

EXPOSE 7791

CMD ["./auth-service"]
