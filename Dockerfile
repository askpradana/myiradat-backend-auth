# ----------- Build Stage -----------
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git and tzdata
RUN apk add --no-cache git tzdata

# Copy go mod files and download dependencies
# COPY go.mod go.sum ./
# RUN go mod download

# Copy the rest of the code
COPY . .

# Build the binary
RUN go build -o auth-service .

# ----------- Final Stage -----------
FROM alpine:latest

WORKDIR /app

# Install timezone support
RUN apk add --no-cache tzdata

# Copy the binary
COPY --from=builder /app/auth-service .

EXPOSE 7791

CMD ["./auth-service"]
