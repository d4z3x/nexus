FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o nexus .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/nexus .

EXPOSE 80 443 8080
VOLUME /app/data

ENV DB_PATH=/app/data/nexus.db

ENTRYPOINT ["./nexus"]
