FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git build-base

WORKDIR /app
COPY src/go/go.mod src/go/go.sum ./
RUN go mod download

COPY src/go/ .

RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /bty-server ./cmd/server/main.go
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /bty-agent ./cmd/agent/main.go

FROM alpine:3.20

RUN apk add --no-cache curl ca-certificates

WORKDIR /app
COPY --from=builder /bty-server .
COPY --from=builder /bty-agent .
COPY config.yaml .

RUN mkdir -p web/dist data loot modules

EXPOSE 8443 8445 8446 9090

CMD ["./bty-server", "-config", "config.yaml"]
