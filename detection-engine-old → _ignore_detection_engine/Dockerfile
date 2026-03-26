FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN go build -o /out/detection-engine ./cmd/engine

FROM alpine:3.21
WORKDIR /app
COPY --from=builder /out/detection-engine ./detection-engine
COPY internal/rules ./internal/rules
EXPOSE 8081
ENTRYPOINT ["/app/detection-engine"]
