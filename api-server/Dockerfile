FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN go build -o /out/api-server ./cmd/server

FROM alpine:3.21
WORKDIR /app
COPY --from=builder /out/api-server ./api-server
EXPOSE 8080
ENTRYPOINT ["/app/api-server"]
