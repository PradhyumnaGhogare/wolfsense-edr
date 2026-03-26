FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0
RUN GOOS=windows GOARCH=amd64 go build -o /out/agent.exe ./cmd/agent

FROM alpine:3.21
WORKDIR /dist
COPY --from=builder /out/agent.exe ./agent.exe
ENTRYPOINT ["/dist/agent.exe"]
