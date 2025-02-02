FROM golang:1.21-alpine

RUN go install github.com/tomnomnom/assetfinder@latest

ENTRYPOINT ["/go/bin/assetfinder"] 