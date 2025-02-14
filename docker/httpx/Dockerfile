FROM golang:1.21-alpine

RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

WORKDIR /app
RUN mkdir -p /tmp

ENTRYPOINT ["httpx"] 