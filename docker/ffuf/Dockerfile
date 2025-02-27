FROM golang:1.21-alpine
RUN apk add --no-cache git
RUN go install github.com/ffuf/ffuf/v2@latest
WORKDIR /app
RUN mkdir -p /wordlists
ENTRYPOINT ["sleep", "infinity"] 