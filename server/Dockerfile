FROM golang:1.23

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir -p /app/temp
RUN chmod -R 777 /app/temp

RUN apt-get update && apt-get install -y docker.io

RUN go build -o main .

EXPOSE 8080

CMD ["./main"]
