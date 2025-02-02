FROM alpine:3.18

RUN apk add --no-cache git bash curl openssl postgresql-client

WORKDIR /app

RUN git clone https://github.com/hannob/tlshelpers.git . && \
    chmod +x getsubdomain

CMD ["./getsubdomain"] 