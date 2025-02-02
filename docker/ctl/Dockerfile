FROM alpine:3.18

RUN apk add --no-cache git bash curl openssl jq

WORKDIR /app

COPY getsubdomain.sh /usr/local/bin/getsubdomain
RUN chmod +x /usr/local/bin/getsubdomain

ENTRYPOINT ["sleep", "infinity"] 