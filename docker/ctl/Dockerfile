FROM alpine:3.18

RUN apk add --no-cache git bash curl openssl jq

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /app

RUN echo '#!/bin/sh' > /usr/local/bin/getsubdomain && \
    echo 'curl -s "https://crt.sh/?q=%.$1&output=json" | jq -r ".[].name_value" 2>/dev/null | tr "[A-Z]" "[a-z]" | sed "s/\*.//g" | sort -u | grep -v "^$"' >> /usr/local/bin/getsubdomain && \
    chmod +x /usr/local/bin/getsubdomain

ENTRYPOINT ["sleep", "infinity"] 