#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain="$1"

curl -s "https://crt.sh/?q=%.${domain}&output=json" | tr -d '\r' | jq -r '.[].name_value' 2>/dev/null | tr '[A-Z]' '[a-z]' | sed 's/\*.//g' | sed 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$' | sort -u || echo "No results found for ${domain}" 