#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain="$1"

# Get subdomains from crt.sh
curl -s "https://crt.sh/?q=%.${domain}&output=json" | \
    jq -r '.[].name_value' | \
    tr '[A-Z]' '[a-z]' | \
    sed 's/\*.//g' | \
    sed 's/[[:space:]]*$//' | \
    grep -v '^[[:space:]]*$' | \
    sort -u 