FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies and Chrome
RUN apt-get update && \
    apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    git \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list \
    && apt-get update \
    && apt-get install -y \
    google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_linux_amd64.zip && \
    apt-get update && \
    apt-get install -y unzip && \
    unzip nuclei_3.3.8_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei_3.3.8_linux_amd64.zip && \
    rm -rf /var/lib/apt/lists/*

# Install Nuclei templates
RUN nuclei -update-templates

# Create necessary directories
RUN mkdir -p /tmp/nuclei-mounts && \
    chmod 777 /tmp/nuclei-mounts

# Set Chrome path for nuclei
ENV CHROME_PATH=/usr/bin/google-chrome

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"] 