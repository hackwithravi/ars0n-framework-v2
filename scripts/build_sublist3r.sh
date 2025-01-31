#!/bin/bash

cd "$(dirname "$0")/../docker/sublist3r"

docker build -t sublist3r:latest . 