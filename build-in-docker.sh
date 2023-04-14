#!/bin/bash

set -e

IMAGE=${1:-bellsoft/liberica-openjdk-alpine:17}
BUILD_CMD=${2:-./mvnw clean verify --no-transfer-progress -Dlicense.skip=true}
SETUP_CMD=$3

if [ -z "$var" ]; then
  echo "No setup command provded, trying to auto-detect"
  if [[ "$IMAGE" == *"debian"* ]]; then
    echo "Using debian setup steps"
    SETUP_CMD='apt-get update && apt-get install -y ca-certificates'
  elif [[ "$IMAGE" == *"alpine"* ]]; then
    echo "Using alpine setup steps"
    SETUP_CMD='apk --update add ca-certificates'
  elif [[ "$IMAGE" == *"centos"* ]]; then
    echo "Using centos setup steps"
    SETUP_CMD='yum clean all && yum install -y ca-certificates'
  else
    echo "unknown distro, skipping setup step"
    SETUP_CMD=
  fi
fi

echo "Using IMAGE: $IMAGE"
docker run -v ./:/src -w /src $IMAGE sh -c "$SETUP_CMD && $BUILD_CMD"


