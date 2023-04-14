#!/bin/bash

BUILD_CMD=./mvnw clean verify --no-transfer-progress -Dlicense.skip=true

IMAGE={0:-bellsoft/liberica-openjdk-alpine:17}

echo "Using IMAGE> $IMAGE"
docker run -v ./:/src -w /src $IMAGE $BUILD_CMD

#declare -a IMAGES=(bellsoft/liberica-openjdk-alpine:17 bellsoft/liberica-openjdk-debian:17)
#for IMAGE in "${$IMAGES[@]}"
#do
#done



