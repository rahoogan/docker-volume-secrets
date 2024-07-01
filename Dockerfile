FROM golang:1.22.4-alpine as builder
COPY . /go/src/github.com/rahoogan/docker-secrets-volume
WORKDIR /go/src/github.com/rahoogan/docker-secrets-volume
RUN set -ex \
    && apk add --no-cache --virtual .build-deps \
    gcc libc-dev \
    && go install --ldflags '-extldflags "-static"' \
    && apk del .build-deps
CMD ["/go/bin/docker-secrets-volume"]

FROM alpine
RUN mkdir -p /run/docker/plugins /mnt/state /mnt/volumes
COPY --from=builder /go/bin/docker-secrets-volume .
CMD ["docker-secrets-volume"]