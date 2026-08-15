# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/localenv-server ./cmd/localenv-server && \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/localenv ./cmd/localenv

FROM alpine:3.21
RUN apk add --no-cache su-exec ca-certificates && \
    addgroup -S localenv && adduser -S -G localenv -h /nonexistent localenv
COPY --from=build /out/localenv-server /usr/local/bin/localenv-server
COPY --from=build /out/localenv /usr/local/bin/localenv
COPY deploy/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/localenv-server /usr/local/bin/localenv /usr/local/bin/docker-entrypoint.sh && \
    mkdir -p /data && chmod 0700 /data

EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["localenv-server"]
