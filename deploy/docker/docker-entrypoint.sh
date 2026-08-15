#!/bin/sh
set -eu

mkdir -p /data
chmod 0700 /data
chown localenv:localenv /data

exec su-exec localenv:localenv "$@"
