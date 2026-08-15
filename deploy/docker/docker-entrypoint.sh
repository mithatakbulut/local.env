#!/bin/sh
set -eu

mkdir -p /data
chmod 0700 /data
chown localenv:localenv /data
# A backup archive can be extracted by the host's root user.  The server runs
# unprivileged and must be able to reopen its restored SQLite database and
# encrypted instance files; do not follow any symlinks while fixing ownership.
find /data -xdev -exec chown -h localenv:localenv {} +

exec su-exec localenv:localenv "$@"
