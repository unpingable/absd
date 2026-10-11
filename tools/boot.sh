#!/bin/sh
# Boots the operator image under QEMU in the foreground.
#
#   tools/boot.sh [OUT] [PORT]
#
# OUT is the directory tools/build.sh wrote (default out/). SSH is forwarded
# from 127.0.0.1:PORT (default 2222):
#
#   ssh -p 2222 -i KEY operator@127.0.0.1
#
# The serial console is OUT/console.log. `shutdown` in the session halts the
# machine and ends this command. See platform/man/afterboot.8.
set -eu

top=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
exec "$top/platform/scripts/boot-operator.sh" "${1:-$top/out}" "${2:-2222}"
