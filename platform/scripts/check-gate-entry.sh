#!/bin/sh
# Cheap host entry checks only. No build, guest, cleanup or source mutation.
set -eu
refuse() { printf 'ABSD ENTRY REFUSED %s\n' "$*" >&2; exit 2; }
command -v id >/dev/null 2>&1 || refuse 'missing host tool: id'
uid=$(id -u)
[ "$uid" != 0 ] || refuse 'uid 0; an unprivileged build account is required'

case $0 in */*) scripts=${0%/*} ;; *) scripts=. ;; esac
commands=0
while IFS= read -r item || [ -n "$item" ]; do
    case $item in
        ''|'#'*) continue ;;
        xfonts-base)
            status=$(dpkg-query -W '-f=${Status}' xfonts-base 2>/dev/null) ||
                refuse 'missing host item: xfonts-base'
            [ "$status" = 'install ok installed' ] || refuse 'missing host item: xfonts-base'
            ;;
        *) command -v "$item" >/dev/null 2>&1 || refuse "missing host tool: $item"
           commands=$((commands + 1)) ;;
    esac
done < "$scripts/gate-host-items.txt"

# The same minimal namespace/identity probe as the full-gate PREREQS.
# Retain the caller's unprivileged uid and discard namespace diagnostics so
# the refusal is one loud line naming the failed host item.
probe=$(timeout 30 bwrap --die-with-parent --unshare-pid --tmpfs / \
    --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
    --symlink usr/bin /bin --symlink usr/sbin /sbin --ro-bind /etc /etc \
    --dev /dev --proc /proc --tmpfs /tmp --clearenv --setenv PATH /usr/bin:/bin \
    /usr/bin/id -u 2>/dev/null) || refuse 'bwrap unprivileged namespace probe failed'
[ "$probe" = "$uid" ] || refuse 'bwrap unprivileged namespace uid differs'
printf 'ABSD ENTRY OK uid=%s commands=%s bwrap=unprivileged xfonts-base=installed\n' "$uid" "$commands"
