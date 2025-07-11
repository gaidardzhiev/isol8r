#!/bin/sh

ROOTFS="$1"

[ -z "$ROOTFS" ] && printf "usage: $0 <newroot>\n" && exit 1

mkdir -p "$ROOTFS" && cd "$ROOTFS" || exit 1

mkdir -p bin dev proc sys tmp etc usr/bin usr/lib usr/lib64 && chmod 1777 tmp || exit 1

command -v busybox >/dev/null 2>&1 || { printf "install busybox first...\n" >&2; exit 1; }

cp "$(command -v busybox)" bin/ && chmod +x bin/busybox || exit 1

cd bin || exit 1

for cmd in sh ls cp mv rm mkdir mount umount echo cat; do
	ln -sf busybox "$cmd" || exit 1
done

cd .. || exit 1

printf 'root:x:0:0:root:/root:/bin/sh\n' > etc/passwd || exit 1

printf 'root:x:0:\n' > etc/group || exit 1

cd dev || exit 1

[ ! -e null ] && sudo mknod -m 666 null c 1 3 || true

[ ! -e zero ] && sudo mknod -m 666 zero c 1 5 || true

[ ! -e random ] && sudo mknod -m 444 random c 1 8 || true

[ ! -e urandom ] && sudo mknod -m 444 urandom c 1 9 || true

mkdir -p "$ROOTFS"/.pivot_root

chmod 700 "$ROOTFS"/.pivot_root

ls -ld "$ROOTFS"/.pivot_root

sudo umount "$ROOTFS"

sudo mount /dev/sdb1 "$ROOTFS"

mount | grep "$ROOTFS"

cd .. || exit 1

printf "minimal rootfs prepared at $ROOTFS\n"

printf "check mount /proc /sys /dev (tmpfs) inside the jail\n"
