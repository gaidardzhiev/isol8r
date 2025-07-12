#!/bin/sh

ROOTFS="$1"

[ -z "$ROOTFS" ] && printf "usage: $0 <newroot>\n" && exit 1

fprep() {
	mkdir -p "$ROOTFS" && cd "$ROOTFS" || return 2
	mkdir -p bin dev proc sys tmp etc usr/bin usr/lib usr/lib64 || return 3
	chmod 1777 tmp || return 4
	command -v busybox >/dev/null 2>&1 || { printf "install busybox first...\n" >&2; exit 1; }
	cp "$(command -v busybox)" bin/ && chmod +x bin/busybox || return 5
	cd bin || return 6
	for cmd in sh ls cp mv rm mkdir mount umount echo cat; do
		ln -sf busybox "$cmd" || return 7
	done
	cd .. || return 8
	printf 'root:x:0:0:root:/root:/bin/sh\n' > etc/passwd || return 9
	printf 'root:x:0:\n' > etc/group || return 10
	cd dev || return 11
	[ ! -e null ] && sudo mknod -m 666 null c 1 3 || true
	[ ! -e zero ] && sudo mknod -m 666 zero c 1 5 || true
	[ ! -e random ] && sudo mknod -m 444 random c 1 8 || true
	[ ! -e urandom ] && sudo mknod -m 444 urandom c 1 9 || true
	cd .. || return 12
	mkdir -p "$ROOTFS/.pivot_root" || return 13
	chmod 700 "$ROOTFS/.pivot_root" || return 14
	ls -ld "$ROOTFS/.pivot_root"
	sudo umount -l "$ROOTFS" 2>/dev/null || true
	sudo mount /dev/sdb1 "$ROOTFS" || return 15
	mount | grep "$ROOTFS"
	printf "minimal rootfs prepared at $ROOTFS\n"
	printf "check mount /proc /sys /dev (tmpfs) inside the jail\n"
}

{ fprep; RET=$?; } || exit 1

[ "$RET" -eq 0 ] 2>/dev/null || printf "%s\n" "$RET"
