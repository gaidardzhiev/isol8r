# Isol8r — Lightweight Linux Namespace Jail

Isol8r is a minimal Linux namespace jail that creates isolated environments for running processes securely. It leverages Linux kernel namespaces, user and group ID mappings, pivot_root, capability dropping, and seccomp filtering to provide strong process isolation similar to lightweight containers.

---

## Features

- Creates isolated namespaces: PID, mount, network, IPC, UTS, user, and cgroup
- Uses `pivot_root` to switch to a minimal root filesystem
- Mounts essential filesystems inside the jail: `/proc`, `/sys`, `/dev` (tmpfs), and `/tmp` (tmpfs)
- Drops all capabilities and switches to an unprivileged user inside the jail
- Applies seccomp filters to restrict syscalls for enhanced security
- Forwards signals from parent to jailed process
- Sets resource limits (memory, processes, open files) to prevent abuse

---

## Requirements

- Linux kernel 4.8+ (for user namespaces and most namespace features)
- `libseccomp` development package installed (`pacman -S libseccomp` on Arch Linux)
- Root privileges to run the jail
- A prepared minimal root filesystem for the jail (see `mkroot.sh`)

---

## Preparing the Root Filesystem

You must prepare a minimal root filesystem directory that the jail will pivot into. This directory should contain:

- Essential directories: `/bin`, `/lib`, `/lib64`, `/usr`, `/proc`, `/sys`, `/dev`, `/tmp`, `/etc`
- Minimal binaries (e.g., `busybox` or `bash`) and their dependencies
- Minimal `/etc/passwd` and `/etc/group` files
- Empty mount points for `/proc`, `/sys`, `/dev`
- Proper permissions (e.g., `/tmp` should be `1777`)

You can use the included `mkroot.sh` script to quickly create a minimal root filesystem.

---

## Building

```
./mkrootfs newroot
make
make install
make strip
make strace
```

---

## Limitations and Notes

- Requires root or appropriate capabilities to create namespaces and perform `pivot_root`.
- Kernel must support all requested namespaces; otherwise, modify the source to remove unsupported flags.
- UID/GID mappings are set to map root inside the jail to your current user outside.
- Seccomp filter is basic; customize for your workload.
- The jail does not provide persistent storage or advanced networking it is a minimal isolation tool.

---

## License

GPL3 License
