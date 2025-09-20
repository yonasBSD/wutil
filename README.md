# wutil
A simple WiFi utility CLI for FreeBSD

## Building
### Dependencies
`wutil` depends on `libifconfig` and it is available via `net/libifconfig`
```console
# # as a package
# pkg install net/libifconfig

# # or as a port
# make -C /usr/ports/net/libifconfig install
```

### Build `wutil` as a port
All required patches are available in the `patch/` directory.
```console
# patch -p1 -d /usr/ports < patch/sysutils_wutil.patch
# make -C /usr/ports/sysutils/wutil install
```

### Build `wutil` with `bmake`
```console
$ make
```

## Usage
### The CLI
```console
$ wutil -h
Usage:  wutil {-h | subcommand [args...]}
        wutil interfaces
        wutil interface <interface>
        wutil [-c <wpa-ctrl-path>] known-networks
        wutil [-c <wpa-ctrl-path>] {known-network | forget} <ssid>
        wutil [-c <wpa-ctrl-path>] set
          [-p <priority>] [--autoconnect {y | n}] <ssid>
        wutil [-c <wpa-ctrl-path>] {scan | networks | status | disconnect}
        wutil [-c <wpa-ctrl-path>] connect
          [-i <eap-id>] [-p <password>] [-h] <ssid> [password]
```

### The TUI
```console
$ wutui
```
<img width="1694" height="1279" alt="image" src="https://github.com/user-attachments/assets/b100b134-fa9d-45cc-8e96-3115a3b55012" />
