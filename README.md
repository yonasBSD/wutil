# wutil
A simple WiFi utility CLI for FreeBSD

To build with bsdmake:
```shell
$ make
```

## Usage
```
$ ./wutil help
Usage:  wutil {-h | subcommand [args...]}
        wutil help
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

### wutui
```
$ ./wutui
```
<img width="1694" height="1279" alt="image" src="https://github.com/user-attachments/assets/b100b134-fa9d-45cc-8e96-3115a3b55012" />
