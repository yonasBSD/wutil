# wutil
A simple WiFi utility CLI for FreeBSD

To build with bsdmake:
```shell
$ make
```

## Usage
```
$ ./wutil help
Usage:  wutil help
        wutil {interface | if} list
        wutil {interface | if} show <interface>
        wutil {interface | if} set
        wutil {interface | if} set [--state {up | down}] <interface>
        wutil {interface | if} set [-s {up | down}] <interface>
        wutil {known-network | kn} [--ctrl-interface <path>] list
        wutil {known-network | kn} [-c <path>] {show | forget} <ssid>
        wutil {known-network | kn} [--ctrl-interface <path>] set
          [--priority <num>] [--autoconnect {yes | no}] <ssid>
        wutil {known-network | kn} [-c <path>] set
          [-p <num>] [-a {y | n}] <ssid>
        wutil {station | sta} [--ctrl-interface <path>]
          {scan | networks | status | disconnect}
        wutil {station | sta} [--ctrl-interface <path>] connect
          [--identity <id>] [--password <password>] [--hidden] <ssid>
        wutil {station | sta} [-c <path>] connect
          [-i <id>] [-p <password>] [-h] <ssid>
```

### wutui
```
$ ./wutui
```
![04-09-2025-000549](https://github.com/user-attachments/assets/f564c27b-1abd-46ab-ab2b-d4b56cd122e4)
