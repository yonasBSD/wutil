# wutil
A simple WiFi utility CLI for FreeBSD

### Building
To build with [xmake-io](https://xmake.io):
```shell
$ xmake
```

To build with bsdmake:
```shell
$ make
```

## Usage
```
$ ./build/bsd/x86_64/release/wutil help
Usage: wutil [commands] [args]
Commands:
  help                                     Show this message and exit
  list                                     List all network interfaces with their current status
  show       <interface>                   Display detailed status for <interface>
  enable     <interface>                   Enable <interface>
  disable    <interface>                   Disable <interface>
  restart    <interface>                   Restart <interface>
  config     <interface>                   Configure network settings for <interface>
                                             Options:
                                               --method [dhcp|manual] Set IP assignment method
                                               --ip <ip_address> Static IP address (required if manual)
                                               --netmask <netmask> Subnet mask (required if manual)
                                               --gateway <gateway> Default gateway (required if manual)
                                               --dns1 <dns_server> Primary DNS server
                                               --dns2 <dns_server> Secondary DNS server (optional)
                                               --search <domain> Search domain (optional)
  scan       <interface>                         Scan available Wi-Fi networks
  disconnect <interface>                   Disconnect from the current Wi-Fi network
  connect    <interface> <ssid> [psk]      Connect to a Wi-Fi network with optional PSK (password)


```
