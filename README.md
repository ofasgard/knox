# knox

A package containing implementations of port knocking using the libpcap wrappers in Google's gopacket library. You can use it to create services that monitor your network interfaces for a specific sequence of ports, even if the ports in question are closed. When a successful port knock is detected, information about the triggering packet is exposed by the package so that you can act on it as you please.

## Dependencies

- [gopacket](https://github.com/google/gopacket)

## Example

This is an example of a simple port knocking listener that triggers on ports 1337, 1338 and 1339:

```go
package main

import "fmt"
import "github.com/ofasgard/knox"

func main() {
	ch := make(chan knox.Hostinfo, 0)
	sig := make(chan error, 0)
	go knox.PortStreamTCP("eth0", "45.33.32.156", 1600, ch, sig)
	res := <-sig
	if res != nil {
		fmt.Println("Error in setting up the sniffer. Check permissions, interface name, IP?")
		fmt.Println(res.Error())
		return
	}
	knock := make(chan knox.Hostinfo, 0)
	go knox.PortKnocker(ch, knock, 1337, 1338, 1339)
	for {
		host_data := <-knock
		fmt.Println("Received a successful knock from", host_data.IP)
	}
}
```

You can test out your portscanner using hping3 like so:

```sh
echo Knock Knock

hping3 -S 45.33.32.156 -p 1337 -c 1 
hping3 -S 45.33.32.156 -p 1338 -c 1 
hping3 -S 45.33.32.156 -p 1339 -c 1 

```
