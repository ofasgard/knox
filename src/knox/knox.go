package knox
//A package containing implementations of port knocking using the libpcap wrappers in Google's gopacket library.

import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"


/* PortStream(iface string, ip string, ch chan Hostinfo, sig chan bool)
*
* iface: the interface to sniff on
* ip: your ip address, for filtering purposes
* ch: the channel to send host information along
* sig: the channel to send error values along
*
* A stream of incoming TCP ports and IPv4 addresses sniffed from an interface.
*/

func PortStream(iface string, ip string, ch chan Hostinfo, sig chan error) {
	handle,err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		sig <- err
		return
	}
	err = handle.SetBPFFilter("tcp and dst host " + ip)
	if err != nil {
		sig <- err
		return
	}
	sig <- nil
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		networklayer := packet.NetworkLayer()
		transportlayer := packet.TransportLayer()
		ipdata := networklayer.(*layers.IPv4)
		tcpdata := transportlayer.(*layers.TCP)
		h := Hostinfo{}
		h.port = int(tcpdata.DstPort)
		h.IP = ipdata.SrcIP.String()
		ch <-h
	}
}

type Hostinfo struct {
	port int
	IP string
}

/* PortKnocker(ch chan Hostinfo, fp payload, ports ...int)
*
* ch: the channel to receive host/port information from portStream()
* fp: the payload object containing a function to trigger
* ports: an ordered list of ports to trigger on
*
* A standard port knocker that can be provided with any sequential port sequence. When it receives the sequence, the payload is triggered.
*/

func PortKnocker(ch chan Hostinfo, fp payload, ports ...int) {
	known_hosts := make(map[string]int)
	for {
		data := <-ch
		var current_index int
		_,ok := known_hosts[data.IP]
		if ok{
			//element exists
			current_index = known_hosts[data.IP]
		} else {
			//element does not exist
			known_hosts[data.IP] = 0
			current_index = 0
		}
		//fmt.Println("[DEBUG] Host:", data.IP, ", Port:", data.port)
		//fmt.Println("[DEBUG] Expecting:", ports[current_index])
		if data.port == ports[current_index] {
			known_hosts[data.IP] += 1
			if known_hosts[data.IP] >= len(ports) {
				fp.Payload(data.IP)
				known_hosts[data.IP] = 0
			}
		} else {
			known_hosts[data.IP] = 0
		}
	}
}
