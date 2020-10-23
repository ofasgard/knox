package knox
//A package containing implementations of port knocking using the libpcap wrappers in Google's gopacket library.

//import "fmt"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"

type Hostinfo struct {
	Packet gopacket.Packet
	Port int
	Srcport int
	IP string
}

/* PortStreamTCP(iface string, ip string, snaplen int, ch chan Hostinfo, sig chan bool)
*
* iface: the interface to sniff on
* ip: your ip address, for filtering purposes
* snaplen: snapshot length of each captured frame
* ch: the channel to send host information along
* sig: the channel to send error values along
*
* A stream of incoming TCP ports and IPv4 addresses sniffed from an interface.
*/

func PortStreamTCP(iface string, ip string, snaplen int, ch chan Hostinfo, sig chan error) {
	handle,err := pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever)
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
		if networklayer == nil { continue }
		transportlayer := packet.TransportLayer()
		if transportlayer == nil { continue }
		ipdata := networklayer.(*layers.IPv4)
		tcpdata := transportlayer.(*layers.TCP)
		h := Hostinfo{}
		h.Packet = packet
		h.Port = int(tcpdata.DstPort)
		h.Srcport = int(tcpdata.SrcPort)
		h.IP = ipdata.SrcIP.String()
		ch <-h
	}
}

/* PortKnocker(ch chan Hostinfo, res chan Hostinfo, ports ...int)
*
* ch: the channel to receive host/port information from PortStreamTCP()
* res: the output channel to send host/port information that triggers the port knocker
* ports: an ordered list of destination ports to trigger on
*
* A standard port knocker that can be provided with any sequential port sequence. When it receives the sequence, it sends info about the packet along the res channel.
*/

func PortKnocker(ch chan Hostinfo, res chan Hostinfo, ports ...int) {
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
		if data.Port == ports[current_index] {
			known_hosts[data.IP] += 1
			if known_hosts[data.IP] >= len(ports) {
				res <- data
				known_hosts[data.IP] = 0
			}
		} else {
			known_hosts[data.IP] = 0
		}
	}
}

/* SrcPortKnocker(ch chan Hostinfo, res chan Hostinfo, ports ...int)
*
* ch: the channel to receive host/port information from PortStreamTCP()
* res: the output channel to send host/port information that triggers the port knocker
* ports: an ordered list of source ports to trigger on
*
* Identical to the basic port knocker, but it triggers based on source instead of destination port. When it receives the sequence, it sends info about the packet along the res channel.
*/

func SrcPortKnocker(ch chan Hostinfo, res chan Hostinfo, ports ...int) {
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
		//fmt.Println("[DEBUG] Host:", data.IP, ", Port:", data.srcport)
		//fmt.Println("[DEBUG] Expecting:", ports[current_index])
		if data.Srcport == ports[current_index] {
			known_hosts[data.IP] += 1
			if known_hosts[data.IP] >= len(ports) {
				res <- data
				known_hosts[data.IP] = 0
			}
		} else {
			known_hosts[data.IP] = 0
		}
	}
}
