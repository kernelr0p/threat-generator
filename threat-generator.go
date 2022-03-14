package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

)

var (
	helpParam       = flag.Bool("h", false, "Print help")
	ifaceName       = flag.String("i", "eth0", "Specify network")
	destIP          = flag.String("d", "", "remote address")
	customPayload   = flag.String("c", "", "payload to test")
	pcapFile        = flag.String("r", "", "pcap file to decode")
	destPort        = flag.String("p", "80", "default port to send packets")
	fuzzTCP         = flag.String("f", "", "Fuzz TCP Packet: [Flags,Options,Payload]")
	handle          *pcap.Handle
	ethLayer        layers.Ethernet
	ipv4Layer       layers.IPv4
	ipv6Layer       layers.IPv6
	tcpLayer        layers.TCP
	tcpLayerDecoded layers.TCP
	udpLayer        layers.UDP
	udpLayerDecode  layers.UDP
	payload         gopacket.Payload
	snapshotLen     int32         = 1024
	promiscuous     bool          = false
	timeout         time.Duration = 30 * time.Second
	buffer          gopacket.SerializeBuffer
	options         gopacket.SerializeOptions
	byteArray       []byte
	err             error
)

func printHelp() {
	help := `
        USAGE: threat-generator [-h] -r pcap [-i iface] [-f flags,options,payload | -c payload] [-d remote] [-p port]
		Where 'remote' is an ip address or host name.
		-r: Pcap file to decode
		-i: Interface
		-c: Custom Payload to test IDS [none by default]
		-f: Fuzz Payload
		-d: Destination IP Address
		-p: Destination port to send n packets
       		-h: Help
        Examples:
	
        sudo go run threat-generator.go -r .pcap -c "cat /etc/passwd" -d remote_ip -p 80
        `
	fmt.Println(help)
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("UDP layer detected.")
		udpLayer, _ = udpLayer.(*layers.UDP)
		fmt.Printf("UDP layer: %+v\n", udpLayer)
		fmt.Println()
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

var fuzzFuncs = []interface{}{FuzzPayloadRandom}

var minPayloadLen = 0
var maxPayloadLen = 256

func FuzzPayloadRandom(i *gopacket.Payload, c fuzz.Continue) {
	randByte := make([]byte, c.Intn(maxPayloadLen-minPayloadLen)+minPayloadLen)
	c.Read(randByte)
	(*i) = randByte
}

func FuzzPayload() []byte {
	var payloadFuzzer *fuzz.Fuzzer
	randSource := rand.NewSource(time.Now().UnixNano())
	randFuzzGen := rand.New(randSource)
	randSeed := randFuzzGen.Int63n(4294967296)
	payloadFuzzer = fuzz.New().NilChance(0).NumElements(minPayloadLen, maxPayloadLen).RandSource(rand.NewSource(randSeed)).Funcs(fuzzFuncs...)
	payloadFuzzer.Fuzz(&payload)
	return []byte(payload)
}

func FuzzOptions(tcpLayerDecoded *layers.TCP) {
	seedSource := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(seedSource)
	options1 := make([]byte, 12)
	if _, err := randomGenerator.Read(options1); err != nil {
		// Handle err
		fmt.Println(err)
	}
	for i := range tcpLayerDecoded.Options {
		tcpLayerDecoded.Options[i].OptionType = layers.TCPOptionKind(randomGenerator.Intn(15))
		tcpLayerDecoded.Options[i].OptionLength = uint8(len(options1))
		tcpLayerDecoded.Options[i].OptionData = options1
	}
}

func FuzzFlags(tcpLayerDecoded *layers.TCP) {
	seedSource := rand.NewSource(time.Now().UnixNano())
	randomGenerator := rand.New(seedSource)
	tcpLayerDecoded.FIN = randomGenerator.Float32() < 0.5
	tcpLayerDecoded.SYN = randomGenerator.Float32() < 0.5
	tcpLayerDecoded.RST = randomGenerator.Float32() < 0.5
	tcpLayerDecoded.PSH = randomGenerator.Float32() < 0.5
	tcpLayerDecoded.ACK = randomGenerator.Float32() < 0.5
	tcpLayerDecoded.URG = randomGenerator.Float32() < 0.5
	tcpLayerDecoded.ECE = randomGenerator.Float32() < 0.5
	tcpLayerDecoded.CWR = randomGenerator.Float32() < 0.5
	tcpLayerDecoded.NS = randomGenerator.Float32() < 0.5
}

func flagsAndOffset(t *layers.TCP) uint16 {
	f := uint16(t.DataOffset) << 12
	if t.FIN {
		f |= 0x0001
	}
	if t.SYN {
		f |= 0x0002
	}
	if t.RST {
		f |= 0x0004
	}
	if t.PSH {
		f |= 0x0008
	}
	if t.ACK {
		f |= 0x0010
	}
	if t.URG {
		f |= 0x0020
	}
	if t.ECE {
		f |= 0x0040
	}
	if t.CWR {
		f |= 0x0080
	}
	if t.NS {
		f |= 0x0100
	}
	f |= 0x0100
	return f
}

func DecodePacket(packet gopacket.Packet) []byte {
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipv4Layer,
		&ipv6Layer,
		&tcpLayer,
		&udpLayer,
		&payload,
	)
	decodedLayers := make([]gopacket.LayerType, 0, 100)

	err := parser.DecodeLayers(packet.Data(), &decodedLayers)
	if err != nil {
		fmt.Println("Trouble decoding layers: ", err)
	}
	ipLayerDecoded := &ipv4Layer
	if destIP != nil {
		ipLayerDecoded.DstIP = net.ParseIP(*destIP)
	}
	tcpLayerDecoded := &tcpLayer
	err = tcpLayerDecoded.SetNetworkLayerForChecksum(&ipv4Layer)
	// err = udpLayerDecoded.SetNetworkLayerForChecksum(&ipv4Layer)
	if err != nil {
		fmt.Println(err)
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil && (*fuzzTCP != "" || *customPayload != "") {
		if strings.Contains(*fuzzTCP, "flags") {
			FuzzFlags(tcpLayerDecoded)
		}
		if strings.Contains(*fuzzTCP, "options") {
			FuzzOptions(tcpLayerDecoded)
		}
		if strings.Contains(*fuzzTCP, "payload") {
			payload = FuzzPayload()
		} else if *customPayload != "" {
			payload = gopacket.Payload(*customPayload)
		}
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&ethLayer,
		&ipv4Layer,
		tcpLayerDecoded,
		// &udpLayer,
		&payload,
		// gopacket.Payload(payload),
	)
	outgoingPacket := buffer.Bytes()
	// Acordar de reiniciar todos los valores
	payload = nil
	// quicpacket.Erase()
	return outgoingPacket
}

func main() {

	flag.Parse()

	// destPort, err := strconv.ParseUint(*destPort, 10, 16)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	if *helpParam || *pcapFile == "" {
		printHelp()
		os.Exit(0)
	}
	// Open file instead of device
	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		fmt.Println(err)
	}
	defer handle.Close()

	// err = handle.SetBPFFilter("dst host " + *destIP + " and dst port " + strconv.Itoa(int(destPort)))
	err = handle.SetBPFFilter("udp or tcp")
	if err != nil {
		fmt.Println(err)
	}
	defer handle.Close()

	// Set options to compute the checksums and length of the headers correct
	options.ComputeChecksums = true
	options.FixLengths = true

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	handle, err = pcap.OpenLive(*ifaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		fmt.Println(err)
	}
	defer handle.Close()

	for packet := range packetSource.Packets() {
		//printPacketInfo(packet)
		outgoingPacket := DecodePacket(packet)
		// byteArray = append(byteArray, outgoingPacket...)
		// fmt.Println("\n\n\n\nBYTEARRAY\n\n\n\n\n ", string(byteArray))
		err = handle.WritePacketData(outgoingPacket)
		if err != nil {
			fmt.Println(err)
		}
	}
}
