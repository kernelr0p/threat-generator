# threat-generator
Threat-Generator is a network fuzzer which reads from a pcap and fuzz the content of the TCP flags, options and payload. It facilitated CVE-2021-1224: https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-snort-tfo-bypass-MmzZrtes.html.

# Installation
```
sudo go get github.com/google/gofuzz
sudo go get github.com/google/gopacket
sudo go get github.com/google/gopacket/layers
sudo go get github.com/google/gopacket/pcap

go build
```
# Usage
```
USAGE: 
 
threat-generator [-h] -r pcap [-i iface] [-f flags,options,payload | -c payload] [-d remote] [-p port]
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
```
