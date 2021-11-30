package packet

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nathants/tinysnitch/pkg/dns"
	"github.com/nathants/tinysnitch/pkg/netfilter"
)

var decodeOptions = gopacket.DecodeOptions{
	Lazy:   true,
	NoCopy: true,
}

const (
	ActionDrop   = 0
	ActionAccept = 1
	ActionRepeat = 4
	ProtoTCP     = "tcp"
	ProtoUDP     = "udp"
	ProtoICMP    = "icmp"
)

type Packet struct {
	Proto   string
	Src     string
	SrcIP   string
	Dst     string
	DstIP   string
	SrcPort string
	DstPort string
	Id      int
}

func (p *Packet) String() string {
	src := fmt.Sprintf("%s:%s", p.Src, p.SrcPort)
	dst := fmt.Sprintf("%s:%s", p.Dst, p.DstPort)
	return fmt.Sprintf("%s %s -> %s", p.Proto, src, dst)
}

func (p *Packet) IsICMP() bool {
	return p.Proto == ProtoICMP
}

func (p *Packet) IsInboundDNS() bool {
	return dns.IsLocalhost(p.DstIP) && p.SrcPort == "53"
}

func (p *Packet) IsOutboundDNS() bool {
	return dns.IsLocalhost(p.SrcIP) && p.DstPort == "53"
}

func (p *Packet) IsLocalTraffic() bool {
	return dns.IsLocalhost(p.SrcIP) && dns.IsLocalhost(p.DstIP)
}

func (p *Packet) IsUDPLooopback() bool {
	return p.Src == p.Dst && p.SrcPort == p.DstPort && p.Proto == ProtoUDP
}

func (p *Packet) ResolveDNS() {
	p.Src = dns.GetHostName(p.Src)
	p.Dst = dns.GetHostName(p.Dst)
}

func (p *Packet) ShouldLog() bool {
	return !p.IsInboundDNS() &&
		!p.IsICMP() &&
		!p.IsUDPLooopback()
}

func (p *Packet) FlipDirection() {
	src := p.Src
	srcPort := p.SrcPort
	dst := p.Dst
	dstPort := p.DstPort
	p.Src = dst
	p.SrcPort = dstPort
	p.Dst = src
	p.DstPort = srcPort
}

func Parse(id int, data []byte) *Packet {

	raw := gopacket.NewPacket(data, layers.LayerTypeIPv4, decodeOptions)

	ipv4, ok := raw.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		netfilter.Finalize(id, ActionDrop)
		return &Packet{Id: -1}
	}

	dnsLayer, ok := raw.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if ok {
		for _, answer := range dnsLayer.Answers {
			if answer.Type == layers.DNSTypeA {
				dns.UpdateHosts(&dns.DNS{
					Name:    string(answer.Name),
					Address: answer.IP.String(),
				})
			}
		}
	}

	p := &Packet{
		Proto:   "*",
		Src:     ipv4.SrcIP.String(),
		SrcIP:   ipv4.SrcIP.String(),
		SrcPort: "*",
		Dst:     ipv4.DstIP.String(),
		DstIP:   ipv4.DstIP.String(),
		DstPort: "*",
		Id:      id,
	}

	tcp, ok := raw.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if ok {
		p.Proto = ProtoTCP
		p.SrcPort = fmt.Sprint(int(tcp.SrcPort))
		p.DstPort = fmt.Sprint(int(tcp.DstPort))
		return p
	}

	udp, ok := raw.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if ok {
		p.Proto = ProtoUDP
		p.SrcPort = fmt.Sprint(int(udp.SrcPort))
		p.DstPort = fmt.Sprint(int(udp.DstPort))
		return p
	}

	udpl, ok := raw.Layer(layers.LayerTypeUDPLite).(*layers.UDPLite)
	if ok {
		p.Proto = ProtoUDP
		p.SrcPort = fmt.Sprint(int(udpl.SrcPort))
		p.DstPort = fmt.Sprint(int(udpl.DstPort))
		return p
	}

	_, ok = raw.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if ok {
		p.Proto = ProtoICMP
		return p
	}

	return p
}
