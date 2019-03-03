package conn

import (
	"fmt"
	"github.com/evilsocket/opensnitch/dns"
	"github.com/evilsocket/opensnitch/log"
	"github.com/evilsocket/opensnitch/netfilter"
	"github.com/evilsocket/opensnitch/netstat"
	"github.com/evilsocket/opensnitch/procmon"
	"github.com/google/gopacket/layers"
	"net"
)

type Connection struct {
	Protocol string
	SrcIP    net.IP
	SrcPort  uint
	DstIP    net.IP
	DstPort  uint
	DstHost  string
	Entry    *netstat.Entry
	Process  *procmon.Process
	pkt      *netfilter.Packet
}

func Parse(nfp netfilter.Packet) *Connection {
	ipLayer := nfp.Packet.Layer(layers.LayerTypeIPv4)
	ipLayer6 := nfp.Packet.Layer(layers.LayerTypeIPv6)
	if ipLayer == nil && ipLayer6 == nil {
		log.Info("nil i fifth")
		return nil
	}
	if ipLayer == nil {
		ip, ok := ipLayer6.(*layers.IPv6)
		if ok == false || ip == nil {
			log.Info("not ok")
			return nil
		}
		if ip.SrcIP.IsLoopback() {
			log.Info("loopy")
			return nil
		}
		if ip.SrcIP.IsMulticast() || ip.DstIP.IsMulticast() {
			log.Info("multi")
			return nil
		}
		con := NewConnection6(&nfp, ip)
		return con
	} else {
		ip, ok := ipLayer.(*layers.IPv4)
		if ok == false || ip == nil {
			log.Info("not ok ipv6")
			return nil
		}
		if ip.SrcIP.IsLoopback() {
			log.Info("loopy ipv6")
			return nil
		}
		if ip.SrcIP.IsMulticast() || ip.DstIP.IsMulticast() {
			log.Info("multi ipv6")
			return nil
		}
		con := NewConnection(&nfp, ip)
		return con
	}
}

func newConnectionImpl(nfp *netfilter.Packet, c *Connection) (cr *Connection) {
	// no errors but not enough info neither
	if !c.parseDirection() {
		log.Error("failed to parse direction")
		// return nil
	}
	// 1. lookup uid and inode using /proc/net/(udp|tcp)
	// 2. lookup pid by inode
	// 3. if this is coming from us, just accept
	// 4. lookup process info by pid
	c.Entry = netstat.FindEntry(c.Protocol, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
	if c.Entry == nil {
		log.Error("Could not find netstat entry for: %s", c.SingleString())
		return c
	}
	pid := procmon.GetPIDFromINode(c.Entry.INode)
	if pid == -1 {
		log.Error("Could not find process id for: %s", c.SingleString())
		return c
	}
	c.Process = procmon.FindProcess(pid)
	if c.Process == nil {
		log.Error("Could not find process by its pid %d for: %s", pid, c.SingleString())
		return c
	}
	return c
}

func NewConnection(nfp *netfilter.Packet, ip *layers.IPv4) (c *Connection) {
	c = &Connection{
		SrcIP:   ip.SrcIP,
		DstIP:   ip.DstIP,
		DstHost: dns.HostOr(ip.DstIP, ip.DstIP.String()),
		pkt:     nfp,
	}
	return newConnectionImpl(nfp, c)
}

func NewConnection6(nfp *netfilter.Packet, ip *layers.IPv6) (c *Connection) {
	c = &Connection{
		SrcIP:   ip.SrcIP,
		DstIP:   ip.DstIP,
		DstHost: dns.HostOr(ip.DstIP, ip.DstIP.String()),
		pkt:     nfp,
	}
	return newConnectionImpl(nfp, c)
}

func (c *Connection) parseDirection() bool {
	ret := false
	for _, layer := range c.pkt.Packet.Layers() {
		if layer.LayerType() == layers.LayerTypeTCP {
			if tcp, ok := layer.(*layers.TCP); ok == true && tcp != nil {
				c.Protocol = "tcp"
				c.DstPort = uint(tcp.DstPort)
				c.SrcPort = uint(tcp.SrcPort)
				ret = true
			}
		} else if layer.LayerType() == layers.LayerTypeUDP {
			if udp, ok := layer.(*layers.UDP); ok == true && udp != nil {
				c.Protocol = "udp"
				c.DstPort = uint(udp.DstPort)
				c.SrcPort = uint(udp.SrcPort)
				ret = true
			}
		}
	}
	for _, layer := range c.pkt.Packet.Layers() {
		if layer.LayerType() == layers.LayerTypeIPv6 {
			if tcp, ok := layer.(*layers.IPv6); ok == true && tcp != nil {
				c.Protocol += "6"
			}
		}
	}
	return ret
}


func (c *Connection) To() string {
	if c.DstHost == "" {
		return c.DstIP.String()
	}
	return c.DstHost
}

func (c *Connection) String() string {
	if c.Entry == nil {
		return fmt.Sprintf("%s\n\n->\n\n%s %s:%d", c.SrcIP, c.Protocol, c.To(), c.DstPort)
	} else if c.Process == nil {
		return fmt.Sprintf("%s uid:%d\n\n->\n\n%s %s:%d", c.SrcIP, c.Entry.UserId, c.Protocol, c.To(), c.DstPort)
	} else {
		return fmt.Sprintf("%s pid:%d uid:%d\n\n->\n\n%s %s:%d", c.Process.Path, c.Process.ID, c.Entry.UserId, c.Protocol, c.To(), c.DstPort)
	}
}

func (c *Connection) SingleString() string {
	if c.Entry == nil {
		return fmt.Sprintf("%s -> %s %s:%d", c.SrcIP, c.Protocol, c.To(), c.DstPort)
	} else if c.Process == nil {
		return fmt.Sprintf("%s uid:%d -> %s %s:%d", c.SrcIP, c.Entry.UserId, c.Protocol, c.To(), c.DstPort)
	} else {
		return fmt.Sprintf("%s pid:%d uid:%d -> %s %s:%d", c.Process.Path, c.Process.ID, c.Entry.UserId, c.Protocol, c.To(), c.DstPort)
	}
}
