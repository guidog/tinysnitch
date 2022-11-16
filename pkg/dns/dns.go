package dns

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	dnsFile = "/etc/tiny-snitch.hosts"
)

type DNS struct {
	Name    string
	Address string
}

func (d *DNS) Parse(line string) {
	line = strings.Trim(line, "\n")
	parts := strings.SplitN(line, " ", 2)
	d.Name = parts[0]
	d.Address = parts[1]
}

func (d *DNS) String() string {
	return fmt.Sprintf("%s %s", d.Name, d.Address)
}

type dnsState struct {
	localhosts map[string]interface{}
	hosts      map[string]string
	newDNS     chan *DNS
	lock       sync.RWMutex
}

var state = &dnsState{
	localhosts: make(map[string]interface{}),
	hosts:      make(map[string]string),
	newDNS:     make(chan *DNS, 4096),
	lock:       sync.RWMutex{},
}

func Start() {
	populateHosts()
	go localhostWatcher()
	go dnsLogger()
}

func UpdateHosts(d *DNS) {
	state.lock.Lock()
	if d.Name != state.hosts[d.Address] {
		state.hosts[d.Address] = strings.ToLower(d.Name)
		state.lock.Unlock()
		state.newDNS <- d
		fmt.Printf("dns %s -> %s\n", d.Name, d.Address)
	} else {
		state.lock.Unlock()
	}
}

func localhostWatcher() {
	// defer func() {}()
	for {
		ifaces, err := net.Interfaces()
		if err != nil {
			panic(err)
		}
		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}
			var toAdd []string
			for _, a := range addrs {
				toAdd = append(toAdd, strings.Split(a.String(), "/")[0])
			}
			state.lock.Lock()
			for _, add := range toAdd {
				state.hosts[add] = "localhost"
				state.localhosts[add] = nil
			}
			state.lock.Unlock()
		}
		time.Sleep(5 * time.Second)
	}
}

func GetHostName(address string) string {
	state.lock.RLock()
	defer state.lock.RUnlock()
	name, ok := state.hosts[address]
	if ok {
		return name
	}
	return address
}

func populateHosts() {
	data, err := os.ReadFile(dnsFile)
	if err != nil {
		f, err := os.Create(dnsFile)
		if err == nil {
			_ = f.Close()
		}
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		dns := DNS{}
		dns.Parse(line)
		state.lock.Lock()
		state.hosts[dns.Address] = strings.ToLower(dns.Name)
		state.lock.Unlock()
	}
}

func IsLocalhost(address string) bool {
	state.lock.RLock()
	defer state.lock.RUnlock()
	_, ok := state.localhosts[address]
	return ok
}

func dnsLogger() {
	// defer func() {}()
	for {
		f, err := os.OpenFile(dnsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
	outer:
		for {
			select {
			case d := <-state.newDNS:
				_, err = f.WriteString(d.String() + "\n")
				if err != nil {
					panic(err)
				}
			default:
				break outer
			}
		}
		err = f.Close()
		if err != nil {
			panic(err)
		}
		time.Sleep(1 * time.Second)
	}
}
