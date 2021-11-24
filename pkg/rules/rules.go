package rules

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nathants/tinysnitch/pkg/dns"
	"github.com/nathants/tinysnitch/pkg/netfilter"
	"github.com/nathants/tinysnitch/pkg/packet"
)

const (
	durationHour   = "hour"
	durationMinute = "minute"
)

func username() string {
	user := os.Getenv("TINYSNITCH_PROMPT_USER")
	if user != "" {
		return user
	}
	fs, err := os.ReadDir("/home")
	if err != nil {
		panic(err)
	}
	var names []string
	for _, f := range fs {
		names = append(names, f.Name())
	}
	if len(names) == 1 {
		return names[0]
	}
	panic(names)
}

func ephemeralPorts() (int, int) {
	data, err := ioutil.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		panic(err)
	}
	parts := strings.SplitN(strings.Trim(string(data), "\n"), "\t", 2)
	low, err := strconv.Atoi(parts[0])
	if err != nil {
		panic(err)
	}
	high, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}
	return low, high
}

var (
	promptUser          = username()
	portsLow, portsHigh = ephemeralPorts()
)

type RuleKey struct {
	Address string
	Port    string
	Proto   string
}

type Rule struct {
	RuleKey
	Action   int
	Duration time.Duration
	Creation time.Time
}

var splitWhitespace = regexp.MustCompile(`\s+`).Split

func (r *Rule) Parse(s string) error {
	parts := splitWhitespace(s, 4)
	if len(parts) != 4 {
		return fmt.Errorf("failed-parsing-rule 4-parts %s", s)
	}
	switch parts[0] {
	case "allow":
		r.Action = packet.ActionAccept
	case "deny":
		r.Action = packet.ActionDrop
	default:
		return fmt.Errorf("failed-parsing-rule action %s", s)
	}
	r.Address = parts[1]
	_, err := strconv.Atoi(parts[2])
	if err != nil && parts[2] != "*" {
		return fmt.Errorf("failed-parsing-rule port %s", s)
	}
	r.Port = parts[2]
	switch parts[3] {
	case packet.ProtoTCP:
	case packet.ProtoUDP:
	case packet.ProtoICMP:
	default:
		return fmt.Errorf("failed-parsing-rule proto %s", s)
	}
	r.Proto = parts[3]
	return nil
}

func (r *Rule) ParseTemp(s string) error {
	orig := s
	parts := splitWhitespace(s, 2)
	if len(parts) != 2 {
		return fmt.Errorf("failed-parsing-temp-rule 2-parts %s", orig)
	}
	duration := parts[0]
	durationParts := strings.SplitN(duration, "-", 2)
	durationAmount, err := strconv.Atoi(durationParts[0])
	if err != nil {
		return fmt.Errorf("failed-parsing-temp-rule duration-amount %s", orig)
	}
	durationUnit := durationParts[1]
	switch durationUnit {
	case durationMinute:
		r.Duration = time.Minute * time.Duration(durationAmount)
	case durationHour:
		r.Duration = time.Hour * time.Duration(durationAmount)
	default:
		return fmt.Errorf("failed-parsing-temp-rule duration-unit %s", orig)
	}
	err = r.Parse(parts[1])
	if err != nil {
		return err
	}
	r.Creation = time.Now()
	return nil
}

func (r *Rule) String() string {
	switch r.Action {
	case packet.ActionAccept:
		return fmt.Sprintf("allow %s %s %s", r.Address, r.Port, r.Proto)
	case packet.ActionDrop:
		return fmt.Sprintf("deny %s %s %s", r.Address, r.Port, r.Proto)
	default:
		panic(r)
	}
}

type rulesState struct {
	lock             sync.RWMutex
	rulesFile        string
	tempRulesFile    string
	adblockRulesFile string
	rules            map[RuleKey]*Rule
	promptQueue      chan *packet.Packet
}

var state = &rulesState{
	lock:        sync.RWMutex{},
	rules:       make(map[RuleKey]*Rule),
	promptQueue: make(chan *packet.Packet, 1024),
}

func Start(rulesFile, tempRulesFile, adblockRulesFile string) {
	state.rulesFile = rulesFile
	state.tempRulesFile = tempRulesFile
	state.adblockRulesFile = adblockRulesFile
	go watchTempRules()
	go watchPermanentRules()
	go watchPromptQueue()
	go gcTemporaryRules()
}

var isIPV4 = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)\.(\d+)$`).MatchString

func splitFour(s string) (string, string, string, string) {
	parts := strings.SplitN(s, ".", 4)
	return parts[0], parts[1], parts[2], parts[3]
}

func matchRule(p *packet.Packet) *Rule {
	switch p.Proto {
	case packet.ProtoTCP:
	case packet.ProtoUDP:
	case packet.ProtoICMP:
	default:
		return &Rule{Action: packet.ActionAccept} // allow all other than tcp, udp, icmp
	}
	lookupKeys := []RuleKey{
		{Address: p.Dst, Port: p.DstPort, Proto: p.Proto}, // exact match
		{Address: p.Dst, Port: "*" /* */, Proto: p.Proto}, // port wildcard
	}
	if isIPV4(p.Dst) {
		a, b, c, _ := splitFour(p.Dst)
		lookupKeys = append(lookupKeys, []RuleKey{
			{Address: a + "." + b + "." + c + ".*", Port: p.DstPort, Proto: p.Proto}, // cidr mask wildcard
			{Address: a + "." + b + ".*.*" /*   */, Port: p.DstPort, Proto: p.Proto}, // cidr mask wildcard
			{Address: a + ".*.*.*" /*           */, Port: p.DstPort, Proto: p.Proto}, // cidr mask wildcard
			{Address: a + "." + b + "." + c + ".*", Port: "*" /* */, Proto: p.Proto}, // cidr mask and port wildcard
			{Address: a + "." + b + ".*.*" /*   */, Port: "*" /* */, Proto: p.Proto}, // cidr mask and port wildcard
			{Address: a + ".*.*.*" /*           */, Port: "*" /* */, Proto: p.Proto}, // cidr mask and port wildcard
		}...)
	} else {
		lookupKeys = append(lookupKeys, []RuleKey{
			{Address: subdomainWildcard(p.Dst), Port: p.DstPort, Proto: p.Proto}, // subdomain wildcard
			{Address: subdomainWildcard(p.Dst), Port: "*" /* */, Proto: p.Proto}, // subdomain and port wildcard
		}...)
	}
	state.lock.RLock()
	defer state.lock.RUnlock()
	for _, key := range lookupKeys {
		rule, ok := state.rules[key]
		if ok {
			return rule
		}
	}
	return nil
}

func subdomainWildcard(address string) string {
	parts := strings.Split(address, ".")
	if len(parts) >= 2 {
		return "*." + strings.Join(parts[len(parts)-2:], ".")
	}
	return address
}

func atoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return i
}

func shouldFlipEphemeralTCP(p *packet.Packet) bool {
	return dns.IsLocalhost(p.Dst) &&
		p.Proto == packet.ProtoTCP &&
		p.SrcPort != "*" &&
		p.DstPort != "*" &&
		portsLow <= atoi(p.DstPort) && atoi(p.DstPort) <= portsHigh &&
		atoi(p.SrcPort) < portsLow
}

func check(p *packet.Packet) bool {
	p.ResolveDNS()
	if shouldFlipEphemeralTCP(p) { // check inbound tcp connections on ephemeral ports as outbound traffic
		p.FlipDirection()
	}
	rule := matchRule(p)
	if rule == nil && p.Proto == packet.ProtoUDP { // udp should do a fallback check for inbound connections as if outbound
		p.FlipDirection()
		rule = matchRule(p)
	}
	if rule != nil {
		switch rule.Action {
		case packet.ActionDrop:
			fmt.Println("deny", p)
		case packet.ActionAccept:
			fmt.Println("allow", p)
		default:
			panic(rule)
		}
		netfilter.Finalize(p.Id, rule.Action)
		return true
	}
	return false
}

func addRule(r *Rule, log bool) {
	state.lock.Lock()
	defer state.lock.Unlock()
	existing, ok := state.rules[r.RuleKey]
	if !ok || *r != *existing {
		state.rules[r.RuleKey] = r
		if log {
			if r.Duration == 0 {
				fmt.Println("add-rule", r)
			} else {
				fmt.Println("add-temp-rule", r.Duration, r)
			}
		}
	}
}

func gcTemporaryRules() {
	for {
		state.lock.RLock()
		var rules []*Rule
		for _, r := range state.rules {
			rules = append(rules, r)
		}
		state.lock.RUnlock()
		for _, r := range rules {
			if r.Duration != 0 && time.Since(r.Creation) > r.Duration {
				state.lock.Lock()
				delete(state.rules, r.RuleKey)
				state.lock.Unlock()
				fmt.Println("expire-rule", r)
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func watchTempRules() {
	for {
		f, err := ioutil.TempFile("/tmp", "temprule.")
		if err != nil {
			panic(err)
		}
		tempFile := f.Name()
		err = f.Close()
		if err != nil {
			panic(err)
		}
		tempRulesFile := state.tempRulesFile
		err = os.Rename(tempRulesFile, tempFile)
		if err != nil {
			time.Sleep(1 * time.Second)
		} else {
			data, err := ioutil.ReadFile(tempFile)
			if err != nil {
				panic(err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				if line != "" {
					r := &Rule{}
					err := r.ParseTemp(line)
					if err != nil {
						fmt.Println(err)
					} else {
						addRule(r, false)
					}
				}
			}
			err = os.Remove(tempFile)
			if err != nil {
				panic(err)
			}
		}
	}
}

func watchPermanentRules() {
	state.lock.RLock()
	rulesFile := state.rulesFile
	adblockRulesFile := state.adblockRulesFile
	state.lock.RUnlock()
	files := []string{
		rulesFile,
		adblockRulesFile,
	}
	started := false
	last := make(map[string]time.Time)
	for {
		rulesUpdate := false
		for _, file := range files {
			stat, err := os.Stat(file)
			var mtime time.Time
			if err == nil {
				mtime = stat.ModTime()
			}
			if last[file] != mtime {
				rulesUpdate = true
			}
			last[file] = mtime
		}
		if !rulesUpdate {
			time.Sleep(1 * time.Second)
			continue
		}
		newRules := make(map[RuleKey]*Rule)
		for _, file := range files {
			count := 0
			data, err := ioutil.ReadFile(file)
			if err != nil {
				fmt.Println("err-on-readfile", file, err)
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if line != "" {
					r := &Rule{}
					err := r.Parse(line)
					if err != nil {
						fmt.Println(err)
						continue
					}
					count++
					addRule(r, started)
					newRules[r.RuleKey] = r
				}
			}
			if !started {
				fmt.Println("loaded", count, "rules from:", file)
			}
		}
		started = true
		gcPermanentRules(newRules)
	}
}

func gcPermanentRules(newRules map[RuleKey]*Rule) {
	var rules []Rule
	state.lock.RLock()
	for _, rule := range state.rules {
		rules = append(rules, *rule)
	}
	state.lock.RUnlock()
	for _, rule := range rules {
		_, ok := newRules[rule.RuleKey]
		if !ok && rule.Duration == 0 {
			state.lock.Lock()
			delete(state.rules, rule.RuleKey)
			state.lock.Unlock()
			fmt.Println("remove-rule", &rule)
		}
	}
}

func prompt(p *packet.Packet) {
	input := base64.StdEncoding.EncodeToString([]byte(p.String()))
	cmd := exec.Command("su", promptUser, "-c", fmt.Sprintf("DISPLAY=:0 tinysnitch-prompt %s", input))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("error-on-prompt", stderr.String())
		netfilter.Finalize(p.Id, packet.ActionDrop)
		return
	}
	processPromptOutput(p, stdout.String())
}

func processPromptOutput(p *packet.Packet, output string) {
	parts := splitWhitespace(output, 5)
	if len(parts) != 5 {
		fmt.Println("error-on-prompt parts", output)
		netfilter.Finalize(p.Id, packet.ActionDrop)
		return
	}
	duration := parts[0]
	subdomains := parts[1]
	action := parts[2]
	ports := parts[3]
	reverse := parts[4]
	if duration == "once" {
		finalize(p.Id, action)
		return
	}
	if reverse == "yes" {
		p.FlipDirection()
	}
	if ports == "no" {
		p.DstPort = "*"
	}
	r := &Rule{}
	if duration != "forever" {
		r.Creation = time.Now()
		parts = strings.SplitN(duration, "-", 2)
		durationAmount, err := strconv.Atoi(parts[0])
		if err != nil {
			fmt.Println("error-on-prompt duration-amount", output)
			netfilter.Finalize(p.Id, packet.ActionDrop)
			return
		}
		durationUnit := parts[1]
		switch durationUnit {
		case "minute":
			r.Duration = time.Minute * time.Duration(durationAmount)
		case "hour":
			r.Duration = time.Hour * time.Duration(durationAmount)
		default:
			fmt.Println("error-on-prompt duration-unit", output)
			netfilter.Finalize(p.Id, packet.ActionDrop)
			return
		}
	}
	if subdomains == "yes" {
		p.Dst = subdomainWildcard(p.Dst)
	}
	switch action {
	case "allow":
		r.Action = packet.ActionAccept
	case "deny":
		r.Action = packet.ActionDrop
	default:
		fmt.Println("error-on-prompt action", output)
		netfilter.Finalize(p.Id, packet.ActionDrop)
		return
	}
	r.Address = p.Dst
	r.Port = p.DstPort
	r.Proto = p.Proto
	addRule(r, true)
	if duration == "forever" {
		persistRule(r)
	}
	finalize(p.Id, action)
}

func finalize(id int, action string) {
	switch action {
	case "allow":
		netfilter.Finalize(id, packet.ActionAccept)
	case "deny":
		netfilter.Finalize(id, packet.ActionDrop)
	default:
		panic(action)
	}
}

func persistRule(r *Rule) {
	f, err := os.OpenFile(state.rulesFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	_, err = f.WriteString(r.String() + "\n")
	if err != nil {
		panic(err)
	}
	err = f.Close()
	if err != nil {
		panic(err)
	}
}

func watchPromptQueue() {
	for {
		p := <-state.promptQueue
		if !check(p) { // check again after pull from prompt-queue since rules can change while queued
			prompt(p)
		}

	}
}

func Process(id int, data []byte) {
	p := packet.Parse(id, data)

	// already dropped
	if p.Id == -1 {
		return
	}

	// some udp traffic gets queued in a strange loopback mode, accept it
	if p.IsUDPLooopback() {
		netfilter.Finalize(p.Id, packet.ActionAccept)
		return
	}

	// run firewall check
	if !check(p) {
		// if no rule matches, queue visual user prompt
		state.promptQueue <- p
	}

}
