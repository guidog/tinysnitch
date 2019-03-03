package iptables

import (
	"fmt"
	"github.com/evilsocket/opensnitch/lib"
)

const DropMark = 0x18BA5

func RunRule(enable bool, rule []string) (err error) {
	action := "-I"
	if enable == false {
		action = "-D"
	}
	rule = append([]string{action}, rule...)
	_, err = lib.Exec("iptables", rule)
	if err != nil {
		return
	}
	_, err = lib.Exec("ip6tables", rule)
	if err != nil {
		return
	}

	return
}

func QueueDNSResponses(enable bool, queueNum int) (err error) {
	// If enable, we're going to insert as #1, not append
	if enable {
		// FIXME: this is basically copy/paste of RunRule() above b/c we can't
		// shoehorn "-I" with the boolean 'enable' switch
		rule := []string{
			"-I",
			"INPUT",
			"1",
			"--protocol", "udp",
			"--sport", "53",
			"-j", "NFQUEUE",
			"--queue-num", fmt.Sprintf("%d", queueNum),
			// "--queue-bypass",
		}
		_, err := lib.Exec("iptables", rule)
		if err != nil {
			return err
		}
		_, err = lib.Exec("ip6tables", rule)
		if err != nil {
			return err
		}
		return err
	}
	// Otherwise, it's going to be disable
	return RunRule(enable, []string{
		"INPUT",
		"--protocol", "udp",
		"--sport", "53",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
	})
}

func QueueConnections(enable bool, queueNum int) (err error) {
	err = RunRule(enable, []string{
		"INPUT",
		"-t", "mangle",
		"-m", "conntrack",
		"--ctstate", "NEW",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
	})
	if err != nil {
	    return err
	}
	err = RunRule(enable, []string{
		"OUTPUT",
		"-t", "mangle",
		"-m", "conntrack",
		"--ctstate", "NEW",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
	})
	if err != nil {
	    return err
	}
	return nil
}

func DropMarked(enable bool) (err error) {
	return RunRule(enable, []string{
		"OUTPUT",
		"-m", "mark",
		"--mark", fmt.Sprintf("%d", DropMark),
		"-j", "DROP",
	})
}
