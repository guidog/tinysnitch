package main

import (
	"flag"

	"github.com/nathants/tinysnitch/pkg/dns"
	"github.com/nathants/tinysnitch/pkg/netfilter"
	"github.com/nathants/tinysnitch/pkg/rules"
)

func main() {

	rulesFile := flag.String("r", "/etc/tinysnitch.rules", "permanent rules file")
	tempRulesFile := flag.String("t", "/tmp/tinysnitch.temp", "temp rules file")
	adblockRulesFile := flag.String("a", "/etc/tinysnitch.adblock", "adblock rules file")
	flag.Parse()

	dns.Start()
	rules.Start(*rulesFile, *tempRulesFile, *adblockRulesFile)

	nfqHandle, nfqQHandle := netfilter.Create(rules.Process)
	nfqFd := netfilter.Setup(nfqHandle, nfqQHandle)
	netfilter.Run(nfqHandle, nfqFd)
}
