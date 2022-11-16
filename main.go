package main

import (
	"flag"

	"github.com/nathants/tiny-snitch/pkg/dns"
	"github.com/nathants/tiny-snitch/pkg/netfilter"
	"github.com/nathants/tiny-snitch/pkg/rules"
)

func main() {

	rulesFile := flag.String("r", "/etc/tiny-snitch.rules", "permanent rules file")
	tempRulesFile := flag.String("t", "/tmp/tiny-snitch.temp", "temp rules file")
	adblockRulesFile := flag.String("a", "/etc/tiny-snitch.adblock", "adblock rules file")
	flag.Parse()

	dns.Start()
	rules.Start(*rulesFile, *tempRulesFile, *adblockRulesFile)

	nfqHandle, nfqQHandle := netfilter.Create(rules.Process)
	nfqFd := netfilter.Setup(nfqHandle, nfqQHandle)
	netfilter.Run(nfqHandle, nfqFd)
}
