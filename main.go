package main

import (
	"flag"
	"github.com/evilsocket/opensnitch/conn"
	"github.com/evilsocket/opensnitch/dns"
	"github.com/evilsocket/opensnitch/iptables"
	"github.com/evilsocket/opensnitch/lib"
	"github.com/evilsocket/opensnitch/log"
	"github.com/evilsocket/opensnitch/netfilter"
	"github.com/evilsocket/opensnitch/procmon"
	"io/ioutil"
	golog "log"
	"os"
	"os/signal"
	"syscall"
)

var (
	setupFirewall    = false
	teardownFirewall = false
	queueNum         = 0
	workers          = 1
	noDebug          = false
	wrkChan          = (chan netfilter.Packet)(nil)
)

func init() {
	flag.BoolVar(&setupFirewall, "setup-firewall", setupFirewall, "Setup Firewall IP-Table Rules.")
	flag.BoolVar(&teardownFirewall, "teardown-firewall", teardownFirewall, "Teardown Firewall IP-Table Rules.")
	flag.IntVar(&queueNum, "queue-num", queueNum, "Netfilter queue number.")
	flag.IntVar(&workers, "workers", workers, "Number of concurrent workers.")
	flag.BoolVar(&noDebug, "noDebug", noDebug, "Disable debug logs.")
}

func setupLogging() {
	golog.SetOutput(ioutil.Discard)
	if !noDebug {
		log.MinLevel = log.DEBUG
	} else {
		log.MinLevel = log.INFO
	}
}

func setupSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		log.Raw("\n")
		log.Important("Got signal: %v", sig)
		err := procmon.Stop()
		if err != nil {
		    log.Fatal("failed to stop procmon")
		}
		os.Exit(0)
	}()
}

func firewall(enable bool) {
	fail := false
	err := iptables.QueueDNSResponses(enable, queueNum)
	if err != nil {
		log.Error("Error while running DNS firewall rule: %s", err)
		fail = true
	}
	err = iptables.QueueConnections(enable, queueNum)
	if err != nil {
		log.Error("Error while running conntrack firewall rule: %s", err)
		fail = true
	}
	err = iptables.DropMarked(enable)
	if err != nil {
		log.Error("Error while running firewall rule: %s", err)
		fail = true
	}
	if fail {
		os.Exit(1)
	}
}

func onPacket(packet netfilter.Packet) {
	if dns.TrackAnswers(packet.Packet) {
		log.Info("dns tracked")
		// packet.SetVerdict(netfilter.NF_ACCEPT)
		// return
	}
	con := conn.Parse(packet)
	if con == nil {
		// log.Error("what are these?: %s", packet.Packet)
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}
	_, err := lib.Exec("notify", []string{"-f24", "-l120", con.String()})
	if err != nil {
		log.Fatal("oh noes")
	}
	if true {
		packet.SetVerdict(netfilter.NF_ACCEPT)
		log.Info("allow: %s", con.SingleString())
	} else {
		packet.SetVerdictAndMark(netfilter.NF_DROP, iptables.DropMark)
		log.Info("deny: %s", con.SingleString())
	}
}

func worker(id int) {
	for {
		select {
		case pkt := <-wrkChan:
			onPacket(pkt)
		}
	}
}

func _main() {
	setupLogging()
	setupSignals()
	if err := procmon.Start(); err != nil {
		log.Fatal("%s", err)
	}
	log.Debug("Starting %d workers ...", workers)

	wrkChan = make(chan netfilter.Packet)
	for i := 0; i < workers; i++ {
		log.Debug("Worker #%d started.", i)
		go worker(i)
	}

	queue, err := netfilter.NewQueue(uint16(queueNum))
	if err != nil {
		log.Fatal("Error while creating queue #%d: %s", queueNum, err)
	}

	pktChan := queue.Packets()
	log.Info("Running on netfilter queue #%d ...", queueNum)
	for {
		select {
		case pkt := <- pktChan:
			wrkChan <- pkt
		}
	}
}

func main() {
	flag.Parse()
	if setupFirewall {
		log.Info("firewall up")
		firewall(true)
	} else if teardownFirewall {
		log.Info("firewall down")
		firewall(false)
	} else {
		log.Info("start opensnitchd")
		_main()
	}
}