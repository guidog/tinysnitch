package main

import (
	"flag"
	"github.com/evilsocket/opensnitch/conman"
	"github.com/evilsocket/opensnitch/core"
	"github.com/evilsocket/opensnitch/dns"
	"github.com/evilsocket/opensnitch/firewall"
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
	err              = (error)(nil)
	queue            = (*netfilter.Queue)(nil)
	pktChan          = (<-chan netfilter.Packet)(nil)
	wrkChan          = (chan netfilter.Packet)(nil)
	sigChan          = (chan os.Signal)(nil)
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
	sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		log.Raw("\n")
		log.Important("Got signal: %v", sig)
		procmon.Stop()
		os.Exit(0)
	}()
}

func worker(id int) {
	log.Debug("Worker #%d started.", id)
	for true {
		select {
		case pkt := <-wrkChan:
			onPacket(pkt)
		}
	}
}

func firewallUp() {
	log.Info("Firewall up ...")
	err = firewall.QueueDNSResponses(true, queueNum)
	if err != nil {
		log.Fatal("Error while running DNS firewall rule: %s", err)
	}
	err = firewall.QueueConnections(true, queueNum)
	if err != nil {
		log.Fatal("Error while running conntrack firewall rule: %s", err)
	}
	err = firewall.DropMarked(true)
	if err != nil {
		log.Fatal("Error while running drop firewall rule: %s", err)
	}
}

func firewallDown() {
	log.Info("Firewall up ...")
	firewall.QueueDNSResponses(false, queueNum)
	firewall.QueueConnections(false, queueNum)
	firewall.DropMarked(false)
}

func onPacket(packet netfilter.Packet) {
	if dns.TrackAnswers(packet.Packet) == true {
		log.Info("dns tracked")
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}
	con := conman.Parse(packet)
	if con == nil {
		// log.Error("what are these?: %s", packet.Packet)
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}
	_, err = core.Exec("notify", []string{
		"-f24",
		"-l120",
		con.String(),
	})
	if err != nil {
		log.Fatal("oh noes")
	}
	if true {
		packet.SetVerdict(netfilter.NF_ACCEPT)
		log.Debug("%s %s -> %s:%d", log.Bold(log.Green("✔")), log.Bold(con.Process.Path), log.Bold(con.To()), con.DstPort)
	} else {
		packet.SetVerdictAndMark(netfilter.NF_DROP, firewall.DropMark)
		log.Warning("%s %s -> %s:%d", log.Bold(log.Red("✘")), log.Bold(con.Process.Path), log.Bold(con.To()), con.DstPort)
	}
}

func main() {
	flag.Parse()
	if setupFirewall {
		firewallUp()
	} else if teardownFirewall {
		firewallDown()
	} else {
		setupLogging()
		log.Important("Starting %s v%s", core.Name, core.Version)
		if err := procmon.Start(); err != nil {
			log.Fatal("%s", err)
		}
		log.Debug("Starting %d workers ...", workers)
		wrkChan = make(chan netfilter.Packet)
		for i := 0; i < workers; i++ {
			go worker(i)
		}
		queue, err := netfilter.NewQueue(uint16(queueNum))
		if err != nil {
			log.Fatal("Error while creating queue #%d: %s", queueNum, err)
		}
		pktChan = queue.Packets()
		log.Info("Running on netfilter queue #%d ...", queueNum)
		for true {
			select {
			case pkt := <-pktChan:
				wrkChan <- pkt
			}
		}
	}
}
