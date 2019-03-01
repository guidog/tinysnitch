package main

import (
	"flag"
	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/firewall"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netfilter"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"io/ioutil"
	golog "log"
	"os"
	"os/signal"
	"syscall"
)

var (
	rulesPath        = "/etc/opensnitchd/rules"
	noLiveReload     = false
	setupFirewall    = false
	teardownFirewall = false
	queueNum         = 0
	workers          = 1
	noDebug          = false
	err              = (error)(nil)
	rules            = (*rule.Loader)(nil)
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
		cleanup()
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

func setupWorkers() {
	log.Debug("Starting %d workers ...", workers)
	wrkChan = make(chan netfilter.Packet)
	for i := 0; i < workers; i++ {
		go worker(i)
	}
}

func cleanup() {
	log.Info("Cleaning up ...")
	go procmon.Stop()
}

func firewallUp() {
	log.Info("Firewall up ...")
	if err = firewall.QueueDNSResponses(true, queueNum); err != nil {
		log.Fatal("Error while running DNS firewall rule: %s", err)
	} else if err = firewall.QueueConnections(true, queueNum); err != nil {
		log.Fatal("Error while running conntrack firewall rule: %s", err)
	} else if err = firewall.DropMarked(true); err != nil {
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
	// DNS response, just parse, track and accept.
	if dns.TrackAnswers(packet.Packet) == true {
		log.Info("dns tracked")
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}
	// Parse the connection state
	con := conman.Parse(packet)
	if con == nil {
		// log.Error("this shouldnt happen anymore: %s", con)
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}
	_, err := core.Exec("notify", []string{
		"-f24",
		"-l120",
		con.String(),
	})
	if err != nil {
		os.Exit(1)
	}
	allow := true
	if allow {
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
		rulesPath, err := core.ExpandPath(rulesPath)
		if err != nil {
			log.Fatal("%s", err)
		}
		setupSignals()
		log.Info("Loading rules from %s ...", rulesPath)
		rules = rule.NewLoader()
		err = rules.Load(rulesPath)
		if err != nil {
			log.Fatal("%s", err)
		}
		setupWorkers()
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
