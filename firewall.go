package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"golang.org/x/net/bpf"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kung-foo/freki/netfilter"
	"github.com/labstack/echo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	processed = 0

	ethHdr = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00,
	}

	packetsProcessed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "firewall",
			Name:      "packets_processed_total",
			Help:      "Total number of packets processed.",
		},
	)

	packetsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "firewall",
			Name:      "packets_dropped_total",
			Help:      "Total number of packets dropped.",
		},
	)

	blockedIPs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "firewall",
			Name:      "packets_dropped",
			Help:      "Number of packets allowed by ip.",
		},
		[]string{"src_ip", "dst_ip"},
	)

	allowedIPs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "firewall",
			Name:      "packets_allowed",
			Help:      "Number of packets allowed by ip.",
		},
		[]string{"src_ip", "dst_ip"},
	)
)

// iptables -A INPUT -j NFQUEUE --queue-num 0
// iptables -A OUTPUT -j NFQUEUE --queue-num 0

func main() {
	q, err := netfilter.New(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	onErrorExit(err)
	defer q.Close()

	m, err := newMatcherFromConfig("./config.json")
	onErrorExit(err)

	go q.Run()
	go serve(m)

	pChan := q.Packets()

	prometheus.MustRegister(
		packetsProcessed,
		packetsDropped,
		allowedIPs,
		blockedIPs,
	)

	for i := 0; i < 3; i++ {
		go worker(m, q, pChan)
	}
	worker(m, q, pChan)
}

type rule struct {
	R  string `json:"rule"`
	ID int    `json:"id"`

	matcher *bpf.VM `json:"-"`
}

type matcher struct {
	Interface string `json:"interface"`
	iface     *pcap.Handle

	Rules []rule `json:"rules"`

	sync.RWMutex
}

func newMatcherFromConfig(path string) (*matcher, error) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	m := &matcher{}
	err = json.Unmarshal(f, m)
	if err != nil {
		return nil, err
	}

	if m.Interface == "" {
		return nil, errors.New("config: interface is mandatory")
	}

	iface, err := pcap.OpenLive(m.Interface, 1, false, time.Second)
	if err != nil {
		return nil, err
	}
	m.iface = iface

	for i, r := range m.Rules {
		if r.R == "" {
			return nil, errors.New("config: rule string is mandatory")
		}

		ins, err := iface.CompileBPFFilter(r.R)
		if err != nil {
			return nil, err
		}

		m.Rules[i].matcher, err = pcapBPFToXNetBPF(ins)
		if err != nil {
			return nil, err
		}
		m.Rules[i].ID = i
	}

	return m, nil
}

func (m *matcher) matches(dat []byte) bool {
	m.RLock()
	defer m.RUnlock()

	for _, r := range m.Rules {
		v, err := r.matcher.Run(dat)
		if err != nil {
			fmt.Println(err)
			return false
		}

		if v == 1 {
			return true
		}
	}
	return false
}

func (m *matcher) rmRule(id int) bool {
	if id < 0 && id >= len(m.Rules) {
		return false
	}

	m.Lock()
	m.Rules = append(m.Rules[:id], m.Rules[id+1:]...)
	m.Unlock()

	return true
}

func (m *matcher) addRule(r rule) bool {
	if r.ID < 0 && r.ID >= len(m.Rules) {
		return false
	}

	if r.R == "" {
		return false
	}

	ins, err := m.iface.CompileBPFFilter(r.R)
	if err != nil {
		return false
	}

	r.matcher, err = pcapBPFToXNetBPF(ins)
	if err != nil {
		return false
	}

	m.Lock()
	r2 := append(m.Rules[:r.ID], r)
	r2 = append(r2, m.Rules[r.ID:]...)
	m.Rules = r2
	m.Unlock()

	return true
}

func init() {
	onInterruptSignal(func() {
		log.Printf("\n%d packets processed", processed)
		os.Exit(0)
	})

}

func onErrorExit(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func onInterruptSignal(fn func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		fn()
	}()
}

func pcapBPFToXNetBPF(pcapbpf []pcap.BPFInstruction) (*bpf.VM, error) {
	raw := make([]bpf.RawInstruction, len(pcapbpf))

	for i, ins := range pcapbpf {
		raw[i] = bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
	}

	filter, _ := bpf.Disassemble(raw)
	return bpf.NewVM(filter)
}

func serve(m *matcher) {
	e := echo.New()
	e.GET("/rules", func(c echo.Context) error {
		m.RLock()
		defer m.RUnlock()
		return c.JSON(http.StatusOK, m)
	})

	e.DELETE("/rules", func(c echo.Context) error {
		r := &rule{}
		if err := c.Bind(r); err != nil {
			return err
		}

		m.rmRule(r.ID)

		m.RLock()
		defer m.RUnlock()
		return c.JSON(http.StatusOK, m)
	})

	e.POST("/rules", func(c echo.Context) error {
		r := &rule{}
		if err := c.Bind(r); err != nil {
			return err
		}

		m.addRule(*r)
		m.RLock()
		defer m.RUnlock()
		return c.JSON(http.StatusOK, m)
	})

	e.GET("/metrics", func(c echo.Context) error {
		return echo.WrapHandler(promhttp.Handler())(c)
	})

	e.Logger.Fatal(e.Start(":1323"))
}

func worker(m *matcher, q *netfilter.Queue, pChan <-chan *netfilter.RawPacket) {
	for p := range pChan {
		buffer := append(ethHdr, p.Data...)
		packet := gopacket.NewPacket(
			buffer,
			layers.LayerTypeEthernet,
			gopacket.DecodeOptions{Lazy: false, NoCopy: true},
		)

		ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		packetsProcessed.Inc()
		if m.matches(buffer) {
			q.SetVerdict(p, netfilter.NF_DROP)
			packetsDropped.Inc()

			if ok {
				blockedIPs.WithLabelValues(ip.SrcIP.String(), ip.DstIP.String()).Inc()
			}

			continue
		}

		if ok {
			allowedIPs.WithLabelValues(ip.SrcIP.String(), ip.DstIP.String()).Inc()
		}
		q.SetVerdict(p, netfilter.NF_ACCEPT)
	}
}
