package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/astaxie/beego/httplib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	promiscuous = true
)

var (
	device       = flag.String("i", "any", "device interface")
	filter       = flag.String("f", "", "filter")
	snapshot     = flag.Int("s", 1024, "snapshot length")
	timeout      = flag.Int("t", -1, "timeout exit application")
	ex_port      = flag.String("e", "", "exclude port")
	url          = flag.String("u", "", "server url")
	capture_time = flag.String("interval", "", "capture time,sleep time")
	quiet        = flag.Bool("q", false, "quiet")

	errorLog = log.New(os.Stderr, "", 0)

	chan_timeout = make(chan bool, 1)
)

type Event struct {
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"time"`
	Length    int       `json:"length"`

	Layer3 string `json:"l3_type"`
	SrcIP  string `json:"src_ip"`
	DstIP  string `json:"dst_ip"`

	Layer4  string `json:"l4_type"`
	SrcPort string `json:"src_port"`
	DstPort string `json:"dst_port"`
}

func process(p gopacket.Packet) {

	defer func() {
		if err := recover(); err != nil {

		}
	}()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	timestamp := p.Metadata().Timestamp
	length := p.Metadata().Length

	srcIP, dstIP := p.NetworkLayer().NetworkFlow().Endpoints()
	l3Type := p.NetworkLayer().LayerType()

	srcPort, dstPort := p.TransportLayer().TransportFlow().Endpoints()
	l4Type := p.TransportLayer().LayerType()

	e := Event{
		Hostname:  hostname,
		Timestamp: timestamp,
		Length:    length,

		Layer3: l3Type.String(),
		SrcIP:  srcIP.String(),
		DstIP:  dstIP.String(),

		Layer4:  l4Type.String(),
		SrcPort: srcPort.String(),
		DstPort: dstPort.String(),
	}

	ports := strings.Split(*ex_port, ",")

	for _, p := range ports {
		if p == srcPort.String() || p == dstPort.String() {
			return
		}

	}

	json_event, err := json.Marshal(e)
	if *url != "" {
		req := httplib.Post(*url)
		req.Param("data", string(json_event))
		req.String()
	}
	if err != nil {
		errorLog.Printf("ERROR: can't marshal %s", e)
	}
	if !*quiet {
		fmt.Println(string(json_event))
	}
	return
}

func main() {
	flag.Parse()

	// Open device
	handle, err := pcap.OpenLive(
		*device,
		int32(*snapshot),
		promiscuous,
		pcap.BlockForever,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Fatal(err)
	}

	//	errorLog.Printf("Started capture: device=%s filter=\"%s\"\n", *device, *filter)
	// capture packets forever
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//	fmt.Println(*timeout)
	//	os.Exit(1)
	if *timeout != -1 {
		go func() {
			time.Sleep(time.Second * time.Duration(*timeout))
			chan_timeout <- true

		}()
	}

	sleepTime := -1
	captrueTime := -1
	sleepFlag := false

	if *capture_time != "" {
		ts := strings.Split(*capture_time, ",")
		if len(ts) == 2 {
			captrueTime, _ = strconv.Atoi(ts[0])
			sleepTime, _ = strconv.Atoi(ts[1])
		}
	}

	go func() {
		c := captrueTime
		s := sleepTime
		a := c + s
		t := 0
		for {

			if t < c {
				sleepFlag = false
			}
			if t > c {
				sleepFlag = true
			}
			if t >= a {
				t = 0
				sleepFlag = false
			}
			time.Sleep(time.Duration(1) * time.Second)
			t = t + 1

		}

	}()

	go func() {
		for packet := range packetSource.Packets() {
			if packet != nil {
				if !sleepFlag {
					process(packet)
				} else {
					continue
				}
			}
		}
	}()

	select {
	case <-chan_timeout:
		os.Exit(0)

	}

}
