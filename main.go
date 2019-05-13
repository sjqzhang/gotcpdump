package main

import (
	//"bytes"
	//"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/astaxie/beego/httplib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	log "github.com/sjqzhang/seelog"

	"github.com/sjqzhang/goutil"
	_ "net/http/pprof"
	//"math/rand"
	"net"
	"os"
	//"os/exec"
	//"regexp"
	"strconv"
	//"reflect"
	"strings"
	"sync"
	//"syscall"
	"time"
	"net/http"
)

const (
	promiscuous  = true
	logConfigStr = `
<seelog type="asynctimer" asyncinterval="1000" minlevel="trace" maxlevel="error">  
	<outputs formatid="common">  
		<buffered formatid="common" size="1048576" flushperiod="1000">  
			<rollingfile type="size" filename="/var/log/pcap.log" maxsize="104857600" maxrolls="10"/>  
		</buffered>
	</outputs>  	  
	 <formats>
		 <format id="common" format="%Date %Time [%LEV] [%File:%Line] [%Func] %Msg%n" />  
	 </formats>  
</seelog>
`
)

var (
	device       = flag.String("i", "any", "device interface")
	filter       = flag.String("f", "", "filter")
	snapshot     = flag.Int("s", 1024, "snapshot length")
	timeout      = flag.Int("t", -1, "timeout exit application")
	ex_port      = flag.String("e", "", "exclude port")
	url          = flag.String("u", "", "server url")
	capture_time = flag.String("interval", "30,30", "capture time,sleep time")
	ratio        = flag.Float64("r", 1, "capture ratio,default:1   1%")
	quiet        = flag.Bool("q", false, "quiet")
	//errorLog              = log.New(os.Stderr, "", 0)
	chan_timeout          = make(chan bool, 1)
	packetCounter int     = 0
	ratioPercent  float32 = 0.1
	localIp       string
	ports         []string
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

type PcapHandler struct {
	handle       *pcap.Handle
	filter       string
	snapshot     int
	device       string
	lock         *sync.Mutex
	isStop       bool
	quiet        bool
	capTime      int
	sleepCapTime int
	eventList    []Event
	ports        []string
	localIp string
	mayPort  chan int
	util *goutil.Common
	url string
}

func NewPcapHandler() (*PcapHandler, error) {
	var (
		err          error
		handle       *pcap.Handle
		capTime      int
		sleepCapTime int
	)
	handle, err = pcap.OpenLive(
		*device,
		int32(*snapshot),
		promiscuous,
		pcap.BlockForever,
	)
	if err != nil {
		log.Error(err)
		panic(err)
	}
	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Error(err)
		panic(err)
	}
	intervals := strings.Split(*capture_time, ",")
	if len(intervals) == 2 {
		capTime, err = strconv.Atoi(intervals[0])
		sleepCapTime, err = strconv.Atoi(intervals[0])
	}
	util:=&goutil.Common{}
	return &PcapHandler{
		handle:       handle,
		filter:       *filter,
		snapshot:     *snapshot,
		device:       *device,
		lock:         &sync.Mutex{},
		isStop:       false,
		capTime:      capTime,
		sleepCapTime: sleepCapTime,
		util:util,
		url:*url,
		quiet:*quiet,
		localIp:util.GetPulicIP(),
	}, err
}
func (this *PcapHandler) ScanLocalPort() {
	ch := make(chan int, 65536)
	Check := func(ch chan int) {
		for {
			port := <-ch
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second*2)
			if err == nil {
				this.ports = append(this.ports, fmt.Sprintf("%d",port))
				conn.Close()
			}
		}
	}

	for i := 0; i < 50; i++ {
		go Check(ch)
	}

	go func() {
		for {
			this.ports = this.ports[0:0]
			for i := 0; i < 65536; i++ {
				ch <- i
			}
			time.Sleep(time.Hour * 1)
		}
	}()

}

func (this *PcapHandler) ReStart() {
	var (
		err    error
		handle *pcap.Handle
	)
	if !this.isStop {
		this.Stop()
	}

	handle, err = pcap.OpenLive(
		*device,
		int32(*snapshot),
		promiscuous,
		pcap.BlockForever,
	)
	if err != nil {
		log.Error("ReStart Fail", err)
		return
	}
	this.handle = handle
	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Error("SetBPFFilter Fail", err)
		return
	}
	this.isStop = false

}

func (this *PcapHandler) Stop() {
	this.lock.Lock()
	defer this.lock.Unlock()
	if this.handle != nil {
		this.handle.Close()
	}
	this.isStop = true

}
func (this *PcapHandler) Capture() {
	packetSource := gopacket.NewPacketSource(this.handle, this.handle.LinkType())
	capPackage := func(packetSource *gopacket.PacketSource) {
		defer func() {
			if re := recover(); re != nil {
			}
		}()
		for packet := range packetSource.Packets() {
			if this.isStop {
				break
			}
			this.Process(packet)
		}
	}
	go func() {
		for {
			if this.isStop {
				break
			}
			capPackage(packetSource)
		}
	}()
}
func (this *PcapHandler) Send() {
	if this.url=="" {
		return
	}
	data,err:=json.Marshal(this.eventList)
	this.eventList=this.eventList[0:0]
	if err!=nil {
		log.Error(err)
		return
	}
	req:=httplib.Post(this.url)
	req.SetTimeout(time.Second*10,time.Second*10)
	req.Param("data",string(data))
	req.String()

}

func (this *PcapHandler) Process(p gopacket.Packet) {
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
		Layer3:    l3Type.String(),
		SrcIP:     srcIP.String(),
		DstIP:     dstIP.String(),

		Layer4:  l4Type.String(),
		SrcPort: srcPort.String(),
		DstPort: dstPort.String(),
	}

	if !this.quiet {
		json_event, _ := json.Marshal(e)
		fmt.Println(string(json_event))
	}

	if (e.DstIP==this.localIp|| e.DstIP=="127.0.0.1" ) && this.util.Contains(e.DstPort,this.ports) {
			this.eventList = append(this.eventList, e)
			if len(this.eventList)<10 {
				return
			} else {
				this.Send()
			}

	}

}

func init() {
	// init log
	if logger, err := log.LoggerFromConfigAsBytes([]byte(logConfigStr)); err != nil {
		panic(err)
	} else {
		log.ReplaceLogger(logger)
	}

}

type HttpHandler struct {
}

func (HttpHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {


	defer func() {
		if err := recover(); err != nil {

		}
	}()

	http.DefaultServeMux.ServeHTTP(res, req)
}

func main() {
	flag.Parse()
	pcapHandle, err := NewPcapHandler()
	if err != nil {
		log.Error(err)
	}
	pcapHandle.ScanLocalPort()
	//pcapHandle.Capture()

	go func() {
		time.Sleep(time.Second * 1)
		for {
			pcapHandle.ReStart()
			pcapHandle.Capture()
			time.Sleep(time.Second * time.Duration(pcapHandle.capTime))
			pcapHandle.Stop()
			time.Sleep(time.Second * time.Duration(pcapHandle.sleepCapTime))
		}
	}()

	http.ListenAndServe(":8000",new(HttpHandler))

	select {}

}
