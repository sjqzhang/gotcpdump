package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/astaxie/beego/httplib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	promiscuous = true
)

var (
	device                = flag.String("i", "any", "device interface")
	filter                = flag.String("f", "", "filter")
	snapshot              = flag.Int("s", 1024, "snapshot length")
	timeout               = flag.Int("t", -1, "timeout exit application")
	ex_port               = flag.String("e", "", "exclude port")
	url                   = flag.String("u", "", "server url")
	capture_time          = flag.String("interval", "30,30", "capture time,sleep time")
	ratio                 = flag.Float64("r", 1, "capture ratio,default:1   1%")
	quiet                 = flag.Bool("q", false, "quiet")
	errorLog              = log.New(os.Stderr, "", 0)
	chan_timeout          = make(chan bool, 1)
	packetCounter int     = 0
	ratioPercent  float32 = 0.1
)

type CommonMap struct {
	sync.Mutex
	m map[string]interface{}
}

func NewCommonMap(size int) *CommonMap {
	if size > 0 {
		return &CommonMap{m: make(map[string]interface{}, size)}
	} else {
		return &CommonMap{m: make(map[string]interface{})}
	}
}
func (s *CommonMap) GetValue(k string) (interface{}, bool) {
	s.Lock()
	defer s.Unlock()
	v, ok := s.m[k]
	return v, ok
}
func (s *CommonMap) Put(k string, v interface{}) {
	s.Lock()
	defer s.Unlock()
	s.m[k] = v
}
func (s *CommonMap) LockKey(k string) {
	s.Lock()
	if v, ok := s.m[k]; ok {
		s.m[k+"_lock_"] = true
		s.Unlock()
		v.(*sync.Mutex).Lock()
	} else {
		s.m[k] = &sync.Mutex{}
		v = s.m[k]
		s.m[k+"_lock_"] = true
		s.Unlock()
		v.(*sync.Mutex).Lock()
	}
}
func (s *CommonMap) UnLockKey(k string) {
	s.Lock()
	if v, ok := s.m[k]; ok {
		v.(*sync.Mutex).Unlock()
		s.m[k+"_lock_"] = false
	}
	s.Unlock()
}
func (s *CommonMap) IsLock(k string) bool {
	s.Lock()
	if v, ok := s.m[k+"_lock_"]; ok {
		s.Unlock()
		return v.(bool)
	}
	s.Unlock()
	return false
}
func (s *CommonMap) Keys() []string {
	s.Lock()
	keys := make([]string, len(s.m))
	defer s.Unlock()
	for k, _ := range s.m {
		keys = append(keys, k)
	}
	return keys
}
func (s *CommonMap) Clear() {
	s.Lock()
	defer s.Unlock()
	s.m = make(map[string]interface{})
}
func (s *CommonMap) Remove(key string) {
	s.Lock()
	defer s.Unlock()
	if _, ok := s.m[key]; ok {
		delete(s.m, key)
	}
}
func (s *CommonMap) AddUniq(key string) {
	s.Lock()
	defer s.Unlock()
	if _, ok := s.m[key]; !ok {
		s.m[key] = nil
	}
}
func (s *CommonMap) AddCount(key string, count int) {
	s.Lock()
	defer s.Unlock()
	if _v, ok := s.m[key]; ok {
		v := _v.(int)
		v = v + count
		s.m[key] = v
	} else {
		s.m[key] = 1
	}
}
func (s *CommonMap) AddCountInt64(key string, count int64) {
	s.Lock()
	defer s.Unlock()
	if _v, ok := s.m[key]; ok {
		v := _v.(int64)
		v = v + count
		s.m[key] = v
	} else {
		s.m[key] = count
	}
}
func (s *CommonMap) Add(key string) {
	s.Lock()
	defer s.Unlock()
	if _v, ok := s.m[key]; ok {
		v := _v.(int)
		v = v + 1
		s.m[key] = v
	} else {
		s.m[key] = 1
	}
}
func (s *CommonMap) Zero() {
	s.Lock()
	defer s.Unlock()
	for k := range s.m {
		s.m[k] = 0
	}
}
func (s *CommonMap) Contains(i ...interface{}) bool {
	s.Lock()
	defer s.Unlock()
	for _, val := range i {
		if _, ok := s.m[val.(string)]; !ok {
			return false
		}
	}
	return true
}
func (s *CommonMap) Get() map[string]interface{} {
	s.Lock()
	defer s.Unlock()
	m := make(map[string]interface{})
	for k, v := range s.m {
		m[k] = v
	}
	return m
}

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

type EventList struct {
	Events []Event `json:"events"`
}

var eventList EventList
var evenMap *CommonMap

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

	key := fmt.Sprintf("%s->s%", srcIP, dstIP)

	if _, ok := evenMap.GetValue(key); ok {
		return
	} else {
		evenMap.Put(key, e)
	}

	ports := strings.Split(*ex_port, ",")

	for _, p := range ports {
		if p == srcPort.String() || p == dstPort.String() {
			return
		}

	}

	//if len(eventList.Events)<5 {
	//	eventList.Events=append(eventList.Events,e)
	//	return
	//}
	//json_event, err := json.Marshal(eventList)
	//eventList.Events=eventList.Events[0:0]
	//if *url != "" {
	//	req := httplib.Post(*url)
	//	req.Param("data", string(json_event))
	//	req.String()
	//}
	//if err != nil {
	//	errorLog.Printf("ERROR: can't marshal %s", e)
	//}
	//if !*quiet {
	//	fmt.Println(string(json_event))
	//}
	//
	//return
}

func capture_by_time(packetSource *gopacket.PacketSource) {

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
			if t >= c {
				sleepFlag = true
			}
			if t > a {
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

func capture_by_ratio(packetSource *gopacket.PacketSource) {

	rand.Seed(time.Now().UnixNano())
	for packet := range packetSource.Packets() {
		if rand.Float32() < ratioPercent {
			process(packet)
			packetCounter++
		}

	}
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

	evenMap = NewCommonMap(0)

	tk := time.NewTicker(time.Second)

	go func(tk *time.Ticker) {
		for _ = range tk.C {
			fmt.Println(packetCounter, *ratio)
			if packetCounter > 10 {
				*ratio = *ratio - 0.1
			}
			if packetCounter < 10 {
				*ratio = *ratio + 0.1
			}
			if *ratio > 100 {
				*ratio = 100
			}
			if *ratio < 0 {
				*ratio = 0.1
			}
			packetCounter = 0
			ratioPercent = float32(*ratio) / 100
		}
	}(tk)

	tk2 := time.NewTicker(time.Second * time.Duration(30+rand.Intn(30)))
	go func() {
		for _ = range tk2.C {
			for _, e := range evenMap.Get() {
				if len(eventList.Events) < 100 {
					eventList.Events = append(eventList.Events, e.(Event))
				}
			}
			if len(eventList.Events) <= 0 {
				return
			}
			evenMap.Clear()
			json_event, err := json.Marshal(eventList)
			eventList.Events = eventList.Events[0:0]
			if *url != "" {
				req := httplib.Post(*url)
				req.Param("data", string(json_event))
				req.String()
			}
			if err != nil {
				errorLog.Printf("ERROR: can't marshal %s", json_event)
			}
			if !*quiet {
				fmt.Println(string(json_event))
			}

		}

	}()

	// Set filter
	err = handle.SetBPFFilter(*filter)
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	if *ratio > 100 || *ratio < 0 {
		log.Fatal("ratio must be between 0~100 ")
		return
	}
	rand.Seed(time.Now().UnixNano())
	capture_by_ratio(packetSource)
	_ = packetSource

}
