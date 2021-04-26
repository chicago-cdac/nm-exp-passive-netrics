package main

import (
	"flag"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sevlyar/go-daemon"
	"fmt"
	"strconv"
)

var (
	signal = flag.String("s", "", `Send signal to the daemon:
  stop — shutdown`)
	input = flag.String("r", "", "Proccess offline pcap as input.")
	device = flag.String("i", "en0", "Interface to capture")
	snapshot_len = flag.String("slen", "96", "snapshot length")
	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	ip6Layer layers.IPv6 // TODO: Add it for ipv6 traffc
	tcpLayer layers.TCP //not using right now
	udpLayer layers.UDP //not using right now
	promiscuous bool = false
	timeout time.Duration = 30 *time.Second
	handle *pcap.Handle
	err error


)

const logFileName = "netricsd.log"
const pidFileName = "netricsd.pid"

// saves the data to a file
func flush_data(timestamp int64, data [60]int) {
	f, err := os.OpenFile("tmp.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	delim := ","
	data_str := fmt.Sprint(timestamp) + ":" + strings.Trim(strings.Join(strings.Fields(fmt.Sprint(data)), delim), "[]")
	_, err2 := f.WriteString(data_str + "\n")
	if err2 != nil {
		//log
	}
	fmt.Println("written")
}



func main() {
	var pcapoffline string
	flag.Parse()

	if len(*device) > 0 {
	//pcap open live
	} else if len(*input) > 0 {
		if strings.HasSuffix(*input, ".pcap") {
			pcapoffline = *input
			fmt.Println(pcapoffline)
		}
	} else {
	}
	daemon.AddCommand(daemon.StringFlag(signal, "stop"), syscall.SIGTERM, termHandler)

	cntxt := &daemon.Context{
		PidFileName: pidFileName,
		PidFilePerm: 0644,
		LogFileName: logFileName,
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
		Args:        []string{"netricsd"},
	}

	if len(daemon.ActiveFlags()) > 0 {
		d, err := cntxt.Search()
		if err != nil {
			log.Fatalf("Unable send signal to the daemon: %s", err.Error())
		}

		daemon.SendCommands(d)
		return
	}

	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatalln(err)
	}
	if d != nil {
		return
	}
	defer cntxt.Release()

	//log.Println("- - - - - - - - - - - - - - -")
	//log.Println("daemon started")

	setupLog()

	go worker()

	err = daemon.ServeSignals()
	if err != nil {
		log.Printf("Error: %s", err.Error())
	}
	//log.Println("daemon terminated")
}

func setupLog() {
	lf, err := NewLogFile(logFileName, os.Stderr)
	if err != nil {
		log.Fatalf("Unable to create log file: %s", err.Error())
	}

	log.SetOutput(lf)
	// rotate log every 30 seconds.
	rotateLogSignal := time.Tick(30 * time.Second)
	go func() {
		for {
			<-rotateLogSignal
			if err := lf.Rotate(); err != nil {
				log.Fatalf("Unable to rotate log: %s", err.Error())
			}
		}
	}()
}

var (
	stop = make(chan struct{})
	done = make(chan struct{})
)

func worker() {

    snapshot_len_int, err :=  strconv.Atoi(*snapshot_len)
    handle, err = pcap.OpenLive(*device, int32(snapshot_len_int), promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    // Use the handle as a packet source to process all packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    currentMin := int64(-1)
    var newTime, newMin, newSec int64

    var per_minute_log [60] int
    for packet := range packetSource.Packets() {

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&ip6Layer,
	)

	foundLayerTypes := []gopacket.LayerType{}

	err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
	if err != nil {
		//fmt.Println("Trouble decoding layers: ", err)
	}

	for _, layerType := range foundLayerTypes {
		if layerType == layers.LayerTypeIPv4 {
			//fmt.Println(packet.Metadata().Timestamp.Unix(), packet.Metadata().Timestamp)
			//fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP, "length:", ipLayer.Length)
		//filtering logic here. Skip all the measurement traffic from the pi
		}
	}

	newTime = packet.Metadata().Timestamp.Unix()
	newMin = 60*int64(newTime / 60)
	newSec = newTime % 60
	if currentMin != newMin {
		if currentMin != -1 {
			flush_data(currentMin, per_minute_log)
		}
		currentMin = newMin
		per_minute_log = [60] int{}
	}

	per_minute_log[newSec] += int(ipLayer.Length)
    }

	done <- struct{}{}
}

func termHandler(sig os.Signal) error {
	log.Println("terminating...")
	stop <- struct{}{}
	if sig == syscall.SIGQUIT {
		<-done
	}
	return daemon.ErrStop
}
