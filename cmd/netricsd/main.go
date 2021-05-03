package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sevlyar/go-daemon"
)

// work with offline capture
const Ticker = 1 // Process packets every (Ticker) Seconds 


var (
	signal = flag.String("s", "", `Send signal to the daemon:
  stop — shutdown`)
	input        = flag.String("r", "", "Proccess offline pcap as input.")
	device       = flag.String("i", "en0", "Interface to capture")
	snapshot_len = flag.String("slen", "96", "snapshot length")
	filter       = flag.String("f", "", "capture filter")
	ethLayer     layers.Ethernet
	ipLayer      layers.IPv4
	ip6Layer     layers.IPv6   // TODO: Add it for ipv6 traffc
	tcpLayer     layers.TCP    //not using right now
	udpLayer     layers.UDP    //not using right now
	promiscuous  bool          = false
	timeout      time.Duration = Ticker * time.Second
	handle       *pcap.Handle
	err          error
)

var (
	stop = make(chan struct{})
	done = make(chan struct{})
)

const logFileName = "netricsd.log"
const pidFileName = "netricsd.pid"
const dataLogFilePref = "nm_passive_consumption"

// saves the data to a file
func flush_data(timestamp int64, data [60]int) {
	//new file for every minute
	//define a constant for the file name template
	fname := fmt.Sprintf("%s_%d.csv", dataLogFilePref, timestamp)
	f, err := os.OpenFile(fname, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
	if err != nil {
		log.Fatal("Error opening log file: %s", err)
	}
	defer f.Close()

	delim := ","
	data_str := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(data)), delim), "[]")

	_, err2 := f.WriteString(data_str + "\n")
	if err2 != nil {
		log.Fatalln("Error writing to log file: %s", err)
	}

	fmt.Println("Data written for %d", timestamp)
}

func main() {
	//var pcapoffline string
	flag.Parse()

	//fmt.Printf("%s %s", *device, *input)

	daemon.AddCommand(daemon.StringFlag(signal, "stop"), syscall.SIGTERM, termHandler)

	cntxt := &daemon.Context{
		PidFileName: pidFileName,
		PidFilePerm: 0644,
		LogFileName: logFileName,
		//LogFileName: "/dev/stdout",
	        LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
		Args:        nil,
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
	fmt.Println("starting daemon")
	log.Println("- - - - - - - - - - - - - - -")
	log.Println("daemon started")

	//setupLog()

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

func worker() {
	snapshot_len_int, err := strconv.Atoi(*snapshot_len)
	if len(*device) > 0 {
		fmt.Println("entered here [%s]", *device)
		handle, err = pcap.OpenLive(*device, int32(snapshot_len_int), promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}

		if *filter != "" {
			err = handle.SetBPFFilter(*filter)
			if err != nil {
				log.Fatal(err)
			}
		}
	} else if len(*input) > 0 {
		log.Printf("opening pcap file %s", *input)
		handle, err = pcap.OpenOffline(*input)
		if err != nil {
			log.Fatal(err)
		}
		//defer handle.Close()
	} else {
		fmt.Println("entered here too")
		log.Printf("%s %s", *input, *device)
		log.Fatal("Specify either device or pcap file %s %s", *input, *device)
	}

	defer handle.Close()
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	currentMin := int64(-1)
	var newTime, newMin, newSec int64

	var per_minute_log [60]int
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&ip6Layer,
	)
LOOP:
	for packet := range packetSource.Packets() {
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			//fmt.Println("Trouble decoding layers: ", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				//filtering logic here. Skip all the measurement traffic from the pi
			}
		}

		newTime = packet.Metadata().Timestamp.Unix()
		newMin = 60 * int64(newTime/60)
		newSec = newTime % 60
		if currentMin != newMin {
			if currentMin != -1 {
				flush_data(currentMin, per_minute_log)
			}
			currentMin = newMin
			per_minute_log = [60]int{}
		}

		per_minute_log[newSec] += int(ipLayer.Length)

		select {
		case <-stop:
			break LOOP
		default:
		}
	}

	//flush remaining data
	flush_data(currentMin, per_minute_log)
	log.Printf("%s: Exiting daemon", time.Now().String())
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
