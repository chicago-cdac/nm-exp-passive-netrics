package main

import (
	"flag"
	"log"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/sevlyar/go-daemon"
)

var (
	signal = flag.String("s", "", `Send signal to the daemon:
  stop — shutdown`)
	input = flag.String("i", "", "Proccess offline pcap as input.")
)

const logFileName = "netricsd.log"
const pidFileName = "netricsd.pid"

func main() {
	var pcapoffline string
	flag.Parse()

	if len(*input) > 0 {
		if strings.HasSuffix(*input, ".pcap") {
			pcapoffline = *input
		}
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
	for {
		log.Print("+ ", time.Now().Unix())
		time.Sleep(time.Second)
		select {
		case <-stop:
			break
		default:
		}
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
