GOPATH=${PWD}/../../netricsd/

all:
	GOPATH=${GOPATH} go build -o netricsd main.go logfile.go
dep:
	GOPATH=${GOPATH} go get github.com/sevlyar/go-daemon
	GOPATH=${GOPATH} go get github.com/google/gopacket
