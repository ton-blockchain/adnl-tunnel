.PHONY: binary library all

ver := $(shell git describe --tags --always --dirty)

binary:
	go build -ldflags "-w -s -X main.GitCommit=$(ver)" -o build/tunnel-node cmd/node/main.go

library:
	go build -o build/libtunnel.a -buildmode=c-archive cmd/lib/lib.go

all:
	GOOS=linux GOARCH=amd64 go build -ldflags "-w -s -X main.GitCommit=$(ver)" -o build/tunnel-node-linux-amd64 cmd/node/main.go
	GOOS=linux GOARCH=arm64 go build -ldflags "-w -s -X main.GitCommit=$(ver)" -o build/tunnel-node-linux-arm64 cmd/node/main.go
	GOOS=darwin GOARCH=arm64 go build -ldflags "-w -s -X main.GitCommit=$(ver)" -o build/tunnel-node-mac-arm64 cmd/node/main.go
	GOOS=darwin GOARCH=amd64 go build -ldflags "-w -s -X main.GitCommit=$(ver)" -o build/tunnel-node-mac-amd64 cmd/node/main.go
	GOOS=windows GOARCH=amd64 go build -ldflags "-w -s -X main.GitCommit=$(ver)" -o build/tunnel-node-x64.exe cmd/node/main.go