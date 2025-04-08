.PHONY: binary library

binary:
	go build -o tunnel-node cmd/node/main.go

library:
	go build -o libtunnel.a -buildmode=c-archive cmd/lib/lib.go