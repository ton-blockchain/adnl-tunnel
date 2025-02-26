.PHONY: binary library

binary:
	go build -o tunnel-node main.go

library:
	go build -o libtunnel.a -buildmode=c-archive lib.go