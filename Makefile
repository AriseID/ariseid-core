# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: idd android ios idd-cross swarm evm all test clean
.PHONY: idd-linux idd-linux-386 idd-linux-amd64 idd-linux-mips64 idd-linux-mips64le
.PHONY: idd-linux-arm idd-linux-arm-5 idd-linux-arm-6 idd-linux-arm-7 idd-linux-arm64
.PHONY: idd-darwin idd-darwin-386 idd-darwin-amd64
.PHONY: idd-windows idd-windows-386 idd-windows-amd64

GOBIN = $(shell pwd)/build/bin
GO ?= latest

idd:
	build/env.sh go run build/ci.go install ./cmd/idd
	@echo "Done building."
	@echo "Run \"$(GOBIN)/idd\" to launch idd."

swarm:
	build/env.sh go run build/ci.go install ./cmd/swarm
	@echo "Done building."
	@echo "Run \"$(GOBIN)/swarm\" to launch swarm."

all:
	build/env.sh go run build/ci.go install

android:
	build/env.sh go run build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/idd.aar\" to use the library."

ios:
	build/env.sh go run build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/Idd.framework\" to use the library."

test: all
	build/env.sh go run build/ci.go test

clean:
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/jteeuwen/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go install ./cmd/abigen

# Cross Compilation Targets (xgo)

idd-cross: idd-linux idd-darwin idd-windows idd-android idd-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/idd-*

idd-linux: idd-linux-386 idd-linux-amd64 idd-linux-arm idd-linux-mips64 idd-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-*

idd-linux-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/idd
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep 386

idd-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/idd
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep amd64

idd-linux-arm: idd-linux-arm-5 idd-linux-arm-6 idd-linux-arm-7 idd-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep arm

idd-linux-arm-5:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/idd
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep arm-5

idd-linux-arm-6:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/idd
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep arm-6

idd-linux-arm-7:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/idd
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep arm-7

idd-linux-arm64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/idd
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep arm64

idd-linux-mips:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/idd
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep mips

idd-linux-mipsle:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/idd
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep mipsle

idd-linux-mips64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/idd
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep mips64

idd-linux-mips64le:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/idd
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/idd-linux-* | grep mips64le

idd-darwin: idd-darwin-386 idd-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/idd-darwin-*

idd-darwin-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/idd
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/idd-darwin-* | grep 386

idd-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/idd
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/idd-darwin-* | grep amd64

idd-windows: idd-windows-386 idd-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/idd-windows-*

idd-windows-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/idd
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/idd-windows-* | grep 386

idd-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/idd
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/idd-windows-* | grep amd64
