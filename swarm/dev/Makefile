.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/ariseid/ariseid-core/cmd/swarm
	go build -o bin/idd     github.com/ariseid/ariseid-core/cmd/idd
	go build -o bin/bootnode github.com/ariseid/ariseid-core/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/ariseid/ariseid-core/swarm/...
