all: opensnitchd

deps:
	dep ensure

opensnitchd: clean
	go build -o opensnitchd .

clean:
	rm -rf opensnitchd

check:
	staticcheck || true
	errcheck || true

dev:
	find -type f \
	| grep go$ \
	| grep -v '\.backup' \
	| sudo entr -r sudo -u $(USER) bash -c " \
		. ~/.bashrc; \
		cd $(GOPATH)/src/github.com/evilsocket/opensnitch; \
		set -x; \
		make; \
		sudo ./opensnitchd \
	"
