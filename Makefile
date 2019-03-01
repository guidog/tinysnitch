all: opensnitchd

deps:
	dep ensure

opensnitchd:
	go build -o opensnitchd .

clean:
	rm -rf opensnitchd

dev:
	find -type f \
	| grep go$ \
	| sudo entr -r sudo -u $(USER) bash -c " \
		. ~/.bashrc && \
		cd $(GOPATH)/src/github.com/evilsocket/opensnitch && \
		set -x; make && \
		sudo ./opensnitchd \
	"
