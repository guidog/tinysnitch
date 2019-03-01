all: opensnitchd

deps:
	@dep ensure

opensnitchd: deps
	@go build -o opensnitchd .

clean:
	@rm -rf opensnitchd
