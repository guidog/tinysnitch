set -x
# TODO move into make file
find -type f| grep go$ | sudo entr -r sudo -u nathants bash -c '. ~/.bashrc && whoami && cd ~/.envs/gopath/github.com/src/evilsocket/opensnitch && set -x; make && sudo ./opensnitchd'
