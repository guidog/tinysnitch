set -x
find -type f| grep go$ | sudo entr -r sudo -u nathants bash -c '. ~/.bashrc && whoami && cd ~/.envs/gopath/src/github.com/evilsocket/opensnitch && set -x; make && sudo ./opensnitchd'
