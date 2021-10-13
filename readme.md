# tinysnitch

## why

it should be easy to monitor and control inbound and outbound connections.

## what

an interactive firewall for inbound and outbound connections.

the rules are global, but the prompt always shows the pid/path/args of the program requesting a new rule.

based on the excellent [opensnitch](https://github.com/evilsocket/opensnitch).

## demo

![](https://github.com/nathants/tinysnitch/raw/master/docs/demo.gif)

![](https://github.com/nathants/tinysnitch/raw/master/docs/prompt.png)

![](https://github.com/nathants/tinysnitch/raw/master/docs/prompt_legend.png)

![](https://github.com/nathants/tinysnitch/raw/master/docs/prompt_help.png)

a split screen monitoring setup for a second monitor using [ptop](https://github.com/nathants/ptop), [color](https://gist.github.com/nathants/336bc5e501ad174aeeb7986f2b0633e4), [pys](https://gist.github.com/nathants/741b066af9faa15f3ed50ed6cf677d67), and a [oneliner](https://gist.github.com/nathants/daa1aa0dee88bc6dc8710c82965b4704) to tail tinysnitch logs into a small and colorful format.

![](https://github.com/nathants/tinysnitch/raw/master/docs/demo.png)

## dependencies

 there are two components with separate dependencies:

 - tinysnitchd:
   - [pypy3](https://pypy.org/)
   - [libnetfilter_queue](https://www.archlinux.org/packages/extra/x86_64/libnetfilter_queue/)
   - [nftables](https://archlinux.org/packages/extra/x86_64/nftables/)

 - tinysnitch-prompt
   - [python3](https://www.python.org/)
   - [pyqt5](https://pypi.org/project/PyQt5/)

## install

setup nftables with `sudo nft -f nftables.conf`

put `tinysnitch/bin` on your `$PATH`.

## usage

tinysnitchd must be launched with sudo as a user process, so the subprocess pyqt5 prompts can actually show up on your screen.

either run it in a background terminal: `sudo -E tinysnitchd`

or automatically run it with cron: `* * * * * sudo -E auto-restart tinysnitchd 2>&1 | rotate-logs /tmp/tinynitchd.log`

[auto-restart](https://gist.github.com/nathants/dc5d43c1e57b9bbb3a654491df93e4d6) and [rotate-logs](https://gist.github.com/nathants/72968aaa7d9ab7c008fe32e399426d2c) are not convenient, not required.

## rules

permanent rules are stored in `/etc/tinysnitch.rules`, and `tinysnitchd` will reload the rules when edited.
