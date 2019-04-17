import subprocess
import pytest
import os

co = lambda *a: subprocess.check_output(' '.join(map(str, a)), shell=True, executable='/bin/bash').decode('utf-8').strip()
cc = lambda *a: subprocess.check_call(' '.join(map(str, a)), shell=True, executable='/bin/bash')

rules_file = co('mktemp')
log_file = co('mktemp')
os.environ['TINYSNITCH_RULES'] = rules_file

def setup_function():
    assert co('sudo whoami') == 'root'
    assert co('sudo iptables-save | grep -v -e "^#" -e "^:"').splitlines() == [
        '*mangle',
        '-A INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0',
        '-A OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0',
        'COMMIT',
        '*filter',
        '-A INPUT -m mark --mark 0x18ba5 -j REJECT --reject-with icmp-port-unreachable',
        '-A INPUT -p udp -m udp --sport 53 -j NFQUEUE --queue-num 0',
        '-A OUTPUT -m mark --mark 0x18ba5 -j REJECT --reject-with icmp-port-unreachable',
        'COMMIT',
        '*nat',
        'COMMIT',
    ]
    assert co('ps -ef | grep tinysnitch | grep -v -e test -e grep | wc -l') == '0'

def teardown_function():
    pids = [x.split()[1] for x in co('ps -ef|grep tinysnitch').splitlines()]
    cc('sudo kill', *pids, '&>/dev/null || true')

def logs():
    xs = co(f'cat {log_file} | grep -e "INFO allow" -e "INFO deny"').splitlines()
    xs = [x.split(' INFO ')[-1].replace('->', '').replace('|', ' ').split(None, 6) for x in xs]
    xs = [(action, proto, dst, program, args) for action, proto, src, dst, pid, program, args in xs]
    return xs

def run(*rules):
    co('echo >', rules_file)
    for rule in rules:
        co('echo', rule, '>>', rules_file)
    cc(f'(sudo tinysnitchd --rules {rules_file} 2>&1 | tee {log_file}) &')

def test_allow():
    run('allow 1.1.1.1    53 udp /usr/bin/curl -',
        'allow google.com 80 tcp /usr/bin/curl -')
    assert co('curl -v google.com 2>&1 | grep "^< HTTP"') == '< HTTP/1.1 301 Moved Permanently'
    assert logs() == [('allow', 'udp', '1.1.1.1:53', '/usr/bin/curl', '-v google.com'),
                      ('allow', 'udp', '1.1.1.1:53', '/usr/bin/curl', '-v google.com'),
                      ('allow', 'tcp', 'google.com:80', '/usr/bin/curl', '-v google.com')]

def test_deny():
    run('deny 1.1.1.1    53 udp /usr/bin/curl -')
    with pytest.raises(subprocess.CalledProcessError):
        cc('curl -v google.com')
    assert logs() == [('deny', 'udp', '1.1.1.1:53', '/usr/bin/curl', '-v google.com'),
                      ('deny', 'udp', '1.1.1.1:53', '/usr/bin/curl', '-v google.com')]
