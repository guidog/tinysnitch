import subprocess
import pytest # pip install pytest

co = lambda *a: subprocess.check_output(' '.join(map(str, a)), shell=True, executable='/bin/bash').decode('utf-8').strip()
cc = lambda *a: subprocess.check_call(' '.join(map(str, a)), shell=True, executable='/bin/bash')

rules_file = co('mktemp')
log_file = co('mktemp')

def logs():
    xs = co(f'cat {log_file} | grep -e "^allow" -e "^deny" || true').splitlines()
    xs = [x.split(' INFO ')[-1].replace('->', '').replace('|', ' ').split(None, 6) for x in xs]
    xs = [' '.join((action, proto, dst)) for action, proto, src, dst in xs]
    return set(xs)

def run(*rules):
    co('echo >', rules_file)
    for rule in rules:
        co('echo', rule, '>>', rules_file)
    teardown_function()
    cc(f'(/usr/bin/sudo tinysnitch -r {rules_file} -a /dev/null -t /dev/null 2>&1 | tee {log_file}) &')

def drop_localhost(xs):
    return {x.replace('127.0.0.1', '').replace('localhost', '').replace('0.0.0.0', '') for x in xs}

udp_client = """

import socket
import sys
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = bytes(sys.argv[1], 'utf-8')
adr, port = sys.argv[2].split(':')
client_socket.sendto(msg, (adr, int(port)))
msg, adr = client_socket.recvfrom(1024)
print(msg.decode())

"""

udp_server = """

import socket
import sys
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', int(sys.argv[1])))
while True:
    msg, adr = server_socket.recvfrom(1024)
    if msg == b'ping':
        server_socket.sendto(b'pong', adr)
    else:
        server_socket.sendto(b'say wut now?', adr)

"""

def setup_module():
    assert co('/usr/bin/sudo whoami') == 'root'
    with open('/tmp/tinysnitch_test_udp_client.py', 'w') as f:
        f.write(udp_client)
    with open('/tmp/tinysnitch_test_udp_server.py', 'w') as f:
        f.write(udp_server)

def teardown_function():
    pids = [x.split()[1] for x in co('ps -ef|grep tinysnitch|grep -v test').splitlines()]
    cc('/usr/bin/sudo kill', *pids, '&>/dev/null || true')

def test_outbound_allow():
    run('allow 1.1.1.1 53 udp',
        'allow google.com 80 tcp')
    assert co('curl -s -m 10 -v google.com 2>&1 | grep "^< HTTP"') == '< HTTP/1.1 301 Moved Permanently'
    assert logs() == {'allow udp 1.1.1.1:53',
                      'allow tcp google.com:80'}

def test_outbound_deny():
    run('deny 1.1.1.1 53 udp')
    with pytest.raises(subprocess.CalledProcessError):
        cc('curl -s -m 10 -v google.com')
    assert logs() == {'deny udp 1.1.1.1:53'}

def test_outbound_deny_tcp():
    run('allow 1.1.1.1 53 udp',
        'deny google.com 80 tcp')
    with pytest.raises(subprocess.CalledProcessError):
        cc('curl -s -m 10 -v google.com')
    assert logs() == {'allow udp 1.1.1.1:53',
                      'deny tcp google.com:80'}

def test_inbound_allow():
    run('allow localhost 8000 tcp')
    proc = subprocess.Popen('cd $(mktemp -d) && echo bar > foo && python3 -m http.server', shell=True)
    try:
        co('curl -s -m 10 localhost:8000/foo')
        assert co('curl -s -m 10 localhost:8000/foo') == 'bar'
        assert drop_localhost(logs()) == {'allow tcp :8000'}
    finally:
        proc.terminate()

def test_inbound_deny_dst():
    run('deny localhost 8000 tcp')
    proc = subprocess.Popen('cd $(mktemp -d) && echo bar > foo && python3 -m http.server', shell=True)
    try:
        with pytest.raises(subprocess.CalledProcessError):
            cc('curl -s -m 10 localhost:8000/foo')
        with pytest.raises(subprocess.CalledProcessError):
            cc('curl -s -m 10 localhost:8000/foo')
        assert drop_localhost(logs()) == {'deny tcp :8000'}
    finally:
        proc.terminate()

def test_inbound_deny_src():
    run('deny localhost 8000 tcp')
    proc = subprocess.Popen('cd $(mktemp -d) && echo bar > foo && python3 -m http.server', shell=True)
    try:
        with pytest.raises(subprocess.CalledProcessError):
            cc('curl -s -m 10 localhost:8000/foo')
        with pytest.raises(subprocess.CalledProcessError):
            cc('curl -s -m 10 localhost:8000/foo')
        assert drop_localhost(logs()) == {'deny tcp :8000'}
    finally:
        proc.terminate()

def test_inbound_allow_udp():
    run('allow localhost 1200 udp')
    proc = subprocess.Popen('python3 /tmp/tinysnitch_test_udp_server.py 1200', shell=True)
    try:
        for _ in range(5):
            try:
                assert co('timeout 1 python3 /tmp/tinysnitch_test_udp_client.py ping 0.0.0.0:1200') == 'pong'
                break
            except:
                pass
        assert logs() == {'allow udp localhost:1200'}
    finally:
        proc.terminate()

def test_inbound_deny_dst_udp():
    run('deny localhost 1200 udp')
    proc = subprocess.Popen('python3 /tmp/tinysnitch_test_udp_server.py 1200', shell=True)
    try:
        for _ in range(5):
            try:
                assert co('timeout 1 python3 /tmp/tinysnitch_test_udp_client.py ping 0.0.0.0:1200') == 'pong'
                break
            except:
                pass
        assert logs() == {'deny udp localhost:1200'}
    finally:
        proc.terminate()

def test_inbound_deny_src_udp():
    run('deny localhost 1200 udp')
    proc = subprocess.Popen('python3 /tmp/tinysnitch_test_udp_server.py 1200', shell=True)
    try:
        for _ in range(5):
            try:
                assert co('timeout 1 python3 /tmp/tinysnitch_test_udp_client.py ping 0.0.0.0:1200') == 'pong'
                break
            except:
                pass
        assert logs() == {'deny udp localhost:1200'}
    finally:
        proc.terminate()
