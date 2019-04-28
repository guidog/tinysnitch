import subprocess
import pytest
import os

co = lambda *a: subprocess.check_output(' '.join(map(str, a)), shell=True, executable='/bin/bash').decode('utf-8').strip()
cc = lambda *a: subprocess.check_call(' '.join(map(str, a)), shell=True, executable='/bin/bash')

rules_file = co('mktemp')
log_file = co('mktemp')
os.environ['TINYSNITCH_RULES'] = rules_file

def logs():
    xs = co(f'cat {log_file} | grep -e "INFO allow" -e "INFO deny"').splitlines()
    xs = [x.split(' INFO ')[-1].replace('->', '').replace('|', ' ').split(None, 6) for x in xs]
    xs = [' '.join((action, proto, dst, program, args)) for action, proto, src, dst, pid, program, args in xs]
    return xs

def run(*rules):
    co('echo >', rules_file)
    for rule in rules:
        co('echo', rule, '>>', rules_file)
    cc(f'(sudo tinysnitchd --rules {rules_file} 2>&1 | tee {log_file}) &')

def setup_module():
    assert co('sudo whoami') == 'root'
    cc('tinysnitch-iptables-add')

def setup_function():
    assert co('ps -ef | grep tinysnitch | grep -v -e test -e grep | wc -l') == '0'

def teardown_function():
    pids = [x.split()[1] for x in co('ps -ef|grep tinysnitch').splitlines()]
    cc('sudo kill', *pids, '&>/dev/null || true')

def test_outbound_allow():
    run('allow 1.1.1.1 53 udp /usr/bin/curl -',
        'allow google.com 80 tcp /usr/bin/curl -')
    assert co('curl -v google.com 2>&1 | grep "^< HTTP"') == '< HTTP/1.1 301 Moved Permanently'
    assert logs() == ['allow udp 1.1.1.1:53 /usr/bin/curl -v google.com',
                      'allow udp 1.1.1.1:53 /usr/bin/curl -v google.com',
                      'allow tcp google.com:80 /usr/bin/curl -v google.com']

def test_outbound_deny():
    run('deny 1.1.1.1 53 udp /usr/bin/curl -')
    with pytest.raises(subprocess.CalledProcessError):
        cc('curl -v google.com')
    assert logs() == ['deny udp 1.1.1.1:53 /usr/bin/curl -v google.com',
                      'deny udp 1.1.1.1:53 /usr/bin/curl -v google.com']

def test_inbound_allow():
    python3 = co('which python3')
    run(f'allow localhost 8000 tcp {python3} -m http.server',
        f'allow localhost 8000 tcp-src {python3} -m http.server')
    proc = subprocess.Popen('cd $(mktemp -d) && echo bar > foo && python3 -m http.server', shell=True)
    try:
        assert co('curl localhost:8000/foo') == 'bar'
        assert logs() == [f'allow tcp localhost:8000 {python3} -m http.server',
                          f'allow tcp localhost:8000 {python3} -m http.server']
    finally:
        proc.terminate()

def test_inbound_deny_dst():
    python3 = co('which python3')
    run(f'deny localhost 8000 tcp {python3} -m http.server',
        f'allow localhost 8000 tcp-src {python3} -m http.server')
    proc = subprocess.Popen('cd $(mktemp -d) && echo bar > foo && python3 -m http.server', shell=True)
    try:
        with pytest.raises(subprocess.CalledProcessError):
            cc('curl localhost:8000/foo')
        assert logs() == [f'deny tcp localhost:8000 {python3} -m http.server']
    finally:
        proc.terminate()

def test_inbound_deny_src():
    python3 = co('which python3')
    run(f'allow localhost 8000 tcp {python3} -m http.server',
        f'deny localhost 8000 tcp-src {python3} -m http.server')
    proc = subprocess.Popen('cd $(mktemp -d) && echo bar > foo && python3 -m http.server', shell=True)
    try:
        with pytest.raises(subprocess.CalledProcessError):
            cc('curl localhost:8000/foo')
        assert logs() == [f'deny tcp-src localhost:8000 {python3} -m http.server']
    finally:
        proc.terminate()

def test_inbound_allow_remote():
    user = os.environ.get('TINYSNITCH_TEST_USER', 'root')
    local = os.environ.get('TINYSNITCH_TEST_LOCAL', '192.168.2.94')
    remote = os.environ.get('TINYSNITCH_TEST_REMOTE', '192.168.2.68')
    python3 = co('which python3')
    ssh = co('which ssh')
    run(f'allow {remote} 22 tcp {ssh} -',
        f'allow localhost 8000 tcp {python3} -m http.server',
        f'allow {remote} 8000 tcp-src {python3} -m http.server')
    try:
        cc(f'ssh {user}@{remote} whoami')
    except:
        print('skipping test_inbound_allow_remote because remote inaccessible')
    else:
        proc = subprocess.Popen('cd $(mktemp -d) && echo bar > foo && python3 -m http.server', shell=True)
        try:
            assert co(f'ssh {user}@{remote} curl {local}:8000/foo') == 'bar'
            assert logs() == [f'allow tcp {remote}:22 /usr/bin/ssh {user}@{remote} whoami',
                              f'allow tcp {remote}:22 /usr/bin/ssh {user}@{remote} curl {local}:8000/foo',
                              f'allow tcp localhost:8000 /home/nathants/.envs/python3/bin/python3 -m http.server']
        finally:
            proc.terminate()
