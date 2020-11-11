import sys
import setuptools

requires = ['argh >0.26, <0.27',
            'scapy >2, <3',
            'dnslib >0.9, <1']

try:
    _ = sys.pypy_version_info
    requires += ['typing >3, <4',
                 'typing-extensions >3, <4']
except AttributeError:
    pass

setuptools.setup(
    version="0.0.1",
    name="tinysnitch",
    packages=['tinysnitch'],
    license='GPL',
    install_requires=requires,
)
