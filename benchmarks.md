here are some rough benchmarks, running [siege](https://www.joedog.org/siege-home/) against a [ran](https://github.com/m3ng9i/ran) http server.

without any firewall we get about 20k/sec.

![](gifs/benchmark_ran.gif)

the [simplest possible](https://github.com/nathants/tinysnitch/tree/golang) golang implementation approving all packets gets about 11k/sec.

![](gifs/benchmark_golang.gif)

the [simplest possible](https://github.com/nathants/tinysnitch/tree/pypy) pypy implementation approving all packets gets about 9k/sec.

![](gifs/benchmark_pypy.gif)

a [simplified opensnitch](https://github.com/nathants/tinysnitch/tree/opensnitch-benchmark) approving all packets after proc lookup gets about 250/sec.

![](gifs/benchmark_opensnitch.gif)

tinysnitch approving all packets after proc lookup gets about 8k/sec.

![](gifs/benchmark_tinysnitch.gif)
