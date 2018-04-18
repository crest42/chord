# chord
A Implementation of the chord protocol - Lightweight, Simple &amp; IPv6 only

This is just another implementation of the protocol described in the following papers:

- http://nms.csail.mit.edu/papers/chord.pdf
- https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf

This Version is far from perfect and there is a lot of work to do. Its not exactly implemented as described in the papers and thus can not guarantee a runtime of O(log n) operations to (re-)build the network.



TODO:

- cleanup

BUILD:

``` make
With example: make all
Lib only: make lib
Tests: make test
Debug Output enabled: make debug
```

Testing:

```
make TARGS="<test args>" test
test args:
  --verbose | -v: Verbose mose
  --kill n | -k n: kill a child every n seconds
  --nodes | -n n: spawn n nodes

make autotest
```

USAGE:

``` bash
./example master <bind addr>
./example slave <bind addr> <master addr>
```
