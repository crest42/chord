# chord
A Implementation of the chord protocol - Lightweight, Simple &amp; IPv6 only

This is just another implementation of the protocol described in the following papers:

- http://nms.csail.mit.edu/papers/chord.pdf
- https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf

This Version is far from perfect and there is a lot of work to do. Its not exactly implemented as described in the papers and thus can not guarantee a runtime of O(log n) operations to (re-)build the network.



TODO:

- cleanup
- static buffer for network msg should be possible
- make address hash from addr byte format not from human readable...
- enable check fingertable && check successorlist for faster lookups

BUILD:

``` make
With example: make all
Lib only: make lib
Tests: make test
```

USAGE:

``` bash
./example master <bind addr>
./example slave <bind addr> <master addr>
```
