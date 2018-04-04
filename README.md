# chord
A Implementation of the chord protocol - Lightweight, Simple &amp; IPv6 only

This is just another implementation of the protocol described in the following papers:

- http://nms.csail.mit.edu/papers/chord.pdf
- https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf

This Version is far from perfect and there is a lot of work to do. Its not exactly implemented as described in the papers and thus can not guarantee a runtime of O(log n) operations to (re-)build the network

TODO:

- get rid of memory leaks
- cleanup
- use static buffer instead of malloc
- static node buffer should be possible since we always need fingertable+successorlist+mynode+precessor nodes e. g. (2*m*60 ~Bytes) + 2*~60 Bytes
- Node Reuse? ABA problem! Locking!
- static buffer for network msg should be possible

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

TEST:

Launch testsuite which spawn n nodes and check if ring is valid based on the output of example. Nodes have ~30Seconds to establish ring and then gets killed by the bash script.
Sorry for my bad bash skills

``` bash
./testsuite [nodecount]
```
