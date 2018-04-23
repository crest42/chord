# chord
A Implementation of the chord protocol - Lightweight, Simple &amp; IPv6 only

This is just another implementation of the protocol described in the following great papers:

- http://nms.csail.mit.edu/papers/chord.pdf
- https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf

For Testing and example see:
https://github.com/crest42/chord-testsuite

TODO:

- cleanup
- mutex or better solution for send and wait for message. Problem: If - for example - a put message is sent and the periodic thread send a whatever msg then we should have a race cond.

BUILD:

``` make
make all
Lib only: make lib
Tests: make test
Debug Output enabled: make debug
```

