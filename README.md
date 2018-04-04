# chord
A Implementation of the chord protocoll - Lightweight, Simple &amp; IPv6 only

This Version is far from perfect and there is a lot of work to do:

TODO:
- get rid of memory leaks
- cleanup
- use static buffer instead of malloc
- static node buffer should be possible since we always need fingertable+successorlist+mynode+precessor nodes e. g. (2*m*60 ~Bytes) + 2*~60 Bytes
- Node Reuse? ABA problem! Locking!
- static buffer for network msg should be possible
- compile with -Wall

BUILD:

With example: sudo gcc -o example chord.c example.c -I. -lcrypto -lpthread -g

USEAGE:
```
./example master <bind addr>
./example slave <bind addr> <master addr>
```
