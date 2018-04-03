# chord
A Implementation of the chord protocoll - Lightweight, Simple &amp; IPv6 only

This Version is far from perfect and there is a lot of work to do:
TODO:
- get rid of memory leaks
- cleanup

BUILD:
With example: sudo gcc -o example chord.c example.c -I. -lcrypto -lpthread -g

USEAGE:
./example master <bind addr>
./example slave <bind addr> <master addr>

