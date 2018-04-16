PHONY = all example lib test
.DEFAULT_GOAL := all
WFLAGS := -Wall -Wextra
all: example

example: lib example.o
	$(CC) example.o -o example -lcrypto -lpthread libchord.a $(CCFLAGS) $(WFLAGS)

chord: chord.o

lib: chord.o
	ar rcs libchord.a chord.o

example.o: example.c
	$(CC) -c example.c -lpthread $(CCFLAGS) $(WFLAGS)

chord.o: chord.c chord.h
	$(CC) -c chord.c $(CCFLAGS) $(WFLAGS)

clean:
	rm -rf *.a *.o example

test: clean all
	perl testsuite.pl $(TARGS)
