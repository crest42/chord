PHONY = all example lib test fulltest
.DEFAULT_GOAL := all
WFLAGS := -Wall -Wextra
all: example

debug: clean
	@$(MAKE) CCFLAGS="-DDEBUG_ENABLE -DDEV -g"  all

example: lib example.o
	$(CC) example.o -o example -lcrypto -lpthread libchord.a $(CCFLAGS) $(WFLAGS)

chord: chord.o

lib: chord.o
	ar rcs libchord.a chord.o

small: clean
	@$(MAKE) CCFLAGS="-Os -m32" all

example.o: example.c
	$(CC) -c example.c -lpthread $(CCFLAGS) $(WFLAGS)

chord.o: chord.c chord.h
	$(CC) -c chord.c $(CCFLAGS) $(WFLAGS)

clean:
	rm -rf *.a *.o example

test: clean all
	perl testsuite.pl $(TARGS)

autotest: clean all
	perl testsuite.pl -n 8 -m 4 -v || exit
	perl testsuite.pl -n 64 -m 256 || exit
	perl testsuite.pl -n 8 -k 10 || exit
