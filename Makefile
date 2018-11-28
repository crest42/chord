PHONY = all lib test fulltest fresh
.DEFAULT_GOAL := all
WFLAGS := -Wall -Wextra -Werror
all: lib 

fresh: clean all
debug: clean
	@$(MAKE) CCFLAGS="-DDEBUG_ENABLE -DDEV -g"  all

lib: chord.o msg_handler.o network.o chord_util.o bootstrap.o
	ar rcs libchord.a chord.o msg_handler.o network.o chord_util.o bootstrap.o

small: clean
	@$(MAKE) CCFLAGS="-Os -m32" all

chord.o: src/chord.c src/network.c src/msg_handler.c include/chord.h include/chord_util.h include/bootstrap.h
	$(CC) -DPOSIX_SOCK -c src/msg_handler.c src/network.c src/chord.c src/chord_util.c src/bootstrap.c $(CCFLAGS) $(WFLAGS)

clean:
	rm -rf *.a *.o
