PHONY = all lib test fulltest fresh
.DEFAULT_GOAL := all
WFLAGS := -Wall -Wextra -Werror
all: lib 

fresh: clean all
debug: clean
	@$(MAKE) CCFLAGS="-DDEBUG_ENABLE -DDEV -g"  all

lib: chord.o
	ar rcs libchord.a chord.o

small: clean
	@$(MAKE) CCFLAGS="-Os -m32" all

chord.o: chord.c chord.h
	$(CC) -c chord.c $(CCFLAGS) $(WFLAGS)

clean:
	rm -rf *.a *.o
