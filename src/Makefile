.PHONY: clean

CC = gcc
CFLAGS = -Wall -O0 -include defs.h

objs := $(shell ls *.c | sed "s/\.c/\.o/g")

demo: $(objs)
	gcc -o demo $(objs)

$(objs): defs.h ssl.h cert.h ec.h extern.h prototypes.h

clean:
	rm -f *.o demo
