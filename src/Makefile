.PHONY: clean

# specify prototypes.h explicity in case the file is missing

demo: prototypes.h *.h *.c
	gcc -Wall -O0 -o demo -include defs.h *.c -lm

prototypes.h: *.c
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f demo
