.PHONY: clean

demo: *.h *.c
	make prototypes.h
	gcc -Wall -O0 -o demo -include defs.h *.c -lm

prototypes.h: *.c
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f demo
