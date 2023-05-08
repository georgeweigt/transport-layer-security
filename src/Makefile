.PHONY: clean check

# specify prototypes.h in case it's missing from *.h

demo: prototypes.h *.h *.c
	gcc -Wall -O0 -o demo -include defs.h -include prototypes.h *.c

prototypes.h: *.c
	make -s -C ../tools make-prototypes
	../tools/make-prototypes *.c > prototypes.h

clean:
	rm -f demo prototypes.h

check:
	make -s -C ../tools wcheck
	../tools/wcheck *.c
