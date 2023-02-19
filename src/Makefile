.PHONY: clean

HFILES := $(shell ls *.h)
CFILES := $(shell ls *.c)

# specify prototypes.h in case it is missing

demo: prototypes.h $(HFILES) $(CFILES)
	gcc -Wall -O0 -o demo -include defs.h -include prototypes.h $(CFILES) -lm

prototypes.h: $(CFILES)
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f demo prototypes.h
