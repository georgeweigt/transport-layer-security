.PHONY: clean checkall

HFILES := $(shell ls *.h)
CFILES := $(shell ls *.c)

# specify prototypes.h in case it's missing from HFILES

demo: prototypes.h $(HFILES) $(CFILES)
	gcc -Wall -O0 -o demo -include defs.h -include prototypes.h $(CFILES) -lm

prototypes.h: $(CFILES)
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f demo prototypes.h

checkall:
	make -s -C ../tools wcheck
	for FILE in *.h *.c; do ../tools/wcheck $$FILE; done
