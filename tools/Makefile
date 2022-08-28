.PHONY: default all clean

default:
	make make-prototypes
	./make-prototypes ../src/ >../src/prototypes.h

all:
	make make-prototypes
	make test-hmac
	make test-elliptic-curve

make-prototypes: make-prototypes.c
	gcc -Wall -O0 -o make-prototypes make-prototypes.c

test-hmac: test-hmac.c
	gcc -Wall -O0 -o test-hmac test-hmac.c

test-elliptic-curve: test-elliptic-curve.c
	gcc -Wall -O0 -o test-elliptic-curve test-elliptic-curve.c

clean:
	rm -f make-prototypes test-hmac test-elliptic-curve
