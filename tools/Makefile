.PHONY: default

default:
	make make-prototypes
	./make-prototypes ../src/ >../src/prototypes.h

make-prototypes: make-prototypes.c
	gcc -O0 -o make-prototypes make-prototypes.c
