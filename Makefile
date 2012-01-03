CFLAGS=-Wall

all: sandboxme example

objects := $(patsubst %.c,%.o,$(wildcard *.c))

%.o : %.c
	gcc -c $(CFLAGS) $< -o $@

sandboxme: sandboxme.o privdrop.o
	gcc $(CFLAGS) $^ -o $@ -lcap

example: example.o libsandbox.o
	gcc $(CFLAGS) $^ -o $@

clean:
	rm -f $(objects) sandboxme example sbx
