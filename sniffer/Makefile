all: sniffer

sniffer: sniffer.o
	gcc sniffer.o -o sniffer

sniffer.o: sniffer.c headers.h
	gcc -c sniffer.c

clear:
	rm -f *.o sniffer
