all: myping

myping: myping.o
	gcc myping.o -o myping

myping.o: myping.c
	gcc -c myping.c

clear:
	rm -f *.o myping