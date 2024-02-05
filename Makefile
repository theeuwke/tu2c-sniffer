CC=gcc 
CFLAGS=
main: main.o
udp: udp.o

tcc: tcc.o

clean:
	rm -f main main.o
