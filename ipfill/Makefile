CC = gcc
CFLAGS = -Wall -pedantic -std=c89 -g
all: client
client: client.o
	${CC} ${CFLAGS} client.o -o client
client.o: client.c
	${CC} ${CFLAGS} -c client.c
clean:
	rm *.o client

