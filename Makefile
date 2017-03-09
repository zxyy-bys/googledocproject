all:main

main: edge_server.c helpfnc.o
	gcc -Wall -g -o main helpfnc.o edge_server.c -lssl -lcrypto -levent_openssl -levent -pthread -lz

helpfnc: helpfnc.h helpfnc.c
	gcc -Wall -g helpfnc.c
.PHONY:clean
clean:
	rm main *.o
