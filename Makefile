all: server client server_small client_small

server: server.c
	gcc -o server server.c

client: echoClient.c
	gcc -o client echoClient.c

server_small: server_small.c
	gcc -o server_small server_small.c

client_small: client_small.c
	gcc -o client_small client_small.c
