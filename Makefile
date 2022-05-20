#Makefile

all :
	gcc server.c -lcrypto -o server
	# ./server
	gcc client.c -lcrypto -o client
	# ./client

