#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include  <fcntl.h>

#define MAXLINE 4096
#define LISTENQ 8
#define ERROR -1
#define MAXCLIENTS 10

int main(int argc, char **argv){
    int listenfd, // listening socket fd
        connfd, // new connection socket fd
        setlistenfd, // listening socket fd opts
        true_int, // listening socket fd opts int value
        n; // no of bytes received 
    pid_t childpid;
    socklen_t clilen;
    // char buf[MAXLINE];
    char data[MAXLINE];
    // socket addr var for server
    struct sockaddr_in servaddr;
    // socket addr var for client
    struct sockaddr_in cliaddr;
    int sockaddr_len = sizeof(struct sockaddr_in);
    // counter for clients
    int active_clients = 0;

    if (argc != 2) {
      perror("Format: Server < Port of the server.");
      exit(1);
    }

    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    if(listenfd == ERROR){
        perror("socket");
        exit(-1);
    }
    
    true_int = 1;
    setlistenfd = setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,&true_int,sizeof(int));
    if(setlistenfd == ERROR){
        perror("setsockopt");
        exit(-1);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(atoi(argv[1]));
    bzero(&servaddr.sin_zero, 8);

    if(bind (listenfd, (struct sockaddr *) &servaddr, sockaddr_len) == ERROR){
        perror("bind");
        exit(-1);
    }

    if(listen (listenfd, LISTENQ) == ERROR){
        perror("listen");
        exit(-1);
    }

    printf("%s\n","Server running...waiting for connections.");


    while(active_clients < MAXCLIENTS){

        connfd = accept(listenfd, (struct sockaddr *) &cliaddr, &sockaddr_len);

        if(connfd == ERROR){
            printf("Error while accepting the conncection\n");
            close(connfd);
            continue;
        }

        active_clients++;
        printf("%s\n","Received request...");

        if ( (childpid = fork ()) == 0 ) {
            printf ("%s\n","Child created for dealing with client requests");
            // close listening socket
            close (listenfd);

            int data_len = 1;

            while(data_len){

                data_len = recv(connfd, data, MAXLINE, 0);

                if(data_len){
                    send(connfd, data, data_len, 0);
                    data[data_len] = '\0';
                    printf("String received from and resent to the client:%s\n", data);
                }else{
                    break;
                }
            }
            
            if(data_len == ERROR){
                perror("Read error");
                exit(-1);
            }
            else if(data_len == 0){
                printf("Client closed connection.");
                close(connfd);
            }

            active_clients--;
        }
    }

}