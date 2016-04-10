#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define LISTENQ 8
#define ERROR -1
#define MAXCLIENTS 10
#define MAX_LEN 16

uint32_t * encode_msg(char *input){
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t *msg_full = (uint32_t *) malloc(sizeof(uint32_t) * (MAX_LEN + 2));

    size_t in_len;

    msg_type = 1;
    msg_full[0] = msg_type;

    in_len = strlen(input);
    while(in_len > 0 && (input[in_len-1] == '\n' || input[in_len-1] == '\r'))
        input[--in_len] == 0;
    msg_len = (uint32_t) in_len;
    msg_full[1] = msg_len;

    uint32_t i = 0;
    for(i = 0; i < sizeof(input); i++){
        msg_full[i+2] = htonl((uint32_t) input[i]);
    }

    printf("Message type is: %u\n", msg_type);
    printf("Length of message is: %u\n", msg_len);
    printf("Encoded message is:");
    for(i = 0; i < MAX_LEN +2 ; i++) {
        printf("%u", msg_full[i]);
    }
    printf("\n");
    return msg_full;
}

char *decode_msg(uint32_t *encoded_msg, size_t data_len){
    char *ret_str = malloc(sizeof(char) * data_len);

    int i = 0;
    for(i = 2; i < data_len; i++){
        ret_str[i-2] = (char) ntohl(encoded_msg[i]);
    }
    return ret_str;
}

uint32_t main(uint32_t argc, char **argv){
    int listenfd, // listening socket fd
        connfd, // new connection socket fd
        setlistenfd, // listening socket fd opts
        true_int, // listening socket fd opts int value
        n; // no of bytes received

    uint32_t ports[10] = {3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 3011};

    pid_t childpid;
    socklen_t clilen;

    uint32_t data[MAX_LEN+2];
    // socket address var for server
    struct sockaddr_in servaddr;
    // socket address var for client
    struct sockaddr_in cliaddr;
    uint32_t sockaddr_len = sizeof(struct sockaddr_in);
    // counter for clients
    uint32_t active_clients = 0;

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
    setlistenfd = setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,&true_int,sizeof(uint32_t));
    if(setlistenfd == ERROR){
        perror("setsockopt");
        exit(-1);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons((uint16_t)atoi(argv[1]));
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
            printf("Error while accepting the connection\n");
            close(connfd);
            continue;
        }

        active_clients++;
        printf("%s\n","Received request...");

        if ( (childpid = fork ()) == 0 ) {
            printf ("%s\n","Child created for dealing with client requests");
            // close listening socket
            close (listenfd);

            ssize_t data_len = 1;

            while(data_len){

                size_t input_size = (MAX_LEN+2)*sizeof(uint32_t);

                data_len = recv(connfd, data, input_size, 0);

                int i = 0;
                printf("Number of bytes read:%zu", data_len);
                printf("Encoded data read is:");
                for(i = 0; i < data_len/4; i++){
                    printf("%u", data[i]);
                }
                printf("\n");

                if(data_len){
                    printf("Decoded message is:%s", decode_msg(data, data_len/4));
                    printf("Bytes resent are: %zu\n", data_len);
                    send(connfd, data, (size_t) data_len, 0);
                }else{
                    break;
                }
            }

            close(connfd);

            active_clients--;
        }
    }

}