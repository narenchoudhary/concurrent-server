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

#define MAX_LEN 16 /*max text line length*/

uint32_t * encode_msg(char *input){
    uint32_t msg_type;

    uint32_t *msg_full = (uint32_t *) malloc(sizeof(uint32_t) * (MAX_LEN + 2));

    size_t msg_len;
    size_t in_len;

    msg_type = 1;
    msg_full[0] = msg_type;

    in_len = strlen(input);
    while(in_len > 0 && (input[in_len-1] == '\n' || input[in_len-1] == '\r'))
        input[--in_len] == 0;
    msg_len = in_len;
    msg_full[1] = (uint32_t) msg_len;

    uint32_t i = 0;
    for(i = 0; i < sizeof(input); i++){
        msg_full[i+2] = htonl((uint32_t) input[i]);
    }

    printf("Message type is: %u\n", msg_type);
    printf("Length of message is: %u\n", (uint32_t) msg_len);
    printf("Encoded message is:");
    for(i = 0; i < MAX_LEN +2 ; i++) {
        printf("%u", msg_full[i]);
    }
    printf("\n");
    return msg_full;
}

char *decode_msg(uint32_t *encoded_msg){
    char *ret_str = malloc(sizeof(char) * MAX_LEN);

    int i = 0;
    for(i = 2; i < MAX_LEN+2; i++){
        ret_str[i-2] = (char) ntohl(encoded_msg[i]);
    }

    printf("Decoded message is: %s\n", ret_str);
    return ret_str;
}


int main(int argc, char **argv)
{
    int sock_fd;
    struct sockaddr_in servaddr;
    char input[MAX_LEN], output[MAX_LEN+2];

    if (argc != 3) {
      perror("Format: TCPClient < IP address of the server < Port of the server.");
      exit(1);
    }

    if ((sock_fd = socket (AF_INET, SOCK_STREAM, 0)) <0) {
      perror("Problem in creating the socket");
      exit(2);
    }


    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(argv[1]);
    servaddr.sin_port =  htons((uint16_t)atoi(argv[2]));

    if (connect(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr))<0) {
      perror("Problem in connecting to the server");
      exit(3);
    }

    while (1) {
        fgets(input, MAX_LEN, stdin);

        uint32_t *encoded_msg = encode_msg(input);

        int i = 0;
        printf("Encoded msg is:");
        for(i = 0; i < MAX_LEN+2; i++){
            printf("%u", encoded_msg[i]);
        }
        printf("\n");

        size_t input_size = sizeof(uint32_t)*(MAX_LEN+2);

        ssize_t bytes_sent = send(sock_fd, input, input_size, 0);
        printf("Bytes sent:%zu\n",bytes_sent);

        ssize_t bytes_received = recv(sock_fd, output, input_size, 0);
        if(bytes_received > 0){

            printf("Encoded msg received is:");
            for(i = 0; i < MAX_LEN+2;i++){
                printf("%u", output[i]);
            }
            printf("\n");

            char *decoded_msg = decode_msg(output);
            printf("Decoded message is:");
            for(;*decoded_msg != NULL;++decoded_msg){
                printf("%c", (unsigned char) decoded_msg);
            }
        }
        else if(bytes_received < 0){
            perror("read");
            exit(-1);
        }
        else if (bytes_received == 0){
            perror("The server terminated prematurely");
            exit(4);
        }
    }
    exit(0);
}
