#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "commonconst.h"

uint16_t * encode_msgC(uint16_t type, char *input);
char *decode_msgC(uint16_t *encoded_msg);
void tcp_handlerC(char *address, uint16_t port);
void udp_handlerC(char *address, uint16_t port);

uint16_t * encode_msgC(uint16_t type, char *input) {

    uint16_t *msg_full = (uint16_t *) malloc(sizeof(uint16_t) * (MAX_LEN + 2));

    size_t in_len;
    in_len = strlen(input);
    while(in_len > 0 && (input[in_len-1] == '\n' || input[in_len-1] == '\r'))
        input[--in_len] == 0;

    msg_full[0] = htons(type);
    msg_full[1] = htons((uint16_t) in_len);

    uint16_t i = 0;
    for(i = 0; i < sizeof(input); i++){
        msg_full[i+2] = htons((uint16_t) input[i]);
    }

    //printf("Encoded message type is:%u\n", ntohs(msg_full[0]));
    //printf("Encoded message length is:%u\n", ntohs(msg_full[1]));

    return msg_full;
}

char *decode_msgC(uint16_t *encoded_msg) {
    char *ret_str = malloc(sizeof(char) * MAX_LEN);

    int i = 0;
    for(i = 2; i < MAX_LEN+2; i++){
        ret_str[i-2] = (char) ntohs(encoded_msg[i]);
    }
    //printf("Decoded message type is:%u\n", ntohs((uint16_t)encoded_msg[0]));
    //printf("Decoded message length is:%u\n", ntohs((uint16_t)encoded_msg[1]));

    return ret_str;
}

void tcp_handlerC(char *address, uint16_t port) {


    int sock_fd;
    struct sockaddr_in servaddr;

    char input[MAX_LEN];
    /* received message is encoded as an array of uint_16 */
    uint16_t output[MAX_LEN+2];

    if ((sock_fd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Problem in creating the socket");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(address);
    servaddr.sin_port =  htons(port);

    if (connect(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("Problem in connecting to the server");
        exit(EXIT_FAILURE);
    }

    printf("Send \"getport\" to get a UDP port from server\n");
    printf("Once UDP Connection is established, send \"quitudp\" to quit udp transmission\n");

    printf("-----------------------------------------------------------------------------------\n");
    printf("Server IP\tOperation\tProtocol\tPort\t\tMore Information\n");
    printf("------------------------------------------------------------------------------------\n");
    printf("%s\tconnect\t\ttcp\t\t%u\t\tconnection initiated to server\n", address, port);

    while (1) {

        printf("%s\tmessage type1\ttcp\t\t%u\t\tmessage sent: ", address, port);
        bzero(input, MAX_LEN);
        fgets(input, MAX_LEN, stdin);
        input[strcspn(input, "\n")] = 0;

        uint16_t *encoded_msg = encode_msgC(1, input);

        int i = 0;
        size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);

        ssize_t bytes_sent = send(sock_fd, encoded_msg, input_size, 0);
        if(bytes_sent < 0){
            perror("send");
            exit(EXIT_FAILURE);
        }
        ssize_t bytes_received = recv(sock_fd, output, input_size, 0);

        if(bytes_received > 0){

            char *decoded_resp = decode_msgC(output);

            if(strcmp(input, "getport") == 0){
                printf("%s\tmessage type2\ttcp\t\t%u\t\tmessage received: %s\n", address, port, decoded_resp);
                printf("%s\ttcp close\ttcp\t\t%u\t\tconnection closed\n", address, port);
                printf("%s\tport received\t---\t\t---\t\tudp port received: %s\n", address, decoded_resp);

                close(sock_fd);

                udp_handlerC(address, (uint16_t) atoi(decoded_resp));
                break;
            }else{
                printf("%s\tmessage type2\ttcp\t\t%u\t\treceived message: %s\n", address, port, decoded_resp);
            }

        }
        else if(bytes_received < 0){
            perror("read");
            exit(EXIT_FAILURE);
        }
        else if (bytes_received == 0){
            printf("%s\trecv error\ttcp\t\t%u\t\tzero bytes received\n", address, port);
            printf("%s\texit\t\ttcp\t\t%u\t\tserver has closed arbitarily\n", address, port);
            close(sock_fd);
            exit(EXIT_FAILURE);
        }
    }

    printf("---\t\texit\t\t---\t\t---\t\texiting\n");
    return;
}

void udp_handlerC(char *address, uint16_t port){

    int sock_fd;
    struct sockaddr_in servaddr;
    socklen_t sockaddr_len = sizeof(struct sockaddr);

    char input[MAX_LEN];
    uint16_t output[MAX_LEN+2];

    if ((sock_fd = socket (AF_INET, SOCK_DGRAM, 0)) <0 ) {
        perror("Problem in creating the socket");
        exit(EXIT_FAILURE);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(address);
    servaddr.sin_port =  htons(port);
    memset(&(servaddr.sin_zero), 0, sizeof(servaddr));

    printf("%s\tudp start\tudp\t\t%u\t\tconnection initiated\n", address, port);

    while(1){

        printf("%s\tmessage type3\tudp\t\t%u\t\tmessage sent: ", address, port);
        bzero(input, MAX_LEN);
        fgets(input, MAX_LEN, stdin);
        input[strcspn(input, "\n")] = 0;

        uint16_t *encoded_msg = encode_msgC(3, input);


        int i = 0;

        size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);

        ssize_t bytes_sent = sendto(sock_fd, encoded_msg, input_size, 0, (struct sockaddr *)&servaddr,
                                    sockaddr_len);
        if(bytes_sent < 0){
            perror("sendto");
            exit(EXIT_FAILURE);
        }else if(bytes_sent == 0){
            /*
            printf("Zero bytes sent.\n");
            printf("It is probably because client closed the connection prematurely.\n");
            printf("Connection closed by server.\n");
             */
            printf("%s\tclose\tudp\t\t%u\t\tserver not active\n", address, port);
            close(sock_fd);
            exit(EXIT_SUCCESS);
        }

        socklen_t size_of = sizeof(struct sockaddr);
        ssize_t bytes_received = recvfrom(sock_fd, output, input_size, 0, (struct sockaddr *)&servaddr,
                                          &sockaddr_len);
        if(bytes_received > 0){
            char *decoded_msg = decode_msgC(output);
            printf("%s\tmessage type4\tudp\t\t%u\t\tmessage received: %s\n", address, port, decoded_msg);
        }
        else if(bytes_received < 0){
            perror("read");
            exit(EXIT_FAILURE);
        }
        else if (bytes_received == 0){
            printf("%s\trecv error\tudp\t\t%u\t\tzero bytes received\n", address, port);
            printf("%s\texit\t\tudp\t\t%u\t\tserver has closed arbitarily\n", address, port);
            /* perror("server closed"); */
            close(sock_fd);
            exit(EXIT_FAILURE);
        }

        if(strcmp(input, "quitudp") == 0){
            printf("%s\tclose udp\tudp\t\t%u\t\tclosing the connection\n", address, port);
            close(sock_fd);
            break;
        }
    }

    return;
}

int main(int argc, char **argv) {
    if (argc != 3) {
      perror("Format: TCPClient < IP address of the server < Port of the server.");
      exit(1);
    }

    tcp_handlerC(argv[1], (uint16_t)(atoi(argv[2])));

    return 0;
}