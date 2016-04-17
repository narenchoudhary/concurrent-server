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
#include <netdb.h>

#define MAX_LEN 16 /*max text line length*/

uint16_t * encode_msgC(uint16_t type, char *input);
char *decode_msgC(uint16_t *encoded_msg);
void tcp_handlerC(char *address, uint16_t port);
void udp_handlerC(char *address, uint16_t port);
void small_tcp_handlerC(char *address, uint16_t port);
void small_udp_handlerC(char *address, uint16_t port);
int main2C(int argc, char **argv);

uint16_t * encode_msgC(uint16_t type, char *input) {

    uint16_t *msg_full = (uint16_t *) malloc(sizeof(uint16_t) * (MAX_LEN + 2));

    size_t in_len;
    in_len = strlen(input);
    while(in_len > 0 && (input[in_len-1] == '\n' || input[in_len-1] == '\r'))
        input[--in_len] == 0;

    msg_full[0] = htons(type);
    msg_full[1] = htons((uint16_t) in_len);

    uint16_t i = 0;
    /*
    printf("Characters to ascii:");
    for(i = 0; i < sizeof(input); i++){
        printf("%u,", (uint16_t) input[i]);
    }
    printf("\n");

    printf("ascii to network order:");
    for(i = 0; i < sizeof(input); i++){
        printf("%u", htons((uint16_t) input[i]));
    }
    printf("\n");
    */

    for(i = 0; i < sizeof(input); i++){
        msg_full[i+2] = htons((uint16_t) input[i]);
    }

    printf("Encoded message type is:%u\n", ntohs(msg_full[0]));
    printf("Encoded message length is:%u\n", ntohs(msg_full[1]));
    /*
    printf("Encoded message is:");
    for(i = 0; i < MAX_LEN +2 ; i++) {
        printf("%u", msg_full[i]);
    }
    printf("\n");
    */

    return msg_full;
}

char *decode_msgC(uint16_t *encoded_msg) {
    char *ret_str = malloc(sizeof(char) * MAX_LEN);

    int i = 0;
    /*
    printf("Separate bytes:");
    for(i = 2; i < MAX_LEN+2; i++){
        printf("%u,", encoded_msg[i]);
    }
    printf("\n");

    printf("Separate bytes to host order:");
    for(i = 2; i < MAX_LEN+2; i++){
        printf("%u,", ntohs(encoded_msg[i]));
    }
    printf("\n");

    printf("Separate host order to characters:");
    for(i = 2; i < MAX_LEN+2; i++){
        printf("%c,", (char) ntohs(encoded_msg[i]));
    }
    printf("\n");
    */

    for(i = 2; i < MAX_LEN+2; i++){
        ret_str[i-2] = (char) ntohs(encoded_msg[i]);
    }
    printf("Decoded message type is:%u\n", ntohs((uint16_t)encoded_msg[0]));
    printf("Decoded message length is:%u\n", ntohs((uint16_t)encoded_msg[1]));
    //printf("Decoded message is:%s\n", ret_str);

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

    printf("Send \"getport\" to get a UDP port from server.\n");
    printf("Once UDP Connection is established, send \"quitudp\" to quit udp transmission.\n");

    while (1) {

        bzero(input, MAX_LEN);
        fgets(input, MAX_LEN, stdin);
        input[strcspn(input, "\n")] = 0;

        uint16_t *encoded_msg = encode_msgC(1, input);

        int i = 0;
        /*
        printf("Encoded msg is:");
        for(i = 0; i < MAX_LEN+2; i++){
            printf("%u", encoded_msg[i]);
        }
        printf("\n");
        */
        size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);

        ssize_t bytes_sent = send(sock_fd, encoded_msg, input_size, 0);
        if(bytes_sent < 0){
            perror("send");
            exit(EXIT_FAILURE);
        }
        //printf("Bytes sent:%zu\n",bytes_sent);
        //printf("Sending over\n");

        ssize_t bytes_received = recv(sock_fd, output, input_size, 0);

        if(bytes_received > 0){
            /*
            printf("Encoded msg received is:");
            for(i = 0; i < MAX_LEN+2;i++){
                printf("%u", output[i]);
            }
            printf("\n");
            */

            char *decoded_resp = decode_msgC(output);
            if(strcmp(input, "getport") == 0){
                printf("Port returned by server is: %u\n", atoi(decoded_resp));
                close(sock_fd);
                udp_handlerC(address, atoi(decoded_resp));
                printf("Connection closed.\n");
                break;
            }else{
                printf("Message returned by server is:%s\n",decoded_resp);
            }

        }
        else if(bytes_received < 0){
            perror("read");
            exit(EXIT_FAILURE);
        }
        else if (bytes_received == 0){
            printf("The server terminated prematurely.\n");
            close(sock_fd);
            exit(EXIT_FAILURE);
        }
    }

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

    while(1){

        bzero(input, MAX_LEN);
        fgets(input, MAX_LEN, stdin);
        input[strcspn(input, "\n")] = 0;

        uint16_t *encoded_msg = encode_msgC(3, input);

        /*
        int i = 0;
        printf("Encoded message is:");
        for(i = 0; i < MAX_LEN+2; i++){
            printf("%u", encoded_msg[i]);
        }
        printf("\n");
        */
        printf("Message sent to server is:%s\n", input);
        size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);

        ssize_t bytes_sent = sendto(sock_fd, encoded_msg, input_size, 0, (struct sockaddr *)&servaddr,
                                    sizeof(struct sockaddr));

        if(bytes_sent > 0){
            //printf("Bytes sent:%zu\n",bytes_sent);
        }else if(bytes_sent < 0){
            perror("sendto");
            exit(EXIT_FAILURE);
        }else if(bytes_sent == 0){
            printf("Zero bytes sent.\n");
            printf("It is probably because client closed the connection prematurely.\n");
            printf("Connection closed by server.\n");
            close(sock_fd);
            exit(EXIT_SUCCESS);
        }

        socklen_t size_of = sizeof(struct sockaddr);
        ssize_t bytes_received = recvfrom(sock_fd, output, input_size, 0, (struct sockaddr *)&servaddr,
                                          &size_of);

        if(bytes_received > 0){
            /*
            printf("Encoded msg received is:");
            for(i = 0; i < MAX_LEN+2;i++){
                printf("%u", output[i]);
            }
            printf("\n");
             */
            char *decoded_msg = decode_msgC(output);
            printf("Message received from server is:%s\n", decoded_msg);
        }
        else if(bytes_received < 0){
            perror("read");
            exit(EXIT_FAILURE);
        }
        else if (bytes_received == 0){
            perror("The server probably has closed. No comunication possible.");
            close(sock_fd);
            exit(EXIT_FAILURE);
        }

        if(strcmp(input, "quitudp") == 0){
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

    printf("Client program has closed.\n");
    return 0;
}

int main2C(int argc, char **argv){

    char input[MAX_LEN];

    fgets(input, MAX_LEN, stdin);
    input[strcspn(input, "\n")] = 0;
    printf("String entered is:%s\n",input);

    char *in_clone = decode_msgC(encode_msgC(1, input));

    printf("Original string is:%s\n", in_clone);

    return 0;
}


void small_tcp_handlerC(char *address, uint16_t port) {

    int sock_fd = socket (AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("Problem in creating the socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(address);
    servaddr.sin_port =  htons(port);

    if (connect(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("Problem in connecting to the server");
        exit(EXIT_FAILURE);
    }

    char input[MAX_LEN];

    printf("Encoding client request(Message1)!\n");
    uint16_t *encoded_msg = encode_msgC(1, "getport");

    size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);

    ssize_t bytes_sent = send(sock_fd, encoded_msg, input_size, 0);

    if(bytes_sent < 0){
        perror("send");
        exit(EXIT_FAILURE);
    }

    uint16_t output[MAX_LEN+2];
    ssize_t bytes_received = recv(sock_fd, output, input_size, 0);

    if(bytes_received > 0){
        printf("\nServer response received!\n");

        char *decoded_resp = decode_msgC(output);

        printf("Port returned by server is: %u\n", atoi(decoded_resp));
        close(sock_fd);
        printf("TCP connection closed.\n");
        small_udp_handlerC(address, (uint16_t)atoi(decoded_resp));
        printf("UDP closed.\n");
    }
    else if(bytes_received < 0){
        perror("read");
        exit(EXIT_FAILURE);
    }
    else if (bytes_received == 0){
        printf("The server terminated prematurely.\n");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    return;
}


void small_udp_handlerC(char *address, uint16_t port){

    int sock_fd;
    struct sockaddr_in servaddr;
    socklen_t sockaddr_len = sizeof(struct sockaddr);

    char input[MAX_LEN];
    uint16_t output[MAX_LEN+2];

    if ((sock_fd = socket (AF_INET, SOCK_DGRAM, 0)) <0 ) {
        perror("Problem in creating the socket\n");
        exit(EXIT_FAILURE);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(address);
    servaddr.sin_port =  htons(port);
    memset(&(servaddr.sin_zero), 0, sizeof(servaddr));

    printf("\nStart Phase2\n");
    printf("Encoding client request (Message3)!\n");
    uint16_t *encoded_msg = encode_msgC(3, "quitudp");

    printf("Message sent to server is:%s\n", "quitudp");

    size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);

    ssize_t bytes_sent = sendto(sock_fd, encoded_msg, input_size, 0, (struct sockaddr *)&servaddr,
                                sizeof(struct sockaddr));

    if(bytes_sent > 0){
        //printf("Bytes sent:%zu\n",bytes_sent);
    }else if(bytes_sent < 0){
        perror("sendto");
        exit(EXIT_FAILURE);
    }else if(bytes_sent == 0){
        printf("Zero bytes sent.\n");
        printf("It is probably because client closed the connection prematurely.\n");
        printf("Connection closed by server.\n");
        close(sock_fd);
        exit(EXIT_SUCCESS);
    }

    socklen_t size_of = sizeof(struct sockaddr);
    ssize_t bytes_received = recvfrom(sock_fd, output, input_size, 0, (struct sockaddr *)&servaddr,
                                      &size_of);

    if(bytes_received > 0){
        printf("\nSever response (Message 4) received!\n");
        printf("Decoding server response.\n");
        char *decoded_msg = decode_msgC(output);
        printf("Message received from server is:%s\n", decoded_msg);
        close(sock_fd);
    }
    else if(bytes_received < 0){
        perror("read");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    else if (bytes_received == 0){
        perror("The server probably has closed. No communication possible.\n");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    return;
}