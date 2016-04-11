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

uint16_t * encode_msg(uint16_t type, char *input);
char *decode_msg(uint16_t *encoded_msg);
void connection_handler(char *address, uint16_t port);
void udp_handler(char *address, uint16_t port);
int main2(int argc, char **argv);

uint16_t * encode_msg(uint16_t type, char *input) {
    size_t msg_len;
    size_t in_len;

    uint16_t *msg_full = (uint16_t *) malloc(sizeof(uint16_t) * (MAX_LEN + 2));

    msg_full[0] = type;

    in_len = strlen(input);
    while(in_len > 0 && (input[in_len-1] == '\n' || input[in_len-1] == '\r'))
        input[--in_len] == 0;
    msg_len = in_len;
    msg_full[1] = (uint16_t) msg_len;

    uint16_t i = 0;
    /*
    printf("Characters to ascii:");
    for(i = 0; i < sizeof(input); i++){
        printf("%u,", (uint16_t) input[i]);
    }
    printf("\n");

    printf("ascii to network order:");
    for(i = 0; i < sizeof(input); i++){
        printf("%u,", htons((uint16_t) input[i]));
    }
    printf("\n");
    */

    for(i = 0; i < sizeof(input); i++){
        msg_full[i+2] = htons((uint16_t) input[i]);
    }

    printf("Encoded message type is: %u\n", type);
    printf("Encoded message length is: %u\n", (uint16_t) msg_len);

    printf("Encoded message is:");
    for(i = 0; i < MAX_LEN +2 ; i++) {
        printf("%u", msg_full[i]);
    }
    printf("\n");

    return msg_full;
}

char *decode_msg(uint16_t *encoded_msg) {
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
    printf("Decoded message type is:%u\n", encoded_msg[1]);
    printf("Decoded message length is:%u\n", encoded_msg[2]);
    printf("Decoded message is: %s\n", ret_str);

    return ret_str;
}

void connection_handler(char *address, uint16_t port) {

    int sock_fd;
    struct sockaddr_in servaddr;

    char input[MAX_LEN];
    uint16_t output[MAX_LEN+2];

    if ((sock_fd = socket (AF_INET, SOCK_STREAM, 0)) <0) {
        perror("Problem in creating the socket");
        exit(2);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(address);
    servaddr.sin_port =  htons(port);

    if (connect(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr))<0) {
        perror("Problem in connecting to the server");
        exit(3);
    }

    int while_count = 0;
    while (while_count < 10) {
        while_count++;

        bzero(input, MAX_LEN);
        fgets(input, MAX_LEN, stdin);

        input[strcspn(input, "\n")] = 0;

        uint16_t *encoded_msg = encode_msg(1, input);

        int i = 0;
        printf("Encoded msg is:");
        for(i = 0; i < MAX_LEN+2; i++){
            printf("%u", encoded_msg[i]);
        }
        printf("\n");

        size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);

        ssize_t bytes_sent = send(sock_fd, encoded_msg, input_size, 0);
        if(bytes_sent < 0){
            perror("send");
            exit(-1);
        }
        printf("Bytes sent:%zu\n",bytes_sent);

        ssize_t bytes_received = recv(sock_fd, output, input_size, 0);

        if(bytes_received > 0){

            printf("Encoded msg received is:");
            for(i = 0; i < MAX_LEN+2;i++){
                printf("%u", output[i]);
            }
            printf("\n");

            char *decoded_resp = decode_msg(output);
            if(strcmp(input, "getport") == 0){
                printf("Port returned is: %u\n", atoi(decoded_resp));
                close(sock_fd);
                udp_handler(address, atoi(decoded_resp));
                printf("Connection closed.\n");
                break;
            }

        }
        else if(bytes_received < 0){
            perror("read");
            exit(-1);
        }
        else if (bytes_received == 0){
            perror("The server terminated prematurely");
            close(sock_fd);
            exit(4);
        }
    }

    return;
}

void udp_handler(char *address, uint16_t port){

    int sock_fd;
    struct sockaddr_in servaddr;
    socklen_t sockaddr_len = sizeof(struct sockaddr);

    char input[MAX_LEN];
    uint16_t output[MAX_LEN+2];

    struct hostent *he;
//    he = getnameinfo((struct sockaddr *)&servaddr, (size_t) sizeof(servaddr),
//                address, (socklen_t) strlen(address), NULL,NULL,0);


    if((he = gethostbyname(address)) == NULL){
        perror("gethostbyname");
        exit(-1);
    }

    if ((sock_fd = socket (AF_INET, SOCK_DGRAM, 0)) <0 ) {
        perror("Problem in creating the socket");
        exit(2);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(address);
    servaddr.sin_port =  htons(port);
    memset(&(servaddr.sin_zero), 0, sizeof(servaddr));

    printf("seraddr set\n");

    int while_count = 0;
    while(while_count < 10){
        while_count++;

        bzero(input, MAX_LEN);
        fgets(input, MAX_LEN, stdin);
        input[strcspn(input, "\n")] = 0;

        uint16_t *encoded_msg = encode_msg(3, input);

        int i = 0;
        printf("Encoded message is:");
        for(i = 0; i < MAX_LEN+2; i++){
            printf("%u", encoded_msg[i]);
        }
        printf("\n");

        size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);

        /*
        fd_set rfds;
        int retval;
        FD_ZERO(&rfds);
        FD_SET(sock_fd, &rfds);
        retval = select(sock_fd+1,&rfds, NULL, NULL, NULL);
        if(retval == -1){
            perror("select");
        }
        */
        printf("Trying to send\n");
        ssize_t bytes_sent = sendto(sock_fd, encoded_msg, input_size, 0, (struct sockaddr *)&servaddr,
                                    sizeof(struct sockaddr));
        printf("Sent\n");
        if(bytes_sent > 0){
            printf("Bytes sent:%zu\n",bytes_sent);
        }else if(bytes_sent < 0){
            perror("sendto");
            exit(0);
        }else if(bytes_sent == 0){
            printf("connection closed by server");
            close(sock_fd);
            break;
        }

        socklen_t size_of = sizeof(struct sockaddr);
        ssize_t bytes_received = recvfrom(sock_fd, output, input_size, 0, (struct sockaddr *)&servaddr,
                                          &size_of);

        if(bytes_received > 0){
            printf("Encoded msg received is:");
            for(i = 0; i < MAX_LEN+2;i++){
                printf("%u", output[i]);
            }
            printf("\n");
            decode_msg(output);
        }
        else if(bytes_received < 0){
            perror("read");
            exit(-1);
        }
        else if (bytes_received == 0){
            perror("The server probably has closed. No comunication possible.");
            close(sock_fd);
            exit(4);
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

    connection_handler(argv[1], (uint16_t)(atoi(argv[2])));
//    udp_handler(argv[1], (uint16_t)(atoi(argv[2])));

    printf("Client program has closed.\n");
    exit(0);
}

int main2(int argc, char **argv){

    char input[MAX_LEN];

    fgets(input, MAX_LEN, stdin);

    printf("String entered is:%s\n",input);

    char *in_clone = decode_msg(encode_msg(1, input));

    printf("%s\n", in_clone);

    return 0;
}
