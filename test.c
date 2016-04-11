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
#include <fcntl.h>

#define MAX_LEN 16

uint16_t * encode_msg(uint16_t msg_type, char *input){

    uint16_t *msg_full = (uint16_t *) malloc(sizeof(uint16_t) * (MAX_LEN + 2));

    size_t in_len;
    in_len = strlen(input);
    while(in_len > 0 && (input[in_len-1] == '\n' || input[in_len-1] == '\r'))
        input[--in_len] == 0;

    msg_full[0] = htons(msg_type);
    msg_full[1] = htons((uint16_t) in_len);


    uint16_t i = 0;
    for(i = 0; i < sizeof(input); i++){
        msg_full[i+2] = htons((uint16_t) input[i]);
    }

    printf("Message type is: %u\n", msg_type);
    printf("Length of message is: %u\n", (uint16_t) in_len);
    printf("Encoded message is:");
    for(i = 0; i < MAX_LEN +2 ; i++) {
        printf("%u", msg_full[i]);
    }
    printf("\n");

    return msg_full;
}

char *decode_msg(uint16_t *encoded_msg){
    char *ret_str = malloc(sizeof(char) * MAX_LEN);

    int i = 0;
    for(i = 2; i < MAX_LEN+2; i++){
//        ret_str[i-2] = (char) (encoded_msg[i]);
        ret_str[i-2] = (char) ntohs(encoded_msg[i]);
    }

    printf("Decoded message type is: %u\n", ntohs((uint16_t) encoded_msg[0]));
    printf("Decoded message length is: %u\n", ntohs((uint16_t) encoded_msg[1]));
    printf("Decoded message is: %s\n", ret_str);

    return ret_str;
}

int main(int argc, char **argv){

    char input[MAX_LEN];

    fgets(input, MAX_LEN, stdin);
    input[strcspn(input, "\n")] = 0;
    printf("String entered is:%s\n",input);

    char *in_clone = decode_msg(encode_msg(1, input));

    printf("%s\n", in_clone);
    printf("%u\n", sizeof(encode_msg(1, input)));

    return 0;
}