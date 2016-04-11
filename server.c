#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <unistd.h>
#include <strings.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define LISTENQ 8
#define ERROR -1
#define MAXCLIENTS 10
#define MAX_LEN 16

uint16_t * encode_msg(uint16_t type, char *input);
char *decode_msg(uint16_t *encoded_msg);
uint16_t get_port(int active_clients);
void free_port(uint16_t port);
uint16_t  *change_msg_type(uint16_t *msg, uint16_t new_type);
void connection_handler(uint16_t port);
uint16_t udp_handler(uint16_t port);


uint16_t ports[10] = {3002,3003,3004,3005,3006,3007,3008,3009,3010,3011};
uint16_t ports_occupied[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


uint16_t * encode_msg(uint16_t type, char *input){
    size_t msg_len;
    size_t in_len;

    uint16_t *msg_full = (uint16_t *) malloc(sizeof(uint16_t) * (MAX_LEN + 2));

    msg_full[0] = type;

    uint16_t i = 0;

    printf("Characters:");
    for(i = 0; i < strlen(input); i++){
        printf("%c,", input[i]);
    }
    printf("\n");

    in_len = strlen(input);
    while(in_len > 0 && (input[in_len-1] == '\n' || input[in_len-1] == '\r'))
        input[--in_len] == 0;
    msg_len = in_len;
    msg_full[1] = (uint16_t) msg_len;


    /*
    printf("Characters:");
    for(i = 0; i < strlen(input); i++){
        printf("%c,", input[i]);
    }
    printf("\n");

    printf("Characters to ascii:");
    for(i = 0; i < strlen(input); i++){
        printf("%u,", (uint16_t) input[i]);
    }
    printf("\n");

    printf("ascii to network order:");
    for(i = 0; i < strlen(input); i++){
        printf("%u,", htons((uint16_t) input[i]));
    }
    printf("\n");
    */

    for(i = 0; i < strlen(input); i++){
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

char *decode_msg(uint16_t *encoded_msg){
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

uint16_t  *change_msg_type(uint16_t *msg, uint16_t new_type){
    uint16_t *msg_copy = malloc(sizeof(uint16_t)*(MAX_LEN+2));
    memcpy(msg_copy, msg_copy, sizeof(uint16_t)*(MAX_LEN+2));
    msg_copy[0] = new_type;
    return msg_copy;
}

void connection_handler(uint16_t port){
    /* chared memory things */

    uint16_t *all_ports = mmap(NULL, 10 * sizeof(uint16_t), PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    all_ports[0] = 3002;
    all_ports[1] = 3003;
    all_ports[2] = 3004;
    all_ports[3] = 3005;
    all_ports[4] = 3006;
    all_ports[5] = 3007;
    all_ports[6] = 3008;
    all_ports[7] = 3009;
    all_ports[8] = 3010;
    all_ports[9] = 3011;


    uint16_t *all_free = mmap(NULL, 10*sizeof(uint16_t), PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    all_free[0] = 0;
    all_free[1] = 0;
    all_free[2] = 0;
    all_free[3] = 0;
    all_free[4] = 0;
    all_free[5] = 0;
    all_free[6] = 0;
    all_free[7] = 0;
    all_free[8] = 0;
    all_free[9] = 0;

    int listen_fd, con_fd, setlisten_fd, true_int;

    pid_t childpid;
    socklen_t clilen;

    char input[MAX_LEN];
    uint16_t data[MAX_LEN+2];

    struct sockaddr_in servaddr;
    struct sockaddr_in cliaddr;
    int sockaddr_len = sizeof(struct sockaddr);
    uint16_t active_clients = 0;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(listen_fd == ERROR){
        perror("socket");
        exit(-1);
    }

    true_int = 1;
    setlisten_fd = setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,&true_int,sizeof(int));
    if(setlisten_fd == ERROR){
        perror("setsockopt");
        exit(-1);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    bzero(&servaddr.sin_zero, 8);

    if(bind (listen_fd, (struct sockaddr *) &servaddr, sockaddr_len) == ERROR){
        perror("tcp bind");
        exit(-1);
    }

    if(listen (listen_fd, LISTENQ) == ERROR){
        perror("listen");
        exit(-1);
    }

    printf("%s\n","Server running...waiting for connections.");

    int error_count = 0;
    int while_count = 0;
    int close_connection = 0;
    while(active_clients < MAXCLIENTS){

        con_fd = accept(listen_fd, (struct sockaddr *) &cliaddr, &sockaddr_len);

        if(con_fd == ERROR){
            printf("Error while accepting the connection\n");
            error_count++;
            close(con_fd);
            exit(-1);
        }

        active_clients++;
        printf("%s\n","Received request...");

        if ( (childpid = fork ()) == 0 ) {
            printf ("%s\n","Child created for dealing with client requests");
            // close listening socket
            //printf("listen_fd closed");
            close (listen_fd);

            ssize_t data_len = 1;

            while(data_len){

                int i;

                size_t input_size = (MAX_LEN+2)*sizeof(uint16_t);

                data_len = recv(con_fd, data, input_size, 0);


                printf("Input Size calculated:%zu\n", input_size);
                printf("Number of bytes read:%zu\n", data_len);
                printf("Encoded message is:");
                for(i = 0; i < data_len/ sizeof(uint16_t); i++){
                    printf("%u", data[i]);
                }
                printf("\n");

                char *decoded_req = decode_msg(data);
                printf("Decoded message is:%s\n", decoded_req);

                int startudp = strcmp(decoded_req, "getport");

                if(startudp != 0){

                    printf("Bytes resent are: %zu\n", data_len);
                    send(con_fd, data, input_size, 0);
                } else{
                    printf("UDP port requested\n");

                    char portstring[MAX_LEN];


                    /* get port logic */
                    uint16_t port_yes = -1;
                    uint16_t udpport;
                    for(i = 0; i < MAXCLIENTS; i++){
                        if(all_free[i] == 0){
                            all_free[i] = 1;
                            udpport = all_ports[i];
                            port_yes = 1;
                            break;
                        }
                    }
                    if(port_yes == ERROR){
                        perror("no free udp port");
                        exit(-1);
                    }
                    /* free port logic ends */

                    printf("Port gen is:%u\n", udpport);
                    sprintf(portstring, "%u", udpport);

                    uint16_t *encoded_resp = encode_msg(2, portstring);
                    ssize_t bytes_sent = send(con_fd, encoded_resp, input_size, 0);
                    printf("Bytes resent are: %zu\n", bytes_sent);

                    uint16_t freeport = udp_handler(udpport);

                    /* free port logic starts */
                    for(i = 0; i < MAXCLIENTS; i++){
                        if(all_ports[i] == freeport){
                            if(all_free[i] == 1){
                                all_free[i] = 0;
                            }else{
                                perror("udp port was already free.");
                                exit(-1);
                            }
                        }
                    }
                    /*free port logic ends */

                    close_connection = 1;
                    break;
                }
            }

            if(data_len == ERROR){
                perror("read error");
                exit(-1);
            }
            if(data_len == 0){
                printf("No data read.\n");
                printf("Cient closed connection probably.\n");
                close(con_fd);
            }
            if(close_connection == 1){
                exit(EXIT_SUCCESS);
            }
        }
    }
}

uint16_t udp_handler(uint16_t port){
    int sock_fd, setlisten_fd, true_int;

    uint16_t data[MAX_LEN+2];

    struct sockaddr_in servaddr;
    struct sockaddr_in cliaddr;
    size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);
    socklen_t sockaddr_len = sizeof(struct sockaddr);

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sock_fd == ERROR){
        perror("socket");
        exit(0);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= INADDR_ANY;
    servaddr.sin_port =  htons(port);
    bzero(&servaddr.sin_zero, 8);

    if(bind(sock_fd, (struct sockaddr *)&servaddr, sockaddr_len) == ERROR){
        perror("udp bind");
        exit(0);
    }

    int while_count = 0;

    while(while_count < 10){
        while_count++;

        printf("Waiting\n");
        ssize_t encoded_udp_req = recvfrom(sock_fd, data, input_size, 0,
                                           (struct sockaddr *)&cliaddr, &sockaddr_len);
        if(encoded_udp_req == ERROR){
            perror("recvfrom");
            exit(0);
        }

        uint16_t i = 0;

        printf("Input Size calculated:%zu\n", input_size);
        printf("Number of bytes read:%zu\n", encoded_udp_req);
        printf("Encoded message is:");
        for(i = 0; i < MAX_LEN+2; i++){
            printf("%u", data[i]);
        }
        printf("\n");

        char *decoded_req = decode_msg(data);
        printf("Decoded message is:%s\n", decoded_req);

        //TODO: Change message type here
//        uint16_t *reenc = encode_msg(4, decoded_req);

        ssize_t udp_resp = sendto(sock_fd, data, input_size, 0, (struct sockaddr *)&cliaddr,
                                  sockaddr_len);
        if(udp_resp > 0){
            printf("Bytes resent are: %zu\n", udp_resp);
        }else if(udp_resp < 0){
            perror("sendto");
            close(sock_fd);
            exit(0);
        }else {
            printf("connection closed by client.");
            close(sock_fd);
        }

        int closeudp = strcmp(decoded_req, "quitudp");
        if(closeudp == 0){
            printf("Phase2 transmission closed\n");
            close(sock_fd);
            break;
        }
    }
    printf("UDP returned\n");
    return port;
}

uint16_t main(uint16_t argc, char **argv){

    if (argc != 2) {
      perror("Format: Server < Port of the server.");
      exit(1);
    }

    connection_handler((uint16_t)atoi(argv[1]));
//    udp_handler((uint16_t)atoi(argv[1]));

    return 0;
}

int main2(int argc, char **argv){

    char input[MAX_LEN];

    /*
    fgets(input, MAX_LEN, stdin);

    input[strcspn(input, "\n")] = 0;

    printf("String entered is:%s\n",input);

    uint16_t *enc = encode_msg(1, input);
    char *in_clone = decode_msg(enc);

    uint16_t *reenc = encode_msg(4, input);
    char *re_clone = decode_msg(reenc);

    printf("Comparison is:%d\n", strcmp(in_clone, "getport"));

    printf("%s\n", in_clone);
    printf("%s\n", re_clone);

    */

    uint16_t *all_ports2 = mmap(NULL, 10 * sizeof(uint16_t), PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    all_ports2[0] = 3002;
    all_ports2[1] = 3003;
    all_ports2[2] = 3004;
    all_ports2[3] = 3005;
    all_ports2[4] = 3006;
    all_ports2[5] = 3007;
    all_ports2[6] = 3008;
    all_ports2[7] = 3009;
    all_ports2[8] = 3010;
    all_ports2[9] = 3011;


    uint16_t *all_free = mmap(NULL, 10*sizeof(uint16_t), PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    all_free[0] = 0;
    all_free[0] = 1;
    all_free[0] = 2;
    all_free[0] = 3;
    all_free[0] = 4;
    all_free[0] = 5;
    all_free[0] = 6;
    all_free[0] = 7;
    all_free[0] = 8;
    all_free[0] = 9;


    if(fork() == 0){

        int i = 0;
        for(i = 0; i < 10; i++){
            if(all_ports2[i] == 3002){
                all_free[i] = 1;
            }
        }
        printf("Present port situation:");
        for(i = 0; i < 10; i++){
            printf("%u,", all_free[i]);
        }
        printf("\n");
        exit(EXIT_SUCCESS);
    }else{
        wait(NULL);
        int i = 0;
        printf("Present port situation:");
        for(i = 0; i < 10; i++){
            printf("%u,", all_free[i]);
        }
        printf("\n");

    }
    /*
    uint16_t change[MAX_LEN+2];
    strcpy(change, change_msg_type(1, encode_msg(1, input)));
    uint16_t *change2 = change_msg_type((uint16_t *) 4, (uint16_t) encode_msg(1, input));

    int i = 0;
    for(i = 0; i < MAX_LEN+2;i++){
        change[i] = change2[i];
    }

    printf("Changed is:");
    for(i = 0; i < MAX_LEN+2;i++){
        printf("%u", change2[i]);
    }
    printf("\n");
    */
    /*
    int i = 0;

    uint16_t p1 = get_port(5);
    uint16_t p2 = get_port(5);
    uint16_t p3 = get_port(5);

    printf("Port1: %u\n", p1);
    printf("Present port situation:");
    for(i = 0; i < 10; i++){
        printf("%u,", ports_occupied[i]);
    }
    printf("\n");
    sprintf(input, "%u", p1);

    printf("Port1 string:%s\n", input);

    printf("Port2: %u\n", p2);
    printf("Present port situation:");
    for(i = 0; i < 10; i++){
        printf("%u,", ports_occupied[i]);
    }
    printf("\n");

    printf("Port3: %u\n", p3);
    printf("Present port situation:");
    for(i = 0; i < 10; i++){
        printf("%u,", ports_occupied[i]);
    }
    printf("\n");

    free_port(p1);
    printf("Present port situation:");
    for(i = 0; i < 10; i++){
        printf("%u,", ports_occupied[i]);
    }
    printf("\n");

    uint16_t p4 = get_port(6);
    printf("Port1: %u\n", p4);

    printf("Present port situation:");
    for(i = 0; i < 10; i++){
        printf("%u,", ports_occupied[i]);
    }
    printf("\n");
     */

    return 0;
}

