#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>

#include "commonconst.h"

uint16_t * encode_msgS(uint16_t type, char *input);
char *decode_msgS(uint16_t *encoded_msg);
void tcp_handlerS(uint16_t port);
uint16_t udp_handlerS(uint16_t port, uint16_t client_no);


/****************************
 * Takes messgae type and character string.
 * Calculates message length.
 * Convert type-length-string into an encoded uint16_t array
 * Returns encoded array
 ***************************/
uint16_t * encode_msgS(uint16_t type, char *input){

    uint16_t *msg_full = (uint16_t *) malloc(sizeof(uint16_t) * (MAX_LEN + 2));

    size_t in_len;
    in_len = strlen(input);
    while(in_len > 0 && (input[in_len-1] == '\n' || input[in_len-1] == '\r'))
        input[--in_len] == 0;

    msg_full[0] = htons(type);
    msg_full[1] = htons((uint16_t) in_len);

    uint16_t i = 0;
    for(i = 0; i < strlen(input); i++){
        msg_full[i+2] = htons((uint16_t) input[i]);
    }

    //printf("Encoded message type is: %u\n", type);
    //printf("Encoded message length is: %u\n", (uint16_t) in_len);

    return msg_full;
}

/****************************
 * Takes encoded message.
 * Decodes the encoded message.
 * Prints message type and message length.
 * Returns decoded message string.
 ***************************/
char *decode_msgS(uint16_t *encoded_msg){
    char *ret_str = malloc(sizeof(char) * MAX_LEN);

    int i = 0;
    for(i = 2; i < MAX_LEN+2; i++){
        ret_str[i-2] = (char) ntohs(encoded_msg[i]);
    }
    //printf("Decoded message type is:%u\n", ntohs(encoded_msg[0]));
    //printf("Decoded message length is:%u\n", ntohs(encoded_msg[1]));

    return ret_str;
}

/****************************
 * Takes port number.
 * Starts server for accepting TCP connection.
 * Echo normal messages back to client.
 * Select free port client messages "getport".
 * Sends port for udp connection to client.
 * Closes TCP connection.
 * Hands over control to udp_handlerS()
 * Frees port when udp_handlerS() returns
 * Terminates connection with client
 * Waits for new connections
 ***************************/
void tcp_handlerS(uint16_t port){
    /* shared memory logic */

    uint16_t *all_ports = mmap(NULL, 10 * sizeof(uint16_t), PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    all_ports[0] = 23002;
    all_ports[1] = 23003;
    all_ports[2] = 23004;
    all_ports[3] = 23005;
    all_ports[4] = 23006;
    all_ports[5] = 23007;
    all_ports[6] = 23008;
    all_ports[7] = 23009;
    all_ports[8] = 23010;
    all_ports[9] = 23011;


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

    uint16_t *active_clients = mmap(NULL, sizeof(uint16_t), PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    *active_clients = 0;

    /* all shared memeory code ends here*/

    int listen_fd, con_fd, setlisten_fd, true_int;

    char input[MAX_LEN];
    uint16_t data[MAX_LEN+2];

    struct sockaddr_in servaddr;
    struct sockaddr_in cliaddr;
    socklen_t sockaddr_len = sizeof(struct sockaddr);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(listen_fd == ERROR){
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* to avoid connection from getting stuck in TIME_WAIT state */
    true_int = 1;
    setlisten_fd = setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,&true_int,sizeof(int));
    if(setlisten_fd == ERROR){
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);

    if(bind (listen_fd, (struct sockaddr *) &servaddr, sockaddr_len) == ERROR){
        perror("tcp bind");
        exit(EXIT_FAILURE);
    }
    if(listen (listen_fd, LISTENQ) == ERROR){
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("----------------------------------------------------------------------------------\n");
    printf("Client No\tPort\tOperation\tProtocol\tMore Information\n");
    printf("----------------------------------------------------------------------------------\n");

    while(*active_clients < MAXCLIENTS){

        con_fd = accept(listen_fd, (struct sockaddr *) &cliaddr, &sockaddr_len);
        if(con_fd == ERROR){
            printf("---\t\t%u\tconnect error\ttcp\t\tTotal clients: %u\n", port, *active_clients);
            close(con_fd);
            continue;
        }

        /* create child process to handle new client requests */
        if (fork () == 0) {
            /* close listening socket copy in child process */
            /* This closes listen_fd in child process and */
            /* listen_fd is still open in parent process */
            close (listen_fd);

            ssize_t data_len = 1;
            int close_connection = 0;

            *active_clients += 1;
            uint16_t client_no = *active_clients;

            printf("%u\t\t%u\tconnect\t\ttcp\t\tTotal clients: %u\n", client_no, port, *active_clients);

            while(data_len){

                int i;
                size_t input_size = (MAX_LEN+2)*sizeof(uint16_t);

                data_len = recv(con_fd, data, input_size, 0);

                char *decoded_req = decode_msgS(data);

                /* check if client requested port for UDP connection */
                int startudp = strcmp(decoded_req, "getport");


                if(startudp != 0){
                    uint16_t *poststring;
                    poststring = encode_msgS(2, decoded_req);
                    ssize_t bytes_sent = send(con_fd, poststring, input_size, 0);
                    printf("%u\t\t%u\tmessage type1\ttcp\t\tmessage received: %s\n", client_no, port, decoded_req);
                    printf("%u\t\t%u\tmessage type2\ttcp\t\tmessage sent: %s\n", client_no, port, decoded_req);
                } else{
                    /* get port logic */
                    uint16_t udpport;
                    for(i = 0; i < MAXCLIENTS; i++){
                        if(all_free[i] == 0){
                            all_free[i] = 1;
                            udpport = all_ports[i];
                            break;
                        }
                    }
                    /* get port logic ends */

                    char portstring[MAX_LEN];
                    sprintf(portstring, "%u", udpport);
                    uint16_t *encoded_resp = encode_msgS(2, portstring);
                    ssize_t bytes_sent = send(con_fd, encoded_resp, input_size, 0);

                    if(bytes_sent < 0){
                        perror("Bytes sent error:");
                        close(con_fd);
                        exit(EXIT_FAILURE);
                    }

                    printf("%u\t\t%u\tmessage type1\ttcp\t\tmessage received: %s\n", client_no, port, decoded_req);
                    printf("%u\t\t%u\tmessage type2\ttcp\t\tmessage sent: %s\n", client_no, port, portstring);
                    printf("%u\t\t%u\ttcp close\ttcp\t\tconnection closed\n", client_no, port);
                    printf("%u\t\t---\tport assigned\ttcp\t\tport assigned: %u\n", client_no, udpport);
                    //Close the TCP connection
                    close(con_fd);

                    // printf("Phase2 starts now:\n");
                    uint16_t freeport = udp_handlerS(udpport, client_no);

                    /* free port logic starts */
                    for(i = 0; i < MAXCLIENTS; i++){
                        if(all_ports[i] == freeport){
                            if(all_free[i] == 1){
                                all_free[i] = 0;
                            }
                        }
                    }
                    printf("%u\t\t---\tfree port\tudp\t\tport freed: %u\n", client_no, freeport);
                    /*free port logic ends */
                    //printf("Connection closed with client with port:%u\n", freeport);
                    //printf("Port %u is FREE now.\n", freeport);

                    *active_clients -= 1;
                    break;
                }
            }

            if(data_len == ERROR){
                perror("read error");
                exit(EXIT_FAILURE);
            }
            if(data_len == 0){
                /*
                printf("No data read.\n");
                printf("Cient closed connection probably.\n");
                 */
                printf("%u\t\t%u\ttcp close\ttcp\t\tclient closed arbitarily\n", client_no, port);
                close(con_fd);
            }

            /* exit child process */
            printf("---\t\t---\texit child\ttcp\t\tactive clients:%u\n", *active_clients);
            exit(EXIT_SUCCESS);
        }

    }
    return;
}

/****************************
 * Takes port number
 * Creates UDP setup
 * Gets message from client
 * Echos back same message
 * Closes socket when client messages "quitudp"
 ****************************/
uint16_t udp_handlerS(uint16_t port, uint16_t client_no){
    int sock_fd;

    uint16_t data[MAX_LEN+2];

    struct sockaddr_in servaddr;
    struct sockaddr_in cliaddr;
    size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);
    socklen_t sockaddr_len = sizeof(struct sockaddr);

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sock_fd == ERROR){
        perror("socket");
        exit(EXIT_FAILURE);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= INADDR_ANY;
    servaddr.sin_port =  htons(port);
    bzero(&servaddr.sin_zero, 8);

    if(bind(sock_fd, (struct sockaddr *)&servaddr, sockaddr_len) == ERROR){
        perror("udp bind");
        exit(EXIT_FAILURE);
    }

    printf("%u\t\t%u\tudp stage\tudp\t\tstage stage start\n", client_no, port);

    while(1){

        ssize_t encoded_udp_req = recvfrom(sock_fd, data, input_size, 0,
                                           (struct sockaddr *)&cliaddr, &sockaddr_len);
        if(encoded_udp_req == ERROR){
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        uint16_t i = 0;

        char *decoded_req = decode_msgS(data);

        uint16_t *poststing;
        ssize_t udp_resp;
        if(strcmp(decoded_req, "quitudp") == 0){
            poststing = encode_msgS(4, "bye");
            udp_resp = sendto(sock_fd, poststing, input_size, 0, (struct sockaddr *)&cliaddr,
                                      sockaddr_len);
            printf("%u\t\t%u\tmessage type3\tudp\t\tmessage received: %s\n", client_no, port, decoded_req);
            printf("%u\t\t%u\tmessage type4\tudp\t\tmessage sent: %u\n", client_no, port, *poststing);
        }else{
            poststing = encode_msgS(4, decoded_req);
            udp_resp = sendto(sock_fd, poststing, input_size, 0, (struct sockaddr *)&cliaddr,
                                      sockaddr_len);
            printf("%u\t\t%u\tmessage type3\tudp\t\tmessage received: %s\n", client_no, port, decoded_req);
            printf("%u\t\t%u\tmessage type4\tudp\t\tmessage sent: %s\n", client_no, port, decoded_req);
        }

        if(udp_resp < 0){
            perror("sendto");
            close(sock_fd);
            exit(0);
        }else if(udp_resp == 0){
            printf("%u\t\t%u\tudp close\tudp\t\tclient closed arbitrarily\n", client_no, port);
            close(sock_fd);
        }else{
                /* if message 3 is "quitudp"
                 * close the socket */
                int closeudp = strcmp(decoded_req, "quitudp");
                if(closeudp == 0){
                    printf("%u\t\t%u\tudp close\tudp\t\tclose udp socketfd\n", client_no, port);
                    close(sock_fd);
                    break;
                }

        }
    }

    return port;
}

uint16_t main(uint16_t argc, char **argv){

    if (argc != 2) {
      perror("Format: Server < Port of the server.");
      exit(1);
    }

    tcp_handlerS((uint16_t)atoi(argv[1]));

    return 0;
}
