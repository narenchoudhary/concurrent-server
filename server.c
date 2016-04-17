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

uint16_t * encode_msgS(uint16_t type, char *input);
char *decode_msgS(uint16_t *encoded_msg);
uint16_t get_port(int active_clients);
void free_port(uint16_t port);
uint16_t  *change_msg_type(uint16_t *msg, uint16_t new_type);
void tcp_handlerS(uint16_t port);
uint16_t udp_handlerS(uint16_t port);
void small_tcp_handlerS(uint16_t port);
uint16_t small_udp_handlerS(uint16_t port);


/****************************
 * Takes messgae type and character string.
 * Calculates message length.
 * Convert type-length-string into an encoded uint16_t array
 * Returns encoded array
 ***************************/
uint16_t * encode_msgS(uint16_t type, char *input){
    size_t in_len;

    uint16_t *msg_full = (uint16_t *) malloc(sizeof(uint16_t) * (MAX_LEN + 2));

    msg_full[0] = htons(type);

    uint16_t i = 0;

    /*
    printf("Characters:");
    for(i = 0; i < strlen(input); i++){
        printf("%c,", input[i]);
    }
    printf("\n");
    */

    in_len = strlen(input);
    while(in_len > 0 && (input[in_len-1] == '\n' || input[in_len-1] == '\r'))
        input[--in_len] == 0;
    msg_full[1] = htons((uint16_t) in_len);


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
    printf("Encoded message length is: %u\n", (uint16_t) in_len);

    /*
    printf("Encoded message is:");
    for(i = 0; i < MAX_LEN +2 ; i++) {
        printf("%u", msg_full[i]);
    }
    printf("\n");
    */

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
    printf("Decoded message type is:%u\n", ntohs(encoded_msg[0]));
    printf("Decoded message length is:%u\n", ntohs(encoded_msg[1]));
    //printf("Decoded message is: %s\n", ret_str);
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
    /* shared memory things */

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

    /* here ends all shared memeory code */

    int listen_fd, con_fd, setlisten_fd, true_int;

    pid_t childpid;
    socklen_t clilen;

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

    printf("%s\n","Server started!");

    while(*active_clients < MAXCLIENTS){

        con_fd = accept(listen_fd, (struct sockaddr *) &cliaddr, &sockaddr_len);


        if(con_fd == ERROR){
            printf("Error while accepting the connection\n");
            close(con_fd);
            continue;
        }

        printf("%s\n","Received request...");

        /* create child process to handle new client requests */
        if ( (childpid = fork ()) == 0 ) {
            printf ("Child process created for new client requests\n");
            /* close listening socket copy in child process */
            /* Do not shutdown listen_fd */
            /* This closes listen_fd in child process and */
            /* listen_fd is still open in parent process */
            close (listen_fd);

            ssize_t data_len = 1;
            int close_connection = 0;

            *active_clients += 1;
            printf("Total client count: %d\n", *active_clients);

            while(data_len){

                int i;

                size_t input_size = (MAX_LEN+2)*sizeof(uint16_t);

                data_len = recv(con_fd, data, input_size, 0);

                //printf("Input Size calculated:%zu\n", input_size);
                //printf("Number of bytes read:%zu\n", data_len);
                /*
                printf("Encoded message is:");
                for(i = 0; i < data_len/ sizeof(uint16_t); i++){
                    printf("%u", data[i]);
                }
                printf("\n");
                */
                char *decoded_req = decode_msgS(data);
                printf("Message received from client is:%s\n", decoded_req);

                /* check if client requested port for UDP connection */
                int startudp = strcmp(decoded_req, "getport");


                if(startudp != 0){
                    /*
                     * Message type #2: TCP Response.
                     * Change the message type to 2
                     * and echo back the string */
                    uint16_t *poststring;
                    poststring = encode_msgS(2, decoded_req);
                    //poststring = change_msg_type(data, 2);
                    ssize_t bytes_sent = send(con_fd, poststring, input_size, 0);
                    //send(con_fd, data, input_size, 0);
                    //printf("Bytes resent are: %zu\n", bytes_sent);
                    printf("Message sent to client is:%s\n",decoded_req);
                } else{
                    /* if udp-port is requested
                     * get an unsed port
                     * send port to client
                     * handover control to udp_handlerS() */
                    printf("UDP port requested by client!\n");

                    /* get port logic */
                    int16_t port_yes = -1;
                    uint16_t udpport;
                    for(i = 0; i < MAXCLIENTS; i++){
                        if(all_free[i] == 0){
                            all_free[i] = 1;
                            udpport = all_ports[i];
                            port_yes = 1;
                            break;
                        }
                    }
                    /* extra check */
                    /* most probably it won't be exectuted ever */
                    if(port_yes == ERROR){
                        perror("no free udp port");
                        exit(EXIT_FAILURE);
                    }
                    /* get port logic ends */

                    char portstring[MAX_LEN];
                    printf("Port assigned to this client is:%u\n", udpport);
                    sprintf(portstring, "%u", udpport);

                    uint16_t *encoded_resp = encode_msgS(2, portstring);
                    ssize_t bytes_sent = send(con_fd, encoded_resp, input_size, 0);
                    if(bytes_sent < 0){
                        perror("Bytes sent error:");
                        close(con_fd);
                        exit(EXIT_FAILURE);
                    }
                    //printf("Bytes resent are: %zu\n", bytes_sent);

                    //Close the TCP connection
                    close(con_fd);

                    printf("Phase2 starts now:\n");
                    uint16_t freeport = udp_handlerS(udpport);
                    printf("Port returned is:%u\n", freeport);

                    int if_freed = 0;

                    /* free port logic starts */
                    for(i = 0; i < MAXCLIENTS; i++){
                        if(all_ports[i] == freeport){
                            if(all_free[i] == 1){
                                all_free[i] = 0;
                                if_freed = 1;
                            }else{
                                printf("udp port was already free.");
                                printf("Something is wrong!");
                            }
                        }
                    }
                    if(if_freed == 1){
                        printf("Connection closed with client with port:%u\n", freeport);
                        printf("Port %u is FREE now.\n", freeport);

                        *active_clients -= 1;

                    }else{
                        printf("No port freed. Error ignored silently.\n");
                    }

                    /*free port logic ends */
                    close_connection = 1;
                    break;
                }
            }

            if(data_len == ERROR){
                perror("read error");
                exit(EXIT_FAILURE);
            }
            if(data_len == 0){
                printf("No data read.\n");
                printf("Cient closed connection probably.\n");
                close(con_fd);
            }

            if(close_connection == 1){
                printf("Closing connection.\n");
                close(con_fd);
            }

            /* exit child process */
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
uint16_t udp_handlerS(uint16_t port){
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

    while(1){

        printf("Server waiting:\n");
        ssize_t encoded_udp_req = recvfrom(sock_fd, data, input_size, 0,
                                           (struct sockaddr *)&cliaddr, &sockaddr_len);
        if(encoded_udp_req == ERROR){
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        uint16_t i = 0;

        //printf("Input Size calculated:%zu\n", input_size);
        //printf("Number of bytes read:%zu\n", encoded_udp_req);
        /*
        printf("Encoded message received by server is:");
        for(i = 0; i < MAX_LEN+2; i++){
            printf("%u", data[i]);
        }
        printf("\n");
        */
        char *decoded_req = decode_msgS(data);
        printf("Message received from client is:%s\n", decoded_req);

        /* changing message type to 4*/
        uint16_t *poststing;
        ssize_t udp_resp;
        if(strcmp(decoded_req, "quitudp") == 0){
            poststing = encode_msgS(4, "bye");
            udp_resp = sendto(sock_fd, poststing, input_size, 0, (struct sockaddr *)&cliaddr,
                                      sockaddr_len);
        }else{
            poststing = encode_msgS(4, decoded_req);
            udp_resp = sendto(sock_fd, poststing, input_size, 0, (struct sockaddr *)&cliaddr,
                                      sockaddr_len);
        }

        printf("Message sent to client is:%s\n", decoded_req);
        if(udp_resp > 0){
            //printf("Bytes resent are: %zu\n", udp_resp);
        }else if(udp_resp < 0){
            perror("sendto");
            close(sock_fd);
            exit(0);
        }else {
            printf("connection closed by client.");
            close(sock_fd);
        }

        /* if message 3 is "quitudp"
         * close the socket */
        int closeudp = strcmp(decoded_req, "quitudp");
        printf("Client requested to close the connection!!\n");
        if(closeudp == 0){
            printf("Phase2 transmission closed.\n");
            close(sock_fd);
            break;
        }
    }
    return port;
}


void small_tcp_handlerS(uint16_t port){
    /* shared memory things */

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

    /* here ends all shared memeory code */

    int listen_fd, con_fd;

    pid_t childpid;
    socklen_t clilen;

    char input[MAX_LEN];
    uint16_t data[MAX_LEN+2];

    socklen_t sockaddr_len = sizeof(struct sockaddr);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(listen_fd == ERROR){
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* to avoid connection from getting stuck in TIME_WAIT state */
    int true_int = 1;
    int setlisten_fd = setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,&true_int,sizeof(int));
    if(setlisten_fd == ERROR){
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in servaddr;
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

    printf("%s\n","Server started!");

    while(1){

        do{
            /* WAIT FOR some client to end transmission */
        }while(*active_clients >= MAXCLIENTS);

        struct sockaddr_in cliaddr;
        con_fd = accept(listen_fd, (struct sockaddr *) &cliaddr, &sockaddr_len);

        if(con_fd == ERROR){
            printf("Error while accepting the connection\n");
            close(con_fd);
            continue;
        }

        printf("\n\n");
        printf("%s\n","Received client request...");

        /* create child process to handle new client requests */
        if ( (childpid = fork ()) == 0 ) {
            printf ("Child process created for new client requests\n");

            /* close listening socket copy in child process */
            /* Do not shutdown listen_fd */
            /* This closes listen_fd in child process and */
            /* listen_fd is still open in parent process */
            close (listen_fd);

            ssize_t data_len = 1;
            int close_connection = 0;

            *active_clients += 1;
            printf("Total client count: %d\n", *active_clients);

            int i;
            size_t input_size = (MAX_LEN+2)*sizeof(uint16_t);

            data_len = recv(con_fd, data, input_size, 0);

            if(data_len == ERROR){
                perror("read error");
                exit(EXIT_FAILURE);
            }
            if(data_len == 0){
                printf("No data read.\n");
                printf("Cient closed connection probably.\n");
                printf("Sever closed connection.\n");
                close(con_fd);
                exit(EXIT_SUCCESS);
            }

            printf("Client request (Message1) received.\n");
            printf("Decoding client request\n");
            char *decoded_req = decode_msgS(data);
            printf("Message received from client is:%s\n", decoded_req);
            printf("UDP port requested by client!\n");

            /* if udp-port is requested
             * get an unsed port
             * send port to client
             * handover control to udp_handlerS() */

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
            printf("Port assigned to this client is:%u\n", udpport);
            sprintf(portstring, "%u", udpport);

            uint16_t *encoded_resp = encode_msgS(2, portstring);
            ssize_t bytes_sent = send(con_fd, encoded_resp, input_size, 0);

            if(bytes_sent < 0){
                perror("Bytes sent error:");
                close(con_fd);
                exit(EXIT_FAILURE);
            }

            printf("Server response (Message 2) sent to client.\n");

            close(con_fd);
            printf("TCP connection closed.\n\n");
            printf("Phase2 starts now:\n");
            uint16_t freeport = small_udp_handlerS(udpport);
            printf("Port returned is:%u\n", freeport);

            int if_freed = 0;

            /* free port logic starts */
            for(i = 0; i < MAXCLIENTS; i++){
                if(all_ports[i] == freeport){
                    if(all_free[i] == 1){
                        all_free[i] = 0;
                        if_freed = 1;
                    }else{
                        printf("udp port was already free.");
                        printf("Something is wrong!");
                    }
                }
            }
            if(if_freed == 1){
                printf("Connection closed with client with port:%u\n", freeport);
                printf("Port %u is FREE now.\n", freeport);

                *active_clients -= 1;

            }else{
                printf("No port freed. Error ignored silently.\n");
            }

            /* exit child process */
            exit(EXIT_SUCCESS);
        }
    } /* child processes if */
}


uint16_t small_udp_handlerS(uint16_t port){

    uint16_t data[MAX_LEN+2];

    struct sockaddr_in servaddr;
    struct sockaddr_in cliaddr;
    size_t input_size = sizeof(uint16_t)*(MAX_LEN+2);
    socklen_t sockaddr_len = sizeof(struct sockaddr);

    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

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

    ssize_t encoded_udp_req = recvfrom(sock_fd, data, input_size, 0,
                                       (struct sockaddr *)&cliaddr, &sockaddr_len);
    if(encoded_udp_req == ERROR){
        perror("recvfrom");
        exit(EXIT_FAILURE);
    }

    char *decoded_req = decode_msgS(data);
    printf("Message received from client is:%s\n", decoded_req);

    uint16_t *poststing;

    poststing = encode_msgS(4, "quitudp");
    ssize_t udp_resp = sendto(sock_fd, poststing, input_size, 0, (struct sockaddr *)&cliaddr,
                              sockaddr_len);

    printf("Message sent to client is:%s\n", decoded_req);
    if(udp_resp < 0){
        perror("sendto");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }else if(udp_resp == 0){
        printf("Server unable to send data to this client.\n");
        printf("Server can't continue. Server killing the process.\n");
        close(sock_fd);
    }else{
        printf("UDP Transmission complete.\n");
        close(sock_fd);
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

/* test function */
int main2(int argc, char **argv){

    char input[MAX_LEN];

    /*
    fgets(input, MAX_LEN, stdin);

    input[strcspn(input, "\n")] = 0;

    printf("String entered is:%s\n",input);

    uint16_t *enc = encode_msgS(1, input);
    char *in_clone = decode_msgS(enc);

    uint16_t *reenc = encode_msgS(4, input);
    char *re_clone = decode_msgS(reenc);

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
    strcpy(change, change_msg_type(1, encode_msgS(1, input)));
    uint16_t *change2 = change_msg_type((uint16_t *) 4, (uint16_t) encode_msgS(1, input));

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

