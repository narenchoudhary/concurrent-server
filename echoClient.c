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

#define MAXLINE 4096 /*max text line length*/

int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_in servaddr;
    char input[MAXLINE], output[MAXLINE];

    if (argc != 3) {
      perror("Format: TCPClient < IP address of the server < Port of the server.");
      exit(1);
    }

    if ((sockfd = socket (AF_INET, SOCK_STREAM, 0)) <0) {
      perror("Problem in creating the socket");
      exit(2);
    }


    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(argv[1]);
    servaddr.sin_port =  htons(atoi(argv[2])); //convert to big-endian order

    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr))<0) {
      perror("Problem in connecting to the server");
      exit(3);
    }

    while (1) {
      fgets(input, MAXLINE, stdin);

      send(sockfd, input, strlen(input), 0);

      int len = recv(sockfd, output, MAXLINE, 0);
      if(len < 0){
        perror("read");
        exit(-1);
      }
      if (len == 0){
         perror("The server terminated prematurely");
         exit(4);
      }
      output[len] = '\0';
      printf("String received from the server: %s\n", output);
    }

    exit(0);
}