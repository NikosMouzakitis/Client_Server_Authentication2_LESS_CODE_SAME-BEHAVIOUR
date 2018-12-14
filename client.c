#include<stdio.h> 
#include<stdlib.h> 
#include<string.h>    
#include<sys/socket.h> 
#include <errno.h>
#include<arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include "color.h"	// color red for fail, green for authenticated message.

#define		ADDRESS		"127.0.0.1"

char pass[10];

int main(int argc, char *argv[])
{

	struct timeval tv1, tv2;
	int malicious = 0;
	struct timeval tv = { 10, 0};

	if(argc != 2) {

		printf("Usage error: ./client.out [password]!\n");

		return (-1);
	}

	strcpy(pass, argv[1]);

	if(strcmp("666",pass) == 0)
		malicious++;

	int sock;
	struct sockaddr_in server;
	char message[1000], server_reply[2000];

	//Create socket
	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock == -1)
	{
		printf(" %sCould not create socket%s", KRED, KWHT);
		exit(-1);
	}
	puts("Socket created");

	server.sin_addr.s_addr = inet_addr(ADDRESS);
	server.sin_family = AF_INET;
	server.sin_port = htons(7777);

	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		perror("connect failed. Error");
		return 1;
	}
	puts("\tConnected\n");
	
	strcpy(message, pass);
	
	// malicious node just keeps the connection
	if(malicious) {
		printf("I will loop forever!\n");
		sleep(6000);	
	}	
	
	if( send(sock, message, strlen(message), 0) < 0) {
		puts("Send failed");
		shutdown(sock, SHUT_RDWR);	
		close(sock);
		return 1;
	}

	gettimeofday(&tv1, NULL);

	printf("Sended message\n");
	
	//Receive a reply from the server

	int nbytes = 0;

	// Forcing receive to fail after 2 seconds without getting a reply
//	setsockopt( sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval)); 

	nbytes = recv(sock, server_reply, 1024, 0);

	if(nbytes < 0) {
		
		printf("%sReceive failed: %d \n %s",KRED, errno, KWHT);	
	
		/*	connectioon reset by peer */

		if(errno == 104) {	
			return (0);
		}	

		while(recv(sock, server_reply, 1024, 0) != 0)
			;	

		shutdown(sock, SHUT_RDWR);	
		close(sock);
		
		printf("%sRecv failed: pid:%d\n", KRED, getpid());	
		printf("Invalid credential provided most possible\n");
		printf("%s\n",KWHT);
		exit(-1);

	}
	
	if(nbytes){
		shutdown(sock, SHUT_RDWR);	
		close(sock);
		gettimeofday(&tv2, NULL);
		
		double time = (double) (tv2.tv_usec - tv1.tv_usec) + (double) (tv2.tv_sec - tv1.tv_sec)*1000000;
		printf("microseconds: %f\n",time);
	
		if(strcmp("invalid", server_reply) == 0) {
			printf("%s Failed to get key%s\n",KRED, KWHT);
			close(sock);
			return (0);	
		}	
		printf("%sAuthenticated.\n",KGRN);
		printf("pid: %d received key: %s\n",getpid(), server_reply);
		printf("%s Auth complete.\n",KWHT);

	} else if(nbytes == 0) {
		shutdown(sock, SHUT_RDWR);	
		close(sock);
		printf("%sFailed to access key..\n",KRED);
		printf("%sInvalid password\n",KWHT);
	}
//	close(sock);
	printf("\t\t\t\t\tclose socket__CLIENT\n");
	
	return 0;
}
