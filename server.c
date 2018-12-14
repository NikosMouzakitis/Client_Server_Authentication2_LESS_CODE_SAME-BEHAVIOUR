#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <libexplain/select.h>  // Details when select fails. Link with -lexplain
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h> // To get tid, through syscall.
#include "color.h"
#include <errno.h>

#define AUTH	0
#define MAX_CL 1000
#define MAXMSG	512
#define MAX_THREADS 1000

int test = 0;
int validReq, invalidReq, maliciousReq;
int bnt, nt;
int connections;
int topen, tclosed, times_over;
int max_open_files;
int active_con;

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

int make_socket(uint16_t port)
{
	int sock;
	struct sockaddr_in name;

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if(sock < 0) {
		printf("error creating socket\n");
		exit(EXIT_FAILURE);
	}

	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	name.sin_addr.s_addr = htonl(INADDR_ANY);

	int enable = 1;

	if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		printf("/error setsockopt\n");
		exit(-1);
	}

	if( bind(sock,  (struct sockaddr *) &name, sizeof(name) ) < 0) {
		printf("/bind() error\n");
		exit(EXIT_FAILURE);
	}

	return sock;
}

void clear_buffer(char *b)
{
	for (int i = 0; i < MAXMSG; i++)
		b[i] = '\0';
}

int read_from_client(int fd)
{
	char buffer[MAXMSG];
	int nbytes;
	clear_buffer(buffer);

	nbytes = read(fd, buffer, MAXMSG);

	pid_t vt = syscall(SYS_gettid);

	if(nbytes < 0) {

		printf("/error read() fd: %d %d\n", fd, vt);
		exit(EXIT_FAILURE);

	} else if(nbytes == 0) {
		return -1;
	} else {

		//	printf("Server, got: %s\n", buffer);

		if( strcmp("123", buffer) == 0) {

			clear_buffer(buffer);

			if( send(fd, "abb3cfe", strlen("abb3cfe"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}

			printf("Access granted.\n");
			validReq++;

			return AUTH;

		} else if ( strcmp("111", buffer) == 0) {

			clear_buffer(buffer);

			if( send(fd, "22833f4", strlen("22833f4"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}

			printf("Access granted.\n");
			validReq++;

			return AUTH;

		} else if (strcmp("check", buffer) == 0) {

			clear_buffer(buffer);

			if( send(fd, "ok", strlen("ok"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}

			//	printf("Server periodic proccess connection.\nSuccess\n");
			validReq++;

			return AUTH;

		} else {

			printf("Invalid password given\nConnection closing\n");
			fflush(stdout);
			invalidReq++;
			clear_buffer(buffer);

			if( send(fd, "invalid", strlen("invalid"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}

			return AUTH;
		}
	}
}

void close_con(int fd)
{
	if( close(fd) != 0) {
		printf("%s close error : %d\n %s", KRED, errno, KWHT);
		exit(-1);
	}
	active_con--;
}

void * serveReq(void * arg)
{
	int i = (int) (unsigned long) arg;
	struct pollfd pfd;
	int pret;
	int enable = 1;

	/* guarantees that thread resources are deallocated upon return */
	if( pthread_detach( pthread_self()) != 0) {
		printf("%s/error detatching thread.%s\n", KRED,KWHT);
		fflush(stdout);
		pthread_mutex_lock(&mtx);
		active_con--;
		close(i);
		pthread_mutex_unlock(&mtx);
		exit(EXIT_FAILURE);
	}

	if( setsockopt(i, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		printf("/error setsockopt accept's\n");
		fflush(stdout);

		pthread_mutex_lock(&mtx);
		active_con--;
		close(i);
		pthread_mutex_unlock(&mtx);

		exit(-1);
	}

	pfd.fd = i;
	pfd.events = POLLIN;
	pid_t tt = syscall(SYS_gettid);
	printf("\t\t %d Handling FD: %d\n",tt, i);
	fflush(stdout);

	/* To handle a just - connecting attack. */
	pret = poll(&pfd, 1, 2000);

	if(pret == 0) {

		printf("TIME_OUT in FD: %d  %d occured.\n", i, tt);

		pthread_mutex_lock(&mtx);
		tclosed++;
		maliciousReq++;
		close_con(i);
		pthread_mutex_unlock(&mtx);

		printf("reducing connections after a TIMEOUT\n");
		pthread_exit(NULL);

	} else 	if( read_from_client(i) <= 0) {

		printf(" \t\t\t\t  %d CLOSING: %d\n",tt, i);
		fflush(stdout);
		pthread_mutex_lock(&mtx);
		tclosed++;
		close_con(i);
		pthread_mutex_unlock(&mtx);

		printf("Reducing connections\n");
	}

	pthread_exit(NULL);

}

int main(int argc, char *argv[])
{
	
	int sock, sockf, i, new;
	struct sockaddr_in client_name;
	size_t size;
	int retv, retv2;
	
	active_con = 0;

	sock = make_socket(7777);

	printf("Server with PID: %d...\n", getpid());

	if( listen(sock, MAX_CL)!= 0 ) {
		printf("/error listen()\n");
		exit(EXIT_FAILURE);
	}
	printf("Awaiting connections\n");
	fflush(stdout);

	while(1) {
			
			pthread_mutex_lock(&mtx);

			if(active_con > MAX_CL-100) {
				pthread_mutex_unlock(&mtx);	
				sleep(2);
			
				continue;
			}

			pthread_mutex_unlock(&mtx);	
		
			new = accept(sock, (struct sockaddr *) &client_name,(socklen_t *) &size);
			
			printf("ACTIVE CONNECTIONS: %d\n", active_con);	

			if(new < 0) {
				continue;
			}

			pthread_mutex_lock(&mtx);
			pthread_create( &(pthread_t) {0}, NULL, (void *) serveReq, (void *) (unsigned long) new);
			active_con++;
			pthread_mutex_unlock(&mtx);

	}

	return (0);
}
