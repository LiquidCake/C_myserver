#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "myserver.h"
#include "mylib.h"
#include "response_handler.h"


extern int errno;

long page_size = -1;


int main(int argc, char *args[]) {
	//log level LOG_NOTICE is "prod"
	setlogmask(LOG_UPTO(LOG_INFO));
	openlog("myserver", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	
	/* NULL is wildcard */
	const char *hostname = NULL;
	const char *port = DEFAULT_PORT;

	if (argc == 1) {
		printf("Trying to start listen on default port %s\n", port);
	} else if (argc == 2) {
		port = args[1];
		printf("Trying to startlisten on port %s\n", port);
	} else if (argc == 3) {
		hostname = args[1];
		port = args[2];
		printf("Trying to start listen on hostname %s, port %s\n", hostname, port);
	} else {
		printf("args: [port] or [hostname port]\n");
		exit(0);
	}
	
	fflush(stdout);
	
	page_size = sysconf(_SC_PAGESIZE);
	
	syslog(LOG_NOTICE, "started on port %s by user %d. Pid: %d. Pagesize: %ld", port, getuid(), getppid(), page_size);


	//get address from OS. Will be linked list of addresses, we just use 1st
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE|AI_ADDRCONFIG;

	struct addrinfo *address = NULL;
	int net_addr_reslt = getaddrinfo(hostname, port, &hints, &address);
	
	if (net_addr_reslt != 0) {
		syslog(LOG_CRIT, "Failed getting net address, code %d. Message: %s", net_addr_reslt, strerror(errno));
		exit(-1);
	}

	//create server socket
	int server_socket_dscr = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
	if (server_socket_dscr == -1) {
		syslog(LOG_CRIT, "Error opening socket. Message: %s", strerror(errno));
		exit(-1);
	}
	
	//set socket options
	if (!set_sock_options(server_socket_dscr)) {
		exit(-1);
	}

	//bind socket to address
	if (bind(server_socket_dscr, address->ai_addr, address->ai_addrlen) == -1) {
		syslog(LOG_CRIT, "Error binding socket. Message: %s", strerror(errno));
		exit(-1);
	}

	//now we can release memory used for addrinfo
	freeaddrinfo(address);

	//listen
	if (listen(server_socket_dscr, SOCKET_QUEUE_LIMIT)) {
		syslog(LOG_CRIT, "Error on calling listen(). Message: %s", strerror(errno));
		exit(-1);
	}
	
	//make sure we dont wait any response from child processes
	signal(SIGCHLD, SIG_IGN);

	for (;;) {
		char client_ip[64];
		struct sockaddr_in client_addr;
		socklen_t socklen = sizeof(client_addr);
		
		int session_dscr = accept(server_socket_dscr, (struct sockaddr*) &client_addr, &socklen);
		
		if (session_dscr != -1) {
			//not thread safe
			strcpy(client_ip, inet_ntoa(client_addr.sin_addr));
		} else {
			//EAGAIN returns periodically due to SO_RCVTIMEO
			if (errno != EAGAIN && errno != EINTR) {
				syslog(LOG_ERR, "Failed to accept connection!. Message: %s", strerror(errno));
			}
			continue;
		}
		
		pid_t child_pid = fork();

		if (child_pid == 0) {
			//happens in child process
			
			close(server_socket_dscr);

			request_loop(session_dscr, client_ip);
			
			close(session_dscr);
			_exit(0);

		} else if (child_pid == -1) {
			syslog(LOG_ERR, "Failed to create child process. Message: %s", strerror(errno));
		}
		
		close(session_dscr);
				
		syslog(LOG_INFO, "[Got request from %s, passed to pid %d]", client_ip, child_pid);
	}
}

bool set_sock_options (int server_socket_dscr) {
	//set reuse address
	int reuseaddr = 1;
	if (setsockopt(server_socket_dscr, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
		syslog(LOG_CRIT, "Error setting socket option SO_REUSEADDR. Message: %s", strerror(errno));
		
		return false;
	}
	
	//set read timeouts
	struct timeval timeout;      
    timeout.tv_sec = SOCK_READ_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    if (setsockopt(server_socket_dscr, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) < 0) {
        syslog(LOG_CRIT, "Error setting socket option SO_RCVTIMEO. Message: %s", strerror(errno));
		
		return false;
	}
	
    if (setsockopt(server_socket_dscr, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) < 0) {
        syslog(LOG_CRIT, "Error setting socket option SO_SNDTIMEO. Message: %s", strerror(errno));
		
		return false;
	}
        
	return true;
}
