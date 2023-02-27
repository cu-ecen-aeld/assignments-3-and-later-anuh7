#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>


#define SIZE 5


char *total_buffer=NULL;

int server_socket_fd;
int client_socket_fd;
int socket_file_fd;


void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
	{
		syslog(LOG_DEBUG, "Caught signal, exiting");
		
	}
	
	close(server_socket_fd);
	close(client_socket_fd); 
	close(socket_file_fd);
	unlink("/var/tmp/aesdsocketdata");
	closelog();
	exit(0);
}


int daemon_creation()
{
	pid_t pid;
	pid = fork();
	
	if (pid == -1)
	{
		syslog(LOG_ERR, "fork failed in daemon process");
		exit(-1);
	}
	
	if (pid > 0)
	{
		exit(0);
	}
	
	if (setsid() == -1)
		return -1;
	
	if (chdir("/") == -1)
		return -1;
	
	open ("/dev/null", O_RDWR); 
	dup (0);
	dup (0); 
	
	return 0;
}



int main(int argc, char *argv[])
{
	openlog(NULL, 0, LOG_USER);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	

	int daemon_flag = 0;
	struct addrinfo hints, *server_info;
	int yes = 1;  
	struct sockaddr_in their_addr;	  	
	socklen_t their_size;
	char buffer[SIZE];
	int received_length;	//received_length
	int received = 0;
	int data_count = 0;	//data_count
	
	if (argc == 2)
	{
		if (strcmp(argv[1], "-d") == 0)
		{
			daemon_flag = 1;
		}
		else 
		{
			syslog(LOG_ERR, "invalid argument");
			return -1;
		}
	}
	
	socket_file_fd = open("/var/tmp/aesdsocketdata", O_RDWR | O_CREAT | O_APPEND, 0666);
	//error
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;     // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
	hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
	
	int status = getaddrinfo(NULL, "9000", &hints, &server_info);
	if (status != 0)
	{
		syslog(LOG_ERR, "Error: getaddrinfo() with code, %d", errno);
	}
	
	server_socket_fd = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);
	if (server_socket_fd == -1)
	{
		syslog(LOG_ERR, "Error: socket() with code, %d", errno);
	}
	
	status = setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if (status != 0)
	{
		syslog(LOG_ERR, "Error: setsocketopt() with code, %d", errno);
	}
	
	
	status = bind(server_socket_fd, server_info->ai_addr, server_info->ai_addrlen);
	if (status != 0)
	{
		syslog(LOG_ERR, "Error: bind() with code, %d", errno);
	}
	
	
	if (daemon_flag == 1)
	{
		if (daemon_creation() != 0)
		{
			syslog(LOG_ERR, "Daemon creation failed");
		}
	}
		
	status = listen(server_socket_fd, 10);
	if (status != 0)
	{
		syslog(LOG_ERR, "Error: listen() with code, %d", errno);
	}
	
	freeaddrinfo(server_info); 
	
	their_size = sizeof(their_addr);

	while(1)
	{
		client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&their_addr, &their_size);
		if (client_socket_fd == -1)
		{
			syslog(LOG_ERR, "Error: accept() with code, %d", errno);
		}
		
      		char address_ip[20]; 
       	const char* ip;
       	ip = inet_ntop(AF_INET, &their_addr.sin_addr, address_ip, sizeof(address_ip));
       	syslog(LOG_DEBUG, "Accepted connection from : %s \n" , ip);

  		memset(buffer, '\0', SIZE);
  		int num = 0;
  		int total_buffer_length = 0;	
  		int old_length = SIZE;  
  		received = 0;
  		
  		while(!received)
  		{
  			received_length = 0;
  			recv(client_socket_fd, &buffer, SIZE, 0);
  			//ERROR
  		 			
  			for (int i=0; i<SIZE; i++)
  			{
  				received_length++;
  				if (buffer[i] == '\n')
  				{
  					received = 1;
  					break;
  				}
  			}
  			
  			if (num == 0)
  			{
  				total_buffer = (char *)malloc(received_length);
  				if (total_buffer == NULL)
  				{
  					syslog(LOG_ERR, "malloc");
  				}
  				memset(total_buffer, '\0', received_length);
  				total_buffer_length = received_length;  				
  			}
  			else
  			{
  				char *ptr = realloc(total_buffer, old_length+received_length);
  				if (ptr == NULL)
  				{
  					syslog(LOG_ERR, "realloc");
  				}
  				else 
  				{
  					total_buffer = ptr;
  					old_length += received_length;
  				}
  				total_buffer_length = old_length;
  			}	
  			memcpy(total_buffer + (num * SIZE), buffer, received_length);
  			num++;
  		}
  		
  		lseek(socket_file_fd, 0, SEEK_END);
  			
  		int write_return = write(socket_file_fd, total_buffer, total_buffer_length);
  		if (write_return == -1)
  		{
  			syslog(LOG_ERR, "Error: write() with code, %d", errno);
  		
  		}
  		
  		else if (write_return != total_buffer_length)
  		{
  			syslog(LOG_ERR, "Error: partial write with code, %d", errno);
  		}
  		
  		data_count += write_return;
  			
  		memset(buffer, '\0', SIZE);
  		lseek(socket_file_fd, 0, SEEK_SET);
  		  			
  		char *buffer_read = (char *)malloc(data_count);
  		
  		if (buffer_read == NULL)
  		{
            		syslog(LOG_ERR, "malloc");
        	}
  			
  		int read_return = read(socket_file_fd, buffer_read, data_count);
  		
  		if (read_return == -1)
  		{
            		syslog(LOG_ERR, "Error: read() with code, %d", errno);
  		}
  			
  		int send_return = send(client_socket_fd, buffer_read, data_count, 0);
  		
  		
      		if (send_return == -1)
      		{
            		syslog(LOG_ERR, "Error: write() with code, %d", errno);
        	}

  		
  		free(buffer_read);
  		free(total_buffer);	
  		syslog(LOG_DEBUG, "Closed connection from %s \n", ip);
	}
	
	return 0;
}

