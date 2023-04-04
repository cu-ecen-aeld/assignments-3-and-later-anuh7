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
#include <pthread.h>
#include <time.h>

#include "../aesd-char-driver/aesd_ioctl.h"


#define SIZE (3)

#define USE_AESD_CHAR_DEVICE

#ifdef USE_AESD_CHAR_DEVICE
char* file_path = "/dev/aesdchar";
#else
char* file_path = "/var/tmp/aesdsocketdata";
#endif
					
const char* ioctl_cmd = "AESDCHAR_IOCSEEKTO:";


int server_socket_fd;
int socket_file_fd;
int data_count;
pthread_mutex_t mtx;
int e_status = 0;

#ifndef USE_AESD_CHAR_DEVICE
bool timeout = false;
timer_t timer;
#endif

typedef struct 
{
    pthread_t tid;
    bool complete_flag;
    int fd;
    struct sockaddr_storage t_addr;
} tdata_t;


typedef struct node
{
    tdata_t data;
    struct node *next;
} node_t;


#ifndef USE_AESD_CHAR_DEVICE
void timestamp();
int timer_init();
#endif

int sll_insert( node_t **head, node_t *new_node)
{
    
    if( new_node == NULL )
    {
        return -1;
    }
    new_node->next = *head;
    *head =  new_node;
    return 0;
}


void signal_handler(int signum)
{
    if (signum == SIGINT) 
    {
        syslog(LOG_DEBUG, "Caught signal SIGINT, exiting!!");
        e_status = 1;
    }
    else if( signum == SIGTERM)
    {
        syslog(LOG_DEBUG, "Caught signal SIGTERM, exiting!!");
        e_status = 1;
    }
    
     #ifndef USE_AESD_CHAR_DEVICE
    else if(signum == SIGALRM)
    {
        syslog(LOG_DEBUG, "Caught signal SIGALRM!!");
        timeout = true;
    }
    #endif

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


void *thread_func( void *thread_param )
{
    tdata_t *thread_data = (tdata_t *) thread_param;
 
    char ip_string[INET_ADDRSTRLEN];
    struct sockaddr_in *p = (struct sockaddr_in *)&thread_data->t_addr;
    syslog(LOG_DEBUG, "IP connection: %s", inet_ntop(AF_INET, &p->sin_addr, ip_string, sizeof(ip_string)));

    char buffer[SIZE];
    int received_length;

    bool received = false;

    memset(buffer, '\0', SIZE);
    int num = 0;
    int total_buffer_length = 0;
    int old_length = SIZE;
    char *total_buffer;

    while(!received)
    {
        received_length = 0;
        int recv_return = recv(thread_data->fd, &buffer, SIZE, 0);
        
        if (recv_return == -1)
        {
        	syslog(LOG_ERR, "recv");
        	goto error;
        }

        for(int i=0; i< SIZE; i++)
        {
            received_length++;
            if( buffer[i] == '\n' )
            {
                received = true;
                break;
            }
        }

        if(num == 0)
        {
            total_buffer = (char *)malloc(received_length);
            if(total_buffer == NULL)
            {
                syslog(LOG_ERR, "malloc");
            }
     
            memset(total_buffer, '\0', received_length);
            total_buffer_length = received_length;
        }
        else
        {
            char *ptr = realloc(total_buffer, old_length+received_length);
            if(ptr == NULL)
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
    
    pthread_mutex_lock(&mtx);
    
    int new_socket_file_fd = open(file_path, O_RDWR | O_CREAT | O_APPEND, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH | S_IWOTH );			////
    
    if(strncmp(total_buffer, ioctl_cmd, strlen(ioctl_cmd)) == 0)
    {
    	struct aesd_seekto seekto;
    	
    	sscanf(total_buffer, "AESDCHAR_IOCSEEKTO:%d, %d", &seekto.write_cmd, &seekto.write_cmd_offset);
    	
    	if(ioctl(new_socket_file_fd, AESDCHAR_IOCSEEKTO, &seekto))
    	{
    		printf("ioctl failed");
    	}
    }
    
    else
    {
       int write_return = write(new_socket_file_fd, total_buffer, total_buffer_length);
    	if( write_return == -1)
    	{
    	    syslog(LOG_ERR, "write");
    	}
    	data_count += write_return;	
    }

   memset(buffer, '\0', SIZE);
   
   #ifndef USE_AESD_CHAR_DEVICE
   lseek(socket_file_fd, 0, SEEK_SET);
   #endif
      
    int read_return;
    

    char *buffer_read = (char *)malloc(SIZE);

    if (buffer_read == NULL) 
    {
        syslog(LOG_ERR, "malloc");
    }
    while( (read_return = read(new_socket_file_fd, buffer_read, SIZE))>0)			
    {
 
        int bytes_sent = send(thread_data->fd, buffer_read, read_return, 0);

        if (bytes_sent == -1) 
        {
            syslog(LOG_ERR, "Error: send()");
            goto free_buffer;
        }
    }
    pthread_mutex_unlock(&mtx);

    if(read_return == -1)
    {
        syslog(LOG_ERR, "Error: read() with code, %d", errno);
    }
    
    free_buffer : free(buffer_read);
    error : free(total_buffer);
    close(thread_data->fd);
    thread_data->complete_flag = true;
    syslog(LOG_DEBUG, "Closed connection from %s", inet_ntop(AF_INET, &p->sin_addr, ip_string, sizeof(ip_string)));
    return NULL;
}


int main(int argc, char *argv[])
{
    openlog(NULL, 0, LOG_USER);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

#ifndef USE_AESD_CHAR_DEVICE					//////
	signal(SIGALRM, signal_handler);
#endif
    
    bool is_daemon = false;

    if( argv[1] == NULL )
    {
        is_daemon =  false;
    }
    else if( strcmp(argv[1], "-d") == 0)
    {
        is_daemon = true;
    }
    else
    {
		syslog(LOG_ERR, "invalid argument");
		return -1;
    }
 
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    struct addrinfo hints, *server_info;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;  
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     

    int ret;

    ret = getaddrinfo(NULL, "9000", &hints, &server_info);
    if( ret !=0 )
    {
        syslog(LOG_ERR, "Error: getaddrinfo() with code, %d", errno);
    }

    server_socket_fd = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);
    if( server_socket_fd == -1 )
    {
        syslog(LOG_ERR, "Error: socket() with code, %d", errno);
    }

    const int yes = 1;
    if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
    {
    	syslog(LOG_ERR, "Error: setsocketopt() with code, %d", errno);
    }
    
    int flags = fcntl(server_socket_fd, F_GETFL);
    fcntl(server_socket_fd, F_SETFL, flags | O_NONBLOCK);
    
    ret = bind(server_socket_fd, server_info->ai_addr, server_info->ai_addrlen);
    if( ret != 0 )
    {
        syslog(LOG_ERR, "Error: bind() with code, %d", errno);
    }



    if( is_daemon )
    {
        if(daemon_creation() != 0)
        {
            syslog(LOG_ERR, "Daemon creation failed");
        }
    }


    ret = listen(server_socket_fd, 10);
    if( ret != 0 )
    {
        syslog(LOG_ERR, "Error: listen() with code, %d", errno);
    }

    freeaddrinfo(server_info);
    addr_size = sizeof their_addr;

	
    socket_file_fd = open(file_path, O_RDWR | O_CREAT | O_APPEND, 0666);	/////


    #ifndef USE_AESD_CHAR_DEVICE
    ret = timer_init();
    if(ret == -1)
    {
        perror("timer creation");
    }
    #endif

    pthread_mutex_init(&mtx, NULL);

    node_t *head =NULL;
    node_t *prev,*current;

    while(!e_status)
    {
    	#ifndef USE_AESD_CHAR_DEVICE
        if(timeout)
        {
            timeout = false;
            timestamp();
        }
        #endif
        
        int client_socket_fd  = accept(server_socket_fd, (struct sockaddr *)&their_addr, &addr_size);
        if( client_socket_fd  == -1 )
        {
            if(errno == EWOULDBLOCK)
            {
          
                continue;
            }
            syslog(LOG_ERR, "Error : accept with error no : %d", errno);
      
            continue;
        }
        node_t *new_node = (node_t *)malloc(sizeof(node_t));
        new_node->data.complete_flag = false;
        new_node->data.fd = client_socket_fd;
        new_node->data.t_addr = their_addr;
     
        int ret = pthread_create( &(new_node->data.tid), NULL, &thread_func, &(new_node->data));
        if( ret != 0 )
        {
            syslog(LOG_ERR, "pthread_create");
        }
        else
        {
            syslog(LOG_DEBUG, "pthread_create");
        }

        sll_insert(&head, new_node);
    }
    current =  head;
    prev = head;
    while(current)
    {
        if((current->data.complete_flag == true) && (current == head))
        {
     
            head = current->next;
            pthread_join(current->data.tid, NULL);
            free(current);
            current = head;
        }
        else if ((current->data.complete_flag == true) && (current != head)) 
        { 
   
            prev->next = current->next;
            current->next = NULL;
            pthread_join(current->data.tid, NULL);
            free(current);
            current = prev->next;
        } 
        else 
        {
       
            prev = current;
            current = current->next;
        }
    }
    printf("All threads exited!!\n");
    close(server_socket_fd);
    close(socket_file_fd);
    pthread_mutex_destroy(&mtx);
    #ifndef USE_AESD_CHAR_DEVICE
    unlink("/var/tmp/aesdsocketdata"); 		//////
    timer_delete(timer);
    #endif
    closelog();
    return 0;
}

#ifndef USE_AESD_CHAR_DEVICE
void timestamp()
{
    time_t timestamp;
    char time_buf[40];
    char buffer[100];

    struct tm* ts;

    time(&timestamp);
    ts = localtime(&timestamp);
 
    strftime(time_buf, 40, "%a, %d %b %Y %T %z", ts);
    sprintf(buffer, "timestamp:%s\n", time_buf);

    lseek(socket_file_fd, 0, SEEK_END);
   
    pthread_mutex_lock(&mtx);
    write(socket_file_fd, buffer, strlen(buffer));
    pthread_mutex_unlock(&mtx);
}


int timer_init()
{
    timer_create(CLOCK_REALTIME, NULL, &timer);

    struct itimerspec delay;
    delay.it_value.tv_sec = 10;
    delay.it_value.tv_nsec = 0;
    delay.it_interval.tv_sec = 10;
    delay.it_interval.tv_nsec = 0;

    timer_settime(timer, 0, &delay, NULL);

    return 0;
}
#endif
