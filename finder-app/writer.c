#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>


int main ( int argc, char *argv[])
{
	openlog(NULL, 0, LOG_USER);

	if (argc != 3)
	{
		printf("Invalid arguments. Please enter correct arguments \n\r");
		printf("Expected arguments as <file_name> <string_to_write> \n\r");
		syslog(LOG_ERR, "Invalid number of arguments: %d", argc);
		return 1;
	}

	int fd;
	size_t write_bytes= strlen(argv[2]);
	ssize_t write_return;

	fd=open (argv[1], O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);

	if (fd==-1)
	{
		syslog(LOG_ERR, "File does not exist. Please create file first");
		return 1;
	}
	
	write_return = write(fd, argv[2], strlen(argv[2]));
	
	if (write_return == -1)
	{
		syslog(LOG_ERR, "Unable to write to given file");
		return 1;
	}

	else if ( write_return != strlen(argv[2]))
	{
		syslog(LOG_ERR, "Program has written only %ld out %ld words", write_return, write_bytes);
		return 1;
	}

	close(fd);
	closelog();
	return 0;
}





