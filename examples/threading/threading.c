#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

// Optional: use these functions to add debug or error prints to your application
// define DEBUG_LOG(msg,...)

#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;

	struct thread_data* thread_func_args = (struct thread_data *) thread_param;
	
	usleep(thread_func_args -> wait_to_obtain_ms * 1000);
	
	int unlock_return = pthread_mutex_lock (thread_func_args -> mutex);
	int lock_return;

	if (unlock_return != 0)
	{
		ERROR_LOG("unable to lock: %s \n", strerror(errno));
	}

	else
	{
		usleep(thread_func_args -> wait_to_release_ms * 1000);
		lock_return = pthread_mutex_unlock (thread_func_args -> mutex);

		if (lock_return != 0)
		{
			ERROR_LOG("unable to release mutex: %s \n", strerror(errno));
		}

		else 
		{
			thread_func_args -> thread_complete_success = true;
		}

	}
   return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
	
	struct thread_data *thread_t = malloc(sizeof(struct thread_data));

	if (thread_t == NULL)
	{
		ERROR_LOG("no memory available, thread not created");
		return false;
	}

	thread_t -> mutex = mutex;
	thread_t -> wait_to_obtain_ms = wait_to_obtain_ms;
	thread_t -> wait_to_release_ms = wait_to_release_ms;
	thread_t -> thread_complete_success = false;

	int ret = pthread_create(thread, NULL, threadfunc, thread_t);

	if (ret != 0)
	{
		ERROR_LOG("unable to create thread: %s \n", strerror(errno));
		free(thread_t);
		return false;
	}


    	return true;
}

