#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

///PROJECT 2///

/* Structure to pass on arguments as a single unit when executing a process. */
struct arguments
{
	uint8_t argc;		/* Number of arguments tokenized from string. */
	char ** argv;		/* Array of argument strings. */
};

/* Will use this struct for synchronization of the child process in wait() and possibly exec? */

/* "Ignore for now"
struct child_process
{
	int pid;
	int load_status;
	int wait;
	int exit;
	int status;
	struct semaphore;
}
*/
/* Process identifier type. */
typedef int pid_t;
typedef int tid_t;
#define PID_ERROR ((pid_t) -1)          /* Error value for pid_t. */

//-PROJECT 2-//

tid_t process_execute (const char *cmd_line);
int process_wait (tid_t child_tid);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
