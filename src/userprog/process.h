#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

///PROJECT 2///

/* Structure to pass on arguments as a single unit when executing a process. */
struct arguments
{
	uint8_t argc;			/* Number of arguments tokenized from string. */
	char ** argv;		/* Array of argument strings. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)          /* Error value for tid_t. */

//-PROJECT 2-//

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
