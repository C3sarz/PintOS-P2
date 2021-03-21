#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"
#include "threads/synch.h"

void syscall_init (void);

/// PROJECT 2 ///

struct lock file_lock;	/* Filesystem lock. */

/*Going to use this to keep track of thread's files and the file descriptor list.*/
struct thread_files
{
    struct list_elem elem;
    struct file *file_address;
    int file_desc;
};

void sys_halt (void);
void sys_exit (int status);
pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, const void *buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);


//- PROJECT 2 -//

#endif /* userprog/syscall.h */
