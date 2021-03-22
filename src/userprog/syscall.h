#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"
#include "threads/synch.h"
#include "filesys/file.h"

void syscall_init (void);

/// PROJECT 2 ///

struct lock file_lock;	/* Filesystem lock. */

void sys_halt (void);
void sys_exit (int status);
pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
bool sys_create (const char *filename, unsigned initial_size);
bool sys_remove (const char *filename);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, const void *buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);
struct open_file_elem * find_file(int fd);


//- PROJECT 2 -//

#endif /* userprog/syscall.h */
