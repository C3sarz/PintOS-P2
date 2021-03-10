#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/// PROJECT 2 ///

/* Handles syscall requests */
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();


  //switch for syscalls?


}

/* Halts the operating system. */
void sys_halt (void)
{
	power_off();
}

/* Stops the process.*/
void sys_exit (int status)
{

}

pid_t sys_exec (const char *cmd_line)
{

}

int sys_wait (pid_t pid)
{

}

bool sys_create (const char *file, unsigned initial_size)
{

}

bool sys_remove (const char *file)
{

}

int sys_open (const char *file)
{

}

int sys_filesize (int fd)
{

}

int sys_read (int fd, void *buffer, unsigned size)
{

}

int sys_write (int fd, const void *buffer, unsigned size)
{

}

void sys_seek (int fd, unsigned position)
{

}

unsigned sys_tell (int fd)
{

}

void sys_close (int fd)
{

}

//- PROJECT 2 -//