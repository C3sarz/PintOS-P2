#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"

static bool valid_user_pointer(const uint32_t * address);
static uint32_t get_word(const uint32_t * address);
static void syscall_handler (struct intr_frame * f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);			/* Initialize lock. */
}

/* Verifies if the given address is valid and belongs to the process.*/
static bool
valid_user_pointer(const uint32_t * address)
{

  /* Check null pointer */
  if(address == NULL)
    return false;

  /* Error if outside of user space. */
  if(is_kernel_vaddr(address) || !is_user_vaddr(address)) 
    return false;

  /* Get page table for process and error check. */
  uint32_t * pagedir = thread_current()->pagedir;
  if(pagedir == NULL)
    return false;

  /* Verify if UADDR is mapped. */
  if(pagedir_get_page(pagedir, address) == NULL)
    return false;

  return true;
}

/* Retrieves a word from user memory. 
If the given pointer is invalid or illegal, the process is terminated */
static uint32_t
get_word(const uint32_t * address)
{
  uint32_t word;
  int i;

  for(i = 0; i < 4; i++)                    /* For every byte i in word */
  {
    unsigned char * byte = (unsigned char *)address + i;  /* Get byte i from word */

    if(!valid_user_pointer(byte))           /* Check if byte address is valid */
    {
      sys_exit(-1);                      /* If invalid, get rid of offending process */
      NOT_REACHED();
    }
    *((uint8_t *) &word + i) = *(byte);     /* Assemble word. */

  }
  return word;
}

/* Handles syscall requests */
static void syscall_handler (struct intr_frame * f) 
{

  int esp_addr = get_word(f->esp);		/* Get system call number from stack pointer. */

  printf ("system call! Number: %d \n", esp_addr);		///DEBUG///
  thread_exit ();										///DEBUG///

  switch(esp_addr)
  {
  	case SYS_HALT:
  		sys_halt();
  		break;

  	case SYS_EXIT:
  		sys_exit(get_word(f->esp+1));
  		break;

  	case SYS_EXEC:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

  	case SYS_WAIT:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

  	case SYS_CREATE:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

  	case SYS_REMOVE:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

  	case SYS_OPEN:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

  	case SYS_FILESIZE:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

  	case SYS_READ:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

  	case SYS_WRITE:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

  	case SYS_SEEK:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

    case SYS_TELL:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

    case SYS_CLOSE:
  		NOT_REACHED(); //NOT IMPLEMENTED YET
  		break;

  	/* Invalid system call scenario: terminate process. */
  	default:
  		printf("Invalid system call: %d\n", esp_addr);
  		thread_exit();
  		break;		
  }
}

/* Halts the operating system. */
void sys_halt (void)
{
	shutdown_power_off(); // Power off PintOS (from threads/init.h).
}

/* Stops the process.*/
void sys_exit (int status)
{
	struct thread * t = thread_current();

	//all code regarding children goes here

	printf("%s: exit(%d)\n", t->name, status);
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