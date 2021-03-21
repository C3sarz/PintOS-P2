#include "userprog/syscall.h"
#include "threads/thread.h"
#include <stdio.h>
#include <list.h>
#include <inttypes.h>
#include <stdbool.h>
#include "threads/malloc.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define STDIN 0
#define STDOUT 1

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

    if(!valid_user_pointer((uint32_t *)byte))           /* Check if byte address is valid */
    {
      sys_exit(-1);                      /* If invalid, get rid of offending process */
      NOT_REACHED();
    }
    *((uint8_t *) &word + i) = *(byte);     /* Assemble word. */

  }
  return word;
}

/* Handles syscall requests */
static void
syscall_handler (struct intr_frame * f) 
{
  int esp_word = get_word(f->esp);		/* Get system call number from stack pointer. */
  switch(esp_word)
  {
  	case SYS_HALT:
  		sys_halt();	/* Halt system. */
  		break;

  	case SYS_EXIT:
  		sys_exit(get_word(f->esp+1));	/* Exit status is the first parameter. */
  		break;

  	case SYS_EXEC:
   		printf ("DEBUG, System call! SYS_EXEC \n");					///DEBUG///
  		thread_exit ();												///DEBUG///
  		break;

  	case SYS_WAIT:
  	{
  		printf ("DEBUG, System call! SYS_WAIT \n");					///DEBUG///
  		thread_exit ();												///DEBUG///
  		break;
  	}

  	case SYS_CREATE:
  	  	printf ("DEBUG, System call! SYS_CREATE \n");					///DEBUG///
  		thread_exit ();													///DEBUG///
  		break;

  	case SYS_REMOVE:
  	  	printf ("DEBUG, System call! SYS_REMOVE \n");					///DEBUG///
  		thread_exit ();													///DEBUG///
  		break;

  	case SYS_OPEN:
  	{
		char * filename = f->esp + 1;		/* Get filename. */
  		if(!valid_user_pointer((uint32_t *)filename))	/* Check pointer validity. */		
  			sys_exit(-1);
  		
  		f->eax = sys_open(filename);
  		break;
  	}

  	case SYS_FILESIZE:
  	{
  		int * fd = f->esp + 1;					/* Get file descriptor. */
  		if(!valid_user_pointer((uint32_t *)fd))	/* Check pointer validity. */		
  			sys_exit(-1);

  		f->eax = sys_filesize(*fd);				/* Find size. */
  		break;
  	}

  	case SYS_READ:
  	  	printf ("DEBUG, System call! SYS_READ \n");					///DEBUG///
  		thread_exit ();		
  		break;

  	case SYS_WRITE:
  	  	printf ("DEBUG, System call! SYS_WRITE \n");					///DEBUG///
  		thread_exit ();	
  		break;

  	case SYS_SEEK:
  	{
  		int * fd = f->esp + 1;					/* Get file descriptor. */
  		unsigned * offset = f->esp + 2;			/* Get position offset. */

  		if(!valid_user_pointer((uint32_t *)fd)	/* Check pointer validity. */
  		|| !valid_user_pointer((uint32_t *)offset))		
  			sys_exit(-1);

  		sys_seek(*fd, *offset);					/* Call function. */			
  		break;
  	}

    case SYS_TELL:
    {
  	  	int * fd = f->esp + 1;					/* Get file descriptor. */
  		if(!valid_user_pointer((uint32_t *)fd))	/* Check pointer validity. */		
  			sys_exit(-1);

    	f->eax = sys_tell(*fd);					/* Call function. */
  		break;
  	}

    case SYS_CLOSE:
  	{
  		int * fd = f->esp + 1;					/* Get file descriptor. */
  		if(!valid_user_pointer((uint32_t *)fd))	/* Check pointer validity. */		
  			sys_exit(-1);

  		sys_close(*fd);							/* Close file. */
  		break;
  	}

  	/* Invalid system call scenario: terminate process. */
  	default:
  		printf("Invalid system call: %d\n", esp_word);
  		thread_exit();
  		break;		
  }
}

/* Halts the operating system. */
void
sys_halt (void)
{
	shutdown_power_off(); // Power off PintOS (from threads/init.h).
}

/* Stops the process.*/
void
sys_exit (int status)
{
	struct thread * t = thread_current();

	//all code regarding children goes here

	printf("%s: exit(%d)\n", t->name, status);
}

// pid_t
// sys_exec (const char *cmd_line)
// {

// }

// int
// sys_wait (pid_t pid)
// {

// }

// bool
// sys_create (const char *file, unsigned initial_size)
// {

// }

// bool
// sys_remove (const char *file)
// {

// }

/* System call to open a file or file stream. */
int
sys_open (const char *file)
{
	struct thread * t = thread_current();
	int fd = -1;
	if(&t->open_files == NULL)						/* Check if list is not NULL */
		return -1;

	lock_acquire(&file_lock);						/* Start critical section. */

	struct file * open_file = filesys_open(file); 	/* Try to open file. */

	if(open_file == NULL)							/* If NULL, return error state. */
	{
		lock_release(&file_lock);
		return -1;
	}

	/* Alocate new list element. */
	struct open_file_elem * new_elem = (struct open_file_elem *) malloc(sizeof(struct open_file_elem));

	/* If malloc fails return error. */
	if(new_elem == NULL)
	{
		lock_release(&file_lock);
		return -1;
	}

	/* Generate fd depending on list values */
	if(list_empty(&t->open_files))
	{
		fd = 2;	/* Default value */
	}

	else		/* Else find highest value and add 1 (So that it will be unique). */
	{
		struct list_elem * e;
		for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
           e = list_next (e))
        {
          struct open_file_elem * curr = list_entry (e, struct open_file_elem, elem);
          if(curr->fd >= fd)
          	fd = curr->fd;
        }
        fd++;			/* Next after biggest fd */
	}

	/* Set up elem and add to list */
	new_elem->fd = fd;
	new_elem->file_ptr = open_file;
	list_push_back(&thread_current()->open_files, &new_elem->elem);
	lock_release(&file_lock);
	return fd;
}

/* Search for open file and return its size in bytes. */
int
sys_filesize (int fd)
{
	struct open_file_elem * open_file_ptr;
	lock_acquire(&file_lock);

	/* Search for the file. */
	open_file_ptr = find_file(fd);

    /* If file is not found return ERROR. */
    if(open_file_ptr == NULL)
    {
    	lock_release(&file_lock);
    	return -1;
    }

    /* Find size, release lock, and return size in bytes. */
    int size = file_length(open_file_ptr->file_ptr);
    lock_release(&file_lock);
    return size;
}

// int
// sys_read (int fd, void *buffer, unsigned size)
// {

// }

/* Writes size bytes from buffer to the open file fd. 
	Returns the number of bytes actually written. */
int
sys_write (int fd, const void *buffer, unsigned size)
{
	int written_bytes = 0;

	/* Error checking. */
	if(size <= 0)
		return written_bytes;

	/* If writing to console... */
	if(fd == STDOUT)
	{
		putbuf((char *)buffer, size);	/* Write to console. */
		written_bytes = size;
	}

	/* If not writing to console. */
	else
	{
		struct open_file_elem * open_file_ptr;
		lock_acquire(&file_lock);

		/* Search for the file. */
		open_file_ptr = find_file(fd);

		/* If file not found, return. */
	    if(open_file_ptr == NULL)
	    {
	    	lock_release(&file_lock);
	    	return -1;
	    }

	    /* Write to file and release lock. */
	    written_bytes = file_write(open_file_ptr->file_ptr, buffer, size);
	    lock_release(&file_lock);
	}
	return written_bytes;
}

/* Changes the next byte to be read 
	in the given file to "offset". */
void
sys_seek (int fd, unsigned offset)
{
	struct open_file_elem * open_file_ptr;
	lock_acquire(&file_lock);

	/* Search for the file. */
	open_file_ptr = find_file(fd);

	/* If file not found, return. */
    if(open_file_ptr == NULL)
    {
    	lock_release(&file_lock);
    	return;
    }

    /* Using given filesystem function for seek. */
    file_seek(open_file_ptr->file_ptr, offset);
	lock_release(&file_lock);
}

// /* Returns the offset of the next byte to be read 
// 	or written in the file given by fd. */
// unsigned
// sys_tell (int fd)
// {
// 	struct open_file_elem * open_file_ptr;
// 	lock_acquire(&file_lock);
// 	unsigned offset;

// 	/* Search for the file. */
// 	open_file_ptr = find_file(fd);

// 	 If file not found, return. 
//     if(open_file_ptr == NULL)
//     {
//     	lock_release(&file_lock);
//     	return 0;	/* Error case ? */
//     }
	
// 	/* Find offset with filesys function. */
//     offset = file_tell(open_file_ptr->file_ptr);

//     lock_release(&file_lock);
//     return offset;
// }
// =======

/* Returns the address of the file descriptor's open file if it's in the current thread's file descriptor list or -1 if not found. */
static unsigned
sys_tell (int fd)
 {
	 lock_acquire(&file_lock);
	//Simply says if we have no file descriptors, return -1 and release the lock.
	if(list_empty(&thread_current()->fd_list))
	{
		//Exit the critical section and return error -1.
		lock_release(&file_lock);
		return -1;
	}

	struct list_elem *iterator;
	//Otherwise go through the list and check for the passed in file descriptor.
	for(iterator = list_front(&thread_current()->fd_list); iterator != list_end(&thread_current()->fd_list); iterator = list_next(&thread_current()->fd_list))
	{
		//Pull the thread files from the list.
		struct thread_files *cur = list_entry(iterator, struct thread_files, elem);
		//If we find the file descriptor in this thread.
		if(cur->file_desc == fd)
		{
			//Place the address in the address variable using the file_tell call.
			unsigned address = (unsigned) file_tell(cur->file_address);
			//Release the lock as we're done with the filesystem.
			lock_release(&file_lock);
			return address;
		}
	}
	//If we don't find the address, still have to release the lock.
	lock_release(&file_lock);
	return -1;
 }

/* Closes an open file given its fd. */
void
sys_close (int fd)
{
	struct open_file_elem * open_file_ptr;
	lock_acquire(&file_lock);

	/* Search for the file. */
	open_file_ptr = find_file(fd);

	/* If file not found, return. */
    if(open_file_ptr == NULL)
    {
    	lock_release(&file_lock);
    	return;
    }

    file_close(open_file_ptr->file_ptr);		/* Close file and release lock. */
    list_remove(&open_file_ptr->elem);			/* Remove file from list. */
    free(open_file_ptr);						/* Free memory for open file object. */
    lock_release(&file_lock);
}

/* Find a file opened by the given process and returns its open file element.
	Returns NULL if the file is not found. */
struct open_file_elem *
find_file(int fd)
{
	struct thread * t = thread_current();
	struct list_elem * e;

	/* Check if list exists and is not empty. */
	if(&t->open_files == NULL || list_empty(&t->open_files))
		return NULL;

	/* Iterate through list to find matching file. */
	for (e = list_begin (&t->open_files); e != list_end (&t->open_files);
        e = list_next (e))
    {
        struct open_file_elem * curr = list_entry (e, struct open_file_elem, elem);
        if(curr->fd == fd)
        {
          	return curr;	/* Found file. */
        }          	
    }
    return NULL;			/* File not found. */
}

// /*Helper function to check a given address and see if it's a valid user address.  Returns pointer to that address.
// Uses some functionality of vaddr in threads folder*/
// void* check_valid(const void *addr)
// {
// 	if(!is_user_vaddr(addr))
// 	{

// 		//Exit the process if not a valid user address.
// 		sys_exit(-1);
// 		return 0;

// 	}
// 	//Represents the address we will return if valid
// 	void *address_returned = pagedir_get_page(thread_current()->pagedir, addr);
// 	//If our address returned is not valid, we exit again.
// 	if(!address_returned)
// 	{
// 		sys_exit(-1);
// 		return 0;
// 	}
// 	//Return the valid user address if it's valid.
// 	return address_returned;
// }
//- PROJECT 2 -//