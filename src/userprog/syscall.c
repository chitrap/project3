#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "lib/string.h"
#include "devices/input.h"
#include "vm/mmap.h"
#include "vm/Page.h"
#include "vm/frame.h"
#include <inttypes.h>
#include <list.h>

static void syscall_handler (struct intr_frame *);
struct lock file_lock; //lock for handing file sys
void validate_page(const void *addr);
struct file* get_file_handle(int file_desc);
void sys_halt(void);
void syscall_init (void);
void sys_exit (int status);
void sys_close (int file_desc);
unsigned sys_tell (int file_desc);
void sys_seek (int file_desc, unsigned offset);
int sys_read (int file_desc, char *buf, unsigned s);
int sys_filesize (int file_desc);
bool sys_remove (const char *file);
bool sys_create (const char *file, unsigned size);
static int sys_wait (pid_t pid);
static pid_t sys_exec (const char *input);
static int sys_open (const char *file);
static int sys_write (int file_desc, const void *buffer, unsigned size);
void get_arguments_from_stack (struct intr_frame *f, int *arg, int n);
struct child_process* add_child (int pid);
void validate_ptr (const void *addr);
void close_all_files (void);
static mapid_t assing_mapid (void);
static void *esp_value;

//File structre
struct file_struct
{
	struct file* file; //file pointer
	int file_desc;     //file discriptor
	struct list_elem elem;
};

//Validates page for address, if didn't get then exits
void
validate_page (const void *addr)
{
	void *ptr = pagedir_get_page (thread_current ()->pagedir, addr);
	if (!ptr)
	{
		sys_exit (-1);
	}

}

//Finds file handle for given file discriptor by searching in
// list of files owned
struct file*
get_file_handle (int file_desc)
{
	//printf("file handle 1\n");
   struct list_elem *e = list_begin (&thread_current()->files_owned_list);
   struct list_elem *next;
   while (e != list_end (&thread_current()->files_owned_list))
   {

     struct file_struct *f = list_entry (e, struct file_struct,
                                          elem);
     next = list_next(e);
     if (file_desc == f->file_desc)
       {
        return f->file;
       }
     e = next;
   }
   return NULL;

}

//initialises sys calls and file lock
void
syscall_init (void) 
{
	lock_init (&file_lock);
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


//shut down os
void
sys_halt (void)
{
	shutdown_power_off();
}

//exit current thread and releases any resources acquired by it
void
sys_exit (int status)
{
	struct thread *current = thread_current();
	struct list_elem *e;	
	//current->chp->status = status; 
    	current->exit_status = status;
	thread_get_child_data(current->parent, current->tid)->exit_status=current->exit_status;
        while (!list_empty (&current->mmap_files) )
        {
           e = list_begin (&current->mmap_files);
           sys_munmap ( list_entry (e, struct struct_mmap, thread_elem)->mapid );
        }
	//printf("\nthread_exit from sys_exit\n"); 
	thread_exit();	 
}

//close sys call, gets file handle and closes file
void
sys_close (int file_desc)
{
	struct file_struct *file_ptr = NULL;
        struct list_elem *e = list_begin (&thread_current()->files_owned_list);
        struct list_elem *next;
        while (e != list_end (&thread_current()->files_owned_list))
        {

                struct file_struct *f = list_entry (e, struct file_struct,
                                          elem);
                next = list_next(e);
                if (file_desc == f->file_desc)
                {
                        file_ptr = f;
                        break;
                }
                e = next;
        }

	if (file_ptr != NULL)
		 {
		 	if (file_desc == file_ptr->file_desc)
		 	{
		 		file_close (file_ptr->file);
		 		list_remove (&file_ptr->elem);
		 		free (file_ptr);
		 	}	
		 }
	

}

//tell sys call, gets file handle and calls file_tell
unsigned
sys_tell (int file_desc)
{
	struct file *file_ptr = get_file_handle (file_desc);
	unsigned cursor = file_tell (file_ptr);
	return cursor;
}

//Seek file call, gets file handle then seeks file at offset
void
sys_seek (int file_desc, unsigned offset)
{
	lock_acquire (&file_lock);
	struct file *file_ptr = get_file_handle (file_desc); 
	file_seek (file_ptr, offset);	
	lock_release (&file_lock);
}

//read sys call, returns no of bytes read from buffer or file
//STDIN_FILENO is reading from buffer
int
sys_read (int file_desc, char *buf, unsigned s)
{
	const void *esp = (const void *)esp_value;
	validate_ptr (buf);
	validate_page (buf);
        int ret = 0; 
	if (file_desc == STDIN_FILENO)
		 {
		 	//read from buffer
		 	int i;
		 	for (i = 0; i < (int) s; i++)
		 		 {
		 		 	*(buf++) = input_getc();
		 		 	return s; 
		 		 }
		 }
        //lock_acquire (&file_lock);	
	struct file* file_ptr = get_file_handle (file_desc);
	if (file_ptr == NULL)
	{
		//lock_release (&file_lock);
		return -1;
	}
	else
        {
          /* We read into the buffer one page at a time. Before the actual 
             read we need to make sure the page it's loaded and pin it's 
             underlying frame. We have to prevent a page fault while a device
             driver access a user driver. Loading one page at a time protects
             the OS from malicious programs that could try to pin all the 
             frames at a give n time. */

          size_t rem = s;
          void *tmp_buffer = (void *)buf;

          ret = 0;
          while (rem > 0)
            {
              /* Round down the buffer address to a page and try to find a
                 static page. If we don't find the page we migth have stack
                 growth. If we find the page we only need to load if is not
                 present in memory. */
              size_t ofs = tmp_buffer - pg_round_down (tmp_buffer);
              struct struct_page *page = vm_find_page_in_supplemental_table (tmp_buffer - ofs);
              
              if (page == NULL && is_stack_access_vaid (esp, tmp_buffer) )
                page = vm_add_zeroed_page_on_stack (tmp_buffer - ofs, true);   
              else if (page == NULL)
                sys_exit (-1);

              /* Load the page and pin the frame. */
              if ( !page->is_page_loaded )
                vm_load_new_page (page, true);

              size_t read_bytes = ofs + rem > PGSIZE ?
                                  rem - (ofs + rem - PGSIZE) : rem;
              lock_acquire (&file_lock);

              ASSERT (page->is_page_loaded);
              ret += file_read (file_ptr, tmp_buffer, read_bytes);
              lock_release (&file_lock);              

              rem -= read_bytes;
              tmp_buffer += read_bytes;

              /* Unpin the frame after we are done. */
              unpin (page->frame_page);
            }
	}
	//off_t bytes_read = file_read (file_ptr, buf, s);
	//lock_release (&file_lock);
	//return bytes_read;
        return ret;
}

//File size sys call, gets file handle and then returns,
// file_length of file
int
sys_filesize (int file_desc)
{
	lock_acquire (&file_lock);	
	struct file *file_ptr = get_file_handle (file_desc);
	int file_size = file_length (file_ptr);
	lock_release (&file_lock);
	return file_size;
}

//remove sys call, removes this file from system
bool
sys_remove (const char *file)
{
	lock_acquire (&file_lock);
	bool status = filesys_remove (file);
	lock_release (&file_lock);
	return status;	
}

//create sys call, calls file_create sys call
bool
sys_create (const char *file, unsigned size)
{
	if (file == NULL)
		 {
		 	sys_exit (-1);
		 }
	validate_ptr (file);
	validate_page (file);
	bool status = filesys_create (file, size);
	return status;
}

//Wait sys call
static int
sys_wait (pid_t pid)
{
	return process_wait (pid);
}

//Exec call, calls process execute
static pid_t
sys_exec (const char *input)
{
	validate_ptr (input);
	validate_page (input);
	pid_t pid = process_execute(input);
	return pid;	 
}

//open sys call
static int
sys_open (const char *file)
{
	if (file == NULL)
		 {
		 	sys_exit (-1);
		 }
	validate_ptr (file);	 
	validate_page (file);	 
	lock_acquire (&file_lock);
	struct file *handle = filesys_open (file);

	if (handle == NULL)
		 {
		 	lock_release (&file_lock);
		 	return -1;
		 }

	struct file_struct *file_ptr = malloc (sizeof (struct file_struct));
	if (file_ptr == NULL)
		 {
		 	lock_release (&file_lock);
		 	return -1;
		 }
	file_ptr->file_desc = thread_current ()->file_desc;
	//so that on opening twice it gives diff fd
	thread_current ()->file_desc++; 
	file_ptr->file = handle;
	list_push_back (&thread_current ()->files_owned_list , &file_ptr->elem);
	//check for file name with thread name for rox-* tests
	if (strcmp (file, thread_current ()->name) == 0)
	 {
	 	file_deny_write (handle);
	 }

	lock_release (&file_lock);	 
	return file_ptr->file_desc;
}

//Write sys 
static int
sys_write (int file_desc, const void *buffer, unsigned size)
{
	const void *esp = (const void *)esp_value;
	//printf("write 1\n");
	validate_ptr (buffer);
	validate_page (buffer);

        int ret = 0;
	if (file_desc == STDOUT_FILENO)
	 {
	 	int left = size;
	 	while (left > 128)
	 		 {
	 		 	putbuf (buffer, 128);
	 		 	buffer = (const char *)buffer + 128;
	 		 	left = left - 128;

	 		 }
	 	putbuf (buffer, left);
	 	return size;
	 }

	 
	 struct file *file_ptr = get_file_handle (file_desc);
	
	 //if lock doesn't acquired then return
	 if (file_ptr == NULL)
	 	 {
	 	 	
	 	 	sys_exit (-1);
	 	 }
	 else {
	 size_t rem = size;
	 void *tmp_buffer = (void *)buffer;
	 ret = 0;
	 while (rem > 0)
	  {
	  	//page loading
	  	size_t ofs = tmp_buffer - pg_round_down (tmp_buffer);
	  	struct struct_page *page = vm_find_page_in_supplemental_table (tmp_buffer - ofs);

	  	if (page == NULL && is_stack_access_vaid (esp, tmp_buffer))
	  	 {
	  	 	page = vm_add_zeroed_page_on_stack (tmp_buffer - ofs, true);
	  	 }
	  	 else if (page == NULL)
	  	 	sys_exit (-1);

	  	 if (!page->is_page_loaded)
	  	  {
	  	  	vm_load_new_page (page, true);
	  	  }
	  	  size_t write_bytes = ofs + rem > PGSIZE ?
	  	  		rem - (ofs + rem - PGSIZE) : rem;

	  	  lock_acquire (&file_lock);
	  	  ASSERT (page->is_page_loaded);
	  	  ret += file_write (file_ptr, tmp_buffer, write_bytes);		
	  	  lock_release (&file_lock);

	  	  rem -= write_bytes;
	  	  tmp_buffer += write_bytes;
	  	  unpin (page->frame_page);

	  }	 
	
	 }

	 return ret;	 
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	//printf("\nsyscall handler...\n");
	int arg[3];  //maximum 3 args are required by a syscall

	//validates the pointer
	validate_ptr((const void *) f->esp);
	validate_page((const void *) f->esp);
        //printf("\n esp: %d\n",*(int *)f->esp);	
	//store value of esp for read and write
	esp_value = f->esp;
	//switch for diff system calls
	switch(* ( int *) f->esp)
	{
		case SYS_HALT:
		 {
			sys_halt();
			break;
		 }
		case SYS_EXIT:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	f->eax = arg[0];
		 	sys_exit(arg[0]);
		 	break;
		 }
		case SYS_EXEC:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	f->eax = sys_exec ((const char*)arg[0]);
		 	break;
		 } 
		case SYS_WAIT:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	f->eax = sys_wait (arg[0]);
		 	break;
		 }
		case SYS_CREATE:
		 {
		 	get_arguments_from_stack(f, &arg[0], 2);
		 	f->eax = sys_create ((const char *)arg[0], (unsigned) arg[1]);
		 	break;
		 }
		case SYS_REMOVE:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	f->eax = sys_remove ((const char *) arg[0]);
		 	break;	
		 }
		case SYS_OPEN:
		 {
		 	get_arguments_from_stack (f, &arg[0], 1);
		 	f->eax = sys_open ((const char *)arg[0]);
		 	break;
		 }
		case SYS_FILESIZE:
		 {
		 	get_arguments_from_stack (f, &arg[0], 1);
		 	f->eax = sys_filesize (arg[0]);
		 	break;
		 } 
		case SYS_READ:
		 {
		 	get_arguments_from_stack (f, &arg[0], 3);
		 	f->eax = sys_read (arg[0], (void *) arg[1], (unsigned) arg[2]);
		 	break;
		 } 
		case SYS_WRITE:
		 {
		 	get_arguments_from_stack (f, &arg[0], 3);
		 	f->eax = sys_write ((int) arg[0], (const void*)arg[1],
		 						(unsigned) arg[2]);
		 	break;
		 } 
		case SYS_SEEK:
		 {
		 	get_arguments_from_stack (f, &arg[0], 2);
		 	sys_seek (arg[0], (unsigned) arg[1]);
		 	break;
		 } 
		case SYS_TELL:
		 {
		 	get_arguments_from_stack (f, &arg[0], 1);
		 	f->eax = sys_tell (arg[0]);
		 	break;
		 } 
		case SYS_CLOSE:
		 {
		 	get_arguments_from_stack (f, &arg[0], 1);
		 	sys_close(arg[0]);
		 	break;
		 } 
		 case SYS_MMAP:
		 {
		 	get_arguments_from_stack(f, &arg[0], 2);
		 	f->eax = sys_mmap((int) arg[0], (void *)arg[1]);
		 	break;
		 }
		 case SYS_MUNMAP:
		 {
		 	get_arguments_from_stack(f, &arg[0], 1);
		 	sys_munmap((mapid_t) arg[0]);
		 	break;
		 }

	}
  
}


mapid_t
sys_mmap(int fd, void* addr){

	size_t s;
	struct file *f;
	s = sys_filesize(fd);
	lock_acquire(&file_lock);
	f = file_reopen(get_file_handle(fd));
	lock_release(&file_lock);

	/* Check for validity.*/
  	if (s <= 0 || f == NULL)
    	return -1;
  	if (addr == NULL || addr == 0x0 || pg_ofs (addr) != 0)
    	return -1;
  	if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    	return -1;

  size_t ofs = 0;
  void *addr_tmp = addr;

  /* Divide the file into pages and create a new file page
     with the corresponding offset for each of them. */
  while (s > 0)
    {
      size_t read_bytes;
      size_t zero_bytes;
      
      if (s >= PGSIZE)
        {
          read_bytes = PGSIZE;
          zero_bytes = 0;
        }
      else
        {
          read_bytes = s;
          zero_bytes = PGSIZE - s;
        }
  
      /* Fail if there is already a mapped page at the same address. */
      if ( vm_find_page_in_supplemental_table (addr_tmp) != NULL)
          return -1;
      
      vm_add_new_page (addr_tmp, f, ofs, read_bytes, zero_bytes, true, -1);
      
      ofs += PGSIZE;
      s -= read_bytes;
      addr_tmp += PGSIZE;
    }

  mapid_t mapid = assing_mapid();
  mmap_insert_by_mapid (mapid, fd, addr, addr_tmp);

  return mapid;

}

static mapid_t
assing_mapid (void)
{
  static mapid_t mapid = 0;
  return mapid++;
}

/*Unmaps a files.*/
void
sys_munmap (mapid_t mapid)
{
  struct struct_mmap *mmap = mmap_find_by_mapid (mapid);
  if (mmap == NULL)
    sys_exit (-1);

  void *address = mmap->start_address;

  /* Free each page mapped in memory for the given file. */
  for (;address < mmap->end_address; address += PGSIZE)
    {
      struct struct_page *p = NULL;

      p = vm_find_page_in_supplemental_table (address);
      if (p == NULL)
        continue;

      if (p->is_page_loaded == true)
        {
          if (p->frame_page != NULL)
    		return;
  		  pin (p->frame_page);

          ASSERT (p->is_page_loaded && p->frame_page != NULL);
          free_frame (p->frame_page, p->pointer_to_pagedir);
        } 
      vm_free_this_page (p);
    }
  mmap_delete_by_mapid(mapid);
}


//get arguments from stack
void
get_arguments_from_stack (struct intr_frame *f, int *arg, int n)
{
	int i;
	
	for(i = 0; i < n; ++i)
		 {
		 	int *ptr = (int *)f->esp + i + 1;	
		 	validate_ptr((const void *)ptr);
		 	arg[i] = *ptr;
		 }
}

//Validates stack pointer
void
validate_ptr (const void *addr)
{
	if (!is_user_vaddr (addr))
	 {
		sys_exit(-1);
	 }
	
}

//CLose open files
void
close_all_files (void)
{
   struct list_elem *el = list_begin (&thread_current()->files_owned_list);
   struct list_elem *nxt;
   while (el != list_end (&thread_current()->files_owned_list))
   {
     struct file_struct *fs = list_entry (el, struct file_struct,
                                          elem);
     nxt = list_next(el);
     file_close (fs->file);
     list_remove (&fs->elem);
     free (fs);
     el = nxt;
   }
}

void
sys_filelock(int flag){
if(flag)
	lock_acquire(&file_lock);
else
	lock_release(&file_lock);
}
