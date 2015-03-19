#include "vm/frame.h"
#include <stdio.h>
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static struct lock frame_lock;
static struct hash frames;

unsigned frame_hash (const struct hash_elem *, void *);
bool frame_comparator (const struct hash_elem *, const struct hash_elem *, void *);
static bool delete_frame (void *);
static struct struct_frame *find_frame (void *);

//Initializes frames hash, called from threads/init.c
//from main function
void
vm_frame_init (void)
{
	lock_init (&frame_lock);
	hash_init (&frames, frame_hash, frame_comparator, NULL);

}


//returns hash value for frame e
unsigned frame_hash (const struct hash_elem *e_, void *aux UNUSED)
{
	const struct struct_frame *sf = hash_entry (e_, struct struct_frame,
		                                        hash_elem);
	return hash_int ((unsigned) sf->page);
}


//Frame comparator by pages in it
bool
frame_comparator (const struct hash_elem *first_, const struct hash_elem *second_,
	             void *aux UNUSED)
{
	const struct struct_frame *f = hash_entry (first_, 
		                           struct struct_frame, hash_elem); 
	const struct struct_frame *s = hash_entry (second_, 
		                           struct struct_frame, hash_elem); 
	return f->page < s->page;
}


//Frees resources
void
free_vm_frames (void *pg)
{
	delete_frame (pg);
	palloc_free_page (pg);
}

//Deletes a frame, free its memory
static bool
delete_frame (void *pg)
{
	struct struct_frame *f = find_frame (pg);
	if (f == NULL)
	 {
	 	return false;
	 }

	 lock_acquire (&frame_lock);
	 hash_delete (&frames, &f->hash_elem);
	 free (f);
	 lock_release (&frame_lock);

	 return true;
}


//returns frame for given page
static struct struct_frame *
find_frame (void *pg)
{
	struct struct_frame sf;
	struct hash_elem *elm;

	sf.page = pg;
	elm = hash_find (&frames, &sf.hash_elem);
	if (elm == NULL)
	 {
	 	return NULL;
	 }

	return hash_entry (elm, struct struct_frame, hash_elem); 

}

//Maps User virtual page to frame of vm by help of pte
bool
upage_to_frame_mapping (void *frame, uint32_t *pte, void *vaddr)
{
	struct struct_frame *sf = find_frame (frame);
	if (sf == NULL)
	 {
	 	return false;
	 }
	 sf->pte = pte;
	 sf->vaddr = vaddr;

	 return true;
}

//Adds frame to Hash by allocating memory
static bool
add_frame (void *pg)
{
	struct struct_frame *sf;
	sf = (struct struct_frame *) malloc (sizeof (struct struct_frame));

	if(sf == NULL)
	 {
	 	return false;
	 }

	 sf->thread = thread_current ();
	 sf->page = pg;

	 lock_acquire (&frame_lock);
	 hash_insert (&frames, &sf->hash_elem);
	 lock_release (&frame_lock);

	 return true;
}

//Gets a free frame
void *
get_frame (enum palloc_flags flags)
{
	void *pg = palloc_get_page (flags);
	if (pg != NULL)
	 {
	 	add_frame (pg);
	 	find_frame (pg);
	 }
	 else
	  {
	  	#ifndef vm
	  		sys_exit (-1);
	  	#endif
	  	PANIC ("Eviction needed !");	
	  }

	  return pg;
}
