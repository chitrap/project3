#include "vm/frame.h"
#include <stdio.h>
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static struct lock frame_lock;
static struct hash frames;

unsigned frame_hash (const struct hash_elem *, void *);
bool frame_comparator (const struct hash_elem *, const struct hash_elem *, void *);

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