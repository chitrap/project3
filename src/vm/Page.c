#include "vm/Page.h"
#include <stdio.h>
#include <string.h>
#include "vm/frame.h"


//Synchronization between load and unload of pages
static struct page_load_lock;
static struct page_unload_lock;

// Initiliase page tables from init.c
void
vm_page_init ()
{
	lock_init (&page_load_lock);
	lock_init (&page_unload_lock);
}

struct struct_page*
vm_add_new_page(void *address, struct file *file_name, off_t ofs, size_t read_bytes,
				size_t zero_bytes, bool writable){
		struct struct_page *new_page = (struct struct_page*) malloc(size_of(struct frame_page));

		if(new_page == NULL){
			return NULL;
		}

		new_page->type = 1; //File type
		new_page->address = address;
		new_page->pointer_to_pagedir = thread_current()->pagedir;
		new_page->file.file_name = file_name;
		new_page->file.ofs = ofs;
		new_page->file.read_bytes = read_bytes;
		new_page->file.zero_bytes = zero_bytes;
		//new_page->file.block_id = block_id;
		new_page->is_writable = writable;
		new_page->is_page_loaded = false;
		new_page->frame_page = NULL;


		add_page_to_pagedir(new_page->pointer_to_pagedir, new_page->address, (void *)new_page);

		return new_page;
}

struct struct_page
vm_add_new_zeroed_page (void *addr, bool writable)
{
	struct struct_page *zero_page = (struct struct_page) malloc (size_of(struct struct_page));
	if (zero_page == NULL)
	 {
	 	return NULL;
	 }

	 zero_page->type = 0; //Zerored page
	 zero_page->address = addr;
	 zero_page->pointer_to_pagedir = thread_current ()->pagedir;
	 zero_page->is_writable = writable;
	 zero_page->is_page_loaded = false;
	 zero_page->frame_page = NULL;
	 add_page_to_pagedir(zero_page->pointer_to_pagedir, zero_page->address, (void *)zero_page);

	 return zero_page;

}
