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


bool
vm_load_new_page (struct struct_page *new_page, bool is_pinned){

	lock_init(&page_load_lock);

	if(new_page->type == 1 && new_page->file->block_id = -1){
		new_page->frame_page = frame_lookup(new_page->file.block_id);
	}

	if(new_page->frame_page = NULL){
		new_page->frame_page = get_frame(PAL_USER);
	}

	lock_release(&page_load_lock);
	set_frame(new_page->frame_page, new_page);

	bool flag = true;

	if(new_page->type == 1){
		sys_t_filelock(true);
		file_seek(new_page->file.file_name, new_page->file.ofs);
		size_t bytes_read = file_read(new_page->file.file_name, new_page->frame_page, new_page->fram_page.read_bytes);
		sys_t_filelock(false);

		if(bytes_read != new_page->file.read_bytes){
			free_frame(page->frame_page, new_page->pointer_to_pagedir);
			flag = false;
		}
		if(flag){
			memset (frame_page + new_page->file.read_bytes, 0, new_page->file.zero_bytes);
  		}
	}
	else if(new_page->type == 0){
			memset (new_page->frame_page, 0, PGSIZE);
	}
	else{
		load_swap_page (new_page->swap.swap_index, new_page->frame_page);
  		free_swap_page (new_page->swap.swap_index);
	}

	if(!flag){
		unpin(new_page->frame_page);
		return false;
	}

	pagedir_clear_page(new_page->pointer_to_pagedir, new_page->addr);
	if (!pagedir_set_page (new_page->pointer_to_pagedir, new_page->addr, new_page->frame_page, new_page->is_writable))
    {
      ASSERT (false);
      unpin (page->frame_page);
      return false;
    }

  	pagedir_set_dirty (new_page->pointer_to_pagedir, new_page->addr, false);
  	pagedir_set_accessed (new_page->pointer_to_pagedir, new_page->addr, true);

  	new_page->is_page_loaded = true;

  	if (!is_pinned)
    	unpin (new_page->frame_page);
  	return true;
}

void
vm_unload(struct struct_page *p, void fpage){
	lock_acquire(&page_unload_lock);
	if(&p->type == 1 && pagedir_is_dirty(p->pointer_to_pagedir, p->addr) && file_writable(p->file.file_name) == false){
		pin(fpage);
		sys_t_filelock(true);
		file_seek(p->file.file_name, p->file.ofs);
		file_write(p->file.file_name, fpage, p->file.read_bytes);
		sys_t_filelock(false);
		unpin(fpage);
	}
	else if(&p->type == 2 || pagedir_is_dirty(p->pointer_to_pagedir, p->addr)){
		p->type = 2;
		p->swap.swap_index = store_swap_page(fpage);
	}
	lock_release(&page_unload_lock);

	pagedir_clear_page(p->pointer_to_pagedir, p->addr);
	pagedir_add_page(p->pointer_to_pagedir, p->addr, (void *)p);
	p->is_page_loaded = false;
	p->frame_page = NULL;
}

