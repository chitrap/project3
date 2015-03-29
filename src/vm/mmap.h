#ifdef VM_MMAP_H
#define VM_MMAP_H

#include <hash.h>

typedef int mapid;

struct struct_mmap;
 {
 	mapid mapid;
 	int fd; //file desc
 	struct hash_elem hash_elem;
 	struct list_elem thread_elem;
 	void *start_address; //user vir start address
 	void *end_address;//user vir end addr
 };

#endif