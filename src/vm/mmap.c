#include "vm/mmap.h"
#include <hash.h>
#include <lists.h>
#include "threads/malloc.h"
#include "threads/thread.h"

static struct lock mmap_file_lock;
static struct hash mmap_files;


//gives hash value for mmap file
static unsigned
mmap_hash (const struct hash_elem *mf_, void *aux UNUSED)
{
	const struct struct_mmap *mf = hash_enrty (mf_, struct struct_mmap, hash_elem);
	return hash_int ((unsigned) mf->mapid);
}

//Mmap comparator
static bool
mmap_comparator (const struct hash_elem *a_,const struct hash_elem *b_,
	             void *aux UNUSED)
{
	const struct struct_mmap *a = hash_enrty (a_, struct struct_mmap, hash_elem);
	const struct struct_mmap *b = hash_enrty (b_, struct struct_mmap, hash_elem);

	return a->mapid < b->mapid;
}

//init mmap table
void
mmap_init (void)
{
	lock_init (&mmap_file_lock);
	hash_init (&mmap_files, mmap_hash, mmap_comparator, NULL), 
}

//find mmap for given mapid or null
struct struct_mmap *
mmap_find_by_mapid (mapid mapid)
{
	struct struct_mmap mf;
	struct hash_elem *e;

	mf.mapid = mapid;
	e = hash_find (&mmap_files, &mf.hash_elem);
	if (e == NULL)
	{
		return NULL;
	}
	return hash_enrty (e, struct struct_mmap, hash_elem);
}

//deletes mapid from file_desc
bool
mmap_delete_by_mapid (mapid mapid)
{
	struct struct_mmap *mf = mmap_find_by_mapid (mapid);
	if (mf == NULL)
	{
		return false;
	}
	lock_acquire (&mmap_file_lock);
	hash_delete (&mmap_files, &mf->hash_elem);
	list_remove (&mf->thread_elem);
	free (mf);
	lock_release (&mmap_file_lock);

	return true;
}

//Insert new mfilefrom given mapid
void
mmap_insert_by_mapid (mapid mapid, int fid, void *start_addr, void *end_addr)
{
	struct struct_mmap *mf = (struct struct_mmap *) malloc (sizeof (struct struct_mmap));
	mf->fd = fid;
	mf->mapid = mapid;
	mf->start_address = start_addr;
	mf->end_address = end_addr;

	lock_acquire (&mmap_file_lock);
	list_push_back (&thread_current ()->mmap_files, &mf->thread_elem);
	hash_insert (&mmap_files, &mf->hash_elem);
	lock_release (&mmap_file_lock);
}

