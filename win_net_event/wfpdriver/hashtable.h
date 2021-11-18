#ifndef _HASHTABLE_H
#define _HASHTABLE_H

typedef struct _HASH_TABLE_ENTRY
{
	UINT64		id;
	struct _HASH_TABLE_ENTRY* pNext;
}HASH_TABLE_ENTRY, * PHASH_TABLE_ENTRY;

typedef struct _HASH_TABLE
{
	unsigned int size;
	PHASH_TABLE_ENTRY pEntries[1];
} HASH_TABLE, * PHASH_TABLE;

PHASH_TABLE hash_table_new(unsigned int size);

void hash_table_free(PHASH_TABLE pTable);

int ht_add_entry(PHASH_TABLE pTable, PHASH_TABLE_ENTRY pEntry);

PHASH_TABLE_ENTRY ht_find_entry(PHASH_TABLE pTable, UINT64 id);

int ht_remove_entry(PHASH_TABLE pTable, UINT64 id);

#endif // !_HASHTABLE_H
