#include "public.h"
#include "hashtable.h"

PHASH_TABLE hash_table_new(unsigned int size)
{
	unsigned int memsize;
	PHASH_TABLE pTable;

	if (size < 1)
		return NULL;

	memsize = sizeof(HASH_TABLE) + sizeof(PHASH_TABLE_ENTRY) * (size - 1);

#if (NTDDI_VERSION >= NTDDI_WIN8)
	pTable = ExAllocatePoolWithTag(NonPagedPoolNx, (memsize), MEM_TAG);
#else
	pTable = ExAllocatePoolWithTag(NonPagedPool, (memsize), MEM_TAG);
#endif
	if (!pTable)
		return NULL;

	RtlSecureZeroMemory(pTable, memsize);

	pTable->size = size;

	return pTable;
}

void hash_table_free(PHASH_TABLE pTable)
{
	if (pTable)
	{
		free_np(pTable);
	}
}

int ht_add_entry(PHASH_TABLE pTable, PHASH_TABLE_ENTRY pEntry)
{ 
	if (pTable == NULL || (!pTable))
		return 0;
	if (pEntry == NULL || (!pEntry))
		return 0;
	UINT64 hash = pEntry->id % pTable->size;
	if (ht_find_entry(pTable, pEntry->id))
		return 0;
	pEntry->pNext = pTable->pEntries[hash];
	pTable->pEntries[hash] = pEntry;
	return 1;
}


PHASH_TABLE_ENTRY ht_find_entry(PHASH_TABLE pTable, UINT64 id)
{
	if (pTable == NULL || (!pTable))
		return 0;

	PHASH_TABLE_ENTRY pEntry = NULL;
	pEntry = pTable->pEntries[id % pTable->size];
	while (pEntry)
	{
		if (pEntry->id == id)
		{
			return pEntry;
		}
		pEntry = pEntry->pNext;
	}
	return NULL;
}

int ht_remove_entry(PHASH_TABLE pTable, UINT64 id)
{
	PHASH_TABLE_ENTRY pEntry, * ppNext;

	ppNext = &pTable->pEntries[id % pTable->size];
	pEntry = *ppNext;

	while (pEntry)
	{
		if (pEntry->id == id)
		{
			*ppNext = pEntry->pNext;
			return 1;
		}

		ppNext = &pEntry->pNext;
		pEntry = *ppNext;
	}

	return 0;
}