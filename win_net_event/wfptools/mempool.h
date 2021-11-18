#ifndef _MEMPOOL_H
#define _MEMPOOL_H

void mempool_init();
void mempool_free();

void* mp_alloc(unsigned int size, int align = 0);
void mp_free(void* buffer, unsigned int maxPoolSize = 0);


#endif // !_MEMPOOLS_H
