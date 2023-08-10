#ifndef _MEMPOOLS_H
#define _MEMPOOLS_H

namespace mempool
{
	void mempools_init();
	void mempools_free();

	void *mp_alloc(unsigned int size, int align = 0);
	void mp_free(void * buffer, unsigned int maxPoolSize = 0);
}

#endif