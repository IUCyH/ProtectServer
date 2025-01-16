#ifndef MEMORY_POOL_H

# define MEMORY_POOL_H

#include <stdio.h>

typedef struct Pool
{
	Queue* queue;
}Pool;

Pool* InitPool(int prevGenerateCount, size_t* sizes);
void* Get(Pool* pool, size_t size);
int Set(Pool* pool, void* data);

#endif
