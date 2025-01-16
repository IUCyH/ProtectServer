#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "queue.h"
#include "memoryPool.h"

Pool* InitPool(int prevGenerateCount, size_t* sizes)
{
	Pool* pool = (Pool*)malloc(sizeof(Pool));

	pool->queue = InitQueue();

	for(int i = 0; i < prevGenerateCount; i++)
	{
		void* data = (void*)malloc(sizes[i]);
		Enqueue(pool->queue, data);
	}

	return pool;
}

void* Get(Pool* pool, size_t size)
{
	if(pool == NULL) return NULL;

	void* data = NULL;

	if(Empty(pool->queue))
	{
		data = (void*)malloc(size);

		if(data == NULL)
		{
			return NULL;
		}
	}
	else
	{
		data = Dequeue(pool->queue);

		if(malloc_usable_size(data) < size)
		{
			void* temp = realloc(data, size);
			if(temp != NULL)
			{
				data = temp;
			}
			else
			{
				free(data);
				return NULL;
			}
		}
	}	

	if(data != NULL)
	{
		memset(data, 0, size);
	}

	return data;
}

int Set(Pool* pool, void* data)
{
	if(pool == NULL) return 0;

	int success = Enqueue(pool->queue, data);

	if(!success)
	{
		if(data != NULL)
		{
			free(data);
		}
	}

	return success;
}
