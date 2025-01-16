#include <stdio.h>
#include <stdlib.h>
#include "linkedList.h"
#include "queue.h"

Queue* InitQueue()
{
	Queue* queue = (Queue*)malloc(sizeof(Queue));

	queue->root = InitList();
	return queue;
}

int Enqueue(Queue* queue, void* data)
{
	if(queue == NULL) return 0;

	int success = Add(queue->root, data);
	return success;
}

void* Dequeue(Queue* queue)
{
	if(queue == NULL) return NULL;

	void* data = queue->root->data->data;

	int success = Remove(queue->root, queue->root->data, 0);
	if(!success)
	{
		return NULL;
	}
	else
	{
		return data;
	}
}

int Empty(Queue* queue)
{
	if(queue == NULL) return 1;

	return (queue->root->count == 0) ? 1 : 0;
}
