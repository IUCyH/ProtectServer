#ifndef QUEUE_H

# define QUEUE_H

#include <stdio.h>
#include "linkedList.h"

typedef struct Queue
{
	Head* root;
}Queue;

Queue* InitQueue();
int Enqueue(Queue* queue, void* data);
void* Dequeue(Queue* queue);
int Empty(Queue* queue);

#endif
