#ifndef LINKED_LIST_H

# define LINKED_LIST_H

#define LIST_FOR_EACH(element, head) for(element = (head != NULL) ? (head)->data : NULL; element != NULL; element = element->next)

#include <stdio.h>

typedef struct Node
{
	void* data;
	struct Node* next;
	struct Node* prev;
}Node;

typedef struct Head
{
	Node* data;
	Node* tail;
	int count;
}Head;

Head* InitList();
int Add(Head* head, void* data);
int Remove(Head* head, Node* node, int shouldFreeData);

#endif
