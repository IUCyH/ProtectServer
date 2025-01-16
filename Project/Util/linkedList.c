#include <stdio.h>
#include <stdlib.h>
#include "linkedList.h"

Head* InitList()
{
	Head* head = (Head*)malloc(sizeof(Head));

	head->data = NULL;
	head->tail = NULL;
	head->count = 0;

	return head;
}

int Add(Head* head, void* data)
{
	if(head == NULL) return 0;

	Node* node = (Node*)malloc(sizeof(Node));

	node->data = data;
	node->next = NULL;
	node->prev = NULL;

	if(head->data == NULL)
	{
		head->data = node;
	}
	else
	{
		head->tail->next = node;
		node->prev = head->tail;
	}

	head->tail = node;
	head->count++;

	return 1;
}

int Remove(Head* head, Node* node, int shouldFreeData)
{
	if(head == NULL || node == NULL || head->count <= 0) return 0;

	if(head->data == node)
	{
		head->data = head->data->next;
		if(head->data != NULL)
		{
			head->data->prev = NULL;
		}
	}
	else
	{
		Node* prev = node->prev;
		Node* next = node->next;

		if(prev != NULL)
		{
			prev->next = next;
		}

		if(next != NULL)
		{
			next->prev = prev;
		}
	}

	head->count--;

	if(shouldFreeData)
	{
		free(node->data);
		free(node);
	}
	return 1;
}
