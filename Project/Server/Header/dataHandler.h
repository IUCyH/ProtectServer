#ifndef DATA_HANDLER_H

# define DATA_HANDLER_H

#include <stdio.h>

typedef struct QueryResult
{
	char*** result;
	int rowCount;
	int fieldCount;
}QueryResult;

void OpenDB();
void CloseDB();
QueryResult* Search(const char* query);

#endif
