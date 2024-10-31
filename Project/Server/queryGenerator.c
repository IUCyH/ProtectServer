#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "queryGenerator.h"

char* MakeWhereInt(const char* original, int keyword)
{
	char* result = (char*)malloc(sizeof(char) * (strlen(original) - 2 + sizeof(int) + 1));

	sprintf(result, original, keyword);
	return result;
}

char* MakeSelectQuery(const char* table, const char* where)
{
	char* query = "SELECT * FROM %s WHERE %s;";
	char* result = (char*)malloc(sizeof(char) * (strlen(query) - 2 + strlen(table) + strlen(where) + 1));

	sprintf(result, query, table, where);
	return result;
}
