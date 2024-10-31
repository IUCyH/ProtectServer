#ifndef QUERY_GENERATOR_H

# define QUERY_GENERATOR_H

#include <stdio.h>

char* MakeWhereInt(const char* original, int keyword);
char* MakeSelectQuery(const char* table, const char* where);

#endif
