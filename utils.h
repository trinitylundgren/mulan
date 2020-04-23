/* Description: Utility functions to support CLI ping program for Linux.
 * Last Modified: 2020-04-21
 * Author: Trinity Lundgren */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>  // size_t

char* safe_strcpy(char*, size_t, char*);
unsigned short checksum(void*, int);
void hex_dump(const void*, size_t);

#endif
