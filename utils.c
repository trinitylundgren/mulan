/* Description: Utility functions to support CLI ping program for Linux.
 * Last Modified: 2020-04-21
 * Author: Trinity Lundgren */

#include "utils.h"

/*
 * Truncating version of strcpy that copies the longest prefix of the source
 * string src into a destination buffer of known size.
 *
 * For example:
 *     char* src = "Watermelon";
 *     char dest[5];
 *     safe_strcpy(dest, 5, src);
 *     printf(dest);
 *
 * Prints:
 *     Wate
 */

char* safe_strcpy(char* dest, size_t size, char* src) {
    size_t i = 0;
    if (size > 0) {
        for (; i < size - 1 && src[i]; ++i) {
            dest[i] = src[i];
        }
        dest[i] = '\0';
    }
    return dest;
}

/*
 * Function to calculate the checksum. Takes as arguments a void pointer to a
 * data buffer and data buffer length.
 *
 * For example:
 *
 *     char* check = "Hello World";
 *     printf("Checksum: %hu", checksum(check, 11));
 *
 * Prints:
 *     Checksum: 12686
 */
unsigned short checksum(void* b, int len) {
    unsigned short* buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}
