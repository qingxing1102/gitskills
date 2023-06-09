#include "log.h"
#include <stdio.h>

void log_data(char *info, unsigned char *data, int len)
{
    int i;
    if (info) printf("%s\n", info);

    for (i = 0; i < len; i++) {
        if (i && i % 16 == 0) printf("\n");
        printf("%02x ", (unsigned char)data[i]);
    }
    printf("\n");
}

