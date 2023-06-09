#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

int load_file(char *path, unsigned char **data, int *data_len)
{
    int ret = 0;
    int size = 0;
    FILE *fp = fopen(path, "rb");

    if (!fp) {
        LOG("fopen() %s failed: %s\n", path, strerror(errno));
        return errno;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size < 1) {
        LOG("%s", "data file is empty\n");
        ret = -1;
        goto end;
    }

    *data = malloc(size);
    if (*data == NULL) {
        ret = errno;
        LOG("malloc() failed: %s\n", strerror(errno));
        goto end;
    }

    ret = fread(*data, 1, size, fp);
    if (ret < 0) {
        ret = errno;
        LOG("fread() failed: %s\n", strerror(errno));
        goto end;
    }
    ret = 0;
    *data_len = size;

end:
    fclose(fp);
    return ret;
}

int write_file(char *path, unsigned char *data, int data_len)
{
    int ret = 0;
    FILE *fp = fopen(path, "wb");

    LOG("path = %s, fp = %p\n", path, fp);
    if (!fp) return errno;
    ret = fwrite(data, 1, data_len, fp);
    if (ret < 0) goto end;
    fflush(fp);

end:
    fclose(fp);
    return ret;
}

