#ifndef __COMMON_H__
#define __COMMON_H__

int load_file(char *path, unsigned char **data, int *data_len);
int write_file(char *path, unsigned char *data, int data_len);
    
#endif /* __COMMON_H__ */
