#ifndef __LOG_H__
#define __LOG_H__
#include <stdio.h>

#define CHECK_FUNC(...) \
    __VA_ARGS__; \
    if (ret) { \
        printf("[%s:%d] " #__VA_ARGS__ " failed: %#x\n", __FUNCTION__, __LINE__, ret); \
        goto end; \
    }

#define LOG(...) \
    do { \
        printf("[%s:%d] ", __FUNCTION__, __LINE__); \
        printf(__VA_ARGS__); \
    } while (0)

void log_data(char *info, unsigned char *data, int len);
    
#endif /* __LOG_H__ */
