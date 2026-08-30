#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int aegis_sha256_file(const char *path, char *out_hex);
int aegis_sha256_buf(const void *data, size_t len, char *out_hex);
#ifdef __cplusplus
}
#endif
#endif
