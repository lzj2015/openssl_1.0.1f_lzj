/* crypto/sm3/sm3.h */

#ifndef SM3_HEADER_H
#define SM3_HEADER_H

#include <openssl/opensslconf.h>
#include <stddef.h>

# ifdef OPENSSL_NO_SM3
#  error SM3 is disabled.
# endif // OPENSSL_NO_SM3

# if defined(__LP32__)
#  define SM3_LONG unsigned long
# elif defined(OPENSSL_SYS_CRAY) || defined(__ILP64__)
#  define SM3_LONG unsigned long
#  define SM3_LONG_LOG2 3
# else
#  define SM3_LONG unsigned int
# endif

# define SM3_DIGEST_LENGTH   32
# define SM3_LBLOCK          16
# define SM3_CBLOCK          64

struct SM3state_st
{
    SM3_LONG digest[8];
    SM3_LONG Nl, Nh;
    SM3_LONG data[SM3_LBLOCK];
    unsigned int num;
};

typedef struct SM3state_st SM3_CTX;

# ifdef __cplusplus
extern "C"
{
# endif
    int SM3_Init(SM3_CTX *c);
    int SM3_Update(SM3_CTX *c, const void *data, size_t len);
    int SM3_Final(unsigned char *md, SM3_CTX *c);
    unsigned char *SM3(const unsigned char *d, size_t n, unsigned char *md);
    void SM3_Transform(SM3_CTX *c, const unsigned char *data);
# ifdef __cplusplus
}
# endif

#endif // !SM3_HEADER_H


