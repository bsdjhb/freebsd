#ifdef _KERNEL
#include <sys/libkern.h>
#else
#include <stdlib.h>
#endif

#include "openssl/base.h"
#include "openssl/rand.h"

int
RAND_bytes(uint8_t *buf, size_t len)
{
#ifdef _KERNEL
	arc4rand(buf, (u_int)len, 0);
#else
	arc4random_buf(buf, len);
#endif
	return(0);
}


