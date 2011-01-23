#ifndef _RSA_TYPES_H
#define _RSA_TYPES_H

#include <inttypes.h>
#include <gmp.h>

typedef struct _rsa_t {
  mpz_t n;    // public modulus
  mpz_t e;    // public exponent
  mpz_t d;    // private exponent
  mpz_t p;    // secret prime factor
  mpz_t q;    // secret prime factor
  mpz_t dmp1; // d mod (p-1)
  mpz_t dmq1; // d mod (q-1)
  mpz_t iqmp; // q^-1 mod p
  uint32_t nBitLen;
} rsa_t;

#endif
