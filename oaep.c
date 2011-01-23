#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "oaep.h"
#include "tiger.h"

/* tiger hash of "CLNT" */
static const uint8_t hash_client[24] = {
  0x05, 0xAE, 0x52, 0x8F, 0x60, 0x10, 0x14, 0xCB,
  0x61, 0xE0, 0x91, 0x3D, 0x66, 0x28, 0xB4, 0x3E,
  0x33, 0x62, 0xB3, 0x70, 0xE4, 0xD6, 0x9E, 0xB6
};

/* tiger hash of "SRVR" */
static const uint8_t hash_server[24] = {
  0x72, 0xF5, 0x3D, 0x22, 0x3D, 0x8B, 0xB2, 0x26,
  0x37, 0x4C, 0xE1, 0x90, 0xB6, 0xEA, 0x05, 0xE6,
  0x5B, 0xF4, 0x71, 0x48, 0xDE, 0xAF, 0x4D, 0x4F
};

static inline uint8_t *MGF1(uint8_t *seed, uint32_t seedLen, uint32_t maskLen) {
  uint32_t max, mod, i, dataLen;
  uint8_t *data, *output, *tmp;

  dataLen = seedLen+4;
  data = malloc(dataLen);
  if(!data) return NULL;
  memcpy(data, seed, seedLen);

  mod = maskLen % hLen;
  max = mod ? ((maskLen-mod)/hLen)+1 : (maskLen/hLen);
  output = malloc(max*hLen);
  if(!output) {
    free(data);
    return NULL;
  }
  tmp = output;

  for(i=0; i<max; i++) {
    *(uint32_t *)(data+seedLen) = htonl(i);
    tiger(data, dataLen, tmp);
    tmp += hLen;
  }
  free(data);
  return output;
}

static inline int32_t fill_random(uint8_t *dest, uint32_t len) {
  int32_t fd, bytes;

  fd = open("/dev/urandom", O_RDONLY);
  if(fd == -1) return -1;
  bytes = read(fd, dest, len);
  close(fd);
  if(bytes != (ssize_t)len) return -1;
  return 0;
}

/* possibly? resist linearization */
static inline uint32_t is_same(const uint8_t *a, const uint8_t *b, const uint32_t len) {
  uint32_t i;
  uint64_t acc;

  acc = 0;
  for(i=0; i<len; i++)
    acc += a[i] ^ b[i];
  if(acc > 0)
    return 0;
  else
    return 1;
}

int32_t oaep_encode(uint8_t *M, uint32_t mLen, uint32_t k, lbl_t label, uint8_t *EM) {
  uint8_t *DB, *seed, *mask;
  uint32_t dbLen, i;

  if((int32_t)mLen > (int32_t)(k-2*hLen-2)) {
    return -1;
  }

  dbLen = (k-hLen-1);
  memset(EM, 0, k);
  seed = EM+1;
  DB = EM+1+hLen;

  if(label == LABEL_CLIENT)
    memcpy(DB, hash_client, hLen);
  else /* LABEL_SERVER */
    memcpy(DB, hash_server, hLen);
  DB[dbLen-mLen-1] = 0x01;
  memcpy(DB+(dbLen-mLen), M, mLen);

  if( fill_random(seed, hLen) == -1 )
    return -3;

  mask = MGF1(seed, hLen, dbLen);
  if(!mask) return -2;
  for(i=0; i<dbLen; i++)
    DB[i] ^= mask[i];
  free(mask);

  mask = MGF1(DB, dbLen, hLen);
  if(!mask) return -2;
  for(i=0; i<hLen; i++)
    seed[i] ^= mask[i];
  free(mask);

  return 0;
}

int32_t oaep_decode(uint8_t *EM, uint32_t k, lbl_t label) {
  int32_t i, dbLen;
  uint8_t *mask, *DB, *seed;
  const uint8_t *lHash;

  if(k < (2*hLen+2))
    return -5;

  dbLen = k - hLen - 1;
  seed = EM+1;
  DB = EM+1+hLen;

  mask = MGF1(DB, dbLen, hLen);
  if(!mask) return -2;
  for(i=0; i<(int32_t)hLen; i++)
    seed[i] ^= mask[i];
  free(mask);
  mask = MGF1(seed, hLen, dbLen);
  if(!mask) return -2;
  for(i=0; i<dbLen; i++)
    DB[i] ^= mask[i];
  free(mask);

  /* FIXME: this is probably vulnerable to linearization */
  if(EM[0]) return -5;
  if(label == LABEL_CLIENT)
    lHash = hash_client;
  else
    lHash = hash_server;
  if(!is_same(lHash, DB, hLen)) {
    return -5;
  }
  for(i=hLen; i<dbLen && DB[i] == 0x00; i++);
  if(i == dbLen || DB[i] != 0x01) {
    return -5;
  }

  return dbLen - i - 1;
}

#if defined(TEST)
int main(int argc, char **argv) {
  int32_t i, padRet;
  uint8_t *EM, *tmp;
  uint8_t hash[3*hLen];

  if(argc != 2) {
    printf("Usage\n");
    return -1;
  }
  memset(hash, 0xCD, sizeof(hash));
  tiger((uint8_t *)argv[1], strlen(argv[1]), hash+hLen);
  i = 1024; /* minimum 592 */
  EM = malloc(1024/8);
  if(!EM) {
    printf("Unable to allocate memory for encoded message.\n");
    return -1;
  }

  padRet = oaep_encode(hash, sizeof(hash), (1024/8), LABEL_CLIENT, EM);
  if(padRet < 0) {
    printf("Failed to encode message, got %d\n", padRet);
    return -1;
  }

  printf("Encoded message:\n");
  for(i=0; i<(1024/8); i++)
    printf("%02X ", EM[i]);
  printf("\n");

  padRet = oaep_decode(EM, (1024/8), LABEL_CLIENT);
  if(padRet < 0) {
    printf("Failed to decode message, got %d\n", padRet);
    return -1;
  }
  printf("padRet is %d, hash is %d bytes\n", padRet, sizeof(hash));

  printf("Decoded message:\n");
  tmp = EM;
  printf("Y:\t\t%02X\n", *tmp);
  tmp++;
  printf("Seed:\t\t");
  for(i=0; i<(int32_t)hLen; i++, tmp++)
    printf("%02X", *tmp);
  printf("\nDB/lHash':\t");
  for(i=0; i<(int32_t)hLen; i++, tmp++)
    printf("%02X", *tmp);
  printf("\nDB/PS+0x01:\t");
  for(i=0; !tmp[i]; i++)
    printf("%02X", tmp[i]);
  printf("%02X\n", tmp[i]);
  tmp += i + 1;
  printf("M:\t\t");
  for(i=0; i<padRet; i++, tmp++)
    printf("%02X", *tmp);
  printf("\n");

  free(EM);
  return 0;
}
#endif
