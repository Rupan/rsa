#ifndef _TIGER_H
#define _TIGER_H

/* the length of the Tiger hash */
const uint32_t hLen = (192/8);

/*
Arguments:
       1: input, a pointer to the data to be hashed
       2: length, the input's size in octets
       3: result, preallocated storage with hLen bytes
*/
void tiger(uint8_t *, uint64_t, uint8_t *);

#endif /* _TIGER_H */
