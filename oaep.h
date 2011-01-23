#ifndef _OAEP_H
#define _OAEP_H

typedef enum _lbl_t {
  LABEL_CLIENT = 0,
  LABEL_SERVER
} lbl_t;

/*
oaep_encode: pad a message M to the appropriate length for a given key
Arguments:
       M: the message to be encoded; must be exactly mLen bytes long
       k: the length in octets of the RSA modulus n; must be >= 74 (592 bits)
   label: one of two possible labels "CLNT" or "SRVR" (as above in lbl_t)
      EM: preallocated storage for the encoded message; must be at least k bytes long
Returns 0 on success.
Returns on error:
      -1: message too long (for the given key length)
      -2: unable to allocate memory
      -3: unable to obtain random bytes
*/
int32_t oaep_encode(uint8_t *M, uint32_t mLen, uint32_t k, lbl_t label, uint8_t *EM);

/*
oaep_decode: reverse the padding operation done in oaep_encode
  This function modifies the data pointed to by EM.
  The message M will be the final bytes in EM when this returns with success.
Arguments:
      EM: the encoded message
       k: the length in octets of the message EM (and the RSA modulus n)
   label: one of two possible labels "CLNT" or "SRVR" (as above in lbl_t)
Returns the length of the message M on success.
Returns on error:
      -2: unable to allocate memory
      -5: decoding or decryption error
*/
int32_t oaep_decode(uint8_t *EM, uint32_t k, lbl_t label);

#endif /* _OAEP_H */
