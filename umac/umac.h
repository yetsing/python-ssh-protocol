/* -----------------------------------------------------------------------
 * 
 * umac.h -- C Implementation UMAC Message Authentication
 *
 * Version 0.90 of draft-krovetz-umac-03.txt -- 2004 October
 *
 * For a full description of UMAC message authentication see the UMAC
 * world-wide-web page at http://www.cs.ucdavis.edu/~rogaway/umac
 * Please report bugs and suggestions to the UMAC webpage.
 *
 * Copyright (c) 1999-2004 Ted Krovetz
 *                                                                 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and with or without fee, is hereby
 * granted provided that the above copyright notice appears in all copies
 * and in supporting documentation, and that the name of the copyright
 * holder not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior permission.
 *
 * Comments should be directed to Ted Krovetz (tdk@acm.org)                                        
 *                                                                   
 * ---------------------------------------------------------------------- */
 
 /* ////////////////////// IMPORTANT NOTES /////////////////////////////////
  *
  * 1) This version does not work properly on messages larger than 16MB
  *
  * 2) If you set the switch to use SSE2, then all data must be 16-byte
  *    aligned
  *
  * 3) When calling the function umac(), it is assumed that msg is in
  * a writable buffer of length divisible by 32 bytes. The message itself
  * does not have to fill the entire buffer, but bytes beyond msg may be
  * zeroed.
  *
  * 4) Two free AES implementations are supported by this implementation of
  * UMAC. Paulo Barreto's version is in the public domain and can be found
  * at http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ (search for
  * "Barreto"). The only two files needed are rijndael-alg-fst.c and
  * rijndael-alg-fst.h.
  * Brian Gladman's version is distributed with GNU Public lisence
  * and can be found at http://fp.gladman.plus.com/AES/index.htm. It
  * includes a fast IA-32 assembly version.
  *
  /////////////////////////////////////////////////////////////////////// */


#ifdef __cplusplus
    extern "C" {
#endif

typedef struct umac_ctx *umac_ctx_t;

umac_ctx_t umac_new(const char key[]);
/* Dynamically allocate a umac_ctx struct, initialize variables, 
 * generate subkeys from key.
 */

#if 0
int umac_reset(umac_ctx_t ctx);
/* Reset a umac_ctx to begin authenicating a new message */
#endif

int umac_update(umac_ctx_t ctx, const char *input, long len);
/* Incorporate len bytes pointed to by input into context ctx */

int umac_final(umac_ctx_t ctx, char tag[], const char nonce[8]);
/* Incorporate any pending data and the ctr value, and return tag. 
 * This function returns error code if ctr < 0. 
 */

int umac_delete(umac_ctx_t ctx);
/* Deallocate the context structure */

#if 0
int umac(umac_ctx_t ctx, char *input, 
         long len, char tag[],
         char nonce[8]);
/* All-in-one implementation of the functions Reset, Update and Final */
#endif


/* uhash.h */


#if 0
typedef struct uhash_ctx *uhash_ctx_t;
  /* The uhash_ctx structure is defined by the implementation of the    */
  /* UHASH functions.                                                   */

uhash_ctx_t uhash_alloc(char key[16]);
  /* Dynamically allocate a uhash_ctx struct and generate subkeys using */
  /* the kdf and kdf_key passed in. If kdf_key_len is 0 then RC6 is     */
  /* used to generate key with a fixed key. If kdf_key_len > 0 but kdf  */
  /* is NULL then the first 16 bytes pointed at by kdf_key is used as a */
  /* key for an RC6 based KDF.                                          */
  
int uhash_free(uhash_ctx_t ctx);

int uhash_set_params(uhash_ctx_t ctx,
                   void       *params);

int uhash_reset(uhash_ctx_t ctx);

int uhash_update(uhash_ctx_t ctx,
               char       *input,
               long        len);

int uhash_final(uhash_ctx_t ctx,
              char        ouput[]);

int uhash(uhash_ctx_t ctx,
        char       *input,
        long        len,
        char        output[]);
#endif

/* matching umac-128 API, we reuse umac_ctx, since it's opaque */
umac_ctx_t umac128_new(const char key[]);
int umac128_update(umac_ctx_t ctx, const char *input, long len);
int umac128_final(umac_ctx_t ctx, char tag[], const char nonce[8]);
int umac128_delete(umac_ctx_t ctx);

#ifdef __cplusplus
    }
#endif
