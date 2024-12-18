#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <gmpxx.h>
#include "time.h"
#include <cryptoTools/Common/Defines.h>
// #include "rb_okvs.h"

const uint32_t PRIME_LENGTH = 512 * 2;
const uint32_t GM_CIPHER_LENGTH_BYTES = 128 * 2;
const uint32_t GM_CIPHER_LENGTH_BLOCKS = 8 * 2;

/* The Goldwasser - Micali public key, is the tuple of the modulus N (where N is a composite number, which is the product
 * of two primes, p,q , i.e N=p*q) and the number a, where a is a quadratic nonresidue modulo N, chosen at random, so that 
 * the Legendre symbols (a/p) and (a/q) are both equal to -1, therefore, the Jacobi symbol (a/p*q) = (a/N) is equal to 1
 */

/* The Goldwasser - Micali public key, is the tuple (a,N) */    
typedef struct pubkey_s
{
        mpz_t N; // the modulus, where N=p*q
        mpz_t a; // the quadratic nonresidue modulo N
}pubkey_t;

/* The Goldwasser - Micali private key, is the tuple of the two prime factors of the composite number N */
typedef struct privkey_s
{
        mpz_t p;
        mpz_t q;
}privkey_t;


/* Functions */


void gen_keys(pubkey_t*, privkey_t*);

mpz_t *enc_bit(mpz_t*, unsigned short, pubkey_t*);

mpz_t **enc_bitstream(mpz_t**, unsigned short*, unsigned short, pubkey_t*); // the message consists of **msg_size** bits

unsigned short *dec_bit(unsigned short*, mpz_t*, privkey_t*);

unsigned short **dec_bitstream(unsigned short**, mpz_t**, unsigned short, privkey_t*);

mpz_t *xor_on_cipher(mpz_t *cyphertext, mpz_t *cyphertext_a, mpz_t *cyphertext_b, pubkey_t *pbkey);

mpz_t **xor_on_cipher_bitstream(mpz_t **cyphertext, mpz_t **cyphertext_a, mpz_t **cyphertext_b, unsigned short msg_size, pubkey_t *pbkey);

void gm_cipher_to_block_vector(const  mpz_t *cyphertext, oc::block* block_vec);

void block_vector_to_gm_cipher(const oc::block* block_vec, mpz_t *cyphertext);
