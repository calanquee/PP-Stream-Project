#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "paillier.h"

#define TEST_PAILLIER_KEY_BYTES 32

void init_rand(gmp_randstate_t rand, paillier_get_rand_t get_rand, int bytes){
	void * buf;
	mpz_t s;
	buf = malloc(bytes);
	get_rand(buf, bytes);
	gmp_randinit_default(rand);
	mpz_init(s);
	mpz_import(s, bytes, 1, 1, 0, 0, buf);
	gmp_randseed(rand, s);
	mpz_clear(s);
	free(buf);
}

void complete_pubkey( paillier_pubkey_t* pub ){
	mpz_mul(pub->n_squared, pub->n, pub->n); /* n_squared = n^2 */
	mpz_add_ui(pub->n_plusone, pub->n, 1); /* n_plusone = n + 1 */
	// printf("sn=%llu\n", mpz_get_si(pub->n));
	// printf("sn^2=%llu\n", mpz_get_si(pub->n_squared));
	// printf("n=%llu\n", mpz_get_ui(pub->n));
	// printf("n^2=%llu\n", mpz_get_ui(pub->n_squared));
}

void complete_prvkey( paillier_prvkey_t* prv, paillier_pubkey_t* pub ){
	mpz_powm(prv->x, pub->n_plusone, prv->lambda, pub->n_squared);
	/* x = g^lambda mod n^2 */
	mpz_sub_ui(prv->x, prv->x, 1);
	/* x = x-1 */
	mpz_div(prv->x, prv->x, pub->n);
	/* x = x/n */
	mpz_invert(prv->x, prv->x, pub->n);
	/* x = x^(-1) mod n */

}

void paillier_keygen( int modulusbits, paillier_pubkey_t** pub, paillier_prvkey_t** prv, paillier_get_rand_t get_rand ){
	mpz_t p;
	mpz_t q;
	gmp_randstate_t rand; /* a state for generating random number */
	/* allocate the new key structures */
	*pub = (paillier_pubkey_t*) malloc(sizeof(paillier_pubkey_t));
	*prv = (paillier_prvkey_t*) malloc(sizeof(paillier_prvkey_t));
	/* initialize our integers */
	mpz_init((*pub)->n);
	mpz_init((*pub)->n_squared);
	mpz_init((*pub)->n_plusone);
	mpz_init((*prv)->lambda);
	mpz_init((*prv)->x);
	mpz_init(p);
	mpz_init(q);
	/* pick random (modulusbits/2)-bit primes p and q */
	init_rand(rand, get_rand, modulusbits / 8 + 1);
	do{
		do{
			mpz_urandomb(p, rand, modulusbits / 2);
		}
		while( !mpz_probab_prime_p(p, 10));
		do{
			mpz_urandomb(q, rand, modulusbits / 2);
		}
		while( !mpz_probab_prime_p(q, 10) );
		/* compute the public modulus n = p q */
		mpz_mul((*pub)->n, p, q);
	}
	while( !mpz_tstbit((*pub)->n, modulusbits - 1) );
	complete_pubkey(*pub);
	(*pub)->bits = modulusbits;
	/* compute the private key lambda = lcm(p-1,q-1) */
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_lcm((*prv)->lambda, p, q); /* 最小公倍数 */
	complete_prvkey(*prv, *pub);
	/* clear temporary integers and randstate */
	mpz_clear(p);
	mpz_clear(q);
	gmp_randclear(rand);
}

paillier_ciphertext_t* paillier_enc(paillier_ciphertext_t* res, paillier_pubkey_t* pub, paillier_plaintext_t* pt, paillier_get_rand_t get_rand)
{
	mpz_t r;
	gmp_randstate_t rand;
	mpz_t x;
	/* pick random blinding factor */
	mpz_init(r);
	init_rand(rand, get_rand, pub->bits / 8 + 1);
	do{
		mpz_urandomb(r, rand, pub->bits);
	}
	while(mpz_cmp(r, pub->n) >= 0);
	/* compute ciphertext */
	if( !res ){
		res = (paillier_ciphertext_t*) malloc(sizeof(paillier_ciphertext_t));
		mpz_init(res->c);
	}
	mpz_init(x);
	mpz_powm(res->c, pub->n_plusone, pt->m, pub->n_squared);
	mpz_powm(x, r, pub->n, pub->n_squared);
	mpz_mul(res->c, res->c, x);
	mpz_mod(res->c, res->c, pub->n_squared);
	mpz_clear(x);
	mpz_clear(r);
	gmp_randclear(rand);
	return res;
}

paillier_plaintext_t* paillier_dec( paillier_plaintext_t* res, paillier_pubkey_t* pub, paillier_prvkey_t* prv, paillier_ciphertext_t* ct ){
	if( !res )
	{
		res = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
		mpz_init(res->m);
	}
	mpz_powm(res->m, ct->c, prv->lambda, pub->n_squared);
	/* m = c^lambda mod n^2 */
	mpz_sub_ui(res->m, res->m, 1);
	/* m = m - 1 */
	mpz_div(res->m, res->m, pub->n);
	/* m = m/n */
	mpz_mul(res->m, res->m, prv->x);
	/* m = m * x */
	mpz_mod(res->m, res->m, pub->n);
	/* m = m mod n */
	return res;
}

void paillier_add( paillier_pubkey_t* pub, paillier_ciphertext_t* res, paillier_ciphertext_t* ct0, paillier_ciphertext_t* ct1 ){
	mpz_mul(res->c, ct0->c, ct1->c);
	mpz_mod(res->c, res->c, pub->n_squared);
}

void paillier_sub( paillier_pubkey_t* pub, paillier_ciphertext_t* res, paillier_ciphertext_t* ct0, paillier_ciphertext_t* ct1 ){
	mpz_invert(ct1->c, ct1->c, pub->n_squared);
	mpz_mul(res->c, ct0->c, ct1->c);
	mpz_mod(res->c, res->c, pub->n_squared);
}

void paillier_mul( paillier_pubkey_t* pub, paillier_ciphertext_t* res, paillier_ciphertext_t* ct, paillier_plaintext_t* pt ){
	mpz_powm(res->c, ct->c, pt->m, pub->n_squared);
}

void paillier_div( paillier_pubkey_t* pub, paillier_ciphertext_t* res, paillier_ciphertext_t* ct, paillier_plaintext_t* pt ){
	mpz_invert(pt->m, pt->m, pub->n_squared);
	mpz_powm(res->c, ct->c, pt->m, pub->n_squared);
}

paillier_plaintext_t* paillier_plaintext_from_si(long int x ){ /* si: signed int */
	paillier_plaintext_t* pt;
	pt = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
	mpz_init_set_si(pt->m, x);
	return pt;
}

paillier_plaintext_t* paillier_plaintext_from_bytes( void* m, int len ){
	paillier_plaintext_t* pt;
	pt = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
	mpz_init(pt->m);
	mpz_import(pt->m, len, 1, 1, 0, 0, m);
	/* copy array m pre len btes -> m */
	return pt;
}

void* paillier_plaintext_to_bytes( int len, paillier_plaintext_t* pt ){
	void* buf0;
	void* buf1;
	size_t written; /* init for 0 */
	buf0 = mpz_export(0, &written, 1, 1, 0, 0, pt->m);
	if( written == len ){
		return buf0;
	}
	buf1 = malloc(len);
	memset(buf1, 0, len);
	if( written == 0 )
		/* no need to copy anything, pt->m = 0 and buf0 was not allocated */
		return buf1;
	else if( written < len )
		/* pad with leading zeros */
		memcpy(buf1 + (len - written), buf0, written);
	else
		/* truncate leading garbage */
		memcpy(buf1, buf0 + (written - len), len);
	free(buf0);
	return buf1;
}

paillier_plaintext_t* paillier_plaintext_from_str(char* str){
	return paillier_plaintext_from_bytes(str, strlen(str));
}

char* paillier_plaintext_to_str( paillier_plaintext_t* pt ){
	char* buf;
	size_t len;
	buf = (char*) mpz_export(0, &len, 1, 1, 0, 0, pt->m);
	buf = (char*) realloc(buf, len + 1);
	buf[len] = 0;
	return buf;
}

paillier_ciphertext_t* paillier_ciphertext_from_bytes( void* c, int len ){
	paillier_ciphertext_t* ct;
	ct = (paillier_ciphertext_t*) malloc(sizeof(paillier_ciphertext_t));
	mpz_init(ct->c);
	mpz_import(ct->c, len, 1, 1, 0, 0, c);
	ct->c_length = len;
	return ct;
}

void* paillier_ciphertext_to_bytes( int len, paillier_ciphertext_t* ct ){
	void* buf;
	int cur_len;
	cur_len = mpz_sizeinbase(ct->c, 2);
	cur_len = PAILLIER_BITS_TO_BYTES(cur_len);
	buf = malloc(len);
	memset(buf, 0, len);
	mpz_export(buf + (len - cur_len), 0, 1, 1, 0, 0, ct->c);
	return buf;
}

char* paillier_ciphertext_to_str( paillier_ciphertext_t* ct ){
	char* buf;
	size_t len;
	buf = (char*) mpz_export(0, &len, 1, 1, 0, 0, ct->c);
	buf = (char*) realloc(buf, len);
	ct->c_length = len;
	return buf;
}
paillier_ciphertext_t* paillier_ciphertext_from_str(char* str,int c_length){
//	printf("paillier strlen(cipher) = %d\n",strlen(str));
//	return paillier_ciphertext_from_bytes(str, strlen(str));
	return paillier_ciphertext_from_bytes(str, c_length);
}


void paillier_pubkey_to_hex(char * pub_key, paillier_pubkey_t* pub){
	mpz_get_str(pub_key, TEST_PAILLIER_KEY_BYTES, pub->n);
}

void paillier_prvkey_to_hex(char * priv_key, paillier_prvkey_t* prv){
	mpz_get_str(priv_key, TEST_PAILLIER_KEY_BYTES, prv->lambda);
}

paillier_pubkey_t* paillier_pubkey_from_hex(char* str){
	paillier_pubkey_t* pub;
	pub = (paillier_pubkey_t*) malloc(sizeof(paillier_pubkey_t));
	mpz_init_set_str(pub->n, str, TEST_PAILLIER_KEY_BYTES);
	pub->bits = mpz_sizeinbase(pub->n, 2);
	mpz_init(pub->n_squared);
	mpz_init(pub->n_plusone);
	complete_pubkey(pub);
	// printf("n=%lld\n", pub->n);
	// printf("n^2=%lld\n", pub->n_squared);
	return pub;
}

paillier_prvkey_t* paillier_prvkey_from_hex( char* str, paillier_pubkey_t* pub ){
	paillier_prvkey_t* prv;
	prv = (paillier_prvkey_t*) malloc(sizeof(paillier_prvkey_t));
	mpz_init_set_str(prv->lambda, str, TEST_PAILLIER_KEY_BYTES);
	mpz_init(prv->x);
	complete_prvkey(prv, pub);
	return prv;
}

void paillier_freepubkey(paillier_pubkey_t* pub){
	mpz_clear(pub->n);
	mpz_clear(pub->n_squared);
	mpz_clear(pub->n_plusone);
	free(pub);
}

void paillier_freeprvkey(paillier_prvkey_t* prv){
	mpz_clear(prv->lambda);
	mpz_clear(prv->x);
	free(prv);
}

void paillier_freeplaintext(paillier_plaintext_t* pt){
	mpz_clear(pt->m);
	free(pt);
}

void paillier_freeciphertext(paillier_ciphertext_t* ct){
	mpz_clear(ct->c);
	free(ct);
}

void paillier_get_rand_file(void* buf, int len, char* file){
	FILE* fp;
	void* p;
	fp = fopen(file, "r");
	p = buf;
	while( len )
	{
		size_t s;
		s = fread(p, 1, len, fp);
		p += s;
		len -= s;
	}
	fclose(fp);
}

void paillier_get_rand_devrandom(void* buf, int len){
	paillier_get_rand_file(buf, len, (char *)"/dev/random");
}

void paillier_get_rand_devurandom(void* buf, int len){
	paillier_get_rand_file(buf, len, (char *)"/dev/urandom");
}

paillier_ciphertext_t* paillier_create_enc_zero(){
	paillier_ciphertext_t* ct;
	/* make a NON-RERANDOMIZED encryption of zero for the purposes of
		 homomorphic computation */
	/* note that this is just the number 1 */
	ct = (paillier_ciphertext_t*) malloc(sizeof(paillier_ciphertext_t));
	mpz_init_set_ui(ct->c, 1);
	return ct;
}