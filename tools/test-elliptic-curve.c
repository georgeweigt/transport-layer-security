#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ssl_malloc malloc

#include "../src/ssl.h"
#include "../src/cert.h"
#include "../src/ec.h"

void ecdhe256_generate(struct ssl_session *p, unsigned char *x, unsigned char *y);
void ecdhe384_generate(struct ssl_session *p, unsigned char *x, unsigned char *y);
int ecdsa256_verify(struct certinfo *p, struct certinfo *q, unsigned char *hash, int hashlen);
int ecdhe256_verify_hash(unsigned char *hash, int hashlen, unsigned char *rr, int r_length, unsigned char *ss, int s_length, unsigned char *xx, unsigned char *yy);
int ecdsa256_verify_f(unsigned *h, unsigned *r, unsigned *s, unsigned *x, unsigned *y);
void ecdsa256_sign_f(unsigned *h, unsigned *d, unsigned char *sig);
int ecdsa384_verify(struct certinfo *p, struct certinfo *q, unsigned char *hash, int hashlen);
int ecdhe384_verify_hash(unsigned char *hash, int hashlen, unsigned char *rr, int r_length, unsigned char *ss, int s_length, unsigned char *xx, unsigned char *yy);
int ecdsa384_verify_f(unsigned *h, unsigned *r, unsigned *s, unsigned *x, unsigned *y);
void ecdsa384_sign_f(unsigned *h, unsigned *d, unsigned char *sig);
void ec_init(void);
unsigned int * ec_modinv(unsigned int *c, unsigned int *p);
void ec_projectify(struct point *S);
int ec_affinify(struct point *S, unsigned *p);
void ec_double(struct point *R, struct point *S, unsigned *p);
void ec_add_xyz(struct point *R, struct point *S, struct point *T, unsigned *p);
void ec_full_add(struct point *R, struct point *S, struct point *T, unsigned *p);
void ec_full_sub(struct point *R, struct point *S, struct point *T, unsigned *p);
void ec_mult(struct point *R, unsigned *d, struct point *S, unsigned *p);
int ec_get_msbit_index(unsigned *u);
int ec_get_bit(unsigned *u, int k);
int ec_F(int t);
void ec_twin_mult(struct point *R, unsigned *d0, struct point *S, unsigned *d1, struct point *T, unsigned *p);
void ec_free_xyz(struct point *u);
unsigned * ec_add(unsigned *u, unsigned *v);
unsigned * ec_sub(unsigned *u, unsigned *v);
unsigned * ec_mul(unsigned *u, unsigned *v);
unsigned * ec_div(unsigned *u, unsigned *v);
void ec_mod(unsigned *u, unsigned *v);
unsigned * ec_pow(unsigned *u, unsigned *v);
void ec_shr(unsigned *u);
int ec_cmp(unsigned *u, unsigned *v);
int ec_equal(unsigned *u, unsigned v);
unsigned * ec_int(int k);
unsigned * ec_new(int n);
void ec_free(unsigned *p);
unsigned * ec_dup(unsigned *u);
void ec_norm(unsigned *u);
unsigned * ec_hexstr_to_bignum(char *s);
unsigned * ec_buf_to_bignum(unsigned char *buf, int len);
void ec_test(void);
void ec_test_full_add(void);
void ec_test_full_sub(void);
void ec_test_double(void);
void ec_test_mult(void);
void ec_test_twin_mult(void);
void ec_test256(void);
void ec_test384(void);
void ecdh_test(void);

#include "../src/ec.c"

int
main(void)
{
	ec_init();
	ec_test();
}
