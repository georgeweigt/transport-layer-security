// Elliptic curve functions
//
// ec_init()			Initialize curve parameters
//
// ecdsa256_verify()		Verify certificate signature
// ecdsa384_verify()
//
// ecdhe256_generate()		Generate ephemeral public key and pre-master secret
// ecdhe384_generate()
//
// ecdhe256_verify_hash()	Verify emphemeral key hash
// ecdhe384_verify_hash()

#define len(p) (p)[-1]
static int ec_malloc_count;
static unsigned *p256, *q256, *gx256, *gy256;
static unsigned *p384, *q384, *gx384, *gy384;

// generate ephemeral key and pre-master secret
//
//	x, y	public key from remote machine

void
ecdhe256_generate(struct ssl_session *p, unsigned char *x, unsigned char *y)
{
	int err, i;
	unsigned *d;
	struct point R, S;

	p->ephemeral_key = ssl_malloc(64);

	bzero(p->ephemeral_key, 64);

	R.x = gx256;
	R.y = gy256;
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	d = ec_new(8);

	do {
		// generate private key d

		for (i = 0; i < 8; i++)
			d[i] = random();

		ec_norm(d);
		ec_mod(d, q256);

		if (ec_equal(d, 0))
			continue;

		// generate public key

		ec_mult(&S, d, &R, p256);
		err = ec_affinify(&S, p256);

	} while (err);

	// save public key for client_key_exchange message

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // buffer overrun
		p->ephemeral_key[32 - 4 * i - 4] = S.x[i] >> 24;
		p->ephemeral_key[32 - 4 * i - 3] = S.x[i] >> 16;
		p->ephemeral_key[32 - 4 * i - 2] = S.x[i] >> 8;
		p->ephemeral_key[32 - 4 * i - 1] = S.x[i];
	}

	for (i = 0; i < len(S.y); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // buffer overrun
		p->ephemeral_key[64 - 4 * i - 4] = S.y[i] >> 24;
		p->ephemeral_key[64 - 4 * i - 3] = S.y[i] >> 16;
		p->ephemeral_key[64 - 4 * i - 2] = S.y[i] >> 8;
		p->ephemeral_key[64 - 4 * i - 1] = S.y[i];
	}

	// generate pre-master secret

	R.x = ec_buf_to_bignum(x, 32);
	R.y = ec_buf_to_bignum(y, 32);

	ec_mult(&S, d, &R, p256);
	ec_affinify(&S, p256);

	bzero(p->secret, 48);

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // buffer overrun
		p->secret[32 - 4 * i - 4] = S.x[i] >> 24;
		p->secret[32 - 4 * i - 3] = S.x[i] >> 16;
		p->secret[32 - 4 * i - 2] = S.x[i] >> 8;
		p->secret[32 - 4 * i - 1] = S.x[i];
	}

	ec_free(d);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
}

// generate ephemeral key and pre-master secret
//
//	x, y	public key from remote machine

void
ecdhe384_generate(struct ssl_session *p, unsigned char *x, unsigned char *y)
{
	int err, i;
	unsigned *d;
	struct point R, S;

	p->ephemeral_key = ssl_malloc(96);

	bzero(p->ephemeral_key, 96);

	R.x = gx384;
	R.y = gy384;
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	d = ec_new(12);

	do {
		// generate private key d

		for (i = 0; i < 12; i++)
			d[i] = random();

		ec_norm(d);
		ec_mod(d, q384);

		if (ec_equal(d, 0))
			continue;

		// generate public key

		ec_mult(&S, d, &R, p384);
		err = ec_affinify(&S, p384);

	} while (err);

	// save public key for client_key_exchange message

	for (i = 0; i < len(S.x); i++) {
		if (48 - 4 * i - 4 < 0)
			break; // buffer overrun
		p->ephemeral_key[48 - 4 * i - 4] = S.x[i] >> 24;
		p->ephemeral_key[48 - 4 * i - 3] = S.x[i] >> 16;
		p->ephemeral_key[48 - 4 * i - 2] = S.x[i] >> 8;
		p->ephemeral_key[48 - 4 * i - 1] = S.x[i];
	}

	for (i = 0; i < len(S.y); i++) {
		if (48 - 4 * i - 4 < 0)
			break; // buffer overrun
		p->ephemeral_key[96 - 4 * i - 4] = S.y[i] >> 24;
		p->ephemeral_key[96 - 4 * i - 3] = S.y[i] >> 16;
		p->ephemeral_key[96 - 4 * i - 2] = S.y[i] >> 8;
		p->ephemeral_key[96 - 4 * i - 1] = S.y[i];
	}

	// generate pre-master secret

	R.x = ec_buf_to_bignum(x, 48);
	R.y = ec_buf_to_bignum(y, 48);

	ec_mult(&S, d, &R, p384);
	ec_affinify(&S, p384);

	bzero(p->secret, 48);

	for (i = 0; i < len(S.x); i++) {
		if (48 - 4 * i - 4 < 0)
			break; // buffer overrun
		p->secret[48 - 4 * i - 4] = S.x[i] >> 24;
		p->secret[48 - 4 * i - 3] = S.x[i] >> 16;
		p->secret[48 - 4 * i - 2] = S.x[i] >> 8;
		p->secret[48 - 4 * i - 1] = S.x[i];
	}

	ec_free(d);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
}

// returns 0 for ok, -1 otherwise

// p is the subject, q is the issuer

int
ecdsa256_verify(struct certinfo *p, struct certinfo *q, unsigned char *hash, int hashlen)
{
	int err;
	unsigned *h, *r, *s, *x, *y;

	if ((q->ec_key_length - 1) / 2 != 32)
		return -1;

	if (p->r_length == 0 || p->s_length == 0)
		return -1;

	if (hashlen > 32)
		hashlen = 32;

	h = ec_buf_to_bignum(hash, hashlen);

	r = ec_buf_to_bignum(p->cert + p->r_offset, p->r_length);
	s = ec_buf_to_bignum(p->cert + p->s_offset, p->s_length);

	x = ec_buf_to_bignum(q->cert + q->ec_key_offset + 1, 32);
	y = ec_buf_to_bignum(q->cert + q->ec_key_offset + 33, 32);

	err = ecdsa256_verify_f(h, r, s, x, y);

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);

	return err;
}

// returns 0 for ok, -1 otherwise

int
ecdhe256_verify_hash(unsigned char *hash, int hashlen, unsigned char *rr, int r_length, unsigned char *ss, int s_length, unsigned char *xx, unsigned char *yy)
{
	int err;
	unsigned *h, *r, *s, *x, *y;

	if (hashlen > 32)
		hashlen = 32;

	h = ec_buf_to_bignum(hash, hashlen);

	r = ec_buf_to_bignum(rr, r_length);
	s = ec_buf_to_bignum(ss, s_length);

	x = ec_buf_to_bignum(xx, 32);
	y = ec_buf_to_bignum(yy, 32);

	err = ecdsa256_verify_f(h, r, s, x, y);

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);

	return err;
}

// Returns 0 for ok, -1 otherwise
//
// All arguments are bignums
//
//	h	hash of certificate
//
//	r, s	signature
//
//	x, y	public key

int
ecdsa256_verify_f(unsigned *h, unsigned *r, unsigned *s, unsigned *x, unsigned *y)
{
	int err;
	unsigned *u, *v, *w;
	struct point R, S, T;

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = gx256;
	S.y = gy256;
	S.z = ec_int(1);

	T.x = x;
	T.y = y;
	T.z = ec_int(1);

	w = ec_modinv(s, q256);

	u = ec_mul(h, w);
	ec_mod(u, q256);

	v = ec_mul(r, w);
	ec_mod(v, q256);

	ec_twin_mult(&R, u, &S, v, &T, p256);

	ec_affinify(&R, p256);

	ec_mod(R.x, q256);

	if (ec_cmp(R.x, r) == 0)
		err = 0;
	else
		err = -1;

	ec_free_xyz(&R);

	ec_free(S.z);
	ec_free(T.z);
	ec_free(u);
	ec_free(v);
	ec_free(w);

	return err;
}

/* All arguments are bignums

	h	hash of certificate

	d	private key

	sig	pointer to 64-byte buffer
*/

void
ecdsa256_sign_f(unsigned *h, unsigned *d, unsigned char *sig)
{
	int i;
	unsigned *k, *r, *s, *t;
	struct point G, R;

	G.x = gx256;
	G.y = gy256;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	for (;;) {

		// choose k from [1, n - 1]

		k = ec_new(8);
		for (i = 0; i < 8; i++)
			k[i] = random();
		ec_norm(k);
		ec_mod(k, q256);
		if (ec_equal(k, 0)) {
			ec_free(k);
			continue;
		}

		// R = k * G

		ec_mult(&R, k, &G, p256);
		ec_affinify(&R, p256);

		// r = R.x mod n

		r = ec_dup(R.x);
		ec_mod(r, q256);

		if (ec_equal(r, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free_xyz(&R);
			continue;
		}

		// k = 1 / k

		t = ec_modinv(k, q256);
		ec_free(k);
		k = t;

		// s = k * (h + r * d) mod n

		s = ec_mul(r, d);
		ec_mod(s, q256);

		t = ec_add(h, s);
		ec_free(s);
		s = t;
		ec_mod(s, q256);

		t = ec_mul(k, s);
		ec_free(s);
		s = t;
		ec_mod(s, q256);

		if (ec_equal(s, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free(s);
			ec_free_xyz(&R);
			continue;
		}

		break;
	}

	// the signature is the pair (r, s)

	bzero(sig, 64);

	for (i = 0; i < len(r); i++) {
		sig[32 - 4 * i - 4] = r[i] >> 24;
		sig[32 - 4 * i - 3] = r[i] >> 16;
		sig[32 - 4 * i - 2] = r[i] >> 8;
		sig[32 - 4 * i - 1] = r[i];
	}

	for (i = 0; i < len(s); i++) {
		sig[64 - 4 * i - 4] = s[i] >> 24;
		sig[64 - 4 * i - 3] = s[i] >> 16;
		sig[64 - 4 * i - 2] = s[i] >> 8;
		sig[64 - 4 * i - 1] = s[i];
	}

	ec_free(k);
	ec_free(r);
	ec_free(s);

	ec_free(G.z);

	ec_free_xyz(&R);
}

// returns 0 for ok, -1 otherwise

// p is the subject, q is the issuer

int
ecdsa384_verify(struct certinfo *p, struct certinfo *q, unsigned char *hash, int hashlen)
{
	int err;
	unsigned *h, *r, *s, *x, *y;

	if ((q->ec_key_length - 1) / 2 != 48)
		return -1;

	if (p->r_length == 0 || p->s_length == 0)
		return -1;

	if (hashlen > 48)
		hashlen = 48;

	h = ec_buf_to_bignum(hash, hashlen);

	r = ec_buf_to_bignum(p->cert + p->r_offset, p->r_length);
	s = ec_buf_to_bignum(p->cert + p->s_offset, p->s_length);

	x = ec_buf_to_bignum(q->cert + q->ec_key_offset + 1, 48);
	y = ec_buf_to_bignum(q->cert + q->ec_key_offset + 49, 48);

	err = ecdsa384_verify_f(h, r, s, x, y);

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);

	return err;
}

// returns 0 for ok, -1 otherwise

int
ecdhe384_verify_hash(unsigned char *hash, int hashlen, unsigned char *rr, int r_length, unsigned char *ss, int s_length, unsigned char *xx, unsigned char *yy)
{
	int err;
	unsigned *h, *r, *s, *x, *y;

	if (hashlen > 48)
		hashlen = 48;

	h = ec_buf_to_bignum(hash, hashlen);

	r = ec_buf_to_bignum(rr, r_length);
	s = ec_buf_to_bignum(ss, s_length);

	x = ec_buf_to_bignum(xx, 48);
	y = ec_buf_to_bignum(yy, 48);

	err = ecdsa384_verify_f(h, r, s, x, y);

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);

	return err;
}

// Returns 0 for ok, -1 otherwise
//
// All arguments are bignums
//
//	h	hash of certificate
//
//	r, s	signature
//
//	x, y	public key

int
ecdsa384_verify_f(unsigned *h, unsigned *r, unsigned *s, unsigned *x, unsigned *y)
{
	int err;
	unsigned *u, *v, *w;
	struct point R, S, T;

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = gx384;
	S.y = gy384;
	S.z = ec_int(1);

	T.x = x;
	T.y = y;
	T.z = ec_int(1);

	w = ec_modinv(s, q384);

	u = ec_mul(h, w);
	ec_mod(u, q384);

	v = ec_mul(r, w);
	ec_mod(v, q384);

	ec_twin_mult(&R, u, &S, v, &T, p384);

	ec_affinify(&R, p384);

	ec_mod(R.x, q384);

	if (ec_cmp(R.x, r) == 0)
		err = 0;
	else
		err = -1;

	ec_free_xyz(&R);

	ec_free(S.z);
	ec_free(T.z);
	ec_free(u);
	ec_free(v);
	ec_free(w);

	return err;
}

/* All arguments are bignums

	h	hash of certificate

	d	private key

	sig	pointer to 96-byte buffer
*/

void
ecdsa384_sign_f(unsigned *h, unsigned *d, unsigned char *sig)
{
	int i;
	unsigned *k, *r, *s, *t;
	struct point G, R;

	G.x = gx384;
	G.y = gy384;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	for (;;) {

		// choose k from [1, n - 1]

		k = ec_new(12);
		for (i = 0; i < 12; i++)
			k[i] = random();
		ec_norm(k);
		ec_mod(k, q384);
		if (ec_equal(k, 0)) {
			ec_free(k);
			continue;
		}

		// R = k * G

		ec_mult(&R, k, &G, p384);
		ec_affinify(&R, p384);

		// r = R.x mod n

		r = ec_dup(R.x);
		ec_mod(r, q384);

		if (ec_equal(r, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free_xyz(&R);
			continue;
		}

		// k = 1 / k

		t = ec_modinv(k, q384);
		ec_free(k);
		k = t;

		// s = k * (h + r * d) mod n

		s = ec_mul(r, d);
		ec_mod(s, q384);

		t = ec_add(h, s);
		ec_free(s);
		s = t;
		ec_mod(s, q384);

		t = ec_mul(k, s);
		ec_free(s);
		s = t;
		ec_mod(s, q384);

		if (ec_equal(s, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free(s);
			ec_free_xyz(&R);
			continue;
		}

		break;
	}

	// the signature is the pair (r, s)

	bzero(sig, 96);

	for (i = 0; i < len(r); i++) {
		sig[48 - 4 * i - 4] = r[i] >> 24;
		sig[48 - 4 * i - 3] = r[i] >> 16;
		sig[48 - 4 * i - 2] = r[i] >> 8;
		sig[48 - 4 * i - 1] = r[i];
	}

	for (i = 0; i < len(s); i++) {
		sig[96 - 4 * i - 4] = s[i] >> 24;
		sig[96 - 4 * i - 3] = s[i] >> 16;
		sig[96 - 4 * i - 2] = s[i] >> 8;
		sig[96 - 4 * i - 1] = s[i];
	}

	ec_free(k);
	ec_free(r);
	ec_free(s);

	ec_free(G.z);

	ec_free_xyz(&R);
}

static char *str_p256 =
	"ffffffff00000001000000000000000000000000ffffffff"
	"ffffffffffffffff";

static char *str_q256 =
	"ffffffff00000000ffffffffffffffffbce6faada7179e84"
	"f3b9cac2fc632551";

static char *str_gx256 =
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0"
	"f4a13945d898c296";

static char *str_gy256 =
	"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ece"
	"cbb6406837bf51f5";

static char *str_p384 =
	"ffffffffffffffffffffffffffffffffffffffffffffffff"
	"fffffffffffffffeffffffff0000000000000000ffffffff";

static char *str_q384 =
	"ffffffffffffffffffffffffffffffffffffffffffffffff"
	"c7634d81f4372ddf581a0db248b0a77aecec196accc52973";

static char *str_gx384 =
	"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98"
	"59f741e082542a385502f25dbf55296c3a545e3872760ab7";

static char *str_gy384 =
	"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c"
	"e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";

void
ec_init(void)
{
	p256 = ec_hexstr_to_bignum(str_p256);
	q256 = ec_hexstr_to_bignum(str_q256);
	gx256 = ec_hexstr_to_bignum(str_gx256);
	gy256 = ec_hexstr_to_bignum(str_gy256);

	p384 = ec_hexstr_to_bignum(str_p384);
	q384 = ec_hexstr_to_bignum(str_q384);
	gx384 = ec_hexstr_to_bignum(str_gx384);
	gy384 = ec_hexstr_to_bignum(str_gy384);
}

// returns 1/c mod p

unsigned int *
ec_modinv(unsigned int *c, unsigned int *p)
{
	unsigned *k, *r, *u, *v, *t, *x1, *x2;
	u = ec_dup(c);
	v = ec_dup(p);
	x1 = ec_int(1);
	x2 = ec_int(0);
	while (!ec_equal(u, 1) && !ec_equal(v, 1)) {
		while ((u[0] & 1) == 0) {
			ec_shr(u);
			if (x1[0] & 1) {
				t = ec_add(x1, p);
				ec_free(x1);
				x1 = t;
			}
			ec_shr(x1);
		}
		while ((v[0] & 1) == 0) {
			ec_shr(v);
			if (x2[0] & 1) {
				t = ec_add(x2, p);
				ec_free(x2);
				x2 = t;
			}
			ec_shr(x2);
		}
		if (ec_cmp(u, v) >= 0) {
			t = ec_sub(u, v);
			ec_free(u);
			u = t;
			// x1 = x1 - x2
			k = ec_sub(p, x2);
			t = ec_add(x1, k);
			ec_free(x1);
			x1 = t;
			ec_mod(x1, p);
			ec_free(k);
		} else {
			t = ec_sub(v, u);
			ec_free(v);
			v = t;
			// x2 = x2 - x1
			k = ec_sub(p, x1);
			t = ec_add(x2, k);
			ec_free(x2);
			x2 = t;
			ec_mod(x2, p);
			ec_free(k);
		}
	}
	if (ec_equal(u, 1)) {
		r = x1;
		ec_free(x2);
	} else {
		r = x2;
		ec_free(x1);
	}
	ec_free(u);
	ec_free(v);
	return r;
}

void
ec_projectify(struct point *S)
{
	ec_free(S->z);
	S->z = ec_int(1);
}

int
ec_affinify(struct point *S, unsigned *p)
{
	unsigned *lambda, *lambda2, *lambda3, *x, *y;

	if (ec_equal(S->z, 0))
		return -1;

	lambda = ec_modinv(S->z, p);

	lambda2 = ec_mul(lambda, lambda);
	ec_mod(lambda2, p);

	lambda3 = ec_mul(lambda2, lambda);
	ec_mod(lambda3, p);

	x = ec_mul(lambda2, S->x);
	ec_mod(x, p);

	y = ec_mul(lambda3, S->y);
	ec_mod(y, p);

	ec_free_xyz(S);

	S->x = x;
	S->y = y;

	ec_free(lambda);
	ec_free(lambda2);
	ec_free(lambda3);

	return 0;
}

void
ec_double(struct point *R, struct point *S, unsigned *p)
{
	unsigned *k, *t, *t1, *t2, *t3, *t4, *t5;

	// take care to handle the case when R and S are the same pointer

	t1 = ec_dup(S->x);
	t2 = ec_dup(S->y);
	t3 = ec_dup(S->z);

	ec_free_xyz(R);

	if (ec_equal(t3, 0)) {
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		ec_free(t1);
		ec_free(t2);
		ec_free(t3);
		return;
	}

	// 7: t4 = t3 * t3

	t4 = ec_mul(t3, t3);
	ec_mod(t4, p);

	// 8: t5 = t1 - t4

	t = ec_sub(p, t4);
	t5 = ec_add(t1, t);
	ec_free(t);
	ec_mod(t5, p);

	// 9: t4 = t1 + t4

	t = ec_add(t1, t4);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 10: t5 = t4 * t5

	t = ec_mul(t4, t5);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 11: t4 = 3 * t5

	k = ec_int(3);
	ec_free(t4);
	t4 = ec_mul(k, t5);
	ec_free(k);
	ec_mod(t4, p);

	// 12: t3 = t3 * t2

	t = ec_mul(t3, t2);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 13: t3 = 2 * t3

	t = ec_add(t3, t3);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 14: t2 = t2 * t2

	t = ec_mul(t2, t2);
	ec_free(t2);
	t2 = t;
	ec_mod(t2, p);

	// 15: t5 = t1 * t2

	t = ec_mul(t1, t2);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 16: t5 = 4 * t5

	k = ec_int(4);
	t = ec_mul(k, t5);
	ec_free(t5);
	t5 = t;
	ec_free(k);
	ec_mod(t5, p);

	// 17: t1 = t4 * t4

	ec_free(t1);
	t1 = ec_mul(t4, t4);
	ec_mod(t1, p);

	// 18: t1 = t1 - 2 * t5

	k = ec_sub(p, t5);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = ec_add(t, k);
	ec_free(k);
	ec_free(t);
	ec_mod(t1, p);

	// 19: t2 = t2 * t2

	t = ec_mul(t2, t2);
	ec_free(t2);
	t2 = t;
	ec_mod(t2, p);

	// 20: t2 = 8 * t2

	k = ec_int(8);
	t = ec_mul(k, t2);
	ec_free(t2);
	t2 = t;
	ec_free(k);
	ec_mod(t2, p);

	// 21: t5 = t5 - t1

	k = ec_sub(p, t1);
	t = ec_add(t5, k);
	ec_free(t5);
	t5 = t;
	ec_free(k);
	ec_mod(t5, p);

	// 22: t5 = t4 * t5

	t = ec_mul(t4, t5);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 23: t2 = t5 - t2

	t = ec_sub(p, t2);
	ec_free(t2);
	t2 = ec_add(t5, t);
	ec_free(t);
	ec_mod(t2, p);

	R->x = t1;
	R->y = t2;
	R->z = t3;

	ec_free(t4);
	ec_free(t5);
}

void
ec_add_xyz(struct point *R, struct point *S, struct point *T, unsigned *p)
{
	unsigned *k, *t, *t1, *t2, *t3, *t4, *t5, *t6, *t7;

	t1 = ec_dup(S->x);
	t2 = ec_dup(S->y);
	t3 = ec_dup(S->z);

	t4 = ec_dup(T->x);
	t5 = ec_dup(T->y);
	t6 = ec_dup(T->z);

	ec_free_xyz(R);

	if (!ec_equal(t6, 1)) {

		// 4: t7 = t6 * t6

		t7 = ec_mul(t6, t6);
		ec_mod(t7, p);

		// 5: t1 = t1 * t7

		t = ec_mul(t1, t7);
		ec_free(t1);
		t1 = t;
		ec_mod(t1, p);

		// 6: t7 = t6 * t7

		t = ec_mul(t6, t7);
		ec_free(t7);
		t7 = t;
		ec_mod(t7, p);

		// 7: t2 = t2 * t7

		t = ec_mul(t2, t7);
		ec_free(t2);
		t2 = t;
		ec_mod(t2, p);

		ec_free(t7);
	}

	// 9: t7 = t3 * t3

	t7 = ec_mul(t3, t3);
	ec_mod(t7, p);

	// 10: t4 = t4 * t7

	t = ec_mul(t4, t7);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 11: t7 = t3 * t7

	t = ec_mul(t3, t7);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 12: t5 = t5 * t7

	t = ec_mul(t5, t7);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 13: t4 = t1 - t4

	t = ec_sub(p, t4);
	ec_free(t4);
	t4 = ec_add(t1, t);
	ec_free(t);
	ec_mod(t4, p);

	// 14: t5 = t2 - t5

	t = ec_sub(p, t5);
	ec_free(t5);
	t5 = ec_add(t2, t);
	ec_free(t);
	ec_mod(t5, p);

	if (ec_equal(t4, 0)) {
		if (ec_equal(t5, 0)) {
			R->x = ec_int(0);
			R->y = ec_int(0);
			R->z = ec_int(0);
		} else {
			R->x = ec_int(1);
			R->y = ec_int(1);
			R->z = ec_int(0);
		}
		ec_free(t1);
		ec_free(t2);
		ec_free(t3);
		ec_free(t4);
		ec_free(t5);
		ec_free(t6);
		ec_free(t7);
		return;
	}

	// 22: t1 = 2 * t1 - t4

	t = ec_add(t1, t1);
	ec_free(t1);
	t1 = t;
	k = ec_sub(p, t4);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = t;
	ec_free(k);
	ec_mod(t1, p);

	// 23: t2 = 2 * t2 - t5

	t = ec_add(t2, t2);
	ec_free(t2);
	t2 = t;
	k = ec_sub(p, t5);
	t = ec_add(t2, k);
	ec_free(t2);
	t2 = t;
	ec_free(k);
	ec_mod(t2, p);

	if (!ec_equal(t6, 1)) {

		// 25: t3 = t3 * t6

		t = ec_mul(t3, t6);
		ec_free(t3);
		t3 = t;
		ec_mod(t3, p);
	}

	// 27: t3 = t3 * t4

	t = ec_mul(t3, t4);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 28: t7 = t4 * t4

	t = ec_mul(t4, t4);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 29: t4 = t4 * t7

	t = ec_mul(t4, t7);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 30: t7 = t1 * t7

	t = ec_mul(t1, t7);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 31: t1 = t5 * t5

	ec_free(t1);
	t1 = ec_mul(t5, t5);
	ec_mod(t1, p);

	// 32: t1 = t1 - t7

	k = ec_sub(p, t7);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = t;
	ec_free(k);
	ec_mod(t1, p);

	// 33: t7 = t7 - 2 * t1

	k = ec_sub(p, t1);
	t = ec_add(t7, k);
	ec_free(t7);
	t7 = ec_add(t, k);
	ec_free(k);
	ec_free(t);
	ec_mod(t7, p);

	// 34: t5 = t5 * t7

	t = ec_mul(t5, t7);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 35: t4 = t2 * t4

	t = ec_mul(t2, t4);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 36: t2 = t5 - t4

	t = ec_sub(p, t4);
	ec_free(t2);
	t2 = ec_add(t5, t);
	ec_free(t);
	ec_mod(t2, p);

	// 37: t2 = t2 / 2

	if (t2[0] & 1) {
		t = ec_add(t2, p);
		ec_free(t2);
		t2 = t;
	}
	ec_shr(t2);

	R->x = t1;
	R->y = t2;
	R->z = t3;

	ec_free(t4);
	ec_free(t5);
	ec_free(t6);
	ec_free(t7);
}

void
ec_full_add(struct point *R, struct point *S, struct point *T, unsigned *p)
{
	unsigned *x, *y, *z;
	struct point U;

	if (ec_equal(S->z, 0)) {
		x = ec_dup(T->x);
		y = ec_dup(T->y);
		z = ec_dup(T->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	if (ec_equal(T->z, 0)) {
		x = ec_dup(S->x);
		y = ec_dup(S->y);
		z = ec_dup(S->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	U.x = NULL;
	U.y = NULL;
	U.z = NULL;

	ec_add_xyz(&U, S, T, p);

	if (ec_equal(U.x, 0) && ec_equal(U.y, 0) && ec_equal(U.z, 0)) {
		ec_free_xyz(&U);
		ec_double(&U, S, p);
	}

	ec_free_xyz(R);

	R->x = U.x;
	R->y = U.y;
	R->z = U.z;
}

void
ec_full_sub(struct point *R, struct point *S, struct point *T, unsigned *p)
{
	struct point U;

	U.x = ec_dup(T->x);
	U.y = ec_sub(p, T->y);
	U.z = ec_dup(T->z);

	ec_full_add(R, S, &U, p);

	ec_free_xyz(&U);
}

void
ec_mult(struct point *R, unsigned *d, struct point *S, unsigned *p)
{
	int h, i, k, l;
	unsigned *t, *u, *x, *y, *z;
	struct point U;

	if (ec_equal(d, 0)) {
		ec_free_xyz(R);
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (ec_equal(d, 1)) {
		x = ec_dup(S->x);
		y = ec_dup(S->y);
		z = ec_dup(S->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	if (ec_equal(S->z, 0)) {
		ec_free_xyz(R);
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (!ec_equal(S->z, 1)) {
		ec_affinify(S, p);
		ec_projectify(S);
	}

	x = ec_dup(S->x);
	y = ec_dup(S->y);
	z = ec_dup(S->z);

	ec_free_xyz(R);

	R->x = x;
	R->y = y;
	R->z = z;

	u = ec_int(3);
	t = ec_mul(u, d);
	ec_free(u);

	l = ec_get_msbit_index(t);

	for (i = l - 1; i > 0; i--) {

		U.x = NULL;
		U.y = NULL;
		U.z = NULL;

		ec_double(R, R, p);

		h = ec_get_bit(t, i);
		k = ec_get_bit(d, i);

		if (h == 1 && k == 0)
			ec_full_add(&U, R, S, p);

		if (h == 0 && k == 1)
			ec_full_sub(&U, R, S, p);

		if (h != k) {
			ec_free_xyz(R);
			R->x = U.x;
			R->y = U.y;
			R->z = U.z;
		}
	}

	ec_free(t);
}

int
ec_get_msbit_index(unsigned *u)
{
	int k, n;
	unsigned m;
	m = 0x80000000;
	n = len(u);
	k = 32 * n - 1;
	while (m > 1) {
		if (u[n - 1] & m)
			break;
		m >>= 1;
		k--;
	}
	return k;
}

int
ec_get_bit(unsigned *u, int k)
{
	int j;
	unsigned m;
	if (k < 0)
		return 0;
	j = k / 32;
	if (j >= len(u))
		return 0;
	m = 1 << (k % 32);
	if (u[j] & m)
		return 1;
	else
		return 0;
}

int
ec_F(int t)
{
	if (18 <= t && t < 22)
		return 9;

	if (14 <= t && t < 18)
		return 10;

	if (22 <= t && t < 24)
		return 11;

	if (4 <= t && t < 12)
		return 14;

	return 12;
}

// R cannot point to S or T

void
ec_twin_mult(struct point *R, unsigned *d0, struct point *S, unsigned *d1, struct point *T, unsigned *p)
{
	int c[2][6], h[2], i, k, m, m0, m1, u[2];
	struct point SpT, SmT;

	SpT.x = NULL;
	SpT.y = NULL;
	SpT.z = NULL;

	SmT.x = NULL;
	SmT.y = NULL;
	SmT.z = NULL;

	ec_full_add(&SpT, S, T, p);
	ec_full_sub(&SmT, S, T, p);

	m0 = ec_get_msbit_index(d0) + 1;
	m1 = ec_get_msbit_index(d1) + 1;

	if (m0 > m1)
		m = m0;
	else
		m = m1;

	c[0][0] = 0;
	c[0][1] = 0;
	c[0][2] = ec_get_bit(d0, m - 1);
	c[0][3] = ec_get_bit(d0, m - 2);
	c[0][4] = ec_get_bit(d0, m - 3);
	c[0][5] = ec_get_bit(d0, m - 4);

	c[1][0] = 0;
	c[1][1] = 0;
	c[1][2] = ec_get_bit(d1, m - 1);
	c[1][3] = ec_get_bit(d1, m - 2);
	c[1][4] = ec_get_bit(d1, m - 3);
	c[1][5] = ec_get_bit(d1, m - 4);

	R->x = ec_int(1);
	R->y = ec_int(1);
	R->z = ec_int(0);

	for (k = m; k > -1; k--) {

		for (i = 0; i < 2; i++) {
			h[i] = 16 * c[i][1] + 8 * c[i][2] + 4 * c[i][3] + 2 * c[i][4] + c[i][5];
			if (c[i][0] == 1)
				h[i] = 31 - h[i];
		}

		for (i = 0; i < 2; i++) {
			if (h[i] < ec_F(h[1 - i]))
				u[i] = 0;
			else {
				if (c[i][0] & 1)
					u[i] = -1;
				else
					u[i] = 1;
			}
		}

		c[0][0] = abs(u[0]) ^ c[0][1];
		c[0][1] = c[0][2];
		c[0][2] = c[0][3];
		c[0][3] = c[0][4];
		c[0][4] = c[0][5];
		c[0][5] = ec_get_bit(d0, k - 5);

		c[1][0] = abs(u[1]) ^ c[1][1];
		c[1][1] = c[1][2];
		c[1][2] = c[1][3];
		c[1][3] = c[1][4];
		c[1][4] = c[1][5];
		c[1][5] = ec_get_bit(d1, k - 5);

		ec_double(R, R, p);

		if (u[0] == -1 && u[1] == -1)
			ec_full_sub(R, R, &SpT, p);

		if (u[0] == -1 && u[1] == 0)
			ec_full_sub(R, R, S, p);

		if (u[0] == -1 && u[1] == 1)
			ec_full_sub(R, R, &SmT, p);

		if (u[0] == 0 && u[1] == -1)
			ec_full_sub(R, R, T, p);

		if (u[0] == 0 && u[1] == 1)
			ec_full_add(R, R, T, p);

		if (u[0] == 1 && u[1] == -1)
			ec_full_add(R, R, &SmT, p);

		if (u[0] == 1 && u[1] == 0)
			ec_full_add(R, R, S, p);

		if (u[0] == 1 && u[1] == 1)
			ec_full_add(R, R, &SpT, p);
	}

	ec_free_xyz(&SpT);
	ec_free_xyz(&SmT);
}

void
ec_free_xyz(struct point *u)
{
	ec_free(u->x);
	ec_free(u->y);
	ec_free(u->z);
	u->x = NULL;
	u->y = NULL;
	u->z = NULL;
}

// returns u + v

unsigned *
ec_add(unsigned *u, unsigned *v)
{
	int i, nu, nv, nw;
	unsigned long long t;
	unsigned *w;
	nu = len(u);
	nv = len(v);
	if (nu > nv)
		nw = nu + 1;
	else
		nw = nv + 1;
	w = ec_new(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (unsigned long long) w[i] + v[i];
		w[i] = t;
		t >>= 32;
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t >>= 32;
	}
	ec_norm(w);
	return w;
}

// returns u - v

unsigned *
ec_sub(unsigned *u, unsigned *v)
{
	int i, nu, nv, nw;
	unsigned long long t;
	unsigned *w;
	nu = len(u);
	nv = len(v);
	if (nu > nv)
		nw = nu;
	else
		nw = nv;
	w = ec_new(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (unsigned long long) w[i] - v[i];
		w[i] = t;
		t = (long long) t >> 32; // cast to extend sign
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t = (long long) t >> 32; // cast to extend sign
	}
	ec_norm(w);
	return w;
}

// returns u * v

unsigned *
ec_mul(unsigned *u, unsigned *v)
{
	int i, j, nu, nv, nw;
	unsigned long long t;
	unsigned *w;
	nu = len(u);
	nv = len(v);
	nw = nu + nv;
	w = ec_new(nw);
	for (i = 0; i < nu; i++)
		w[i] = 0;
	for (j = 0; j < nv; j++) {
		t = 0;
		for (i = 0; i < nu; i++) {
			t += (unsigned long long) u[i] * v[j] + w[i + j];
			w[i + j] = t;
			t >>= 32;
		}
		w[i + j] = t;
	}
	ec_norm(w);
	return w;
}

// returns floor(u / v)

unsigned *
ec_div(unsigned *u, unsigned *v)
{
	int i, k, nu, nv;
	unsigned *q, qhat, *w;
	unsigned long long a, b, t;
	ec_norm(u);
	ec_norm(v);
	if (len(v) == 1 && v[0] == 0)
		return NULL; // v = 0
	nu = len(u);
	nv = len(v);
	k = nu - nv;
	if (k < 0) {
		q = ec_new(1);
		q[0] = 0;
		return q; // u < v, return zero
	}
	u = ec_dup(u);
	q = ec_new(k + 1);
	w = ec_new(nv + 1);
	b = v[nv - 1];
	do {
		q[k] = 0;
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (unsigned long long) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (unsigned long long) u[i] - w[i - k];
				u[i] = t;
				t = (long long) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (unsigned long long) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			q[k] += qhat;
			ec_norm(u);
			nu = len(u);
		}
	} while (--k >= 0);
	ec_norm(q);
	ec_free(u);
	ec_free(w);
	return q;
}

// u = u mod v

void
ec_mod(unsigned *u, unsigned *v)
{
	int i, k, nu, nv;
	unsigned qhat, *w;
	unsigned long long a, b, t;
	ec_norm(u);
	ec_norm(v);
	if (len(v) == 1 && v[0] == 0)
		return; // v = 0
	nu = len(u);
	nv = len(v);
	k = nu - nv;
	if (k < 0)
		return; // u < v
	w = ec_new(nv + 1);
	b = v[nv - 1];
	do {
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (unsigned long long) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (unsigned long long) u[i] - w[i - k];
				u[i] = t;
				t = (long long) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (unsigned long long) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			ec_norm(u);
			nu = len(u);
		}
	} while (--k >= 0);
	ec_free(w);
}

// returns u ** v

unsigned *
ec_pow(unsigned *u, unsigned *v)
{
	unsigned *t, *w;
	u = ec_dup(u);
	v = ec_dup(v);
	// w = 1
	w = ec_new(1);
	w[0] = 1;
	for (;;) {
		if (v[0] & 1) {
			// w = w * u
			t = ec_mul(w, u);
			ec_free(w);
			w = t;
		}
		// v = v >> 1
		ec_shr(v);
		// v = 0?
		if (len(v) == 1 && v[0] == 0)
			break;
		// u = u * u
		t = ec_mul(u, u);
		ec_free(u);
		u = t;
	}
	ec_free(u);
	ec_free(v);
	return w;
}

// u = u >> 1

void
ec_shr(unsigned *u)
{
	int i;
	for (i = 0; i < len(u) - 1; i++) {
		u[i] >>= 1;
		if (u[i + 1] & 1)
			u[i] |= 0x80000000;
	}
	u[i] >>= 1;
	ec_norm(u);
}

// compare u and v

int
ec_cmp(unsigned *u, unsigned *v)
{
	int i;
	ec_norm(u);
	ec_norm(v);
	if (len(u) < len(v))
		return -1;
	if (len(u) > len(v))
		return 1;
	for (i = len(u) - 1; i >= 0; i--) {
		if (u[i] < v[i])
			return -1;
		if (u[i] > v[i])
			return 1;
	}
	return 0; // u = v
}

int
ec_equal(unsigned *u, unsigned v)
{
	if (len(u) == 1 && u[0] == v)
		return 1;
	else
		return 0;
}

unsigned *
ec_int(int k)
{
	unsigned *u;
	u = ec_new(1);
	u[0] = k;
	return u;
}

unsigned *
ec_new(int n)
{
	unsigned *p;
	p = (unsigned *) malloc((n + 1) * sizeof (unsigned));
	if (p == NULL) {
		printf("malloc kaput\n");
		exit(1);
	}
	*p = n;
	ec_malloc_count++;
	return p + 1;
}

void
ec_free(unsigned *p)
{
	if (p) {
		free(p - 1);
		ec_malloc_count--;
	}
}

unsigned *
ec_dup(unsigned *u)
{
	int i;
	unsigned *v;
	v = ec_new(len(u));
	for (i = 0; i < len(u); i++)
		v[i] = u[i];
	return v;
}

// remove leading zeroes

void
ec_norm(unsigned *u)
{
	while (len(u) > 1 && u[len(u) - 1] == 0)
		len(u)--;
}

unsigned *
ec_hexstr_to_bignum(char *s)
{
	int d, i, len, n;
	unsigned *u;
	len = strlen(s);
	n = (len + 7) / 8; // convert len to number of unsigned ints
	u = ec_new(n);
	for (i = 0; i < n; i++)
		u[i] = 0;
	for (i = 0; i < len; i++) {
		d = s[len - i - 1];
		if ('0' <= d && d <= '9')
			d -= '0';
		else if ('A' <= d && d <= 'F')
			d -= 'A' - 10;
		else if ('a' <= d && d <= 'f')
			d -= 'a' - 10;
		else {
			ec_free(u);
			return NULL;
		}
		u[i / 8] |= d << (4 * (i % 8));
	}
	ec_norm(u);
	return u;
}

unsigned *
ec_buf_to_bignum(unsigned char *buf, int len)
{
	int i, n, t;
	unsigned int *u;
	n = (len + 3) / 4;
	u = ec_new(n);
	t = 0;
	for (i = 0; i < len; i++) {
		t = t << 8 | buf[i];
		if ((len - i - 1) % 4 == 0) {
			u[--n] = t;
			t = 0;
		}
	}
	ec_norm(u);
	return u;
}

void
ec_test(void)
{
	int t = ec_malloc_count;
	ec_test_full_add();
	ec_test_full_sub();
	ec_test_double();
	ec_test_mult();
	ec_test_twin_mult();
	ec_test256();
	ec_test384();
	ecdh_test();
	if (t != ec_malloc_count)
		printf("err: ec_memory_leak\n");
}

void
ec_test_full_add(void)
{
	unsigned *p, *x, *y;
	struct point R, S, T;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xt =
		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330e"
		"ad7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051";

	char *str_yt =
		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d2"
		"5afa22a7b5dce0d9470da89233cee178592f49b6fecb5092";

	char *str_xr =
		"12dc5ce7acdfc5844d939f40b4df012e68f865b89c3213ba"
		"97090a247a2fc009075cf471cd2e85c489979b65ee0b5eed";

	char *str_yr =
		"167312e58fe0c0afa248f2854e3cddcb557f983b3189b67f"
		"21eee01341e7e9fe67f6ee81b36988efa406945c8804a4b0";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	T.x = ec_hexstr_to_bignum(str_xt);
	T.y = ec_hexstr_to_bignum(str_yt);
	T.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_full_add(&R, &S, &T, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_full_add\n");
	else
		printf("err: ec_full_add\n");

	ec_free(p);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);
}

void
ec_test_full_sub(void)
{
	unsigned *p, *x, *y;
	struct point R, S, T;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xt =
		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330e"
		"ad7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051";

	char *str_yt =
		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d2"
		"5afa22a7b5dce0d9470da89233cee178592f49b6fecb5092";

	char *str_xr =
		"6afdaf8da8b11c984cf177e551cee542cda4ac2f25cd522d"
		"0cd710f88059c6565aef78f6b5ed6cc05a6666def2a2fb59";

	char *str_yr =
		"7bed0e158ae8cc70e847a60347ca1548c348decc6309f48b"
		"59bd5afc9a9b804e7f7876178cb5a7eb4f6940a9c73e8e5e";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	T.x = ec_hexstr_to_bignum(str_xt);
	T.y = ec_hexstr_to_bignum(str_yt);
	T.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_full_sub(&R, &S, &T, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_full_sub\n");
	else
		printf("err: ec_full_sub\n");

	ec_free(p);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);
}

void
ec_test_double(void)
{
	unsigned *p, *x, *y;
	struct point R, S;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xr =
		"2a2111b1e0aa8b2fc5a1975516bc4d58017ff96b25e1bdff"
		"3c229d5fac3bacc319dcbec29f9478f42dee597b4641504c";

	char *str_yr =
		"fa2e3d9dc84db8954ce8085ef28d7184fddfd1344b4d4797"
		"343af9b5f9d837520b450f726443e4114bd4e5bdb2f65ddd";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_double(&R, &S, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_double\n");
	else
		printf("err: ec_double\n");

	ec_free(p);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
}

void
ec_test_mult(void)
{
	unsigned *d, *p, *x, *y;
	struct point R, S;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_d =
		"a4ebcae5a665983493ab3e626085a24c104311a761b5a8fd"
		"ac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480";

	char *str_xr =
		"e4f77e7ffeb7f0958910e3a680d677a477191df166160ff7"
		"ef6bb5261f791aa7b45e3e653d151b95dad3d93ca0290ef2";

	char *str_yr =
		"ac7dee41d8c5f4a7d5836960a773cfc1376289d3373f8cf7"
		"417b0c6207ac32e913856612fc9ff2e357eb2ee05cf9667f";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	d = ec_hexstr_to_bignum(str_d);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_mult(&R, d, &S, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_mult\n");
	else
		printf("err: ec_mult\n");

	ec_free(p);
	ec_free(d);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
}

void
ec_test_twin_mult(void)
{
	unsigned *d, *e, *p, *x, *y;
	struct point R, S, T;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xt =
		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330e"
		"ad7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051";

	char *str_yt =
		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d2"
		"5afa22a7b5dce0d9470da89233cee178592f49b6fecb5092";

	char *str_d =
		"a4ebcae5a665983493ab3e626085a24c104311a761b5a8fd"
		"ac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480";

	char *str_e =
		"afcf88119a3a76c87acbd6008e1349b29f4ba9aa0e12ce89"
		"bcfcae2180b38d81ab8cf15095301a182afbc6893e75385d";

	char *str_xr =
		"917ea28bcd641741ae5d18c2f1bd917ba68d34f0f0577387"
		"dc81260462aea60e2417b8bdc5d954fc729d211db23a02dc";

	char *str_yr =
		"1a29f7ce6d074654d77b40888c73e92546c8f16a5ff6bcbd"
		"307f758d4aee684beff26f6742f597e2585c86da908f7186";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	T.x = ec_hexstr_to_bignum(str_xt);
	T.y = ec_hexstr_to_bignum(str_yt);
	T.z = ec_int(1);

	d = ec_hexstr_to_bignum(str_d);
	e = ec_hexstr_to_bignum(str_e);

	ec_twin_mult(&R, d, &S, e, &T, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_twin_mult\n");
	else
		printf("err: ec_twin_mult\n");

	ec_free(p);
	ec_free(d);
	ec_free(e);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);
}

// Key file for prime256v1
//
//   0 119: SEQUENCE {
//   2   1:   INTEGER 1
//   5  32:   OCTET STRING
//        :     3C 7A C4 FE 35 55 88 CE 3D 5B 0A 46 A5 51 37 1C   Private key d
//        :     2E 25 33 09 3A 71 0D 33 66 43 2D 59 7A AA 5C 27
//  39  10:   [0] {
//  41   8:     OBJECT IDENTIFIER '1 2 840 10045 3 1 7'
//        :     }
//  51  68:   [1] {
//  53  66:     BIT STRING
//        :       04 EF 7B A2 0E 11 D7 EF BB 6B DD 9A A1 AD 3D B2   Public key (x, y)
//        :       8F 8C FC 1E 7D D8 0E BD E3 CA 99 34 35 94 EF 31
//        :       16 26 E6 F3 4E B2 13 9B 6D 55 0A 91 9A 37 3A 17
//        :       86 57 92 A4 79 F5 6F 09 A6 77 6F 85 93 90 69 A8
//        :       C0
//        :     }
//        :   }

void
ec_test256(void)
{
	unsigned *d, *h, *r, *s, *x, *y;
	unsigned char sig[64];

	// certificate's SHA1 hash

	char *str_h = "ce89669c8efcfe2c4f84e517339110908bb7303c";

	// private key

	char *str_d =
		"3C7AC4FE355588CE3D5B0A46A551371C"
		"2E2533093A710D3366432D597AAA5C27";

	// public key

	char *str_x =
		"EF7BA20E11D7EFBB6BDD9AA1AD3DB2"
		"8F8CFC1E7DD80EBDE3CA99343594EF31"
		"16";

	char *str_y =
		"26E6F34EB2139B6D550A919A373A17"
		"865792A479F56F09A6776F85939069A8"
		"C0";

	h = ec_hexstr_to_bignum(str_h);
	d = ec_hexstr_to_bignum(str_d);
	x = ec_hexstr_to_bignum(str_x);
	y = ec_hexstr_to_bignum(str_y);

	ecdsa256_sign_f(h, d, sig);

	r = ec_buf_to_bignum(sig, 32);
	s = ec_buf_to_bignum(sig + 32, 32);

	if (ecdsa256_verify_f(h, r, s, x, y) == 0)
		printf("ok: ec_test256\n");
	else
		printf("err: ec_test256\n");

	ec_free(h);
	ec_free(d);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);
}

// Key file for secp384r1
//
//  0 164: SEQUENCE {
//  3   1:   INTEGER 1
//  6  48:   OCTET STRING
//       :     6D 46 21 67 FB B1 A9 00 07 E3 ED 34 3E 69 4C E4   Private key d
//       :     11 34 1B 8A 85 A6 B3 7F 87 4C 7F 6A 18 C4 E7 A3
//       :     7B CB AF 2A B3 31 7F D7 56 FE 51 E7 2C FD 2B 50
// 56   7:   [0] {
// 58   5:     OBJECT IDENTIFIER secp384r1 (1 3 132 0 34)
//       :     }
// 65 100:   [1] {
// 67  98:     BIT STRING
//       :       04 04 7E 6E 9A 1A A8 FF AC 27 9A 22 8C 4D 1E C4   Public key (x, y)
//       :       F8 C6 30 65 70 C4 56 8F 3C 09 33 F5 E0 60 98 00
//       :       6D 74 8F DB CD B4 29 F2 24 39 F1 51 CB 7F D4 B8
//       :       03 36 AA 35 72 EB 38 6D 08 0D 5C 10 C3 CA AD F5
//       :       BF 08 35 DE 99 1F 98 4B 04 F9 DE 49 9C 01 57 73
//       :       54 64 C3 3B BF BE A0 19 CE FD 76 4D 26 99 B7 2D
//       :       FE
//       :     }
//       :   }

void
ec_test384(void)
{
	unsigned *d, *h, *r, *s, *x, *y;
	unsigned char sig[96];

	// certificate's SHA1 hash

	char *str_h = "ce89669c8efcfe2c4f84e517339110908bb7303c";

	// private key

	char *str_d =
		"6D462167FBB1A90007E3ED343E694CE4"
		"11341B8A85A6B37F874C7F6A18C4E7A3"
		"7BCBAF2AB3317FD756FE51E72CFD2B50";

	// public key

	char *str_x =
		"047E6E9A1AA8FFAC279A228C4D1EC4"
		"F8C6306570C4568F3C0933F5E0609800"
		"6D748FDBCDB429F22439F151CB7FD4B8"
		"03";

	char *str_y =
		"36AA3572EB386D080D5C10C3CAADF5"
		"BF0835DE991F984B04F9DE499C015773"
		"5464C33BBFBEA019CEFD764D2699B72D"
		"FE";

	h = ec_hexstr_to_bignum(str_h);
	d = ec_hexstr_to_bignum(str_d);
	x = ec_hexstr_to_bignum(str_x);
	y = ec_hexstr_to_bignum(str_y);

	ecdsa384_sign_f(h, d, sig);

	r = ec_buf_to_bignum(sig, 48);
	s = ec_buf_to_bignum(sig + 48, 48);

	if (ecdsa384_verify_f(h, r, s, x, y) == 0)
		printf("ok: ec_test384\n");
	else
		printf("err: ec_test384\n");

	ec_free(h);
	ec_free(d);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);
}

void
ecdh_test(void)
{
	unsigned *dA, *dB;
	struct point RA, RB, SA, SB;

	// private key A

	static char *str_dA =
		"6D462167FBB1A90007E3ED343E694CE4"
		"11341B8A85A6B37F874C7F6A18C4E7A3"
		"7BCBAF2AB3317FD756FE51E72CFD2B50";

	// public key A

	static char *str_xA =
		"047E6E9A1AA8FFAC279A228C4D1EC4"
		"F8C6306570C4568F3C0933F5E0609800"
		"6D748FDBCDB429F22439F151CB7FD4B8"
		"03";

	static char *str_yA =
		"36AA3572EB386D080D5C10C3CAADF5"
		"BF0835DE991F984B04F9DE499C015773"
		"5464C33BBFBEA019CEFD764D2699B72D"
		"FE";

	// private key B

	static char *str_dB =
		"D2D5EABC6FD9BCFF6E98162F0A145B40"
		"DFBD81FA7CB328A96F217320727FD023"
		"F8DED1A475BFD02BA13999B1F9989BB6";

	// public key B

	static char *str_xB =
		"B6A4A9F5432CCB8D2E3D5FAA519FFC"
		"F898469995DDC622285027412268BE4A"
		"CA9B4C25730432ED22F8796915FE5393"
		"E2";

	static char *str_yB =
		"16E95C98ED178B592962FD5321A803"
		"8C3A12DE7540065DC564849D3FEC2A52"
		"A0A693254E47D506558D836C06D5C3C4"
		"6D";

	dA = ec_hexstr_to_bignum(str_dA);
	dB = ec_hexstr_to_bignum(str_dB);

	RA.x = ec_hexstr_to_bignum(str_xA);
	RA.y = ec_hexstr_to_bignum(str_yA);
	RA.z = ec_int(1);

	RB.x = ec_hexstr_to_bignum(str_xB);
	RB.y = ec_hexstr_to_bignum(str_yB);
	RB.z = ec_int(1);

	SA.x = NULL;
	SA.y = NULL;
	SA.z = NULL;

	ec_mult(&SA, dB, &RA, p384);
	ec_affinify(&SA, p384);

	SB.x = NULL;
	SB.y = NULL;
	SB.z = NULL;

	ec_mult(&SB, dA, &RB, p384);
	ec_affinify(&SB, p384);

	if (ec_cmp(SA.x, SB.x) == 0)
		printf("ok: ecdh_test\n");
	else
		printf("err: ecdh_test\n");
#if 0
	// print A's pre-master secret

	int i;
	char buf[48];

	bzero(buf, 48);

	for (i = 0; i < len(SA.x); i++) {
		buf[48 - 4 * i - 4] = SA.x[i] >> 24;
		buf[48 - 4 * i - 3] = SA.x[i] >> 16;
		buf[48 - 4 * i - 2] = SA.x[i] >> 8;
		buf[48 - 4 * i - 1] = SA.x[i];
	}

	print_buf("A", buf, 48);

	// print B's pre-master secret

	bzero(buf, 48);

	for (i = 0; i < len(SB.x); i++) {
		buf[48 - 4 * i - 4] = SB.x[i] >> 24;
		buf[48 - 4 * i - 3] = SB.x[i] >> 16;
		buf[48 - 4 * i - 2] = SB.x[i] >> 8;
		buf[48 - 4 * i - 1] = SB.x[i];
	}

	print_buf("B", buf, 48);
#endif
	ec_free(dA);
	ec_free(dB);

	ec_free_xyz(&RA);
	ec_free_xyz(&RB);
	ec_free_xyz(&SA);
	ec_free_xyz(&SB);
}
