// Check certificate chain and re-sign provisioned certificate
//
//
// Outline of certificate chain:
//  ________
// |________| Total length (3 bytes)
// |________| Length of 1st certificate (3 bytes)
// |        |
// |        | 1st certificate
// |________|
// |________| Length of 2nd certificate (3 bytes)
// |        |
// |        | 2nd certificate
// |________|
//     .
//     .
//     .
//  ________
// |________| Length of last certificate (3 bytes)
// |        |
// |        | Last certificate
// |________|

static int debug = 1;
int cert_malloc_count;

// returns 0 if ok, -1 otherwise

int
checkchain(struct ssl_session *p, unsigned char *buf, int len)
{
	int err, k, n;
	time_t t;
	struct certinfo a, b, c;

	if (len < 6)
		return -1; // format error

	// check total length

	n = buf[0] << 16 | buf[1] << 8 | buf[2];

	if (n + 3 != len)
		return -1;

	// length of first certificate

	n = buf[3] << 16 | buf[4] << 8 | buf[5];

	if (n + 6 > len)
		return -1; // format error

	// parse the first certificate in the chain

	c.cert = buf + 6;
	c.cert_length = n;

	err = parse_certificate(&c);

	if (err) {
		if (debug)
			printf("certificate parse error (%s, line %d)\n", __FILE__, __LINE__);
		return -1;
	}

	time(&t);

	if (t < c.not_before || t > c.not_after) {
		if (debug)
			printf("time validation error (%s, line %d)\n", __FILE__, __LINE__);
		return -1;
	}

	err = check_signing_algorithm(p, &c);

	if (err) {
		if (debug)
			printf("signing algorithm error (%s, line %d)\n", __FILE__, __LINE__);
		return -1;
	}

	// find trust anchor

	memcpy(&a, &c, sizeof (struct certinfo));

	k = 6;

	while (istrusted(&a) == 0) {

		// go to next cert in chain

		k += a.cert_length;

		if (k == len) {
			if (debug)
				printf("no trust anchor in certificate chain (%s, line %d)\n", __FILE__, __LINE__);
			return -1;
		}

		if (len - k < 3) {
			if (debug)
				printf("format error (%s, line %d)\n", __FILE__, __LINE__);
			return -1;
		}

		// length of cert

		n = buf[k] << 16 | buf[k + 1] << 8 | buf[k + 2];

		k += 3;

		if (k + n > len) {
			if (debug)
				printf("format error (%s, line %d)\n", __FILE__, __LINE__);
			return -1;
		}

		b.cert = buf + k;
		b.cert_length = n;

		err = parse_certificate(&b);

		if (err) {
			if (debug)
				printf("certificate parse error (%s, line %d)\n", __FILE__, __LINE__);
			return -1;
		}

		if (t < b.not_before || t > b.not_after) {
			if (debug)
				printf("time validation error (%s, line %d)\n", __FILE__, __LINE__);
			return -1;
		}

		if (issignedby(&a, &b) == 0) { // issignedby() is in certmain.c
			if (debug)
				printf("signing error (%s, line %d)\n", __FILE__, __LINE__);
			return -1;
		}

		memcpy(&a, &b, sizeof (struct certinfo));
	}

	// copy key for sending pre-master secret to server

	copy_certificate_key(p, &c);

	return 0;
}

int
isselfsigned(struct certinfo *p)
{
	if (p->issuer_length != p->subject_length)
		return 0;

	if (memcmp(p->cert + p->issuer_offset, p->cert + p->subject_offset, p->issuer_length) == 0)
		return 1;
	else
		return 0;
}

// copy key for encrypting pre-master secret

void
copy_certificate_key(struct ssl_session *p, struct certinfo *ci)
{
	p->encryption_algorithm = ci->encryption_algorithm;

	switch (p->encryption_algorithm) {

	case RSA_ENCRYPTION:

		p->modulus = ssl_malloc(ci->modulus_length);
		memcpy(p->modulus, ci->cert + ci->modulus_offset, ci->modulus_length);
		p->modulus_length = ci->modulus_length;

		p->exponent = ssl_malloc(ci->exponent_length);
		memcpy(p->exponent, ci->cert + ci->exponent_offset, ci->exponent_length);
		p->exponent_length = ci->exponent_length;

		p->signature_length = ci->signature_length;

		break;

	case PRIME256V1:

		p->x = ssl_malloc(32);
		memcpy(p->x, ci->cert + ci->ec_key_offset + 1, 32);

		p->y = ssl_malloc(32);
		memcpy(p->y, ci->cert + ci->ec_key_offset + 33, 32);

		break;

	case SECP384R1:

		p->x = ssl_malloc(48);
		memcpy(p->x, ci->cert + ci->ec_key_offset + 1, 48);

		p->y = ssl_malloc(48);
		memcpy(p->y, ci->cert + ci->ec_key_offset + 49, 48);

		break;
	}
}

// check that certificate signing algorithm matches cipher suite

int
check_signing_algorithm(struct ssl_session *p, struct certinfo *ci)
{
	int err = -1;

	switch (p->cipher_suite) {

	case TLS_RSA_WITH_RC4_128_SHA:
	case TLS_RSA_WITH_AES_128_CBC_SHA:
	case TLS_RSA_WITH_AES_256_CBC_SHA:
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
	case TLS_RSA_WITH_AES_256_CBC_SHA256:

		if (ci->encryption_algorithm == RSA_ENCRYPTION)
			err = 0;
		break;

	case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
	case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:

	case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:

		if (ci->encryption_algorithm == PRIME256V1 || ci->encryption_algorithm == SECP384R1)
			err = 0;
		break;

	default:
		printf("missing case label (file %s, line %d)\n", __FILE__, __LINE__);
		break;
	}

	return err;
}

unsigned char *
cert_malloc(int n)
{
	unsigned char *p = malloc(n);
	if (p == NULL) {
		printf("malloc fail (%s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}
	cert_malloc_count++;
	return p;
}

void
cert_free(unsigned char *p)
{
	free(p);
	cert_malloc_count--;
}

// return 1 if certificate p is a trust anchor, 0 if not

int
istrusted(struct certinfo *p)
{
	return 1;
#if 0
	int i;
	time_t t;

	// look for a certificate match

	for (i = 0; i < nca; i++)
		if (ca[i].cert_length == p->cert_length && memcmp(ca[i].cert, p->cert, p->cert_length) == 0)
			return 1;

	time(&t);

	// look for an issuer and subject match

	for (i = 0; i < nca; i++) {

		if (p->issuer_length != ca[i].subject_length)
			continue;

		if (memcmp(p->cert + p->issuer_offset, ca[i].cert + ca[i].subject_offset, p->issuer_length) != 0)
			continue;

		// check validity

		if (t < ca[i].not_before || t > ca[i].not_after)
			continue;

		// verify that p is signed by ca[i]

		if (issignedby(p, ca + i))
			return 1; // trusted
	}

	return 0; // not trusted
#endif
}

// is p signed by q?

int
issignedby(struct certinfo *p, struct certinfo *q)
{
	int err = -1;
	unsigned char hash[64], *z;

	// check that issuer matches subject

	if (p->issuer_length != q->subject_length)
		return 0;

	if (memcmp(p->cert + p->issuer_offset, q->cert + q->subject_offset, p->issuer_length) != 0)
		return 0;

	switch (p->signature_algorithm) {

	case MD5_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = encrypt_signature(p, q);
		err = check_md5_signature(p, z);
		cert_free(z);
		break;

	case SHA1_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = encrypt_signature(p, q);
		err = check_sha1_signature(p, z);
		cert_free(z);
		break;

	case SHA224_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = encrypt_signature(p, q);
		err = check_sha224_signature(p, z);
		cert_free(z);
		break;

	case SHA256_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = encrypt_signature(p, q);
		err = check_sha256_signature(p, z);
		cert_free(z);
		break;

	case SHA384_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = encrypt_signature(p, q);
		err = check_sha384_signature(p, z);
		cert_free(z);
		break;

	case SHA512_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = encrypt_signature(p, q);
		err = check_sha512_signature(p, z);
		cert_free(z);
		break;

	case ECDSA_WITH_SHA1:
		sha1(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		err = check_ecdsa_signature(p, q, hash, 20);
		break;

	case ECDSA_WITH_SHA224:
		sha224(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		err = check_ecdsa_signature(p, q, hash, 28);
		break;

	case ECDSA_WITH_SHA256:
		sha256(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		err = check_ecdsa_signature(p, q, hash, 32);
		break;

	case ECDSA_WITH_SHA384:
		sha384(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		err = check_ecdsa_signature(p, q, hash, 48);
		break;
	}

	if (err)
		return 0;
	else
		return 1;
}

// Returns (signature ** exponent) mod modulus
//
//	p	subject certificate (signature)
//
//	q	issuer certificate (exponent, modulus)

unsigned char *
encrypt_signature(struct certinfo *p, struct certinfo *q)
{
	int i;
	unsigned char *z;
	unsigned *a, *b, *c, *y;

	a = buf_to_int(p->cert + p->signature_offset, p->signature_length);
	b = buf_to_int(q->cert + q->exponent_offset, q->exponent_length);
	c = buf_to_int(q->cert + q->modulus_offset, q->modulus_length);

	y = modpow(a, b, c);

	z = cert_malloc(p->signature_length);

	bzero(z, p->signature_length);

	for (i = 0; i < y[-1]; i++) {
		if (p->signature_length - 4 * i - 4 < 0)
			break; // buffer overrun
		z[p->signature_length - 4 * i - 4] = y[i] >> 24;
		z[p->signature_length - 4 * i - 3] = y[i] >> 16;
		z[p->signature_length - 4 * i - 2] = y[i] >> 8;
		z[p->signature_length - 4 * i - 1] = y[i];
	}

	mfree(a);
	mfree(b);
	mfree(c);
	mfree(y);

	return z;
}

int
check_md5_signature(struct certinfo *p, unsigned char *z)
{
	int i, k;
	unsigned char hash[16];

	if (p->signature_length < 37) // 3 + 18 + 16
		return -1;

	md5(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 37; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10", 18) != 0)
		return -1;

	k += 18;

	if (memcmp(z + k, hash, 16) != 0)
		return -1;

	return 0; // ok
}

int
check_sha1_signature(struct certinfo *p, unsigned char *z)
{
	int i, k;
	unsigned char hash[20];

	if (p->signature_length < 38) // 3 + 15 + 20
		return -1;

	sha1(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 38; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14", 15) != 0)
		return -1;

	k += 15;

	if (memcmp(z + k, hash, 20) != 0)
		return -1;

	return 0; // ok
}

int
check_sha224_signature(struct certinfo *p, unsigned char *z)
{
	int i, k;
	unsigned char hash[28];

	if (p->signature_length < 50) // 3 + 19 + 28
		return -1;

	sha224(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 50; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x29\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x18", 19) != 0)
		return -1;

	k += 19;

	if (memcmp(z + k, hash, 28) != 0)
		return -1;

	return 0; // ok
}

int
check_sha256_signature(struct certinfo *p, unsigned char *z)
{
	int i, k;
	unsigned char hash[32];

	if (p->signature_length < 54) // 3 + 19 + 32
		return -1;

	sha256(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 54; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20", 19) != 0)
		return -1;

	k += 19;

	if (memcmp(z + k, hash, 32) != 0)
		return -1;

	return 0; // ok
}

int
check_sha384_signature(struct certinfo *p, unsigned char *z)
{
	int i, k;
	unsigned char hash[48];

	if (p->signature_length < 70) // 3 + 19 + 48 = 70
		return -1;

	sha384(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 70; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30", 19) != 0)
		return -1;

	k += 19;

	if (memcmp(z + k, hash, 48) != 0)
		return -1;

	return 0; // ok
}

int
check_sha512_signature(struct certinfo *p, unsigned char *z)
{
	int i, k;
	unsigned char hash[64];

	if (p->signature_length < 86) // 3 + 19 + 64 = 86
		return -1;

	sha512(p->cert + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 86; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40", 19) != 0)
		return -1;

	k += 19;

	if (memcmp(z + k, hash, 64) != 0)
		return -1;

	return 0; // ok
}

// returns 0 for ok, -1 otherwise

int
check_ecdsa_signature(struct certinfo *p, struct certinfo *q, unsigned char *hash, int hashlen)
{
	int err = -1;

	switch (q->encryption_algorithm) {

	case PRIME256V1:
		err = ecdsa256_verify(p, q, hash, hashlen);
		break;

	case SECP384R1:
		err = ecdsa384_verify(p, q, hash, hashlen);
		break;
	}

	return err;
}
