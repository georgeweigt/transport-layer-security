void
hmac_sha256(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out)
{
	int i;
	uint8_t pad[64], hash[32];

	memset(pad, 0, 64);

	// keys longer than 64 are hashed

	if (keylen > 64)
		sha256(key, keylen, pad);
	else
		memcpy(pad, key, keylen);

	// xor ipad

	for (i = 0; i < 64; i++)
		pad[i] ^= 0x36;

	// hash

	sha256_with_key(pad, buf, len, hash);

	// xor opad

	for (i = 0; i < 64; i++)
		pad[i] ^= 0x36 ^ 0x5c;

	// hash

	sha256_with_key(pad, hash, 32, out);
}

void
sha256(uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[64];
	uint32_t hash[8];
	uint64_t m;

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x6a09e667;
	hash[1] = 0xbb67ae85;
	hash[2] = 0x3c6ef372;
	hash[3] = 0xa54ff53a;
	hash[4] = 0x510e527f;
	hash[5] = 0x9b05688c;
	hash[6] = 0x1f83d9ab;
	hash[7] = 0x5be0cd19;

	for (i = 0; i < n; i++) {
		sha256_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 64);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 56) {
		sha256_hash_block(block, hash);
		memset(block, 0, 64);
	}

	m = (uint64_t) 8 * len; // number of bits

	block[56] = m >> 56;
	block[57] = m >> 48;
	block[58] = m >> 40;
	block[59] = m >> 32;
	block[60] = m >> 24;
	block[61] = m >> 16;
	block[62] = m >> 8;
	block[63] = m;

	sha256_hash_block(block, hash);

	for (i = 0; i < 8; i++) {
		out[4 * i + 0] = hash[i] >> 24;
		out[4 * i + 1] = hash[i] >> 16;
		out[4 * i + 2] = hash[i] >> 8;
		out[4 * i + 3] = hash[i];
	}
}

void
sha256_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[64];
	uint32_t hash[8];
	uint64_t m;

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x6a09e667;
	hash[1] = 0xbb67ae85;
	hash[2] = 0x3c6ef372;
	hash[3] = 0xa54ff53a;
	hash[4] = 0x510e527f;
	hash[5] = 0x9b05688c;
	hash[6] = 0x1f83d9ab;
	hash[7] = 0x5be0cd19;

	sha256_hash_block(key, hash);

	for (i = 0; i < n; i++) {
		sha256_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 64);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 56) {
		sha256_hash_block(block, hash);
		memset(block, 0, 64);
	}

	m = (uint64_t) 8 * (len + 64); // number of bits

	block[56] = m >> 56;
	block[57] = m >> 48;
	block[58] = m >> 40;
	block[59] = m >> 32;
	block[60] = m >> 24;
	block[61] = m >> 16;
	block[62] = m >> 8;
	block[63] = m;

	sha256_hash_block(block, hash);

	for (i = 0; i < 8; i++) {
		out[4 * i + 0] = hash[i] >> 24;
		out[4 * i + 1] = hash[i] >> 16;
		out[4 * i + 2] = hash[i] >> 8;
		out[4 * i + 3] = hash[i];
	}
}

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTR(n, x) (((x) >> (n)) | ((x) << (32 - (n))))

#define Sigma0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))
#define Sigma1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))

#define sigma0(x) (ROTR(7, x) ^ ROTR(18, x) ^ ((x) >> 3))
#define sigma1(x) (ROTR(17, x) ^ ROTR(19, x) ^ ((x) >> 10))

uint32_t K256[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define K K256

void
sha256_hash_block(uint8_t *buf, uint32_t *hash)
{
	int t;
	uint32_t a, b, c, d, e, f, g, h, T1, T2, W[64];

	for (t = 0; t < 16; t++) {
		W[t] = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
		buf += 4;
	}

	for (t = 16; t < 64; t++)
		W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];
	f = hash[5];
	g = hash[6];
	h = hash[7];

	for (t = 0; t < 64; t++) {
		T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
		T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
	hash[5] += f;
	hash[6] += g;
	hash[7] += h;
}
