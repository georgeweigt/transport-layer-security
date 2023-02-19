// Expanded key layout:
//			 _______
// expanded_key		|	|
//			|	|
//			|	| 256 byte expanded encryption key
//			|	|
//			|_______|
// expanded_key + 256	|_______| 16 byte encryption IV
// expanded_key + 272	|	|
//			|	|
//			|	| 256 byte expanded decryption key
//			|	|
//			|_______|
// expanded_key + 528	|_______| 16 byte decryption IV
// expanded key + 544

void
aes128_init(struct ssl_session *p, uint8_t *encrypt_key, uint8_t *decrypt_key, uint8_t *encrypt_iv, uint8_t *decrypt_iv)
{
	uint32_t w[44], v[44];
	p->expanded_key = p->expanded_key_tab;
	while (((unsigned long long) p->expanded_key) & 0xf)
		p->expanded_key++; // align
	key_expansion(encrypt_key, w, v);
	memcpy(p->expanded_key, w, 176);
	key_expansion(decrypt_key, w, v);
	memcpy(p->expanded_key + 272, v, 176);
	if (p->tls_version == TLS_V10) {
		memcpy(p->expanded_key + 256, encrypt_iv, 16);
		memcpy(p->expanded_key + 528, decrypt_iv, 16);
	}
}

void
aes128_encrypt(struct ssl_session *p, unsigned char *buf, int num_blocks)
{
	int i, j;

	if (p->tls_version != TLS_V10) {
		memcpy(p->expanded_key + 256, buf, 16); // iv
		buf += 16;
		num_blocks--;
	}

	for (i = 0; i < num_blocks; i++) {
		for (j = 0; j < 16; j++)
			buf[j] ^= p->expanded_key[256 + j];
		encrypt_nib((uint32_t *) p->expanded_key, buf, buf);
		memcpy(p->expanded_key + 256, buf, 16);
		buf += 16;
	}
}

void
aes128_decrypt(struct ssl_session *p, unsigned char *buf, int num_blocks)
{
	int i, j;
	uint8_t iv[16];

	if (p->tls_version != TLS_V10) {
		memcpy(p->expanded_key + 528, buf, 16); // iv
		buf += 16;
		num_blocks--;
	}

	for (i = 0; i < num_blocks; i++) {
		memcpy(iv, buf, 16);
		decrypt_nib((uint32_t *) (p->expanded_key + 272), buf, buf);
		for (j = 0; j < 16; j++)
			buf[j] ^= p->expanded_key[528 + j];
		memcpy(p->expanded_key + 528, iv, 16);
		buf += 16;
	}
}

uint32_t etab0[256]; // encryption tables
uint32_t etab1[256];
uint32_t etab2[256];
uint32_t etab3[256];

uint32_t dtab0[256]; // decryption tables
uint32_t dtab1[256];
uint32_t dtab2[256];
uint32_t dtab3[256];

uint32_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// sbox[] and inv_sbox[] are from FIPS Publication 197

uint8_t sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

uint8_t inv_sbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

// multiply a and b mod x^8 + x^4 + x^3 + x + 1 (see FIPS Pub 197, p. 10)

int
mul(int a, int b)
{
	int i, t = 0;
	for (i = 0; i < 8; i++) {
		t <<= 1;
		if (t & 0x100)
			t ^= 0x11b;
		a <<= 1;
		if (a & 0x100)
			t ^= b;
	}
	return t;
}

// multiply a times column b

#define MUL(a, b0, b1, b2, b3) mul(a, b0) | mul(a, b1) << 8 | mul(a, b2) << 16 | mul(a, b3) << 24

// Initialize encryption and decryption tables

void
aes_init()
{
	int i, k;

	for (i = 0; i < 256; i++) {
		k = sbox[i];
		etab0[i] = MUL(k, 2, 1, 1, 3);
		etab1[i] = MUL(k, 3, 2, 1, 1);
		etab2[i] = MUL(k, 1, 3, 2, 1);
		etab3[i] = MUL(k, 1, 1, 3, 2);
		k = inv_sbox[i];
		dtab0[i] = MUL(k, 14, 9, 13, 11);
		dtab1[i] = MUL(k, 11, 14, 9, 13);
		dtab2[i] = MUL(k, 13, 11, 14, 9);
		dtab3[i] = MUL(k, 9, 13, 11, 14);
	}
}

// Initialize w[44] and v[44] from encryption key

void
key_expansion(uint8_t *key, uint32_t *w, uint32_t *v)
{
	int i;
	uint32_t *k, t;

	k = w;

	k[0] = key[3] << 24 | key[2] << 16 | key[1] << 8 | key[0];
	k[1] = key[7] << 24 | key[6] << 16 | key[5] << 8 | key[4];
	k[2] = key[11] << 24 | key[10] << 16 | key[9] << 8 | key[8];
	k[3] = key[15] << 24 | key[14] << 16 | key[13] << 8 | key[12];

	for (i = 0; i < 10; i++) {
		t = k[3];
		k[4] = k[0] ^ (etab2[t >> 8 & 0xff] & 0xff) ^ (etab3[t >> 16 & 0xff] & 0xff00) ^ (etab0[t >> 24] & 0xff0000) ^ (etab1[t & 0xff] & 0xff000000) ^ rcon[i];
		k[5] = k[1] ^ k[4];
		k[6] = k[2] ^ k[5];
		k[7] = k[3] ^ k[6];
		k += 4;
	}

	for (i = 0; i < 44; i++)
		v[i] = w[i];

	k = v;

	for (i = 0; i < 9; i++) {
		k += 4;
		k[0] = dtab0[etab1[k[0] & 0xff] >> 24] ^ dtab1[etab1[k[0] >> 8 & 0xff] >> 24] ^ dtab2[etab1[k[0] >> 16 & 0xff] >> 24] ^ dtab3[etab1[k[0] >> 24 & 0xff] >> 24];
		k[1] = dtab0[etab1[k[1] & 0xff] >> 24] ^ dtab1[etab1[k[1] >> 8 & 0xff] >> 24] ^ dtab2[etab1[k[1] >> 16 & 0xff] >> 24] ^ dtab3[etab1[k[1] >> 24 & 0xff] >> 24];
		k[2] = dtab0[etab1[k[2] & 0xff] >> 24] ^ dtab1[etab1[k[2] >> 8 & 0xff] >> 24] ^ dtab2[etab1[k[2] >> 16 & 0xff] >> 24] ^ dtab3[etab1[k[2] >> 24 & 0xff] >> 24];
		k[3] = dtab0[etab1[k[3] & 0xff] >> 24] ^ dtab1[etab1[k[3] >> 8 & 0xff] >> 24] ^ dtab2[etab1[k[3] >> 16 & 0xff] >> 24] ^ dtab3[etab1[k[3] >> 24 & 0xff] >> 24];
	}
}

#define s03 (s0 >> 24)
#define s02 (s0 >> 16 & 0xff)
#define s01 (s0 >> 8 & 0xff)
#define s00 (s0 & 0xff)

#define s13 (s1 >> 24)
#define s12 (s1 >> 16 & 0xff)
#define s11 (s1 >> 8 & 0xff)
#define s10 (s1 & 0xff)

#define s23 (s2 >> 24)
#define s22 (s2 >> 16 & 0xff)
#define s21 (s2 >> 8 & 0xff)
#define s20 (s2 & 0xff)

#define s33 (s3 >> 24)
#define s32 (s3 >> 16 & 0xff)
#define s31 (s3 >> 8 & 0xff)
#define s30 (s3 & 0xff)

#define t03 (t0 >> 24)
#define t02 (t0 >> 16 & 0xff)
#define t01 (t0 >> 8 & 0xff)
#define t00 (t0 & 0xff)

#define t13 (t1 >> 24)
#define t12 (t1 >> 16 & 0xff)
#define t11 (t1 >> 8 & 0xff)
#define t10 (t1 & 0xff)

#define t23 (t2 >> 24)
#define t22 (t2 >> 16 & 0xff)
#define t21 (t2 >> 8 & 0xff)
#define t20 (t2 & 0xff)

#define t33 (t3 >> 24)
#define t32 (t3 >> 16 & 0xff)
#define t31 (t3 >> 8 & 0xff)
#define t30 (t3 & 0xff)

// encrypt one block (16 bytes)

void
encrypt_nib(uint32_t *w, uint8_t *in, uint8_t *out)
{
	uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

	s0 = in[3] << 24 | in[2] << 16 | in[1] << 8 | in[0];
	s1 = in[7] << 24 | in[6] << 16 | in[5] << 8 | in[4];
	s2 = in[11] << 24 | in[10] << 16 | in[9] << 8 | in[8];
	s3 = in[15] << 24 | in[14] << 16 | in[13] << 8 | in[12];

	s0 ^= w[0];
	s1 ^= w[1];
	s2 ^= w[2];
	s3 ^= w[3];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[4];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[5];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[6];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[7];

	s0 = etab0[t00] ^ etab1[t11] ^ etab2[t22] ^ etab3[t33] ^ w[8];
	s1 = etab0[t10] ^ etab1[t21] ^ etab2[t32] ^ etab3[t03] ^ w[9];
	s2 = etab0[t20] ^ etab1[t31] ^ etab2[t02] ^ etab3[t13] ^ w[10];
	s3 = etab0[t30] ^ etab1[t01] ^ etab2[t12] ^ etab3[t23] ^ w[11];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[12];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[13];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[14];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[15];

	s0 = etab0[t00] ^ etab1[t11] ^ etab2[t22] ^ etab3[t33] ^ w[16];
	s1 = etab0[t10] ^ etab1[t21] ^ etab2[t32] ^ etab3[t03] ^ w[17];
	s2 = etab0[t20] ^ etab1[t31] ^ etab2[t02] ^ etab3[t13] ^ w[18];
	s3 = etab0[t30] ^ etab1[t01] ^ etab2[t12] ^ etab3[t23] ^ w[19];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[20];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[21];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[22];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[23];

	s0 = etab0[t00] ^ etab1[t11] ^ etab2[t22] ^ etab3[t33] ^ w[24];
	s1 = etab0[t10] ^ etab1[t21] ^ etab2[t32] ^ etab3[t03] ^ w[25];
	s2 = etab0[t20] ^ etab1[t31] ^ etab2[t02] ^ etab3[t13] ^ w[26];
	s3 = etab0[t30] ^ etab1[t01] ^ etab2[t12] ^ etab3[t23] ^ w[27];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[28];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[29];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[30];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[31];

	s0 = etab0[t00] ^ etab1[t11] ^ etab2[t22] ^ etab3[t33] ^ w[32];
	s1 = etab0[t10] ^ etab1[t21] ^ etab2[t32] ^ etab3[t03] ^ w[33];
	s2 = etab0[t20] ^ etab1[t31] ^ etab2[t02] ^ etab3[t13] ^ w[34];
	s3 = etab0[t30] ^ etab1[t01] ^ etab2[t12] ^ etab3[t23] ^ w[35];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[36];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[37];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[38];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[39];

	s0 = (etab2[t00] & 0xff) ^ (etab3[t11] & 0xff00) ^ (etab0[t22] & 0xff0000) ^ (etab1[t33] & 0xff000000) ^ w[40];
	s1 = (etab2[t10] & 0xff) ^ (etab3[t21] & 0xff00) ^ (etab0[t32] & 0xff0000) ^ (etab1[t03] & 0xff000000) ^ w[41];
	s2 = (etab2[t20] & 0xff) ^ (etab3[t31] & 0xff00) ^ (etab0[t02] & 0xff0000) ^ (etab1[t13] & 0xff000000) ^ w[42];
	s3 = (etab2[t30] & 0xff) ^ (etab3[t01] & 0xff00) ^ (etab0[t12] & 0xff0000) ^ (etab1[t23] & 0xff000000) ^ w[43];

	out[0] = s0;
	out[1] = s0 >> 8;
	out[2] = s0 >> 16;
	out[3] = s0 >> 24;

	out[4] = s1;
	out[5] = s1 >> 8;
	out[6] = s1 >> 16;
	out[7] = s1 >> 24;

	out[8] = s2;
	out[9] = s2 >> 8;
	out[10] = s2 >> 16;
	out[11] = s2 >> 24;

	out[12] = s3;
	out[13] = s3 >> 8;
	out[14] = s3 >> 16;
	out[15] = s3 >> 24;
}

// decrypt one block (16 bytes)

void
decrypt_nib(uint32_t *v, uint8_t *in, uint8_t *out)
{
	uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

	s0 = in[3] << 24 | in[2] << 16 | in[1] << 8 | in[0];
	s1 = in[7] << 24 | in[6] << 16 | in[5] << 8 | in[4];
	s2 = in[11] << 24 | in[10] << 16 | in[9] << 8 | in[8];
	s3 = in[15] << 24 | in[14] << 16 | in[13] << 8 | in[12];

	s0 ^= v[40];
	s1 ^= v[41];
	s2 ^= v[42];
	s3 ^= v[43];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[36];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[37];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[38];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[39];

	s0 = dtab0[t00] ^ dtab1[t31] ^ dtab2[t22] ^ dtab3[t13] ^ v[32];
	s1 = dtab0[t10] ^ dtab1[t01] ^ dtab2[t32] ^ dtab3[t23] ^ v[33];
	s2 = dtab0[t20] ^ dtab1[t11] ^ dtab2[t02] ^ dtab3[t33] ^ v[34];
	s3 = dtab0[t30] ^ dtab1[t21] ^ dtab2[t12] ^ dtab3[t03] ^ v[35];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[28];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[29];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[30];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[31];

	s0 = dtab0[t00] ^ dtab1[t31] ^ dtab2[t22] ^ dtab3[t13] ^ v[24];
	s1 = dtab0[t10] ^ dtab1[t01] ^ dtab2[t32] ^ dtab3[t23] ^ v[25];
	s2 = dtab0[t20] ^ dtab1[t11] ^ dtab2[t02] ^ dtab3[t33] ^ v[26];
	s3 = dtab0[t30] ^ dtab1[t21] ^ dtab2[t12] ^ dtab3[t03] ^ v[27];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[20];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[21];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[22];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[23];

	s0 = dtab0[t00] ^ dtab1[t31] ^ dtab2[t22] ^ dtab3[t13] ^ v[16];
	s1 = dtab0[t10] ^ dtab1[t01] ^ dtab2[t32] ^ dtab3[t23] ^ v[17];
	s2 = dtab0[t20] ^ dtab1[t11] ^ dtab2[t02] ^ dtab3[t33] ^ v[18];
	s3 = dtab0[t30] ^ dtab1[t21] ^ dtab2[t12] ^ dtab3[t03] ^ v[19];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[12];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[13];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[14];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[15];

	s0 = dtab0[t00] ^ dtab1[t31] ^ dtab2[t22] ^ dtab3[t13] ^ v[8];
	s1 = dtab0[t10] ^ dtab1[t01] ^ dtab2[t32] ^ dtab3[t23] ^ v[9];
	s2 = dtab0[t20] ^ dtab1[t11] ^ dtab2[t02] ^ dtab3[t33] ^ v[10];
	s3 = dtab0[t30] ^ dtab1[t21] ^ dtab2[t12] ^ dtab3[t03] ^ v[11];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[4];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[5];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[6];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[7];

	s0 = inv_sbox[t00] ^ inv_sbox[t31] << 8 ^ inv_sbox[t22] << 16 ^ inv_sbox[t13] << 24 ^ v[0];
	s1 = inv_sbox[t10] ^ inv_sbox[t01] << 8 ^ inv_sbox[t32] << 16 ^ inv_sbox[t23] << 24 ^ v[1];
	s2 = inv_sbox[t20] ^ inv_sbox[t11] << 8 ^ inv_sbox[t02] << 16 ^ inv_sbox[t33] << 24 ^ v[2];
	s3 = inv_sbox[t30] ^ inv_sbox[t21] << 8 ^ inv_sbox[t12] << 16 ^ inv_sbox[t03] << 24 ^ v[3];

	out[0] = s0;
	out[1] = s0 >> 8;
	out[2] = s0 >> 16;
	out[3] = s0 >> 24;

	out[4] = s1;
	out[5] = s1 >> 8;
	out[6] = s1 >> 16;
	out[7] = s1 >> 24;

	out[8] = s2;
	out[9] = s2 >> 8;
	out[10] = s2 >> 16;
	out[11] = s2 >> 24;

	out[12] = s3;
	out[13] = s3 >> 8;
	out[14] = s3 >> 16;
	out[15] = s3 >> 24;
}
