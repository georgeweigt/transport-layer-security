void
rc4_init(struct ssl_session *p, unsigned char *encrypt_key, unsigned char *decrypt_key)
{
	int i, j, t;
	struct rc4 *q;

	q = &p->encrypt;

	for (i = 0; i < 256; i++)
		q->S[i] = i;
	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + q->S[i] + encrypt_key[i % 16]) & 0xff;
		t = q->S[i];
		q->S[i] = q->S[j];
		q->S[j] = t;
	}

	q = &p->decrypt;

	for (i = 0; i < 256; i++)
		q->S[i] = i;
	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + q->S[i] + decrypt_key[i % 16]) & 0xff;
		t = q->S[i];
		q->S[i] = q->S[j];
		q->S[j] = t;
	}
}

void
rc4_encrypt(struct ssl_session *p, unsigned char *buf, int n)
{
	rc4(&p->encrypt, buf, n);
}

void
rc4_decrypt(struct ssl_session *p, unsigned char *buf, int n)
{
	rc4(&p->decrypt, buf, n);
}

void
rc4(struct rc4 *p, unsigned char *buf, int n)
{
	int k, t;
	for (k = 0; k < n; k++) {
		p->i = (p->i + 1) & 0xff;
		p->j = (p->j + p->S[p->i]) & 0xff;
		t = p->S[p->i];
		p->S[p->i] = p->S[p->j];
		p->S[p->j] = t;
		buf[k] ^= p->S[(p->S[p->i] + p->S[p->j]) & 0xff];
	}
}
