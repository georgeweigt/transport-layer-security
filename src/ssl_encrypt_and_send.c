//          ______
//         |______| 69 bytes (5 for header, 64 for iv)
//   buf ->|      |
//         |      | len bytes
//         |______|

void
ssl_encrypt_and_send(struct ssl_session *p, int type, uint8_t *buf, int len)
{
	SSLTRACE
	int i, pad;
	uint32_t t;

	// sequence number

	for (i = 0; i < 8; i++)
		buf[i - 13] = p->send_sequence_number >> (56 - 8 * i);

	p->send_sequence_number++;

	switch (p->cipher_suite) {

	case TLS_RSA_WITH_RC4_128_SHA:
	case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
	case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		hmac_sha1(p->write_mac_key, 20, buf - 13, len + 13, buf + len);
		len += 20; // add 20 for hmac
		rc4_encrypt(p, buf, len);
		break;

	case TLS_RSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		hmac_sha1(p->write_mac_key, 20, buf - 13, len + 13, buf + len);
		len += 20; // add 20 for hmac
		if (p->tls_version > TLS_V10) {
			// insert iv
			buf -= 16;
			len += 16;
			for (i = 0; i < 4; i++) {
				t = random();
				buf[4 * i + 0] = t >> 24;
				buf[4 * i + 1] = t >> 16;
				buf[4 * i + 2] = t >> 8;
				buf[4 * i + 3] = t;
			}
		}
		pad = 15 - (len & 0xf);
		memset(buf + len, pad, pad + 1);
		len += pad + 1;
		aes128_encrypt(p, buf, len / 16);
		break;
#if 0
	case TLS_RSA_WITH_AES_256_CBC_SHA:
	case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		hmac_sha1(p->write_mac_key, 20, buf - 13, len + 13, buf + len);
		len += 20; // add 20 for hmac
		if (p->tls_version > TLS_V10) {
			// insert iv
			buf -= 16;
			len += 16;
			for (i = 0; i < 4; i++) {
				t = random();
				buf[4 * i + 0] = t >> 24;
				buf[4 * i + 1] = t >> 16;
				buf[4 * i + 2] = t >> 8;
				buf[4 * i + 3] = t;
			}
		}
		pad = 15 - (len & 0xf);
		memset(buf + len, pad, pad + 1);
		len += pad + 1;
		aes256_encrypt(p, buf, len / 16);
		break;
#endif
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
		hmac_sha256(p->write_mac_key, 32, buf - 13, len + 13, buf + len);
		len += 32; // add 32 for hmac
		if (p->tls_version > TLS_V10) {
			// insert iv
			buf -= 16;
			len += 16;
			for (i = 0; i < 4; i++) {
				t = random();
				buf[4 * i + 0] = t >> 24;
				buf[4 * i + 1] = t >> 16;
				buf[4 * i + 2] = t >> 8;
				buf[4 * i + 3] = t;
			}
		}
		pad = 15 - (len & 0xf);
		memset(buf + len, pad, pad + 1);
		len += pad + 1;
		aes128_encrypt(p, buf, len / 16);
		break;
#if 0
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		hmac_sha256(p->write_mac_key, 32, buf - 13, len + 13, buf + len);
		len += 32; // add 32 for hmac
		if (p->tls_version > TLS_V10) {
			// insert iv
			buf -= 16;
			len += 16;
			for (i = 0; i < 4; i++) {
				t = random();
				buf[4 * i + 0] = t >> 24;
				buf[4 * i + 1] = t >> 16;
				buf[4 * i + 2] = t >> 8;
				buf[4 * i + 3] = t;
			}
		}
		pad = 15 - (len & 0xf);
		memset(buf + len, pad, pad + 1);
		len += pad + 1;
		aes256_encrypt(p, buf, len / 16);
		break;
#endif
	default:
		if (p->debug)
			printf("missing case label (%s, line %d)\n", __FILE__, __LINE__);
		break;
	}

	// write record header again (buf ptr and len changed)

	buf[-5] = type;
	buf[-4] = p->tls_version >> 8;
	buf[-3] = p->tls_version;
	buf[-2] = len >> 8;
	buf[-1] = len;

	p->send_buf = buf - 5;
	p->send_len = len + 5;

	ssl_send(p);
}
