// decrypt payload then check hmac

void
ssl_decrypt(struct ssl_session *p)
{
	SSLTRACE
	int err, i;
	uint8_t hmac[32];

	switch (p->cipher_suite) {

	case TLS_RSA_WITH_RC4_128_SHA:
	case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
	case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:

		// check payload length

		if (p->payload_length < 20) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
			return;
		}

		// decrypt

		rc4_decrypt(p, p->payload, p->payload_length);

		// sequence number

		for (i = 0; i < 8; i++)
			p->payload[i - 13] = p->expected_sequence_number >> (56 - 8 * i);

		p->expected_sequence_number++;

		// subtract hmac length

		p->payload_length -= 20;

		// fix up record header

		p->payload[-2] = p->payload_length >> 8;
		p->payload[-1] = p->payload_length;

		// check hmac

		hmac_sha1(p->check_mac_key, 20, p->payload - 13, p->payload_length + 13, hmac);

		if (memcmp(hmac, p->payload + p->payload_length, 20) != 0) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
		}

		break;

	case TLS_RSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:

		// check payload length

		if (p->payload_length < 32 || (p->payload_length & 0xf) != 0) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
			return;
		}

		// decrypt

		aes128_decrypt(p, p->payload, p->payload_length / 16);

		// check hmac (rfc recommends doing hmac check anyway in event of pad error)

		err = ssl_hmac_prep(p, 20);

		hmac_sha1(p->check_mac_key, 20, p->payload - 13, p->payload_length + 13, hmac);

		if (err || memcmp(hmac, p->payload + p->payload_length, 20) != 0) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
		}

		break;
#if 0
	case TLS_RSA_WITH_AES_256_CBC_SHA:
	case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:

		// check payload length

		if (p->payload_length < 32 || (p->payload_length & 0xf) != 0) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
			return;
		}

		// decrypt

		aes256_decrypt(p, p->payload, p->payload_length / 16);

		// check hmac (rfc recommends doing hmac check anyway in event of pad error)

		err = ssl_hmac_prep(p, 20);

		hmac_sha1(p->check_mac_key, 20, p->payload - 13, p->payload_length + 13, hmac);

		if (err || memcmp(hmac, p->payload + p->payload_length, 20) != 0) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
		}

		break;
#endif
	case TLS_RSA_WITH_AES_128_CBC_SHA256:

		// check payload length

		if (p->payload_length < 48 || (p->payload_length & 0xf) != 0) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
			return;
		}

		// decrypt

		aes128_decrypt(p, p->payload, p->payload_length / 16);

		// check hmac (rfc recommends doing hmac check anyway in event of pad error)

		err = ssl_hmac_prep(p, 32);

		hmac_sha256(p->check_mac_key, 32, p->payload - 13, p->payload_length + 13, hmac);

		if (err || memcmp(hmac, p->payload + p->payload_length, 32) != 0) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
		}

		break;
#if 0
	case TLS_RSA_WITH_AES_256_CBC_SHA256:

		// check payload length

		if (p->payload_length < 48 || (p->payload_length & 0xf) != 0) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
			return;
		}

		// decrypt

		aes256_decrypt(p, p->payload, p->payload_length / 16);

		// check hmac (rfc recommends doing hmac check anyway in event of pad error)

		err = ssl_hmac_prep(p, 32);

		hmac_sha256(p->check_mac_key, 32, p->payload - 13, p->payload_length + 13, hmac);

		if (err || memcmp(hmac, p->payload + p->payload_length, 32) != 0) {
			send_alert_20_bad_record_mac(p);
			ssl_disconnect(p, "bad_record_mac", __LINE__);
		}

		break;
#endif
	default:
		if (p->debug)
			printf("missing case label (%s, line %d)\n", __FILE__, __LINE__);
		break;
	}
}
