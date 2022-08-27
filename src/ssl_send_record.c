void
ssl_send_record(struct ssl_session *p, int type, uint8_t *buf, int len)
{
	SSLTRACE

	buf[-5] = type;
	buf[-4] = p->tls_version >> 8;
	buf[-3] = p->tls_version;
	buf[-2] = len >> 8;
	buf[-1] = len;

	if (p->sent_change_cipher_spec)
		ssl_encrypt_and_send(p, type, buf, len);
	else {
		p->send_buf = buf - 5;
		p->send_len = len + 5;
		ssl_send(p);
	}
}
