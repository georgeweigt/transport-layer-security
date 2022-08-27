void
ssl_recv_record(struct ssl_session *p, uint8_t *record_buf, int record_len)
{
	SSLTRACE

	p->payload = record_buf + 5;
	p->payload_length = record_len - 5;

	if (p->received_change_cipher_spec) {
		ssl_decrypt(p);
		if (p->state == SSL_DISCONNECTED)
			return;
	}

	switch (record_buf[0]) {

	case CHANGE_CIPHER_SPEC:
		receive_change_cipher_spec(p);
		break;

	case ALERT:
		ssl_recv_alert(p);
		break;

	case HANDSHAKE:
		ssl_recv_handshake_frag(p);
		break;

	case APPLICATION_DATA:
		receive_application_data(p);
		break;

	default:
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		break;
	}
}
