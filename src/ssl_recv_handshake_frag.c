void
ssl_recv_handshake_frag(struct ssl_session *p)
{
	SSLTRACE
	int n;

	// typical case: perfect alignment with record protocol

	if (p->handshake_buffer == NULL && p->payload_length >= 4) {
		p->handshake_length = p->payload[1] << 16 | p->payload[2] << 8 | p->payload[3];
		if (p->handshake_length + 4 == p->payload_length) {
			p->hbuf = p->payload;
			receive_handshake_message(p);
			p->hbuf = NULL;
			return;
		}
	}

	// alloc handshake buffer space

	if (p->handshake_buffer == NULL) {

		p->handshake_buffer = ssl_malloc(p->payload_length);
		p->handshake_malloc_length = p->payload_length;
		p->handshake_receive_length = 0;

	} else if (p->handshake_receive_length + p->payload_length > p->handshake_malloc_length) {

		if (p->handshake_malloc_length > 30000) { // the 16 MB limit is an attack vector
			send_alert_0_close_notify(p);
			ssl_disconnect(p, "buffer", __LINE__);
			return;
		}

		p->handshake_buffer = realloc(p->handshake_buffer, p->handshake_receive_length + p->payload_length);

		if (p->handshake_buffer == NULL) {
			printf("realloc failure (%s, line %d)\n", __FILE__, __LINE__);
			exit(1);
		}

		p->handshake_malloc_length = p->handshake_receive_length + p->payload_length;
	}

	// update handshake buffer

	memcpy(p->handshake_buffer + p->handshake_receive_length, p->payload, p->payload_length);

	p->handshake_receive_length += p->payload_length;

	for (;;) {

		if (p->handshake_receive_length < 4)
			break; // incomplete

		// get length from header

		p->handshake_length = p->handshake_buffer[1] << 16 | p->handshake_buffer[2] << 8 | p->handshake_buffer[3];

		// add 4 for header length

		n = p->handshake_length + 4;

		if (p->handshake_receive_length < n)
			break; // incomplete

		p->hbuf = p->handshake_buffer;
		receive_handshake_message(p);
		p->hbuf = NULL;

		// pull up

		p->handshake_receive_length -= n;
		memmove(p->handshake_buffer, p->handshake_buffer + n, p->handshake_receive_length);
	}

	if (p->handshake_receive_length == 0) {
		ssl_free(p->handshake_buffer);
		p->handshake_buffer = NULL;
	}
}
