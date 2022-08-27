// call when socket has receive data

void
ssl_recv(struct ssl_session *p)
{
	SSLTRACE
	int len, n;

	if (p->send_len)
		return; // can't receive while send is blocked

	// len is available buffer space

	len = sizeof p->inbuf - p->inbuf_length - SSLPAD - SSLPAD;

	if (len == 0) {
		ssl_disconnect(p, "record_size", __LINE__);
		return;
	}

	// receive

	n = recv(p->fd, p->inbuf + SSLPAD + p->inbuf_length, len, 0);

	if (n == 0) {
		ssl_disconnect(p, "half_close", __LINE__);
		return;
	}

	if (n < 0) {
		if (errno == EAGAIN)
			;
		else
			ssl_disconnect(p, "recv_err", __LINE__);
		return;
	}

	p->inbuf_length += n;

	for (;;) {

		if (p->inbuf_length < 5)
			break; // incomplete record header

		// get record length from header

		len = p->inbuf[SSLPAD + 3] << 8 | p->inbuf[SSLPAD + 4];

		// n is the total record length

		n = len + 5;

		if (p->inbuf_length < n)
			break; // incomplete record

		ssl_recv_record(p, p->inbuf + SSLPAD, n);

		// pull up

		p->inbuf_length -= n;

		if (p->inbuf_length)
			memmove(p->inbuf + SSLPAD, p->inbuf + SSLPAD + n, p->inbuf_length);
	}
}
