void
ssl_send(struct ssl_session *p)
{
	SSLTRACE

	int n = send(p->fd, p->send_buf, p->send_len, 0);

	if (n < 0) {
		if (errno != EAGAIN)
			ssl_disconnect(p, "send_err", __LINE__);
		return;
	}

	p->send_buf += n;
	p->send_len -= n;
}
