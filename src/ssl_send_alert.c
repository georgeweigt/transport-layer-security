void
ssl_send_alert(struct ssl_session *p, int level, int descr)
{
	SSLTRACE
	uint8_t *buf = p->outbuf + SSLPAD;

	if (p->debug) {
		printf("sending alert level %d (%s)\n", level, alert_level_str(level));
		printf("sending alert descr %d (%s)\n", descr, alert_descr_str(descr));
	}

	buf[0] = level;
	buf[1] = descr;

	ssl_send_record(p, ALERT, buf, 2);
}
