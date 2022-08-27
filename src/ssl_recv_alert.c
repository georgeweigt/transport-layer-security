void
ssl_recv_alert(struct ssl_session *p)
{
	SSLTRACE
	int alert_level, alert_descr;

	// check length

	if (p->payload_length != 2) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	alert_level = p->payload[0];
	alert_descr = p->payload[1];

	if (p->debug) {
		printf("received alert level %d (%s)\n", alert_level, alert_level_str(alert_level));
		printf("received alert descr %d (%s)\n", alert_descr, alert_descr_str(alert_descr));
	}

	// 1,0 is close_notify

	if (alert_level == 1 && alert_descr == 0) {
		send_alert_0_close_notify(p);
		ssl_disconnect(p, "close_notify", __LINE__);
		return;
	}

	// close on fatal error

	if (alert_level == 2) {
		send_alert_0_close_notify(p);
		ssl_disconnect(p, "alert_fatal", __LINE__);
		return;
	}
}
