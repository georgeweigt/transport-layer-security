// SSL functions
//
// ssl_start_client_session()
//
// ssl_start_server_session()
//
// ssl_data_in()

int ssl_malloc_count;
static int allow_missing_length_field = 1; // common error in older browsers

// cipher suites sent to server

int cipher_suite_tab[] = {
	TLS_RSA_WITH_AES_128_CBC_SHA,
};

//	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
//	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
//	TLS_RSA_WITH_AES_256_CBC_SHA,
//	TLS_RSA_WITH_AES_128_CBC_SHA,
//	TLS_RSA_WITH_AES_128_CBC_SHA256,
//	TLS_RSA_WITH_RC4_128_SHA,

void
ssl_disconnect(struct ssl_session *p, char *reason, int line)
{
	SSLTRACE
	if (p->debug)
		printf("ssl_disconnect (%s) from line %d\n", reason, line);
	p->state = SSL_DISCONNECTED;
}

void
ssl_close(struct ssl_session *p)
{
	SSLTRACE

	if (p->handshake_buffer) {
		ssl_free(p->handshake_buffer);
		p->handshake_buffer = NULL;
	}

	if (p->client_hello) {
		ssl_free(p->client_hello);
		p->client_hello = NULL;
	}

	if (p->server_name) {
		ssl_free(p->server_name);
		p->server_name = NULL;
	}

	ssl_free_keys(p);
}

void
ssl_start_client_session(struct ssl_session *p, char *hostname)
{
	SSLTRACE
	int i;
	time_t t;

	if (strlen(hostname) + 1 > sizeof p->hostname)
		return;

	strcpy(p->hostname, hostname);

	time(&t);

	p->tls_version = TLS_V12;

	p->client_random[0] = (uint32_t) t >> 24;
	p->client_random[1] = (uint32_t) t >> 16;
	p->client_random[2] = (uint32_t) t >> 8;
	p->client_random[3] = (uint32_t) t;

	for (i = 4; i < 32; i++)
		p->client_random[i] = random();

	send_client_hello(p);

	p->state = WAITING_FOR_SERVER_HELLO;
}

void
ssl_start_server_session(struct ssl_session *p)
{
	SSLTRACE
	int i;
	time_t t;
	time(&t);
	p->server_mode = 1;
	p->server_random[0] = (unsigned) t >> 24;
	p->server_random[1] = (unsigned) t >> 16;
	p->server_random[2] = (unsigned) t >> 8;
	p->server_random[3] = (unsigned) t;
	for (i = 4; i < 32; i++)
		p->server_random[i] = random();
	p->signature_length = provisioned_ci.signature_length;
	p->state = WAITING_FOR_CLIENT_HELLO;
}

void
receive_application_data(struct ssl_session *p)
{
	SSLTRACE
	p->app_data_recv_count += p->payload_length;
	main_recv(p->payload, p->payload_length);
}

void
receive_handshake_message(struct ssl_session *p)
{
	SSLTRACE

	switch (p->state) {

	case WAITING_FOR_CLIENT_HELLO:
		receive_client_hello(p);
		break;

	case WAITING_FOR_SERVER_HELLO:
		receive_server_hello(p);
		break;

	case WAITING_FOR_SERVER_CERTIFICATE:
		receive_server_certificate(p);
		break;

	case WAITING_FOR_SERVER_KEY_EXCHANGE:
		receive_server_key_exchange(p);
		break;

	case WAITING_FOR_SERVER_HELLO_DONE:
		receive_server_hello_done(p);
		break;

	case WAITING_FOR_CLIENT_KEY_EXCHANGE:
		receive_client_key_exchange(p);
		break;

	case WAITING_FOR_CLIENT_FINISHED:
		receive_client_finished(p);
		break;

	case WAITING_FOR_SERVER_FINISHED:
		receive_server_finished(p);
		break;

	default:
		break;
	}
}

void
send_client_hello(struct ssl_session *p)
{
	SSLTRACE
	int i, j, k, n;
	int ec = 0;
	uint8_t *buf = p->outbuf + SSLPAD;

	k = 0;

	buf[k++] = CLIENT_HELLO;

	k += 3; // skip over handshake length

	buf[k++] = p->tls_version >> 8; // version
	buf[k++] = p->tls_version;

	memcpy(buf + k, p->client_random, 32);

	k += 32;

	buf[k++] = 0; // no session id

	buf[k++] = 0; // byte length of cipher suite list
	buf[k++] = 2 * sizeof cipher_suite_tab / sizeof (int);

	for (i = 0; i < sizeof cipher_suite_tab / sizeof (int); i++) {
		buf[k++] = cipher_suite_tab[i] >> 8;
		buf[k++] = cipher_suite_tab[i];
		if ((cipher_suite_tab[i] & 0xf000) == 0xc000)
			ec = 1; // set elliptic curve flag
	}

	buf[k++] = 0x01; // no compression
	buf[k++] = 0x00;

	// client hello extensions

	j = k; // save start of extension list

	k += 2; // skip over extension list length

	// server name extension

	n = strlen(p->hostname);
	buf[k++] = 0; // extension id (2 bytes)
	buf[k++] = 0;
	buf[k++] = (n + 5) >> 8; // extension length
	buf[k++] = n + 5;
	buf[k++] = (n + 3) >> 8; // list length
	buf[k++] = n + 3;
	buf[k++] = 0; // name type
	buf[k++] = n >> 8; // name length
	buf[k++] = n;
	memcpy(buf + k, p->hostname, n);
	k += n;

	// extensions for elliptic curve cipher suites

	if (ec) {

		// supported elliptic curves extension (RFC 4492, p. 12)

		buf[k++] = 0;
		buf[k++] = 10; // extension type (RFC 4492, p. 11)

		buf[k++] = 0;
		buf[k++] = 6; // extension length

		buf[k++] = 0;
		buf[k++] = 4; // list length

		buf[k++] = 0;
		buf[k++] = 23; // secp256r1 (same as prime256v1)

		buf[k++] = 0;
		buf[k++] = 24; // secp384r1

		// supported point formats extension (RFC 4492, p. 13)

		buf[k++] = 0;
		buf[k++] = 11; // extension type (RFC 4492, p. 11)

		buf[k++] = 0;
		buf[k++] = 2; // extension length

		buf[k++] = 1; // list length

		buf[k++] = 0; // uncompressed point format
	}

	// write extension list length

	n = k - j - 2; // 2 byte length field is not included

	buf[j + 0] = n >> 8;
	buf[j + 1] = n;

	// write handshake message length

	n = k - 4; // 4 byte handshake header is not included

	buf[1] = n >> 24;
	buf[2] = n >> 16;
	buf[3] = n;

	start_handshake_hash(p, buf, k);

	ssl_send_record(p, HANDSHAKE, buf, k);
}

void
receive_client_hello(struct ssl_session *p)
{
	SSLTRACE
	int err, i, k = 0, len, n;
	uint8_t *buf;

	// check message type

	if (p->hbuf[0] != CLIENT_HELLO) {
		send_alert_10_unexpected_message(p);
		ssl_disconnect(p, "unexpected_message", __LINE__);
		return;
	}

	// prepare to parse client hello data

	buf = p->hbuf + 4;
	len = p->handshake_length;

	// check version

	if (k + 2 > len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	p->tls_version = buf[k] << 8 | buf[k + 1];

	switch (p->tls_version) {
	case TLS_V10:
	case TLS_V11:
	case TLS_V12:
		break;
	default:
		send_alert_70_protocol_version(p);
		ssl_disconnect(p, "protocol_version", __LINE__);
		return;
	}

	k += 2; // advance to next element

	// save client random

	if (k + 32 > len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	for (i = 0; i < 32; i++)
		p->client_random[i] = buf[k++];

	// session id

	if (k + 1 > len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	n = buf[k++];

	if (n > 32 || k + n > len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	k += n;

	// check list of cipher suites

	if (k + 2 > len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	n = buf[k] << 8 | buf[k + 1]; // n is length of cipher suite list in bytes

	k += 2;

	if (n % 2 != 0 || k + n > len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	// client facing ssl only supports rsa encryption

	for (i = 0; i < n; i += 2) {
		p->cipher_suite = buf[k + i] << 8 | buf[k + i + 1];
		if (p->cipher_suite == TLS_RSA_WITH_RC4_128_SHA)
			break;
		if (p->cipher_suite == TLS_RSA_WITH_AES_128_CBC_SHA)
			break;
		if (p->cipher_suite == TLS_RSA_WITH_AES_128_CBC_SHA256)
			break;
#if 0
		if (p->cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA)
			break;
		if (p->cipher_suite == TLS_RSA_WITH_AES_256_CBC_SHA256)
			break;
#endif
	}

	if (i == n) {
		send_alert_40_handshake_failure(p); // no acceptable cipher suite
		ssl_disconnect(p, "handshake_failure", __LINE__);
		return;
	}

	k += n; // advance to next element

	// check compression list for null (no compression)

	if (k + 1 > len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	n = buf[k++];

	if (k + n > len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	for (i = 0; i < n; i++)
		if (buf[k + i] == 0)
			break;

	if (i == n) {
		send_alert_40_handshake_failure(p);
		ssl_disconnect(p, "handshake_failure", __LINE__);
		return;
	}

	k += n; // advance to next element

	// parse extensions

	if (k < len) {

		// need at least 2 more bytes

		if (k + 2 > len) {
			send_alert_50_decode_error(p);
			ssl_disconnect(p, "decode_error", __LINE__);
			return;
		}

		n = buf[k] << 8 | buf[k + 1]; // n is length of extension_list

		k += 2;

		// need at least n more bytes

		if (k + n > len) {
			send_alert_50_decode_error(p);
			ssl_disconnect(p, "decode_error", __LINE__);
			return;
		}

		err = ssl_parse_extension_list(p, buf + k, n);

		if (err) {
			send_alert_50_decode_error(p);
			ssl_disconnect(p, "decode_error", __LINE__);
			return;
		}

		k += n;
	}

	// parsing is complete

	start_handshake_hash(p, p->hbuf, p->handshake_length + 4);

	send_server_hello(p);

	send_server_certificate(p);

	send_server_hello_done(p);

	p->state = WAITING_FOR_CLIENT_KEY_EXCHANGE;
}

int
ssl_parse_extension_list(struct ssl_session *p, uint8_t *buf, int len)
{
	int err, k = 0, n, t;

	while (k < len) {

		// need at least 4 more bytes

		if (k + 4 > len)
			return -1;

		t = buf[k] << 8 | buf[k + 1];		// t is extension type
		n = buf[k + 2] << 8 | buf[k + 3];	// n is extension length

		k += 4;

		// need at least n more bytes

		if (k + n > len)
			return -1;

		switch (t) {
		case 0:
			err = ssl_parse_server_name(p, buf + k, n);
			if (err)
				return -1;
			break;
		default:
			break;
		}

		k += n;
	}

	return 0;
}

// returns 0 for ok, otherwise -1

int
ssl_parse_server_name(struct ssl_session *p, uint8_t *buf, int len)
{
	int k = 0, n;

	if (len == 0)
		return 0; // empty extension

	// need at least 2 more bytes

	if (k + 2 > len)
		return -1;

	n = buf[k] << 8 | buf[k + 1]; // n is length of server name list

	if (n == 0)
		return 0; // empty list

	k += 2;

	// need at least n more bytes

	if (k + n > len)
		return -1;

	len = k + n;

	// need at least 3 more bytes

	if (k + 3 > len)
		return -1;

	n = buf[k + 1] << 8 | buf[k + 2]; // n is length of server name

	if (n == 0)
		return 0;

	k += 3;

	// need at least n more bytes

	if (k + n > len)
		return -1;

	// make a copy of server name

	if (p->server_name == NULL) {
		p->server_name = ssl_malloc(n);
		memcpy(p->server_name, buf + k, n);
		p->server_name_length = n;
	}

	return 0;
}

void
send_server_hello(struct ssl_session *p)
{
	SSLTRACE
	int k, n;
	uint8_t *buf = p->outbuf + SSLPAD;

	k = 0;

	buf[k++] = SERVER_HELLO;

	k += 3; // skip over length field

	buf[k++] = p->tls_version >> 8; // version
	buf[k++] = p->tls_version;

	memcpy(buf + k, p->server_random, 32);

	k += 32;

	buf[k++] = 0; // no session id

	buf[k++] = p->cipher_suite >> 8;
	buf[k++] = p->cipher_suite;

	buf[k++] = 0x00; // no compression

	n = k - 4; // length does not include header

	buf[1] = n >> 24; // length
	buf[2] = n >> 16;
	buf[3] = n;

	update_handshake_hash(p, buf, k);

	ssl_send_record(p, HANDSHAKE, buf, k);
}

void
receive_server_hello(struct ssl_session *p)
{
	SSLTRACE
	int i, k, len, n;
	uint8_t *buf;

	// check message type

	if (p->hbuf[0] != SERVER_HELLO) {
		send_alert_10_unexpected_message(p);
		ssl_disconnect(p, "unexpected_message", __LINE__);
		return;
	}

	// prepare to parse server hello data

	buf = p->hbuf + 4;
	len = p->handshake_length;
	k = 0;

	// check version

	if (k + 2 > len) { // check length
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	if ((buf[k] << 8 | buf[k + 1]) != p->tls_version) {
		send_alert_70_protocol_version(p);
		ssl_disconnect(p, "protocol_version", __LINE__);
		return;
	}

	k += 2; // advance to next element

	// save server random

	if (k + 32 > len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	for (i = 0; i < 32; i++)
		p->server_random[i] = buf[k++];

	// session id

	if (k + 1 > len) { // check length
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	n = buf[k++]; // get byte count

	if (n > 32 || k + n > len) { // check length
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	k += n; // advance to next element

	// cipher suite

	if (k + 2 > len) { // check length
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	p->cipher_suite = buf[k] << 8 | buf[k + 1]; // get cipher suite

	k += 2; // advance to next element

	// check that cipher suite was sent in client-hello message

	for (i = 0; i < sizeof cipher_suite_tab / sizeof (int); i++)
		if (p->cipher_suite == cipher_suite_tab[i])
			break;

	if (i == sizeof cipher_suite_tab / sizeof (int)) {
		send_alert_40_handshake_failure(p);
		ssl_disconnect(p, "handshake_failure", __LINE__);
		return;
	}

	// check for no compression

	if (k + 1 > len) { // check length
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	if (buf[k++] != 0) { // check value
		send_alert_40_handshake_failure(p);
		ssl_disconnect(p, "handshake_failure", __LINE__);
		return;
	}

	// parsing is complete

	update_handshake_hash(p, p->hbuf, p->handshake_length + 4);

	p->state = WAITING_FOR_SERVER_CERTIFICATE;
}

void
send_server_certificate(struct ssl_session *p)
{
	SSLTRACE
	int cert_length;
	uint8_t *buf;

	cert_length = provisioned_ci.cert_length;

	buf = ssl_malloc(cert_length + 128);

	buf[32] = CERTIFICATE;

	buf[33] = (cert_length + 6) >> 16;
	buf[34] = (cert_length + 6) >> 8;
	buf[35] = cert_length + 6;

	buf[36] = (cert_length + 3) >> 16;	// chain length
	buf[37] = (cert_length + 3) >> 8;
	buf[38] = cert_length + 3;

	buf[39] = cert_length >> 16;
	buf[40] = cert_length >> 8;
	buf[41] = cert_length;

	memcpy(buf + 42, provisioned_ci.cert, cert_length);

	update_handshake_hash(p, buf + 32, cert_length + 10);

	ssl_send_record(p, HANDSHAKE, buf + 32, cert_length + 10);

	ssl_free(buf);
}

// Outline of certificate chain
//  ________
// |________| Total length (3 bytes)
// |________| Length of 1st certificate (3 bytes)
// |        |
// |        | 1st certificate
// |________|
// |________| Length of 2nd certificate (3 bytes)
// |        |
// |        | 2nd certificate
// |________|
//     .
//     .
//     .
//  ________
// |________| Length of last certificate (3 bytes)
// |        |
// |        | Last certificate
// |________|

void
receive_server_certificate(struct ssl_session *p)
{
	SSLTRACE
	int err, k, len;

	// check message type

	if (p->hbuf[0] != CERTIFICATE) {
		send_alert_10_unexpected_message(p);
		ssl_disconnect(p, "unexpected_message", __LINE__);
		return;
	}

	// check message length

	if (p->handshake_length < 3) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	// check chain length

	len = p->hbuf[4] << 16 | p->hbuf[5] << 8 | p->hbuf[6];

	if (len + 3 != p->handshake_length) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	// check certificate lengths

	k = 0;

	while (k + 3 < len)
		k += (p->hbuf[k + 7] << 16 | p->hbuf[k + 8] << 8 | p->hbuf[k + 9]) + 3;

	if (k != len) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	// check certificate chain

	err = checkchain(p, p->hbuf + 4, p->handshake_length);

	if (err) {
		send_alert_42_bad_certificate(p);
		ssl_disconnect(p, "bad_certificate", __LINE__);
		return;
	}

	update_handshake_hash(p, p->hbuf, p->handshake_length + 4);

	switch (p->cipher_suite) {
	case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		p->state = WAITING_FOR_SERVER_KEY_EXCHANGE;
		break;
	default:
		p->state = WAITING_FOR_SERVER_HELLO_DONE;
		break;
	}
}

void
send_server_hello_done(struct ssl_session *p)
{
	SSLTRACE
	uint8_t buf[64];

	buf[32] = SERVER_HELLO_DONE;

	buf[33] = 0; // length
	buf[34] = 0;
	buf[35] = 0;

	update_handshake_hash(p, buf + 32, 4);

	ssl_send_record(p, HANDSHAKE, buf + 32, 4);
}

void
receive_server_key_exchange(struct ssl_session *p)
{
	SSLTRACE
	int err;
	struct ephemeral_key key;

	// check message type

	if (p->hbuf[0] != SERVER_KEY_EXCHANGE) {
		send_alert_10_unexpected_message(p);
		ssl_disconnect(p, "unexpected_message", __LINE__);
		return;
	}

	update_handshake_hash(p, p->hbuf, p->handshake_length + 4);

	// parse ephemeral key from server

	err = parse_server_key_message(p, &key);

	if (err) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	// check key signature (signed using certificate key)

	err = check_ephemeral_key_signature(p, &key);

	if (err) {
		send_alert_51_decrypt_error(p);
		ssl_disconnect(p, "decrypt_error", __LINE__);
		return;
	}

	// compute client public key (returned to server) and pre-master secret

	switch (p->ephemeral_encryption_algorithm) {
	case PRIME256V1:
		ecdhe256_generate(p, key.x, key.y);
		break;
	case SECP384R1:
		ecdhe384_generate(p, key.x, key.y);
		break;
	}

	p->state = WAITING_FOR_SERVER_HELLO_DONE;
}

int
parse_server_key_message(struct ssl_session *p, struct ephemeral_key *key)
{
	int k, len, m;
	uint8_t *buf = p->hbuf + 4;

	if (p->handshake_length < 5)
		return -1;

	// expect named_curve (see RFC 4492, p. 17)

	if (buf[0] != 3)
		return -1;

	// named curve (see RFC 4492, p. 12)

	switch (buf[1] << 8 | buf[2]) {
	case 23:
		p->ephemeral_encryption_algorithm = PRIME256V1;
		break;
	case 24:
		p->ephemeral_encryption_algorithm = SECP384R1;
		break;
	default:
		return -1;
	}

	// expect uncompressed point format

	if (buf[4] != 4)
		return -1;

	// check public key length

	len = buf[3];

	k = 4;

	switch (p->ephemeral_encryption_algorithm) {
	case PRIME256V1:
		if (len != 65 || k + len > p->handshake_length)
			return -1;
		key->x = buf + k + 1;
		key->y = buf + k + 33;
		break;
	case SECP384R1:
		if (len != 97 || k + len > p->handshake_length)
			return -1;
		key->x = buf + k + 1;
		key->y = buf + k + 49;
		break;
	}

	k += len;

	// expect sha1 hash algorithm (see RFC 5246, p. 46)

	if (k + 1 > p->handshake_length)
		return -1;

	if (buf[k++] != 2)
		return -1;

	// expect ecdsa signature algorithm (see RFC 5246, p. 46)

	if (k + 1 > p->handshake_length)
		return -1;

	if (buf[k++] != 3)
		return -1;

	// get signature length

	if (k + 2 > p->handshake_length)
		return -1;

	len = buf[k] << 8 | buf[k + 1];

	k += 2;

	m = k + len;

	if (m > p->handshake_length)
		return -1;

	// expect x.509 sequence type

	if (k + 1 > m)
		return -1;

	if (buf[k++] != SEQUENCE)
		return -1;

	// get length

	len = ssl_get_x509_length(buf, &k, m);

	if (len < 1 || k + len != m)
		return -1;

	// get r

	if (k + 1 > m)
		return -1;

	if (buf[k++] != INTEGER)
		return -1;

	len = ssl_get_x509_length(buf, &k, m);

	if (len < 1 || k + len > m)
		return -1;

	key->r = buf + k;
	key->r_length = len;

	k += len;

	// get s

	if (k + 1 > m)
		return -1;

	if (buf[k++] != INTEGER)
		return -1;

	len = ssl_get_x509_length(buf, &k, m);

	if (len < 1 || k + len > m)
		return -1;

	key->s = buf + k;
	key->s_length = len;

	return 0;
}

int
ssl_get_x509_length(uint8_t *buf, int *offset, int end)
{
	int i, k, len, n;

	k = *offset;

	if (k >= end)
		return -1;

	len = buf[k++];

	if ((len & 0x80) == 0) {
		*offset = k;
		return len;
	}

	n = len & 0x7f; // n is a byte count

	len = 0;

	for (i = 0; i < n; i++) {
		if (k >= end)
			return -1;
		if (len & 0xff000000)
			return -1; // overflow
		len = len << 8 | buf[k++];
	}

	*offset = k;

	return len;
}

// ephemeral key is signed using key from certificate

int
check_ephemeral_key_signature(struct ssl_session *p, struct ephemeral_key *key)
{
	int err = -1, len;
	uint8_t buf[165]; // 32 + 32 + 5 + 48 + 48 = 165
	uint8_t hash[64];

	switch (p->ephemeral_encryption_algorithm) {
	case PRIME256V1:
		len = 64;
		break;
	case SECP384R1:
		len = 96;
		break;
	default:
		if (p->debug)
			printf("missing case label (%s, line %d)\n", __FILE__, __LINE__);
		return -1;
	}

	memcpy(buf, p->client_random, 32);
	memcpy(buf + 32, p->server_random, 32);
	memcpy(buf + 64, p->hbuf + 4, len + 5);

	len += 32 + 32 + 5;

	sha1(buf, len, hash);

	switch (p->encryption_algorithm) { // encryption algorithm from server's certifcate
	case PRIME256V1:
		err = ecdhe256_verify_hash(hash, 20, key->r, key->r_length, key->s, key->s_length, p->x, p->y); // use (x, y) from certificate
		break;
	case SECP384R1:
		err = ecdhe384_verify_hash(hash, 20, key->r, key->r_length, key->s, key->s_length, p->x, p->y); // use (x, y) from certificate
		break;
	default:
		if (p->debug)
			printf("missing case label (%s, line %d)\n", __FILE__, __LINE__);
		return -1;
	}

	return err;
}

void
receive_server_hello_done(struct ssl_session *p)
{
	SSLTRACE

	// check message type

	if (p->hbuf[0] != SERVER_HELLO_DONE) {
		send_alert_10_unexpected_message(p);
		ssl_disconnect(p, "unexpected_message", __LINE__);
		return;
	}

	// check message length

	if (p->handshake_length != 0) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	update_handshake_hash(p, p->hbuf, p->handshake_length + 4);

	send_client_key_exchange(p);
	send_change_cipher_spec(p);

	p->sent_change_cipher_spec = 1;

	compute_master_secret(p);
	compute_keys(p);
	compute_handshake_hash(p, 0);

	send_finished(p);

	p->state = WAITING_FOR_SERVER_CHANGE_CIPHER_SPEC;
}

void
send_client_key_exchange(struct ssl_session *p)
{
	SSLTRACE
	int n;
	uint8_t *buf = p->outbuf + SSLPAD;

	buf[0] = CLIENT_KEY_EXCHANGE;

	n = ssl_client_key_out(p, buf + 6);

	buf[4] = n >> 8; // Google requires this field. However, Wikipedia has a bug and does not accept this field for ECDHE.
	buf[5] = n;

	n += 2; // add 2 bytes for length field

	buf[1] = n >> 16; // handshake message length
	buf[2] = n >> 8;
	buf[3] = n;

	n += 4; // add 4 bytes for handshake header

	update_handshake_hash(p, buf, n);

	ssl_send_record(p, HANDSHAKE, buf, n);
}

// only for rsa cipher suites

void
receive_client_key_exchange(struct ssl_session *p)
{
	SSLTRACE
	int k, n;

	// check message type

	if (p->hbuf[0] != CLIENT_KEY_EXCHANGE) {
		send_alert_10_unexpected_message(p);
		ssl_disconnect(p, "unexpected_message", __LINE__);
		return;
	}

	// check key length

	n = p->hbuf[4] << 8 | p->hbuf[5];

	k = 6;

	if (n + 2 != p->handshake_length) {
		if (p->handshake_length == p->signature_length && allow_missing_length_field) {
			n = p->handshake_length;
			k = 4;
			if (p->debug)
				printf("missing length field id=%d (%s, line %d)\n", p->id, __FILE__, __LINE__);
		} else {
			send_alert_50_decode_error(p);
			ssl_disconnect(p, "decode_error", __LINE__);
			return;
		}
	}

	update_handshake_hash(p, p->hbuf, p->handshake_length + 4);

	// decrypt to get the pre-master secret

	rsa_decrypt(p->hbuf + k, n, &provisioned_ki);

	// save pre-master secret

	memcpy(p->secret, p->hbuf + 4 + p->handshake_length - 48, 48);

	compute_master_secret(p);
	compute_keys(p);

	p->state = WAITING_FOR_CLIENT_CHANGE_CIPHER_SPEC;
}

void
send_change_cipher_spec(struct ssl_session *p)
{
	SSLTRACE
	uint8_t *buf = p->outbuf + SSLPAD;

	buf[0] = 1; // payload

	ssl_send_record(p, CHANGE_CIPHER_SPEC, buf, 1);
}

// change cipher spec is record type, not handshake message

void
receive_change_cipher_spec(struct ssl_session *p)
{
	SSLTRACE

	// check payload length

	if (p->payload_length != 1) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	// check value

	if (p->payload[0] != 1) {
		send_alert_47_illegal_parameter(p);
		ssl_disconnect(p, "illegal_parameter", __LINE__);
		return;
	}

	p->received_change_cipher_spec = 1;

	// change state

	switch (p->state) {
	case WAITING_FOR_CLIENT_CHANGE_CIPHER_SPEC:
		p->state = WAITING_FOR_CLIENT_FINISHED;
		break;
	case WAITING_FOR_SERVER_CHANGE_CIPHER_SPEC:
		p->state = WAITING_FOR_SERVER_FINISHED;
		break;
	default:
		send_alert_0_close_notify(p);
		ssl_disconnect(p, "bug", __LINE__);
		break;
	}
}

void
send_finished(struct ssl_session *p)
{
	SSLTRACE
	uint8_t *buf = p->outbuf + SSLPAD;

	buf[0] = FINISHED;

	buf[1] = 0; // length
	buf[2] = 0;
	buf[3] = 12;

	memcpy(buf + 4, p->handshake_hash, 12); // payload

	//   4 handshake header
	//  12 handshake payload
	// ---
	//  16 total

	update_handshake_hash(p, buf, 16);

	ssl_send_record(p, HANDSHAKE, buf, 16);
}

void
receive_client_finished(struct ssl_session *p)
{
	SSLTRACE

	// check message type

	if (p->hbuf[0] != FINISHED) {
		send_alert_10_unexpected_message(p);
		ssl_disconnect(p, "unexpected_message", __LINE__);
		return;
	}

	// check message length

	if (p->handshake_length != 12) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	// compute hash of all handshake messages

	compute_handshake_hash(p, 0);

	// check handshake hash

	if (memcmp(p->hbuf + 4, p->handshake_hash, 12) != 0) {
		send_alert_51_decrypt_error(p);
		ssl_disconnect(p, "decrypt_error", __LINE__);
		return;
	}

	update_handshake_hash(p, p->hbuf, p->handshake_length + 4);

	send_change_cipher_spec(p);

	p->sent_change_cipher_spec = 1;

	compute_handshake_hash(p, 1);

	send_finished(p);

	p->state = SSL_READY;

	if (p->debug)
		printf("ssl ready (server side)\n");
}

void
receive_server_finished(struct ssl_session *p)
{
	SSLTRACE

	// check message type

	if (p->hbuf[0] != FINISHED) {
		send_alert_10_unexpected_message(p);
		ssl_disconnect(p, "unexpected_message", __LINE__);
		return;
	}

	// check message length

	if (p->handshake_length != 12) {
		send_alert_50_decode_error(p);
		ssl_disconnect(p, "decode_error", __LINE__);
		return;
	}

	// compute hash of all handshake messages

	compute_handshake_hash(p, 1);

	// check handshake hash

	if (memcmp(p->hbuf + 4, p->handshake_hash, 12) != 0) {
		send_alert_51_decrypt_error(p);
		ssl_disconnect(p, "decrypt_error", __LINE__);
		return;
	}

	p->state = SSL_READY;

	if (p->debug)
		printf("ssl ready (client side)\n");
}

void
send_alert_0_close_notify(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 1, 0); // warning, close_notify
}

void
send_alert_10_unexpected_message(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 10); // fatal, unexpected_message
}

void
send_alert_20_bad_record_mac(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 20); // fatal, bad_record_mac
}

void
send_alert_22_record_overflow(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 22); // fatal, record_overflow
}

void
send_alert_40_handshake_failure(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 40); // fatal, handshake_failure
}

void
send_alert_42_bad_certificate(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 42); // fatal, bad_certificate
}

void
send_alert_43_unsupported_certificate(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 43); // fatal, unsupported_certificate
}

void
send_alert_47_illegal_parameter(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 47); // fatal, illegal_parameter
}

void
send_alert_50_decode_error(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 50); // fatal, decode_error
}

void
send_alert_51_decrypt_error(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 51); // fatal, decrypt_error
}

void
send_alert_70_protocol_version(struct ssl_session *p)
{
	SSLTRACE
	ssl_send_alert(p, 2, 70); // fatal, protocol_version
}

// compute master secret from pre-master secret

void
compute_master_secret(struct ssl_session *p)
{
	SSLTRACE
	switch (p->tls_version) {
	case TLS_V10:
	case TLS_V11:
		compute_master_secret_v10(p);
		break;
	case TLS_V12:
		compute_master_secret_v12(p);
		break;
	}
}

// RFC 2246, p. 47

void
compute_master_secret_v10(struct ssl_session *p)
{
	SSLTRACE
	int i;
	uint8_t buf[97]; // 20 + 13 + 32 + 32 = 97
	uint8_t md5_out[48];
	uint8_t sha1_out[60];

	// md5

	// seed = "master secret" + client_random + server_random

	memcpy(buf + 16, "master secret", 13);
	memcpy(buf + 16 + 13, p->client_random, 32);
	memcpy(buf + 16 + 13 + 32, p->server_random, 32);

	for (i = 0; i < 3; i++) { // 3 * 16 bytes = 48 bytes
		if (i == 0)
			hmac_md5(p->secret, 24, buf + 16, 13 + 32 + 32, buf);
		else
			hmac_md5(p->secret, 24, buf, 16, buf);
		hmac_md5(p->secret, 24, buf, 16 + 13 + 32 + 32, md5_out + 16 * i);
	}

	// sha1

	// seed = "master secret" + client_random + server_random

	memcpy(buf + 20, "master secret", 13);
	memcpy(buf + 20 + 13, p->client_random, 32);
	memcpy(buf + 20 + 13 + 32, p->server_random, 32);

	for (i = 0; i < 3; i++) { // 3 * 20 bytes = 60 bytes
		if (i == 0)
			hmac_sha1(p->secret + 24, 24, buf + 20, 13 + 32 + 32, buf);
		else
			hmac_sha1(p->secret + 24, 24, buf, 20, buf);
		hmac_sha1(p->secret + 24, 24, buf, 20 + 13 + 32 + 32, sha1_out + 20 * i);
	}

	for (i = 0; i < 48; i++)
		p->secret[i] = md5_out[i] ^ sha1_out[i];
}

void
compute_master_secret_v12(struct ssl_session *p)
{
	SSLTRACE
	int i;
	uint8_t buf[109]; // 32 + 13 + 32 + 32 = 109
	uint8_t out[64];

	// seed = "master secret" + client_random + server_random

	memcpy(buf + 32, "master secret", 13);
	memcpy(buf + 45, p->client_random, 32);
	memcpy(buf + 77, p->server_random, 32);

	for (i = 0; i < 2; i++) { // 2 * 32 bytes = 64 bytes
		if (i == 0)
			// A(0) = seed
			// A(1) = HMAC_hash(secret, A(0))
			hmac_sha256(p->secret, 48, buf + 32, 77, buf);
		else
			// A(i) = HMAC_hash(secret, A(i-1))
			hmac_sha256(p->secret, 48, buf, 32, buf);
		// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		// HMAC_hash(secret, A(2) + seed) +
		// HMAC_hash(secret, A(3) + seed) + ...
		hmac_sha256(p->secret, 48, buf, 109, out + 32 * i);
	}

	memcpy(p->secret, out, 48);
}

void
compute_keys(struct ssl_session *p)
{
	SSLTRACE
	uint8_t kmat[160];

	switch (p->tls_version) {
	case TLS_V10:
	case TLS_V11:
		compute_keys_v10(p, kmat);
		break;
	case TLS_V12:
		compute_keys_v12(p, kmat);
		break;
	}

	switch (p->cipher_suite) {

	case TLS_RSA_WITH_RC4_128_SHA: // 72 bytes of key material
	case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
	case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		if (p->server_mode) {
			memcpy(p->check_mac_key, kmat, 20);
			memcpy(p->write_mac_key, kmat + 20, 20);
			rc4_init(p, kmat + 56, kmat + 40); // server key, client key
		} else {
			memcpy(p->write_mac_key, kmat, 20);
			memcpy(p->check_mac_key, kmat + 20, 20);
			rc4_init(p, kmat + 40, kmat + 56); // client key, server key
		}
		break;

	case TLS_RSA_WITH_AES_128_CBC_SHA: // 104 bytes of key material
	case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		if (p->server_mode) {
			memcpy(p->check_mac_key, kmat, 20);
			memcpy(p->write_mac_key, kmat + 20, 20);
			aes128_init(p, kmat + 56, kmat + 40, kmat + 88, kmat + 72); // server key, client key
		} else {
			memcpy(p->write_mac_key, kmat, 20);
			memcpy(p->check_mac_key, kmat + 20, 20);
			aes128_init(p, kmat + 40, kmat + 56, kmat + 72, kmat + 88); // client key, server key
		}
		break;
#if 0
	case TLS_RSA_WITH_AES_256_CBC_SHA: // 136 bytes of key material
	case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		if (p->server_mode) {
			memcpy(p->check_mac_key, kmat, 20);
			memcpy(p->write_mac_key, kmat + 20, 20);
			aes256_init(p, kmat + 72, kmat + 40, kmat + 120, kmat + 104); // server key, client key
		} else {
			memcpy(p->write_mac_key, kmat, 20);
			memcpy(p->check_mac_key, kmat + 20, 20);
			aes256_init(p, kmat + 40, kmat + 72, kmat + 104, kmat + 120); // client key, server key
		}
		break;
#endif
	case TLS_RSA_WITH_AES_128_CBC_SHA256: // 128 bytes of key material
		if (p->server_mode) {
			memcpy(p->check_mac_key, kmat, 32);
			memcpy(p->write_mac_key, kmat + 32, 32);
			aes128_init(p, kmat + 80, kmat + 64, kmat + 112, kmat + 96); // server key, client key
		} else {
			memcpy(p->write_mac_key, kmat, 32);
			memcpy(p->check_mac_key, kmat + 32, 32);
			aes128_init(p, kmat + 64, kmat + 80, kmat + 96, kmat + 112); // client key, server key
		}
		break;
#if 0
	case TLS_RSA_WITH_AES_256_CBC_SHA256: // 160 bytes of key material
		if (p->server_mode) {
			memcpy(p->check_mac_key, kmat, 32);
			memcpy(p->write_mac_key, kmat + 32, 32);
			aes256_init(p, kmat + 96, kmat + 64, kmat + 144, kmat + 128); // server key, client key
		} else {
			memcpy(p->write_mac_key, kmat, 32);
			memcpy(p->check_mac_key, kmat + 32, 32);
			aes256_init(p, kmat + 64, kmat + 96, kmat + 128, kmat + 144); // client key, server key
		}
		break;
#endif
	default:
		if (p->debug)
			printf("missing case label (%s, line %d)\n", __FILE__, __LINE__);
		break;
	}
}

void
compute_keys_v10(struct ssl_session *p, uint8_t *kmat)
{
	SSLTRACE
	int i;
	uint8_t buf[97]; // 20 + 13 + 32 + 32 = 97
	uint8_t md5_out[160];
	uint8_t sha1_out[160];

	// md5

	memcpy(buf + 16, "key expansion", 13);
	memcpy(buf + 16 + 13, p->server_random, 32);
	memcpy(buf + 16 + 13 + 32, p->client_random, 32);

	for (i = 0; i < 10; i++) { // 10 * 16 bytes = 160 bytes
		if (i == 0)
			// A(0) = seed
			// A(1) = HMAC_hash(secret, A(0))
			hmac_md5(p->secret, 24, buf + 16, 13 + 32 + 32, buf);
		else
			// A(i) = HMAC_hash(secret, A(i-1))
			hmac_md5(p->secret, 24, buf, 16, buf);
		// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		// HMAC_hash(secret, A(2) + seed) +
		// HMAC_hash(secret, A(3) + seed) + ...
		hmac_md5(p->secret, 24, buf, 16 + 13 + 32 + 32, md5_out + 16 * i);
	}

	// sha1

	memcpy(buf + 20, "key expansion", 13);
	memcpy(buf + 20 + 13, p->server_random, 32);
	memcpy(buf + 20 + 13 + 32, p->client_random, 32);

	for (i = 0; i < 8; i++) { // 8 * 20 bytes = 160 bytes
		if (i == 0)
			// A(0) = seed
			// A(1) = HMAC_hash(secret, A(0))
			hmac_sha1(p->secret + 24, 24, buf + 20, 13 + 32 + 32, buf);
		else
			// A(i) = HMAC_hash(secret, A(i-1))
			hmac_sha1(p->secret + 24, 24, buf, 20, buf);
		// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		// HMAC_hash(secret, A(2) + seed) +
		// HMAC_hash(secret, A(3) + seed) + ...
		hmac_sha1(p->secret + 24, 24, buf, 20 + 13 + 32 + 32, sha1_out + 20 * i);
	}

	for (i = 0; i < 160; i++)
		kmat[i] = md5_out[i] ^ sha1_out[i];
}

void
compute_keys_v12(struct ssl_session *p, uint8_t *kmat)
{
	SSLTRACE
	int i;
	uint8_t buf[109]; // 32 + 13 + 32 + 32 = 109

	// seed = "key expansion" + server_random + client_random

	memcpy(buf + 32, "key expansion", 13);
	memcpy(buf + 45, p->server_random, 32);
	memcpy(buf + 77, p->client_random, 32);

	for (i = 0; i < 5; i++) { // 5 * 32 bytes = 160 bytes
		if (i == 0)
			// A(0) = seed
			// A(1) = HMAC_hash(secret, A(0))
			hmac_sha256(p->secret, 48, buf + 32, 77, buf);
		else
			// A(i) = HMAC_hash(secret, A(i-1))
			hmac_sha256(p->secret, 48, buf, 32, buf);
		// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		// HMAC_hash(secret, A(2) + seed) +
		// HMAC_hash(secret, A(3) + seed) + ...
		hmac_sha256(p->secret, 48, buf, 109, kmat + 32 * i);
	}
}

// compute hash over all handshake messages exchanged so far

void
compute_handshake_hash(struct ssl_session *p, int server)
{
	SSLTRACE
	switch (p->tls_version) {
	case TLS_V10:
	case TLS_V11:
		compute_handshake_hash_v10(p, server);
		break;
	case TLS_V12:
		compute_handshake_hash_v12(p, server);
		break;
	}
}

void
compute_handshake_hash_v10(struct ssl_session *p, int server)
{
	SSLTRACE
	int i;
	uint8_t hash[36]; // 16 bytes for md5, 20 bytes for sha1
	uint8_t buf[71]; // 20 + 15 + 36 = 71
	uint8_t md5_out[16];
	uint8_t sha1_out[20];

	finish_handshake_hash_v10(p, hash);

	// md5

	if (server)
		memcpy(buf + 16, "server finished", 15);
	else
		memcpy(buf + 16, "client finished", 15);

	memcpy(buf + 16 + 15, hash, 36);

	hmac_md5(p->secret, 24, buf + 16, 15 + 36, buf);
	hmac_md5(p->secret, 24, buf, 16 + 15 + 36, md5_out);

	// sha1

	if (server)
		memcpy(buf + 20, "server finished", 15);
	else
		memcpy(buf + 20, "client finished", 15);

	memcpy(buf + 20 + 15, hash, 36);

	hmac_sha1(p->secret + 24, 24, buf + 20, 15 + 36, buf);
	hmac_sha1(p->secret + 24, 24, buf, 20 + 15 + 36, sha1_out);

	for (i = 0; i < 12; i++)
		p->handshake_hash[i] = md5_out[i] ^ sha1_out[i];
}

void
compute_handshake_hash_v12(struct ssl_session *p, int server)
{
	SSLTRACE
	uint8_t buf[79]; // 32 + 15 + 32 = 79

	// seed = "server finished" + hash

	if (server)
		memcpy(buf + 32, "server finished", 15);
	else
		memcpy(buf + 32, "client finished", 15);

	finish_handshake_hash_v12(p, buf + 47);

	hmac_sha256(p->secret, 48, buf + 32, 47, buf);
	hmac_sha256(p->secret, 48, buf, 79, buf);

	memcpy(p->handshake_hash, buf, 12);
}

void
start_handshake_hash(struct ssl_session *p, uint8_t *buf, int len)
{
	SSLTRACE
	switch (p->tls_version) {
	case TLS_V10:
	case TLS_V11:
		start_handshake_hash_v10(p, buf, len);
		break;
	case TLS_V12:
		start_handshake_hash_v12(p, buf, len);
		break;
	}
}

void
start_handshake_hash_v10(struct ssl_session *p, uint8_t *buf, int len)
{
	SSLTRACE

	p->hhlen = 0;
	p->total_length = 0;

	// md5

	p->md5_hash[0] = 0x67452301;
	p->md5_hash[1] = 0xefcdab89;
	p->md5_hash[2] = 0x98badcfe;
	p->md5_hash[3] = 0x10325476;

	// sha1

	p->sha1_hash[0] = 0x67452301;
	p->sha1_hash[1] = 0xefcdab89;
	p->sha1_hash[2] = 0x98badcfe;
	p->sha1_hash[3] = 0x10325476;
	p->sha1_hash[4] = 0xc3d2e1f0;

	update_handshake_hash_v10(p, buf, len);
}

void
start_handshake_hash_v12(struct ssl_session *p, uint8_t *buf, int len)
{
	SSLTRACE

	p->hhlen = 0;
	p->total_length = 0;

	p->sha256_hash[0] = 0x6a09e667;
	p->sha256_hash[1] = 0xbb67ae85;
	p->sha256_hash[2] = 0x3c6ef372;
	p->sha256_hash[3] = 0xa54ff53a;
	p->sha256_hash[4] = 0x510e527f;
	p->sha256_hash[5] = 0x9b05688c;
	p->sha256_hash[6] = 0x1f83d9ab;
	p->sha256_hash[7] = 0x5be0cd19;

	update_handshake_hash_v12(p, buf, len);
}

void
update_handshake_hash(struct ssl_session *p, uint8_t *buf, int len)
{
	SSLTRACE
	switch (p->tls_version) {
	case TLS_V10:
	case TLS_V11:
		update_handshake_hash_v10(p, buf, len);
		break;
	case TLS_V12:
		update_handshake_hash_v12(p, buf, len);
		break;
	}
}

void
update_handshake_hash_v10(struct ssl_session *p, uint8_t *buf, int len)
{
	SSLTRACE
	int i;
	for (i = 0; i < len; i++) {
		p->hhbuf[p->hhlen++] = buf[i];
		if (p->hhlen == 64) {
			md5_hash_block(p->hhbuf, p->md5_hash);
			sha1_hash_block(p->hhbuf, p->sha1_hash);
			p->hhlen = 0;
		}
	}
	p->total_length += len;
}

void
update_handshake_hash_v12(struct ssl_session *p, uint8_t *buf, int len)
{
	SSLTRACE
	int i;
	for (i = 0; i < len; i++) {
		p->hhbuf[p->hhlen++] = buf[i];
		if (p->hhlen == 64) {
			sha256_hash_block(p->hhbuf, p->sha256_hash);
			p->hhlen = 0;
		}
	}
	p->total_length += len;
}

void
finish_handshake_hash_v10(struct ssl_session *p, uint8_t *buf)
{
	SSLTRACE
	int i, r;
	unsigned md5_hash[4];
	unsigned sha1_hash[5];
	uint8_t block[64];
	uint64_t m;

	memcpy(md5_hash, p->md5_hash, 16);
	memcpy(sha1_hash, p->sha1_hash, 20);

	// depending on remainder, hash 1 or 2 more blocks

	r = p->hhlen;

	bzero(block, 64);
	memcpy(block, p->hhbuf, r);
	block[r] = 0x80;

	if (r > 55) {
		md5_hash_block(block, md5_hash);
		sha1_hash_block(block, sha1_hash);
		bzero(block, 64);
	}

	m = (uint64_t) 8 * p->total_length; // number of bits

	block[56] = m;
	block[57] = m >> 8;
	block[58] = m >> 16;
	block[59] = m >> 24;
	block[60] = m >> 32;
	block[61] = m >> 40;
	block[62] = m >> 48;
	block[63] = m >> 56;

	md5_hash_block(block, md5_hash);

	block[56] = m >> 56;
	block[57] = m >> 48;
	block[58] = m >> 40;
	block[59] = m >> 32;
	block[60] = m >> 24;
	block[61] = m >> 16;
	block[62] = m >> 8;
	block[63] = m;

	sha1_hash_block(block, sha1_hash);

	// copy md5 to buf

	for (i = 0; i < 4; i++) {
		buf[4 * i + 0] = md5_hash[i];
		buf[4 * i + 1] = md5_hash[i] >> 8;
		buf[4 * i + 2] = md5_hash[i] >> 16;
		buf[4 * i + 3] = md5_hash[i] >> 24;
	}

	// copy sha1 to buf + 16

	for (i = 0; i < 5; i++) {
		buf[16 + 4 * i + 0] = sha1_hash[i] >> 24;
		buf[16 + 4 * i + 1] = sha1_hash[i] >> 16;
		buf[16 + 4 * i + 2] = sha1_hash[i] >> 8;
		buf[16 + 4 * i + 3] = sha1_hash[i];
	}
}

void
finish_handshake_hash_v12(struct ssl_session *p, uint8_t *out)
{
	SSLTRACE
	int i, r;
	unsigned sha256_hash[8];
	uint8_t block[64];
	uint64_t m;

	memcpy(sha256_hash, p->sha256_hash, 32); // don't clobber running hash

	// depending on remainder, hash 1 or 2 more blocks

	r = p->hhlen;

	bzero(block, 64);
	memcpy(block, p->hhbuf, r);
	block[r] = 0x80;

	if (r > 55) {
		sha256_hash_block(block, sha256_hash);
		bzero(block, 64);
	}

	m = (uint64_t) 8 * p->total_length; // number of bits

	block[56] = m >> 56;
	block[57] = m >> 48;
	block[58] = m >> 40;
	block[59] = m >> 32;
	block[60] = m >> 24;
	block[61] = m >> 16;
	block[62] = m >> 8;
	block[63] = m;

	sha256_hash_block(block, sha256_hash);

	for (i = 0; i < 8; i++) {
		out[4 * i + 0] = sha256_hash[i] >> 24;
		out[4 * i + 1] = sha256_hash[i] >> 16;
		out[4 * i + 2] = sha256_hash[i] >> 8;
		out[4 * i + 3] = sha256_hash[i];
	}
}

// for debugging

void
print_buf(char *s, uint8_t *buf, int len)
{
	int i;
	printf("%s (%d bytes)\n", s, len);
	for (i = 0; i < len; i++) {
		printf(" %02x", buf[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	if (i % 16)
		printf("\n");
}

// returns key length

int
ssl_client_key_out(struct ssl_session *p, uint8_t *out)
{
	int len = 0;

	switch (p->cipher_suite) {

	case TLS_RSA_WITH_RC4_128_SHA:
	case TLS_RSA_WITH_AES_128_CBC_SHA:
	case TLS_RSA_WITH_AES_256_CBC_SHA:
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		rsa_generate(p, out);
		len = p->signature_length;
		break;

	case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
	case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
		switch (p->encryption_algorithm) {
		case PRIME256V1:
			ecdhe256_generate(p, p->x, p->y);
			out[0] = 65; // length
			out[1] = 4; // uncompressed
			memcpy(out + 2, p->ephemeral_key, 64);
			len = 66;
			break;
		case SECP384R1:
			ecdhe384_generate(p, p->x, p->y);
			out[0] = 97; // length
			out[1] = 4; // uncompressed
			memcpy(out + 2, p->ephemeral_key, 96);
			len = 98;
			break;
		default:
			if (p->debug)
				printf("missing case label (%s, line %d)\n", __FILE__, __LINE__);
			len = 0;
			break;
		}
		break;

	case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		switch (p->ephemeral_encryption_algorithm) {
		case PRIME256V1:
			out[0] = 65; // length
			out[1] = 4; // uncompressed
			memcpy(out + 2, p->ephemeral_key, 64);
			len = 66;
			break;
		case SECP384R1:
			out[0] = 97; // length
			out[1] = 4; // uncompressed
			memcpy(out + 2, p->ephemeral_key, 96);
			len = 98;
			break;
		default:
			if (p->debug)
				printf("missing case label (%s, line %d)\n", __FILE__, __LINE__);
			len = 0;
			break;
		}
		break;

	default:
		if (p->debug)
			printf("missing case label (%s, line %d)\n", __FILE__, __LINE__);
		len = 0;
		break;
	}

	ssl_free_keys(p);

	return len;
}

// From RFC 3447, p. 25:
//
// 2. EME-PKCS1-v1_5 encoding:
//
//    a. Generate an octet string PS of length k - mLen - 3 consisting
//       of pseudo-randomly generated nonzero octets. The length of PS
//       will be at least eight octets.
//
//    b. Concatenate PS, the message M, and other padding to form an
//       encoded message EM of length k octets as
//
//          EM = 0x00 || 0x02 || PS || 0x00 || M.

void
rsa_generate(struct ssl_session *p, uint8_t *out)
{
	int i, k, n, t;

	// generate pre-master secret

	p->secret[0] = p->tls_version >> 8;
	p->secret[1] = p->tls_version;

	for (i = 2; i < 48; i++)
		p->secret[i] = random();

	// encode

	k = 0;

	out[k++] = 0x00;
	out[k++] = 0x02;

	//   3 block type (0x02) and marker (0x00) bytes
	//  48 pre-master secret (M)
	// ---
	//  51 total

	n = p->signature_length - 51;

	// pad with non-zero random bytes

	for (i = 0; i < n; i++) {
		do
			t = random() & 0xff;
		while (t == 0);
		out[k++] = t;
	}

	out[k++] = 0x00;

	memcpy(out + k, p->secret, 48);

	rsa_encrypt(p, out, p->signature_length);
}

void
ssl_free_keys(struct ssl_session *p)
{
	SSLTRACE

	if (p->modulus) {
		ssl_free(p->modulus);
		p->modulus = NULL;
	}

	if (p->exponent) {
		ssl_free(p->exponent);
		p->exponent = NULL;
	}

	if (p->x) {
		ssl_free(p->x);
		p->x = NULL;
	}

	if (p->y) {
		ssl_free(p->y);
		p->y = NULL;
	}

	if (p->ephemeral_key) {
		ssl_free(p->ephemeral_key);
		p->ephemeral_key = NULL;
	}
}

uint8_t *
ssl_malloc(int len)
{
	uint8_t *p = malloc(len);
	if (p == NULL) {
		printf("malloc failure (file %s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}
	ssl_malloc_count++;
	return p;
}

void
ssl_free(uint8_t *p)
{
	if (p) {
		free(p);
		ssl_malloc_count--;
	}
}

// returns 0 for ok, -1 for error

int
ssl_hmac_prep(struct ssl_session *p, int hmac_length)
{
	int err, i, pad_length, pad_value;

	err = 0;

	// remove 16 byte iv (payload_length > 16 already checked)

	if (p->tls_version > TLS_V10) {
		p->payload += 16;
		p->payload_length -= 16;
		memcpy(p->payload - 5, p->payload - 21, 5); // copy 5 byte record header
	}

	pad_value = p->payload[p->payload_length - 1];

	pad_length = pad_value + 1;

	if (p->payload_length < hmac_length + pad_length) {
		err = -1;
		hmac_length = 0; // carry on to defend against timing attacks
		pad_length = 0;
	}

	p->payload_length -= pad_length;

	for (i = p->payload_length; i < p->payload_length + pad_length; i++)
		if (p->payload[i] != pad_value)
			err = -1;

	p->payload_length -= hmac_length;

	// sequence number

	for (i = 0; i < 8; i++)
		p->payload[i - 13] = p->expected_sequence_number >> (56 - 8 * i);

	p->expected_sequence_number++;

	// fix up record header

	p->payload[-2] = p->payload_length >> 8;
	p->payload[-1] = p->payload_length;

	return err;
}

char *
alert_level_str(int alert_level)
{
	char *str;
	switch (alert_level) {
	case 1:
		str = "warning";
		break;
	case 2:
		str = "fatal";
		break;
	default:
		str = "?";
		break;
	}
	return str;
}

char *
alert_descr_str(int alert_descr)
{
	char *str;
	switch (alert_descr) {
	case 0:
		str = "close_notify";
		break;
	case 10:
		str = "unexpected_message";
		break;
	case 20:
		str = "bad_record_mac";
		break;
	case 21:
		str = "decryption_failed_RESERVED";
		break;
	case 22:
		str = "record_overflow";
		break;
	case 40:
		str = "handshake_failure";
		break;
	case 42:
		str = "bad_certificate";
		break;
	case 43:
		str = "unsupported_certificate";
		break;
	case 44:
		str = "certificate_revoked";
		break;
	case 45:
		str = "certificate_expired";
		break;
	case 46:
		str = "certificate_unknown";
		break;
	case 47:
		str = "illegal_parameter";
		break;
	case 48:
		str = "unknown_ca";
		break;
	case 49:
		str = "access_denied";
		break;
	case 50:
		str = "decode_error";
		break;
	case 51:
		str = "decrypt_error";
		break;
	case 70:
		str = "protocol_version";
		break;
	case 71:
		str = "insufficient_security";
		break;
	case 80:
		str = "internal_error";
		break;
	case 86:
		str = "inappropriate_fallback";
		break;
	case 90:
		str = "user_canceled";
		break;
	case 109:
		str = "missing_extension";
		break;
	case 110:
		str = "unsupported_extension";
		break;
	case 112:
		str = "unrecognized_name";
		break;
	case 113:
		str = "bad_certificate_status_response";
		break;
	case 115:
		str = "unknown_psk_identity";
		break;
	case 116:
		str = "certificate_required";
		break;
	case 120:
		str = "no_application_protocol";
		break;
	default:
		str = "?";
		break;
	}
	return str;
}
