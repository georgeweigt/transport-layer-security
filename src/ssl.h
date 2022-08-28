#define SSLTRACE // printf("T %s\n", __func__); // uncomment to debug seg faults

#define SSLPAD 128 // good for aes 512

// TLS versions

#define TLS_V10 0x0301
#define TLS_V11 0x0302
#define TLS_V12 0x0303

// cipher suites

#define TLS_RSA_WITH_RC4_128_SHA	0x0005
#define TLS_RSA_WITH_AES_128_CBC_SHA	0x002f
#define TLS_RSA_WITH_AES_256_CBC_SHA	0x0035
#define TLS_RSA_WITH_AES_128_CBC_SHA256	0x003c
#define TLS_RSA_WITH_AES_256_CBC_SHA256 0x003d

#define TLS_ECDH_ECDSA_WITH_RC4_128_SHA		0xc002
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA	0xc004
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA	0xc005

#define TLS_ECDHE_ECDSA_WITH_RC4_128_SHA	0xc007
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA	0xc009
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA	0xc00a

// RFC 2246, p. 17

#define CHANGE_CIPHER_SPEC 20
#define ALERT 21
#define HANDSHAKE 22
#define APPLICATION_DATA 23

// RFC 2246, p. 32

#define HELLO_REQUEST 0
#define CLIENT_HELLO 1
#define SERVER_HELLO 2
#define CERTIFICATE 11
#define SERVER_KEY_EXCHANGE 12
#define CERTIFICATE_REQUEST 13
#define SERVER_HELLO_DONE 14
#define CERTIFICATE_VERIFY 15
#define CLIENT_KEY_EXCHANGE 16
#define FINISHED 20

// session states

#define SSL_DISCONNECTED			0
#define WAITING_FOR_CLIENT_HELLO		1
#define WAITING_FOR_SERVER_HELLO		3
#define WAITING_FOR_SERVER_CERTIFICATE		4
#define WAITING_FOR_SERVER_KEY_EXCHANGE		5
#define WAITING_FOR_SERVER_HELLO_DONE		6
#define WAITING_FOR_CLIENT_KEY_EXCHANGE		7
#define WAITING_FOR_CLIENT_CHANGE_CIPHER_SPEC	8
#define WAITING_FOR_CLIENT_FINISHED		9
#define WAITING_FOR_SERVER_CHANGE_CIPHER_SPEC	10
#define WAITING_FOR_SERVER_FINISHED		11
#define SSL_READY				12

struct ssl_session {

	uint64_t send_sequence_number;
	uint64_t expected_sequence_number;

	uint64_t app_data_recv_count;

	char hostname[128];
	int fd;
	uint8_t *send_buf;
	int send_len;

	int id;
	int state;
	int cipher_suite;
	int tls_version;

	struct {
		unsigned server_mode : 1;
		unsigned sent_change_cipher_spec : 1;
		unsigned received_change_cipher_spec : 1;
		unsigned exclusion : 1;
		unsigned debug : 1;
	};

	uint8_t client_random[32];
	unsigned char server_random[32];
	unsigned char secret[48]; // master and pre-master secret

	unsigned char write_mac_key[32];
	unsigned char check_mac_key[32];

	int handshake_length;

	uint8_t inbuf[20000];
	uint8_t outbuf[20000];

	int inbuf_length;
	uint8_t *payload;
	int payload_length;

	unsigned char *hbuf; // pointer to handshake message (either inbuf or handshake_buffer)

	unsigned char *handshake_buffer;
	int handshake_receive_length;
	int handshake_malloc_length;

	int total_length; // total length of all handshake messages

	unsigned char hhbuf[64]; // handshake hash buffer
	int hhlen;

	union {
		struct {
			unsigned md5_hash[4]; // running handshake message hashes
			unsigned sha1_hash[5];
		};
		unsigned sha256_hash[8]; // TLS version 1.2
	};

	unsigned char handshake_hash[12]; // finished hash result

	unsigned char *client_hello; // received client hello message
	int client_hello_length;

	unsigned char *server_name; // server name from client hello extension
	int server_name_length;

	int encryption_algorithm;

	unsigned char *exponent; // rsa exponent
	int exponent_length;

	unsigned char *modulus; // rsa modulus
	int modulus_length;

	int signature_length;

	unsigned char *x, *y; // elliptic curve public key from certificate
	unsigned char *ephemeral_key;
	int ephemeral_encryption_algorithm;

	union {
		struct {
			struct rc4 {
				int i, j;
				unsigned char S[256];
			} encrypt, decrypt;
		};
		struct {
			unsigned char *expanded_key;
			unsigned char expanded_key_tab[560]; // 16 bytes for alignment pad, 32 bytes for 2 iv, 16 + 512 + 32 = 560
		};
	};
};

struct ephemeral_key {

	unsigned char *x, *y; // public key

	unsigned char *r; // signature r
	int r_length;

	unsigned char *s; // signature s
	int s_length;
};

// alert descr (rfc 8446 p. 86)

#define SSL_CLOSE_NOTIFY 0
#define SSL_UNEXPECTED_MESSAGE 10
#define SSL_BAD_RECORD_MAC 20
#define SSL_RECORD_OVERFLOW 22
#define SSL_HANDSHAKE_FAILURE 40
#define SSL_BAD_CERTIFICATE 42
#define SSL_UNSUPPORTED_CERTIFICATE 43
#define SSL_CERTIFICATE_REVOKED 44
#define SSL_CERTIFICATE_EXPIRED 45
#define SSL_CERTIFICATE_UNKNOWN 46
#define SSL_ILLEGAL_PARAMETER 47
#define SSL_UNKNOWN_CA 48
#define SSL_ACCESS_DENIED 49
#define SSL_DECODE_ERROR 50
#define SSL_DECRYPT_ERROR 51
#define SSL_PROTOCOL_VERSION 70
#define SSL_INSUFFICIENT_SECURITY 71
#define SSL_INTERNAL_ERROR 80
#define SSL_INAPPROPRIATE_FALLBACK 86
#define SSL_USER_CANCELED 90
#define SSL_MISSING_EXTENSION 109
#define SSL_UNSUPPORTED_EXTENSION 110
#define SSL_UNRECOGNIZED_NAME 112
#define SSL_BAD_CERTIFICATE_STATUS_RESPONSE 113
#define SSL_UNKNOWN_PSK_IDENTITY 115
#define SSL_CERTIFICATE_REQUIRED 116
#define SSL_NO_APPLICATION_PROTOCOL 120
