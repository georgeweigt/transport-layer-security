#define INTEGER 2
#define BIT_STRING 3
#define OCTET_STRING 4
#define OID 6
#define UTF8STRING 12
#define PRINTABLE_STRING 19
#define IA5STRING 22
#define UTCTIME 0x17
#define GENERALIZEDTIME 0x18
#define SEQUENCE 0x30
#define SET 0x31

// encryption algorithms

#define RSA_ENCRYPTION 1
#define PRIME256V1 2 // NIST P-256
#define SECP384R1 3 // NIST P-384

// signature algorithms

#define MD5_WITH_RSA_ENCRYPTION 1
#define SHA1_WITH_RSA_ENCRYPTION 2
#define SHA224_WITH_RSA_ENCRYPTION 3
#define SHA256_WITH_RSA_ENCRYPTION 4
#define SHA384_WITH_RSA_ENCRYPTION 5
#define SHA512_WITH_RSA_ENCRYPTION 6
#define ECDSA_WITH_SHA1 7
#define ECDSA_WITH_SHA224 8
#define ECDSA_WITH_SHA256 9
#define ECDSA_WITH_SHA384 10

struct keyinfo {

	int modulus_offset;
	int modulus_length;

	int public_exponent_offset;
	int public_exponent_length;

	int private_exponent_offset;
	int private_exponent_length;

	int prime1_offset;
	int prime1_length;

	int prime2_offset;
	int prime2_length;

	int exponent1_offset;
	int exponent1_length;

	int exponent2_offset;
	int exponent2_length;

	int coefficient_offset;
	int coefficient_length;

	int key_data_length;
	unsigned char key_data[10000];
};

struct certinfo {

	int top_offset;
	int top_length;

	int info_offset;
	int info_length;

	int serial_number_offset;
	int serial_number_length;

	int algorithm_offset;
	int algorithm_length;

	int issuer_offset;
	int issuer_length;

	int validity_offset;
	int validity_length;

	int subject_offset;
	int subject_length;

	int public_key_offset;
	int public_key_length;

	int modulus_offset;
	int modulus_length;

	int exponent_offset;
	int exponent_length;

// Example:
//
// 347 118:     SEQUENCE {
// 349  16:       SEQUENCE {
// 351   7:         OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
// 360   5:         OBJECT IDENTIFIER secp384r1 (1 3 132 0 34)
//        :         }
// 367  98:       BIT STRING
//        :         04 03 47 7B 2F 75 C9 82 15 85 FB 75 E4 91 16 D4
//        :         AB 62 99 F5 3E 52 0B 06 CE 41 00 7F 97 E1 0A 24
//        :         3C 1D 01 04 EE 3D D2 8D 09 97 0C E0 75 E4 FA FB
//        :         77 8A 2A F5 03 60 4B 36 8B 16 23 16 AD 09 71 F4
//        :         4A F4 28 50 B4 FE 88 1C 6E 3F 6C 2F 2F 09 59 5B
//        :         A5 5B 0B 33 99 E2 C3 3D 89 F9 6A 2C EF B2 D3 06
//        :         E9
//        :       }
//
// ec_key_offset is the index of 04 in BIT STRING.

	int ec_key_offset;
	int ec_key_length;

	int signature_algorithm_offset;
	int signature_algorithm_length;

	int signature_offset;
	int signature_length;

	int r_offset; // ecdsa r and s
	int r_length;

	int s_offset;
	int s_length;

	int encryption_algorithm;
	int signature_algorithm;

	time_t not_before;
	time_t not_after;

	int line; // debug info

	unsigned char *cert;
	int cert_length;
};

struct certcache {

	struct certinfo server_info; // server certificate info

	unsigned char *server_cert; // certificate received from server
	int server_length;

	unsigned char *client_cert; // certificate sent to client
	int client_length;
};
