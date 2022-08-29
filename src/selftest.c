void
selftest(void)
{
	test_md5();
	test_sha1();
	test_sha224();
	test_sha256();
	test_sha384();
	test_sha512();

	ec_test();

	exit(0);
}

void
stop(char *s)
{
	printf("%s test failed\n", s);
	exit(1);
}

void
test_md5(void)
{
	int i;
	char s[33];
	uint8_t hash[16];

	printf("testing md5\n");

	md5((uint8_t *) "", 0, hash);

	for (i = 0; i < 16; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "d41d8cd98f00b204e9800998ecf8427e") != 0)
		stop("md5");

	md5((uint8_t *) "message digest", 14, hash);

	for (i = 0; i < 16; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "f96b697d7cb7938d525a2f31aaf161d0") != 0)
		stop("md5");

	hmac_md5((uint8_t *) "", 0, (uint8_t *) "", 0, hash);

	for (i = 0; i < 16; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "74e6f7298a9c2d168935f58c001bad88") != 0)
		stop("md5");

	hmac_md5((uint8_t *) "key", 3, (uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 16; i++)
		sprintf(s + 2 * i, "%02x", ((uint8_t *) hash)[i]);

	if (strcmp(s, "80070713463e7749b90c2dc24911e275") != 0)
		stop("md5");
}

void
test_sha1(void)
{
	int i;
	char s[41];
	uint8_t hash[20];

	printf("testing sha1\n");

	sha1((uint8_t *) "", 0, hash);

	for (i = 0; i < 20; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "da39a3ee5e6b4b0d3255bfef95601890afd80709") != 0)
		stop("sha1");

	sha1((uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 20; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") != 0)
		stop("sha1");

	hmac_sha1((uint8_t *) "", 0, (uint8_t *) "", 0, hash);

	for (i = 0; i < 20; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d") != 0)
		stop("sha1");

	hmac_sha1((uint8_t *) "key", 3, (uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 20; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9") != 0)
		stop("sha1");
}

void
test_sha224(void)
{
	int i;
	char s[57];
	uint8_t hash[28];

	printf("testing sha224\n");

	sha224((uint8_t *) "", 0, hash);

	for (i = 0; i < 28; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f") != 0)
		stop("sha224");

	sha224((uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 28; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525") != 0)
		stop("sha224");

	// RFC 4231 Test Case 1

	hmac_sha224((uint8_t *) "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, (uint8_t *) "Hi There", 8, hash);

	for (i = 0; i < 28; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22") != 0)
		stop("sha224");

	// RFC 4231 Test Case 2

	hmac_sha224((uint8_t *) "Jefe", 4, (uint8_t *) "what do ya want for nothing?", 28, hash);

	for (i = 0; i < 28; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44") != 0)
		stop("sha224");
}

void
test_sha256(void)
{
	int i;
	char s[65];
	uint8_t hash[32];

	printf("testing sha256\n");

	sha256((uint8_t *) "", 0, hash);

	for (i = 0; i < 32; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") != 0)
		stop("sha256");

	sha256((uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 32; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592") != 0)
		stop("sha256");

	hmac_sha256((uint8_t *) "", 0, (uint8_t *) "", 0, hash);

	for (i = 0; i < 32; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad") != 0)
		stop("sha256");

	hmac_sha256((uint8_t *) "key", 3, (uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 32; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8") != 0)
		stop("sha256");
}

void
test_sha384(void)
{
	int i;
	char s[97];
	uint8_t hash[48];

	printf("testing sha384\n");

	sha384((uint8_t *) "", 0, hash);

	for (i = 0; i < 48; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b") != 0)
		stop("sha384");

	sha384((uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 48; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1") != 0)
		stop("sha384");

	// RFC 4231 Test Case 1

	hmac_sha384((uint8_t *) "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, (uint8_t *) "Hi There", 8, hash);

	for (i = 0; i < 48; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6") != 0)
		stop("sha384");

	// RFC 4231 Test Case 2

	hmac_sha384((uint8_t *) "Jefe", 4, (uint8_t *) "what do ya want for nothing?", 28, hash);

	for (i = 0; i < 48; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649") != 0)
		stop("sha384");
}

void
test_sha512(void)
{
	int i;
	char s[129];
	uint8_t hash[64];

	printf("testing sha512\n");

	sha512((uint8_t *) "", 0, hash);

	for (i = 0; i < 64; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e") != 0)
		stop("sha512");

	sha512((uint8_t *) "abc", 3, hash);

	for (i = 0; i < 64; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") != 0)
		stop("sha512");

	// RFC 4231 Test Case 1

	hmac_sha512((uint8_t *) "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, (uint8_t *) "Hi There", 8, hash);

	for (i = 0; i < 64; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854") != 0)
		stop("sha512");

	// RFC 4231 Test Case 2

	hmac_sha512((uint8_t *) "Jefe", 4, (uint8_t *) "what do ya want for nothing?", 28, hash);

	for (i = 0; i < 64; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737") != 0)
		stop("sha512");
}
