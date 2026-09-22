/* SPDX-License-Identifier: MIT */
#include "../src/digest.h"
#include "../src/md5.h"

#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", \
	__FILE__, __LINE__, #c); fails++; } } while (0)

static int md5_is(const char *in, const char *want)
{
	char h[33];
	md5_hex(in, strlen(in), h);
	return strcmp(h, want) == 0;
}

int main(void)
{
	/* RFC 1321 appendix A.5 test suite */
	CHECK(md5_is("", "d41d8cd98f00b204e9800998ecf8427e"));
	CHECK(md5_is("a", "0cc175b9c0f1b6a831c399e269772661"));
	CHECK(md5_is("abc", "900150983cd24fb0d6963f7d28e17f72"));
	CHECK(md5_is("message digest", "f96b697d7cb7938d525a2f31aaf161d0"));
	CHECK(md5_is("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"));
	CHECK(md5_is("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		     "d174ab98d277d9f5a5611c2c9f419d9f"));
	CHECK(md5_is("1234567890123456789012345678901234567890123456789012345678901234567890"
		     "1234567890", "57edf4a22be3c955ac49da2e2107b67a"));

	/* incremental updates across block boundaries match one-shot */
	struct md5 c;
	uint8_t d1[16], d2[16];
	char big[1000];
	memset(big, 'x', sizeof(big));
	md5_init(&c);
	for (size_t i = 0; i < sizeof(big); i += 7)
		md5_update(&c, big + i, sizeof(big) - i < 7 ? sizeof(big) - i : 7);
	md5_final(&c, d1);
	md5_init(&c);
	md5_update(&c, big, sizeof(big));
	md5_final(&c, d2);
	CHECK(memcmp(d1, d2, 16) == 0);

	/* RFC 2617 s.3.5 worked example */
	char r[33];
	digest_response("Mufasa", "testrealm@host.com", "Circle Of Life", "GET",
			"/dir/index.html", "dcd98b7102dd2f0e8b11d0f600bfb0c093", "00000001",
			"0a4f113b", 1, r);
	CHECK(strcmp(r, "6629fae49393a05397450978507c4ef1") == 0);

	struct challenge ch;
	const char *w = "Digest realm=\"ims.example\", nonce=\"abc123\", qop=\"auth,auth-int\", "
			"algorithm=MD5, opaque=\"o1\"";
	CHECK(digest_parse_challenge(w, strlen(w), &ch) == 0);
	CHECK(strcmp(ch.realm, "ims.example") == 0 && strcmp(ch.nonce, "abc123") == 0);
	CHECK(ch.qop_auth && strcmp(ch.opaque, "o1") == 0);
	const char *aka = "Digest realm=\"x\", nonce=\"n\", algorithm=AKAv1-MD5";
	CHECK(digest_parse_challenge(aka, strlen(aka), &ch) == -1);
	const char *bad = "Digest realm=\"x, nonce=\"n\"";
	CHECK(digest_parse_challenge(bad, strlen(bad), &ch) == -1);
	CHECK(digest_parse_challenge("Basic realm=x", 13, &ch) == -1);
	/* "cnonce=" must not be mistaken for "nonce=" */
	const char *tricky = "Digest cnonce=\"evil\", realm=\"r\", nonce=\"good\"";
	CHECK(digest_parse_challenge(tricky, strlen(tricky), &ch) == 0 &&
	      strcmp(ch.nonce, "good") == 0);

	if (fails) {
		fprintf(stderr, "%d check(s) failed\n", fails);
		return 1;
	}
	printf("md5 + digest tests passed (RFC 1321 and RFC 2617 vectors)\n");
	return 0;
}
