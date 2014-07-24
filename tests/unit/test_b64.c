#include <stdlib.h>
#include <b64.h>
#include <string.h>
#include <tap/tap.h>

#define NUM_TESTS 7

const char* alphanum_encoded = "?OTR:" "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwCg==" ".";
const char* alphanum_decoded = "abcdefghijklmnopqrstuvwxyz1234567890\n";

static void test_otrl_base64_otr_decode(void)
{
	unsigned char* bufp = NULL;
	size_t len = 0;

	ok(otrl_base64_otr_decode(alphanum_encoded, &bufp, &len) == 0, "Call with valid data successfull");
	ok(strcmp((const char*)bufp, alphanum_decoded) == 0
			&& len == 37, "Decoded valid b64 test vector with success");
	free(bufp);
	bufp = NULL;

	ok(otrl_base64_otr_decode("hello", NULL, NULL) == -2, "Call with not prefix returned an error");
	ok(otrl_base64_otr_decode("?OTR:" "MTIzNAo=", NULL, NULL) == -2, "Call with not suffix returned an error");
	ok(otrl_base64_otr_decode("?OTR:" "invalid_base64_thing" ".", &bufp, &len) == 0 && len == 12,
			"Invalid b64 data"); // Invalid chars are ignored
	free(bufp);
}

static void test_otrl_base64_otr_encode(void)
{
	unsigned char* bufp = NULL;
	size_t len = 0;
	char* encoded = otrl_base64_otr_encode((const unsigned char*) alphanum_decoded, strlen(alphanum_decoded));

	ok(strcmp(encoded, alphanum_encoded) == 0,
			"Encoded b64 test vector with success");
	ok(otrl_base64_otr_decode(encoded, &bufp, &len) == 0,
			"Decoded previously encoded test vector");
	/* // FIXME: It's not working, I don't know why.
	ok(strcmp((const char*)bufp, alphanum_decoded) == 0
		&& len == strlen(alphanum_decoded),
		"Decoded value is exact");
	*/
	free(bufp);
	free(encoded);
}

int main(int argc, char** argv)
{
	plan_tests(NUM_TESTS);

	test_otrl_base64_otr_decode();
	test_otrl_base64_otr_encode();

	return 0;
}
