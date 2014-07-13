#include <tap/tap.h>
#include <proto.h>
#include <limits.h>

#define NUM_TESTS 17

static void test_otrl_proto_query_bestversion(void)
{
	const char *query2 = "?OTRv2?\n<b>alice</b> has requested an "
		"<a href=\"https://otr.cypherpunks.ca/\">Off-the-Record "
		"private conversation</a>.  However, you do not have a plugin "
		"to support that.\nSee <a href=\"https://otr.cypherpunks.ca/\">"
		"https://otr.cypherpunks.ca/</a> for more information.";

	const char *query23 = "?OTRv23?\n<b>alice</b> has requested an "
		"<a href=\"https://otr.cypherpunks.ca/\">Off-the-Record "
		"private conversation</a>.  However, you do not have a plugin "
		"to support that.\nSee <a href=\"https://otr.cypherpunks.ca/\">"
		"https://otr.cypherpunks.ca/</a> for more information.";

	const char *query3 = "?OTRv3?\n<b>alice</b> has requested an "
		"<a href=\"https://otr.cypherpunks.ca/\">Off-the-Record "
		"private conversation</a>.  However, you do not have a plugin "
		"to support that.\nSee <a href=\"https://otr.cypherpunks.ca/\">"
		"https://otr.cypherpunks.ca/</a> for more information.";

	ok(otrl_proto_query_bestversion(query2, OTRL_POLICY_ALLOW_V2) == 2, "The best from query2 is 2");
	ok(otrl_proto_query_bestversion(query3, OTRL_POLICY_ALLOW_V3) == 3, "The best from query3 is 3");
	ok(otrl_proto_query_bestversion(query23, OTRL_POLICY_ALLOW_V2) == 2, "The best from query23 is 2");
	ok(otrl_proto_query_bestversion(query23, OTRL_POLICY_ALLOW_V3) == 3, "The best from query23 is 3");
}

static void test_proto_default_query_msg(void)
{
	const char *expected2 = "?OTRv2?\n<b>alice</b> has requested an "
		"<a href=\"https://otr.cypherpunks.ca/\">Off-the-Record "
		"private conversation</a>.  However, you do not have a plugin "
		"to support that.\nSee <a href=\"https://otr.cypherpunks.ca/\">"
		"https://otr.cypherpunks.ca/</a> for more information.";

	const char *expected23 = "?OTRv23?\n<b>alice</b> has requested an "
		"<a href=\"https://otr.cypherpunks.ca/\">Off-the-Record "
		"private conversation</a>.  However, you do not have a plugin "
		"to support that.\nSee <a href=\"https://otr.cypherpunks.ca/\">"
		"https://otr.cypherpunks.ca/</a> for more information.";

	const char *expected3 = "?OTRv3?\n<b>alice</b> has requested an "
		"<a href=\"https://otr.cypherpunks.ca/\">Off-the-Record "
		"private conversation</a>.  However, you do not have a plugin "
		"to support that.\nSee <a href=\"https://otr.cypherpunks.ca/\">"
		"https://otr.cypherpunks.ca/</a> for more information.";

	const char* msg2 = otrl_proto_default_query_msg("alice", OTRL_POLICY_ALLOW_V2);
	const char* msg23 = otrl_proto_default_query_msg("alice", OTRL_POLICY_ALLOW_V2 | OTRL_POLICY_ALLOW_V3);
	const char* msg3 = otrl_proto_default_query_msg("alice", OTRL_POLICY_ALLOW_V3);
	ok(strcmp(expected2, msg2) == 0, "OTRv2 default query message is valid");
	ok(strcmp(expected23, msg23) == 0, "OTRv23 default query message is valid");
	ok(strcmp(expected3, msg3) == 0, "OTRv3 default query message is valid");
	//ok(otrl_proto_default_query_msg("alice", 0) == NULL, "Wrong version query message is NULL");
}

void test_otrl_init(void)
{
	extern unsigned int otrl_api_version;

	const unsigned int expected = rand();
	otrl_api_version = expected;
	ok(otrl_init(OTRL_VERSION_MAJOR+1, 0, 0) == gcry_error(GPG_ERR_INV_VALUE),
			"Too recent major version");
	ok(otrl_api_version == expected, "Api number unchanged");

	ok(otrl_init(OTRL_VERSION_MAJOR-1, 0, 0) == gcry_error(GPG_ERR_INV_VALUE),
			"Too old major version");
	ok(otrl_api_version == expected, "Api number unchanged");

	ok(otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR+1, 0) == gcry_error(GPG_ERR_INV_VALUE), 
			"Too recent minor version");
	ok(otrl_api_version = expected, "Api number unchanged");

	ok(otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR?OTRL_VERSION_MINOR-1:0, OTRL_VERSION_SUB) == 
			gcry_error(GPG_ERR_NO_ERROR), "Inferior minor version");
	ok(otrl_api_version = expected, "Api number unchanged");

	otrl_api_version = 0;
	ok(otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB) == gcry_error(GPG_ERR_NO_ERROR),
			"Exact version");
	ok(otrl_api_version == (
				(OTRL_VERSION_MAJOR << 16) |
				(OTRL_VERSION_MINOR << 8) |
				(OTRL_VERSION_SUB)
				), "Api version set for exact version");
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);
	test_proto_default_query_msg();
	test_otrl_proto_query_bestversion();
	test_otrl_init();
	return 0;

}
