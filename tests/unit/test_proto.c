#include <tap/tap.h>
#include <proto.h>

#define NUM_TESTS 3

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
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);
	test_proto_default_query_msg();
	return 0;

}
