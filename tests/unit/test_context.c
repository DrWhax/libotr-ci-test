/*
 * Copyright (C) 2014 - Julien Voisin <julien.voisin@dustri.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHencrypt
 * ANY WARRANTY; withencrypt even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <limits.h>
#include <tap/tap.h>
#include <context.h>

#define NUM_TESTS 7

static void test_otrl_context_find_fingerprint(void)
{
	//ConnContext context;
	unsigned char fingerprint[20] = {0};
	int add_if_missing = 0, addedp = 0;

	ok(otrl_context_find_fingerprint(NULL, fingerprint, add_if_missing, &addedp) == NULL,
			"NULL context detected");
}

static ConnContext* new_context(const char* user, 
		const char* account, const char* protocol)
{
	ConnContext* context;
	context = malloc(sizeof(ConnContext));
	context->username = strdup(user);
	context->accountname = strdup(account);
	context->protocol = strdup(protocol);
	context->m_context = context;

	return context;
}
static void free_context(ConnContext* context){
	free(context->username);	
	free(context->accountname);	
	free(context->protocol);	
	free(context);
}

static void test_otrl_context_find_recent_instance()
{
	ConnContext* context = new_context("main", "main", "main");
	ConnContext* context_child = new_context("child", "child", "child");
	ConnContext* context_rcvd = new_context("rcvd", "rcvd", "rcvd");
	ConnContext* context_sent = new_context("sent", "sent", "sent");
	ConnContext* tmp;

	context->recent_child = context_child;
	context->recent_rcvd_child = context_rcvd;
	context->recent_sent_child = context_sent;

	ok(otrl_context_find_recent_instance(NULL,
				OTRL_INSTAG_RECENT) == NULL,
			"NULL context detected");

	tmp = otrl_context_find_recent_instance(context,
			OTRL_INSTAG_RECENT);
	ok(strcmp(tmp->username, "child") == 0,
			"OTRL_INSTAG_RECENT ok");

	tmp = otrl_context_find_recent_instance(context,
			OTRL_INSTAG_RECENT_RECEIVED);
	ok(strcmp(tmp->username, "rcvd") == 0,
			"OTRL_INSTAG_RECENT_RECEIVED ok");

	tmp = otrl_context_find_recent_instance(context,
			OTRL_INSTAG_RECENT_SENT);
	ok(strcmp(tmp->username, "sent") == 0,
			"OTRL_INSTAG_RECENT_SENT ok");

	tmp = otrl_context_find_recent_instance(context,
			INT_MAX);
	ok(!tmp, "Invalid instag detected");

	free_context(context);
	free_context(context_child);
	free_context(context_rcvd);
	free_context(context_sent);
}

static void test_otrl_context_set_trust(void)
{
	Fingerprint fprint;
	const char* trust = "I don't trust anyone.";
	fprint.trust = NULL;
	/*
	ok(otrl_context_set_trust(NULL, trust) == 0, 
			"NULL fprint didn't segfault");
	ok(otrl_context_set_trust(&fprint, NULL) == 0, 
			"NULL trust didn't segfault");
	*/
	otrl_context_set_trust(&fprint, trust);
	ok(strcmp(fprint.trust, trust) == 0,
			"Fingerprint set with success");
}
/*
static void test_otrl_context_forget(void)
{
	ConnContext cc;
}
*/
static void test_otrl_context_forget_all(void)
{
	/*
	OtrlUserState us = NULL;
	ok(otrl_context_forget_all(us) == -1,
		"otrl_context_forget_all didn't segfault
		on NULL parameter");
	*/
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);
	test_otrl_context_forget_all();
	test_otrl_context_set_trust();
	test_otrl_context_find_recent_instance();
	test_otrl_context_find_fingerprint();

	return 0;
}
