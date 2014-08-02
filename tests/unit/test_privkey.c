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

#include <tap/tap.h>
#include <gcrypt.h>
#include <privkey.h>

#define NUM_TESTS 1

static void test_otrl_privkey_hash_to_human(void)
{
	char human[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	unsigned char hash[20];
	int i;

	for(i=0; i<20; i++)
		hash[i] = 'A' + i;

	otrl_privkey_hash_to_human(human, hash);
	ok(strcmp("41424344 45464748 494A4B4C 4D4E4F50 51525354", human) == 0,
			"Hash to human ok");
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);

	test_otrl_privkey_hash_to_human();

	return 0;
}
