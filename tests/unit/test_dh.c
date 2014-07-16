/*
 * Copyright (C) 2014 - Julien Voisin <julien.voisin@dustri.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <tap/tap.h>
#include <gcrypt.h>
#include <dh.h>

#define NUM_TESTS 4

static void test_otrl_dh_gen_keypair(void)
{
	DH_keypair kp;
	//gcry_mpi_t pubkey;
	//gcry_mpi_t DH1536_GENERATOR = NULL;

	ok(otrl_dh_gen_keypair(DH1536_GROUP_ID+1, &kp) == gcry_error(GPG_ERR_INV_VALUE),
			"Invalid group detected");
	ok(otrl_dh_gen_keypair(DH1536_GROUP_ID, &kp) == gcry_error(GPG_ERR_NO_ERROR),
			"valid group set");
	ok(kp.groupid == DH1536_GROUP_ID, "Group set");

	//gcry_mpi_powm(pubkey, DH1536_GENERATOR, kp.priv, DH1536_MODULUS);
	//ok(pubkey == kp.pub, "matching pubkey");
}


int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);
	test_otrl_dh_gen_keypair();
	return 0;
}
