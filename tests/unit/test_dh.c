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

#define NUM_TESTS 5

/*
 * The re-implementation/inclusion of crypto stuff is
 * necessary because libotr doesn't expose them.
 */

static const char* DH1536_MODULUS_S = "0x"
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
static const char *DH1536_GENERATOR_S = "0x02";
static const int DH1536_MOD_LEN_BITS = 1536;

static gcry_mpi_t DH1536_MODULUS = NULL;
static gcry_mpi_t DH1536_MODULUS_MINUS_2 = NULL;
static gcry_mpi_t DH1536_GENERATOR = NULL;

static void test_otrl_dh_gen_keypair(void)
{
	DH_keypair kp;
	gcry_mpi_t pubkey = NULL;

	otrl_dh_keypair_init(&kp);

	ok(otrl_dh_gen_keypair(DH1536_GROUP_ID+1, &kp) == gcry_error(GPG_ERR_INV_VALUE),
			"Invalid group detected");
	ok(otrl_dh_gen_keypair(DH1536_GROUP_ID, &kp) == gcry_error(GPG_ERR_NO_ERROR),
			"valid group set");
	ok(kp.groupid == DH1536_GROUP_ID, "Group set");

    pubkey = gcry_mpi_new(DH1536_MOD_LEN_BITS);
	gcry_mpi_powm(pubkey, DH1536_GENERATOR, kp.priv, DH1536_MODULUS);
	ok(gcry_mpi_cmp(pubkey, kp.pub) == 0, "Matching pubkey");
	otrl_dh_keypair_free(&kp);
}

static void test_otrl_dh_keypair_free(void)
{
	DH_keypair kp;

	otrl_dh_gen_keypair(DH1536_GROUP_ID, &kp);
	otrl_dh_keypair_free(&kp);
	ok(kp.pub == NULL && kp.priv == NULL && kp.groupid == DH1536_GROUP_ID,
			"DH_keypair free'd with success");
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);

	otrl_dh_init(); // Initialize math stuff

	gcry_mpi_scan(&DH1536_MODULUS, GCRYMPI_FMT_HEX,
	(const unsigned char *)DH1536_MODULUS_S, 0, NULL);
    gcry_mpi_scan(&DH1536_GENERATOR, GCRYMPI_FMT_HEX,
	(const unsigned char *)DH1536_GENERATOR_S, 0, NULL);
    DH1536_MODULUS_MINUS_2 = gcry_mpi_new(DH1536_MOD_LEN_BITS);
    gcry_mpi_sub_ui(DH1536_MODULUS_MINUS_2, DH1536_MODULUS, 2);

	test_otrl_dh_gen_keypair();
	test_otrl_dh_keypair_free();
	return 0;
}
