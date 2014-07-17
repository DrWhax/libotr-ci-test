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
#include <dh.h>

#define NUM_TESTS 17

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

static void test_otrl_dh_compute_v2_auth_keys(void)
{
	const char test_vector[] = "This is a test vector";
    size_t slen = 0;
	size_t sessionidlenp = 0;
    unsigned char *sdata = NULL;
    unsigned char *hashdata = NULL;
    gcry_mpi_t s = NULL;
    unsigned char ctr[16] = {0};

	DH_keypair our_dh, their_dh;
	gcry_mpi_t public_key = NULL;


	unsigned char sessionid[8];
	gcry_md_hd_t mac_m1 = NULL, mac_m1p = NULL, mac_m2 = NULL, mac_m2p = NULL;
	gcry_cipher_hd_t enc_c = NULL, enc_cp = NULL;
	unsigned char encrypt[32] = {0};

	unsigned char sessionid_expected[8];
	gcry_md_hd_t mac_m1_expected = NULL, mac_m1p_expected = NULL, mac_m2_expected = NULL, mac_m2p_expected = NULL;
	gcry_cipher_hd_t enc_c_expected = NULL, enc_cp_expected = NULL;
	unsigned char expected_encrypt[32] = {0};

	otrl_dh_gen_keypair(DH1536_GROUP_ID, &our_dh);
	otrl_dh_gen_keypair(DH1536_GROUP_ID, &their_dh);

	our_dh.groupid++;
	ok(otrl_dh_compute_v2_auth_keys(&our_dh, their_dh.pub,
			sessionid, &sessionidlenp, &enc_c, &enc_cp,
			&mac_m1, &mac_m1p, &mac_m2, &mac_m2p) == gcry_error(GPG_ERR_INV_VALUE),
			"Invalid group detected");
	our_dh.groupid--;
	
	gcry_mpi_scan(&public_key, GCRYMPI_FMT_USG, "1", 0, NULL);
	ok(otrl_dh_compute_v2_auth_keys(&our_dh, public_key,
			sessionid, &sessionidlenp, &enc_c, &enc_cp,
			&mac_m1, &mac_m1p, &mac_m2, &mac_m2p) == gcry_error(GPG_ERR_INV_VALUE),
			"Public key too small");

    gcry_mpi_scan(&public_key, GCRYMPI_FMT_HEX, (const unsigned char *)DH1536_MODULUS_S, 0, NULL);
    gcry_mpi_add_ui(public_key, DH1536_MODULUS, 1);
	ok(otrl_dh_compute_v2_auth_keys(&our_dh, DH1536_MODULUS,
			sessionid, &sessionidlenp, &enc_c, &enc_cp,
			&mac_m1, &mac_m1p, &mac_m2, &mac_m2p) == gcry_error(GPG_ERR_INV_VALUE),
			"Public key too big");

	ok(otrl_dh_compute_v2_auth_keys(&our_dh, their_dh.pub, sessionid, &sessionidlenp, &enc_c, &enc_cp,
			&mac_m1, &mac_m1p, &mac_m2, &mac_m2p) == gcry_error(GPG_ERR_NO_ERROR),
			"Auth keys generated");
	ok(sessionidlenp == 8, "Session id len p set to correct value");

    s = gcry_mpi_snew(DH1536_MOD_LEN_BITS);
    gcry_mpi_powm(s, their_dh.pub, our_dh.priv, DH1536_MODULUS);

    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &slen, s);
    sdata = gcry_malloc_secure(slen + 5);
    sdata[1] = (slen >> 24) & 0xff;
    sdata[2] = (slen >> 16) & 0xff;
    sdata[3] = (slen >> 8) & 0xff;
    sdata[4] = slen & 0xff;
    gcry_mpi_print(GCRYMPI_FMT_USG, sdata+5, slen, NULL, s);
    gcry_mpi_release(s);

    hashdata = gcry_malloc_secure(32);
    sdata[0] = 0x00;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, slen+5);
    memmove(sessionid_expected, hashdata, 8);
	ok(memcmp(sessionid_expected, sessionid, 8) == 0, "Session id is correct");

    sdata[0] = 0x01;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, slen+5);

    gcry_cipher_open(&enc_c_expected, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    gcry_cipher_setkey(enc_c_expected, hashdata, 16);
    gcry_cipher_setctr(enc_c_expected, ctr, 16);
	gcry_cipher_encrypt(enc_c_expected, expected_encrypt, sizeof(expected_encrypt), test_vector, strlen(test_vector));
	gcry_cipher_encrypt(enc_c, encrypt, sizeof(encrypt), test_vector, strlen(test_vector));
	ok(memcmp(encrypt, expected_encrypt, sizeof(encrypt)) == 0, "Enc ok");

    gcry_cipher_open(&(enc_cp_expected), GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    gcry_cipher_setkey(enc_cp_expected, hashdata+16, 16);
    gcry_cipher_setctr(enc_cp_expected, ctr, 16);
	gcry_cipher_encrypt(enc_cp_expected, expected_encrypt, sizeof(expected_encrypt), test_vector, strlen(test_vector));
	gcry_cipher_encrypt(enc_cp, encrypt, sizeof(encrypt), test_vector, strlen(test_vector));
	ok(memcmp(encrypt, expected_encrypt, sizeof(encrypt)) == 0, "Encp ok");

    sdata[0] = 0x02;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, slen+5);
    gcry_md_open(&mac_m1_expected, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(mac_m1_expected, hashdata, 32);
	gcry_md_write(mac_m1_expected, test_vector, sizeof(test_vector));
	gcry_md_write(mac_m1, test_vector, sizeof(test_vector));
	ok(memcmp(gcry_md_read(mac_m1_expected, 0), gcry_md_read(mac_m1, 0), 32) == 0, "mac_m1 set");

    sdata[0] = 0x03;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, slen+5);
    gcry_md_open(&mac_m2_expected, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(mac_m2_expected, hashdata, 32);
	gcry_md_write(mac_m2_expected, test_vector, sizeof(test_vector));
	gcry_md_write(mac_m2, test_vector, sizeof(test_vector));
	ok(memcmp(gcry_md_read(mac_m2_expected, 0), gcry_md_read(mac_m2, 0), 32) == 0, "mac_m2 set");

    sdata[0] = 0x04;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, slen+5);
    gcry_md_open(&mac_m1p_expected, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(mac_m1p_expected, hashdata, 32);
	gcry_md_write(mac_m1p_expected, test_vector, sizeof(test_vector));
	gcry_md_write(mac_m1p, test_vector, sizeof(test_vector));
	ok(memcmp(gcry_md_read(mac_m1p_expected, 0), gcry_md_read(mac_m1p, 0), 32) == 0, "mac_m1p set");

    sdata[0] = 0x05;
    gcry_md_hash_buffer(GCRY_MD_SHA256, hashdata, sdata, slen+5);
    gcry_md_open(&mac_m2p_expected, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(mac_m2p_expected, hashdata, 32);
	gcry_md_write(mac_m2p_expected, test_vector, sizeof(test_vector));
	gcry_md_write(mac_m2p, test_vector, sizeof(test_vector));
	ok(memcmp(gcry_md_read(mac_m2p_expected, 0), gcry_md_read(mac_m2p, 0), 32) == 0, "mac_m2p set");

    gcry_free(sdata);
    gcry_free(hashdata);
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
	test_otrl_dh_compute_v2_auth_keys();
	return 0;
}
