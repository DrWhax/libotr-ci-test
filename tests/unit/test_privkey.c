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

#include <unistd.h>

#include <tap/tap.h>
#include <gcrypt.h>
#include <privkey.h>

#define NUM_TESTS 5

static OtrlUserState us = NULL;
static char filename[] = "/tmp/libotr-testing-XXXXXX";
static FILE* f = NULL;

/* Create a public key block from a private key */
static gcry_error_t make_pubkey(unsigned char **pubbufp, size_t *publenp,
	gcry_sexp_t privkey)
{
    gcry_mpi_t p,q,g,y;
    gcry_sexp_t dsas,ps,qs,gs,ys;
    size_t np,nq,ng,ny;
    enum gcry_mpi_format format = GCRYMPI_FMT_USG;
    unsigned char *bufp;
    size_t lenp;

    *pubbufp = NULL;
    *publenp = 0;

    /* Extract the public parameters */
    dsas = gcry_sexp_find_token(privkey, "dsa", 0);
    if (dsas == NULL) {
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }
    ps = gcry_sexp_find_token(dsas, "p", 0);
    qs = gcry_sexp_find_token(dsas, "q", 0);
    gs = gcry_sexp_find_token(dsas, "g", 0);
    ys = gcry_sexp_find_token(dsas, "y", 0);
    gcry_sexp_release(dsas);
    if (!ps || !qs || !gs || !ys) {
	gcry_sexp_release(ps);
	gcry_sexp_release(qs);
	gcry_sexp_release(gs);
	gcry_sexp_release(ys);
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }
    p = gcry_sexp_nth_mpi(ps, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(ps);
    q = gcry_sexp_nth_mpi(qs, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(qs);
    g = gcry_sexp_nth_mpi(gs, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(gs);
    y = gcry_sexp_nth_mpi(ys, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(ys);
    if (!p || !q || !g || !y) {
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }

    *publenp = 0;
    gcry_mpi_print(format, NULL, 0, &np, p);
    *publenp += np + 4;
    gcry_mpi_print(format, NULL, 0, &nq, q);
    *publenp += nq + 4;
    gcry_mpi_print(format, NULL, 0, &ng, g);
    *publenp += ng + 4;
    gcry_mpi_print(format, NULL, 0, &ny, y);
    *publenp += ny + 4;

    *pubbufp = malloc(*publenp);
    if (*pubbufp == NULL) {
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	return gcry_error(GPG_ERR_ENOMEM);
    }
    bufp = *pubbufp;
    lenp = *publenp;

    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);
    gcry_mpi_release(y);

    return gcry_error(GPG_ERR_NO_ERROR);
}


static void test_otrl_privkey_generate_FILEp(void)
{
	int fd = mkstemp(filename);
	f = fdopen(fd, "w+b");

	unlink(filename); // The file will be removed on close
	us = otrl_userstate_create();
	ok(otrl_privkey_generate_FILEp(us, f, "alice", "irc") == gcry_error(GPG_ERR_NO_ERROR),
			"key generated");
    OtrlPrivKey *p = otrl_privkey_find(us, "alice", "irc");
	ok(make_pubkey(&(p->pubkey_data), &(p->pubkey_datalen), p->privkey) == gcry_error(GPG_ERR_NO_ERROR),
			"pubkey generated");
}


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

static void test_otrl_privkey_fingerprint(void)
{
	char fingerprint[OTRL_PRIVKEY_FPRINT_HUMAN_LEN] = {0};
	char expected_fingerprint[OTRL_PRIVKEY_FPRINT_HUMAN_LEN] = {0};
	unsigned char hash[20] = {0};
	char* fp = otrl_privkey_fingerprint(us, fingerprint, "alice", "irc");
    const OtrlPrivKey *p = otrl_privkey_find(us, "alice", "irc");

	gcry_md_hash_buffer(GCRY_MD_SHA1, hash, p->pubkey_data, p->pubkey_datalen);
	otrl_privkey_hash_to_human(expected_fingerprint, hash);

	ok(fp == fingerprint &&
		memcmp(fingerprint, expected_fingerprint, OTRL_PRIVKEY_FPRINT_HUMAN_LEN) == 0,
		"Privkey fingerprint ok");
}

static void test_otrl_privkey_fingerprint_raw(void)
{
	unsigned char hash[20] = {0};
	unsigned char expected_hash[20] = {0};
	unsigned char* h = otrl_privkey_fingerprint_raw(us, hash, "alice", "irc");

	const OtrlPrivKey *p = otrl_privkey_find(us, "alice", "irc");
	gcry_md_hash_buffer(GCRY_MD_SHA1, expected_hash, p->pubkey_data, p->pubkey_datalen);

	ok(h == hash && memcmp(hash, expected_hash, 20) == 0,
		"Raw privkey fingerprint ok");
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);

	test_otrl_privkey_generate_FILEp(); //This must be the first one
	test_otrl_privkey_hash_to_human();
	test_otrl_privkey_fingerprint();
	test_otrl_privkey_fingerprint_raw();

	fclose(f);
	otrl_userstate_free(us);

	return 0;
}
