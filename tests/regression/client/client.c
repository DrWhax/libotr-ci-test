/*
 * Copyright (C) 2014 - David Goulet <dgoulet@ev0ke.net>
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

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <gcrypt.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <context.h>
#include <privkey.h>
#include <proto.h>
#include <message.h>

#include <tap/tap.h>

#define zmalloc(x) calloc(1, x)

GCRY_THREAD_OPTION_PTHREAD_IMPL;

/* Global OTR user state. */
static OtrlUserState user_state;

/* Getopt options. */
static struct option long_opts[] = {
	{ "load-instag", 1, NULL, 'i' },
	{ "load-key",    1, NULL, 'k' },
	{ "load-fp",     1, NULL, 'f' },
	{ "timeout",     1, NULL, 't' },
	{ "max-msg",     1, NULL, 'm' },
	{ "disconnect",  0, NULL, 'd' },

	/* Closure. */
	{ NULL, 0, NULL, 0 }
};

static char *opt_instag_path;
static char *opt_key_path;
static char *opt_key_fp_path;
static unsigned int opt_max_num_msg;
static int opt_disconnect;
/* By default, don't fragment. */
static int opt_max_size = 0;

static const char *protocol = "otr-test";
static const char *alice_name = "alice";
static const char *bob_name = "bob";

static const char *unix_sock_bob_path = "/tmp/otr-test-bob.sock";
static const char *unix_sock_alice_path = "/tmp/otr-test-alice.sock";

/* Alice and Bob thread's socket. */
static int alice_sock;
static int bob_sock;
/* Declare it global because we use it multiple times. */
static struct sockaddr_un alice_sun;
static struct sockaddr_un bob_sun;

static int timeout_max = 1000;
static unsigned int num_recv_msg;
static unsigned int session_disconnected;

/*
 * Used to have mutual exclusion for the receiving/sending OTR api to avoid a
 * libgcrypt race that asserts on a mutex. More info:
 * http://lists.gnupg.org/pipermail/gcrypt-devel/2014-July/003140.html
 */
static pthread_mutex_t msg_lock = PTHREAD_MUTEX_INITIALIZER;

/* Logging lock. Libtap behaves badly with multi threaded output. */
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

#define OK(cond, fmt, args...)                   \
	do {                                         \
		pthread_mutex_lock(&log_lock);           \
		ok(cond, fmt, ## args);                  \
		pthread_mutex_unlock(&log_lock);         \
	} while (0)

static inline pid_t gettid(void)
{
	return syscall(__NR_gettid);
}

/*
 * Used to pass OTR message between threads. This contains the cipher and
 * plaintext so we are able to validate what's expected in both threads.
 */
struct otr_msg {
	size_t plaintext_len;
	size_t ciphertext_len;
	char *plaintext;
	char *ciphertext;
};

struct otr_info {
	const char *user;
	int sock;
	unsigned int gone_secure;
};

/* Stub */
static int send_otr_msg(int sock, const char *to, const char *from,
		struct otr_info *oinfo, const char *message);

static OtrlPolicy ops_policy(void *opdata, ConnContext *context)
{
	//return OTRL_POLICY_ALWAYS;
	return OTRL_POLICY_DEFAULT;
}

static void ops_inject_msg(void *opdata, const char *accountname,
		const char *protocol, const char *recipient, const char *message)
{
	ssize_t ret;
	struct otr_info *oinfo = opdata;
	struct otr_msg *msg;

	msg = zmalloc(sizeof(*msg));
	if (!msg) {
		perror("zmalloc inject");
		return;
	}

	msg->ciphertext = strdup(message);
	msg->ciphertext_len = strlen(message);

	ret = send(oinfo->sock, &msg, sizeof(msg), 0);
	if (ret < 0) {
		perror("send msg");
	}
}

static void ops_gone_secure(void *opdata, ConnContext *context)
{
	struct otr_info *oinfo = opdata;

	session_disconnected = 0;
	oinfo->gone_secure = 1;
	/* XXX: gone_insecure is never called ref bug #40 so this will always be
	 * true. */
	OK(oinfo->gone_secure, "Gone secure for %s",
			oinfo->user);
}

static void ops_gone_insecure(void *opdata, ConnContext *context)
{
	struct otr_info *oinfo = opdata;

	OK(oinfo->gone_secure, "Gone insecure for %s",
			oinfo->user);
	oinfo->gone_secure = 0;
}

static int ops_max_message_size(void *opdata, ConnContext *context)
{
	return opt_max_size;
}

static const char *ops_otr_error_message(void *opdata, ConnContext *context,
		OtrlErrorCode code)
{
	char *msg = NULL;

	switch (code) {
	case OTRL_ERRCODE_NONE:
		break;
	case OTRL_ERRCODE_ENCRYPTION_ERROR:
		msg = strdup("OTRL_ERRCODE_ENCRYPTION_ERROR");
		break;
	case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
		msg = strdup("OTRL_ERRCODE_MSG_NOT_IN_PRIVATE");
		break;
	case OTRL_ERRCODE_MSG_UNREADABLE:
		msg = strdup("OTRL_ERRCODE_MSG_UNREADABLE");
		break;
	case OTRL_ERRCODE_MSG_MALFORMED:
		msg = strdup("OTRL_ERRCODE_MSG_MALFORMED");
		break;
	}

	return msg;
}

static void ops_otr_error_message_free(void *opdata, const char *err_msg)
{
	free((char *) err_msg);
}

static void ops_handle_msg_event(void *opdata, OtrlMessageEvent msg_event,
		ConnContext *context, const char *message, gcry_error_t err)
{
	//char* msg = "";
	struct otr_info *oinfo = opdata;

	switch(msg_event) {
	case OTRL_MSGEVENT_NONE:
		//msg = "OTRL_MSGEVENT_NONE";
		break;
	case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
		//msg = "OTRL_MSGEVENT_ENCRYPTION_REQUIRED";
		break;
	case OTRL_MSGEVENT_ENCRYPTION_ERROR:
		//msg = "OTRL_MSGEVENT_ENCRYPTION_ERROR";
		break;
	case OTRL_MSGEVENT_CONNECTION_ENDED:
		//msg = "OTRL_MSGEVENT_CONNECTION_ENDED";
		oinfo->gone_secure = 0;
		break;
	case OTRL_MSGEVENT_SETUP_ERROR:
		//msg = "OTRL_MSGEVENT_SETUP_ERROR";
		break;
	case OTRL_MSGEVENT_MSG_REFLECTED:
		//msg = "OTRL_MSGEVENT_MSG_REFLECTED";
		break;
	case OTRL_MSGEVENT_MSG_RESENT:
		//msg = "OTRL_MSGEVENT_MSG_RESENT";
		break;
	case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
		//msg = "OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE";
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
		//msg = "OTRL_MSGEVENT_RCVDMSG_UNREADABLE";
		break;
	case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
		//msg = "OTRL_MSGEVENT_RCVDMSG_MALFORMED";
		break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
		//msg = "OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD";
		break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
		//msg = "OTRL_MSGEVENT_LOG_HEARTBEAT_SENT";
		break;
	case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
		//msg = "OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR";
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
		//msg = "OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED";
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
		//msg = "OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED";
		break;
	case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
		//msg = "OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE";
		break;
	default:
		//msg = "Unknown OTRL message event";
		break;
	}
}

static void ops_create_instag(void *opdata, const char *accountname,
		const char *protocol)
{
	otrl_instag_generate(user_state, "/dev/null", accountname,
			protocol);
}

static int ops_is_logged_in(void *opdata, const char *accountname,
		const char *protocol, const char *recipient)
{
	/* Always logged in or else we don't receive a disconnected TLV. */
	return 1;
}

/* OTR message operations. */
static OtrlMessageAppOps ops = {
	ops_policy,
	NULL, /* create_privkey */
	ops_is_logged_in,
	ops_inject_msg,
	NULL, /* update_context_list */
	NULL, /* new_fingerprint */
	NULL, /* write_fingerprints */
	ops_gone_secure,
	ops_gone_insecure,
	NULL, /* still_secure */
	ops_max_message_size,
	NULL, /* account_name */
	NULL, /* account_name_free */
	NULL, /* received_symkey */
	ops_otr_error_message,
	ops_otr_error_message_free,
	NULL, /* resent_msg_prefix */
	NULL, /* resent_msg_prefix_free */
	NULL, /* handle_smp_event */
	ops_handle_msg_event,
	ops_create_instag,
	NULL, /* convert_msg */
	NULL, /* convert_free */
	NULL, /* timer_control */
};

static void cleanup(void)
{
	if (alice_sock) {
		close(alice_sock);
		unlink(alice_sun.sun_path);
		alice_sock = 0;
	}

	if (bob_sock) {
		(void) close(bob_sock);
		unlink(bob_sun.sun_path);
		bob_sock = 0;
	}

	exit_status();
	exit(EXIT_SUCCESS);
}

static void update_msg_counter(void)
{
	num_recv_msg++;
	if (num_recv_msg == opt_max_num_msg) {
		cleanup();
	}
}

/*
 * Generate random string and stores it in out of size len.
 */
static void gen_random_string(char *out, size_t len)
{
	size_t i;
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (i = 0; i < len; i++) {
		out[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	out[len - 1] = '\0';
}

static int send_otr_msg(int sock, const char *to, const char *from,
		struct otr_info *oinfo, const char *message)
{
	char *new_msg = NULL;
	ssize_t ret;
	gcry_error_t err;
	struct otr_msg *omsg;

	omsg = zmalloc(sizeof(*omsg));
	if (!omsg) {
		perror("zmalloc send otr msg");
		goto error;
	}

	if (!message) {
		size_t len = rand() % 600;
		char *msg = zmalloc(len);
		if (!msg) {
			perror("random msg");
			goto error;
		}
		gen_random_string(msg, len);
		omsg->plaintext = msg;
		omsg->plaintext_len = strlen(msg);
	} else {
		omsg->plaintext = strdup(message);
		omsg->plaintext_len = strlen(message);
	}

	pthread_mutex_lock(&msg_lock);
	err = otrl_message_sending(user_state, &ops, oinfo, from, protocol, to,
			OTRL_INSTAG_BEST, omsg->plaintext, NULL, &new_msg,
			OTRL_FRAGMENT_SEND_SKIP, NULL, NULL, NULL);
	pthread_mutex_unlock(&msg_lock);
	if (err) {
		goto error;
	}
	if (new_msg) {
		free(omsg->ciphertext);
		omsg->ciphertext = strdup(new_msg);
		omsg->ciphertext_len = strlen(omsg->ciphertext);
		otrl_message_free(new_msg);
	}

	ret = send(sock, &omsg, sizeof(omsg), 0);
	if (ret < 0) {
		perror("send OTR msg");
		goto error;
	}

	return 0;

error:
	if(omsg){
		free(omsg->plaintext);
		free(omsg->ciphertext);
		free(omsg);
	}
	return -1;
}

static int recv_otr_msg(int sock, const char *to, const char *from,
		struct otr_info *oinfo)
{
	int err;
	ssize_t ret;
	char *new_msg = NULL;
	struct otr_msg *omsg;
	OtrlTLV *tlvs = NULL;

	ret = recv(sock, &omsg, sizeof(omsg), 0);
	if (ret < 0) {
		goto error;
	}

	pthread_mutex_lock(&msg_lock);
	err = otrl_message_receiving(user_state, &ops, oinfo, to, protocol, from,
			omsg->ciphertext, &new_msg, &tlvs, NULL, NULL, NULL);
	pthread_mutex_unlock(&msg_lock);
	if (!err) {
		if (new_msg) {
			OK(strncmp(omsg->plaintext, new_msg, omsg->plaintext_len) == 0,
					"Message exchanged is valid");
			update_msg_counter();
		}
	} else {
		OK(err == 1, "Internal OTR message valid");
	}

	free(omsg->plaintext);
	free(omsg->ciphertext);
	free(omsg);

	OtrlTLV *tlv = otrl_tlv_find(tlvs, OTRL_TLV_DISCONNECTED);
	/*
	 * XXX: Somehow you can end up with a disconnected TLV in a gone secure
	 * session. This is probably a bug but since the gone_insecure is never
	 * called (see bug #48) we have no reliable way of knowing the state of the
	 * session at this point.
	 */
	if (tlv && !oinfo->gone_secure) {
		OK(session_disconnected, "Disconnected TLV confirmed");
	}

	otrl_tlv_free(tlvs);

	return 0;

error:
	return -1;
}

static int add_sock_to_pollset(int epfd, int sock, uint32_t req_ev)
{
	int ret;
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = req_ev;
	ev.data.fd = sock;

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
	if (ret < 0) {
		perror("epoll_ctl add");
	}
	return ret;
}

static void *alice_thread(void *data)
{
	int sock_to_bob, sock_from_bob = 0, epfd, ret;
	struct otr_info oinfo;

	/* Poll size is ignored since 2.6.8 */
	epfd = epoll_create(42);
	if (epfd < 0) {
		perror("epoll_create Bob");
		goto error;
	}

	sock_to_bob = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock_to_bob < 0) {
		perror("Bob socket to Alice");
		goto sock_error;
	}
	oinfo.sock = sock_to_bob;
	oinfo.user = "Alice";

	ret = connect(sock_to_bob, (struct sockaddr *) &bob_sun,
			sizeof(bob_sun));
	if (ret < 0) {
		perror("connect to Alice");
		goto end;
	}

	/* Add our socket to epoll set. */
	ret = add_sock_to_pollset(epfd, alice_sock,
			EPOLLIN | EPOLLERR | EPOLLHUP);
	if (ret < 0) {
		goto end;
	}

	while (1) {
		int i, nb_fd, timeout;
		struct epoll_event ev[3];
		memset(ev, 0, sizeof(ev));

		/* 
		 * Set random timeout and when we do timeout, use that to send message
		 * to Alice.
		 */
		timeout = (rand() % (timeout_max - 1));

		ret = epoll_wait(epfd, ev, 3, timeout);
		if (ret < 0) {
			perror("epoll_wait Alice");
			goto end;
		}
		nb_fd = ret;

		/* Each timeout to 10 finishes the OTR session. */
		if (!(timeout % 3) && opt_disconnect) {
			pthread_mutex_lock(&msg_lock);
			session_disconnected = 1;
			oinfo.gone_secure = 0;
			otrl_message_disconnect(user_state, &ops, &oinfo,
					alice_name, protocol, bob_name, OTRL_INSTAG_BEST);
			pthread_mutex_unlock(&msg_lock);
			OK(!oinfo.gone_secure, "OTR message disconnect");
		}

		/* No event thus timeout, send message to Alice. */
		if (nb_fd == 0) {
			(void) send_otr_msg(sock_to_bob, bob_name, alice_name, &oinfo,
					NULL);
			continue;
		}

		for (i = 0; i < nb_fd; i++) {
			int fd;
			uint32_t event;

			fd = ev[i].data.fd;
			event = ev[i].events;

			if (fd == alice_sock) {
				if (event & (EPOLLERR | EPOLLHUP)) {
					goto end;
				} else if (event & EPOLLIN) {
					socklen_t len;
					struct sockaddr_un sun;

					/* Connection from Alice, accept it so we can handle it. */
					sock_from_bob = accept(fd, (struct sockaddr *) &sun,
							&len);
					ret = add_sock_to_pollset(epfd, sock_from_bob,
							EPOLLIN | EPOLLERR | EPOLLHUP);
					if (ret < 0) {
						goto end;
					}
				}
				continue;
			} else if (fd == sock_from_bob) {
				if (event & (EPOLLERR | EPOLLHUP)) {
					/* Stop since Bob's thread just shut us down. */
					goto end;
				} else if (event & EPOLLIN) {
					(void) recv_otr_msg(sock_from_bob, alice_name, bob_name,
							&oinfo);
				}
				continue;
			} else {
				goto end;
			}
		}
	}

end:
	if (sock_from_bob) {
		(void) close(sock_from_bob);
	}
	(void) close(sock_to_bob);
sock_error:
	(void) close(epfd);
error:
	/* Only call cleanup from here, it will close Bob's socket
	 * thus the thread will stop. */
	cleanup();
	return NULL;
}

static void *bob_thread(void *data)
{
	int sock_to_alice, sock_from_alice = 0, epfd, ret;
	struct otr_info oinfo;

	/* Poll size is ignored since 2.6.8 */
	epfd = epoll_create(42);
	if (epfd < 0) {
		perror("epoll_create Bob");
		goto error;
	}

	sock_to_alice = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock_to_alice < 0) {
		perror("Bob socket to Alice");
		goto sock_error;
	}
	oinfo.sock = sock_to_alice;
	oinfo.user = "Bob";

	ret = connect(sock_to_alice, (struct sockaddr *) &alice_sun,
			sizeof(alice_sun));
	if (ret < 0) {
		perror("connect to Alice");
		goto end;
	}

	/* Add our socket to epoll set. */
	ret = add_sock_to_pollset(epfd, bob_sock,
			EPOLLIN | EPOLLERR | EPOLLHUP);
	if (ret < 0) {
		goto end;
	}

	while (1) {
		int i, timeout = 500, nb_fd;
		struct epoll_event ev[3];
		memset(ev, 0, sizeof(ev));

		/* 
		 * Set random timeout and when we do timeout, use that to send message
		 * to Alice.
		 */
		timeout = (rand() % (timeout_max - 1));

		ret = epoll_wait(epfd, ev, 42, timeout);
		if (ret < 0) {
			perror("epoll_wait Bob");
			goto end;
		}
		nb_fd = ret;

		/* No event thus timeout, send message to Alice. */
		if (nb_fd == 0) {
			(void) send_otr_msg(sock_to_alice, alice_name, bob_name, &oinfo,
					NULL);
			continue;
		}

		for (i = 0; i < nb_fd; i++) {
			int fd;
			uint32_t event;

			fd = ev[i].data.fd;
			event = ev[i].events;

			if (fd == bob_sock) {
				if (event & EPOLLERR) {
					goto end;
				} else if (event & (EPOLLIN | EPOLLHUP)) {
					socklen_t len;
					struct sockaddr_un sun;

					/* Connection from Alice, accept it so we can handle it. */
					sock_from_alice = accept(fd, (struct sockaddr *) &sun,
							&len);
					ret = add_sock_to_pollset(epfd, sock_from_alice,
							EPOLLIN | EPOLLERR | EPOLLHUP);
					if (ret < 0) {
						goto end;
					}
				}
				continue;
			} else if (fd == sock_from_alice) {
				if (event & (EPOLLERR | EPOLLHUP)) {
					goto end;
				} else if (event & EPOLLIN) {
					(void) recv_otr_msg(sock_from_alice, bob_name,
							alice_name, &oinfo);
				}
				continue;
			} else {
				goto end;
			}
		}
	}

end:
	if (sock_from_alice) {
		(void) close(sock_from_alice);
	}
	(void) close(sock_to_alice);
sock_error:
	(void) close(epfd);
error:
	return NULL;
}

static void run(void)
{
	int ret;
	void *status;
	pthread_t alice_th, bob_th;

	ret = pthread_create(&alice_th, NULL, alice_thread, NULL);
	if (ret) {
		fail("pthread_create sender thread failed (errno: %d)", errno);
		goto end;
	}

	ret = pthread_create(&bob_th, NULL, bob_thread, NULL);
	if (ret) {
		fail("pthread_create receiver thread failed (errno: %d)", errno);
		goto exit_receiver;
	}

	(void) pthread_join(bob_th, &status);

exit_receiver:
	(void) pthread_join(alice_th, &status);
end:
	return;
}

/*
 * Load OTR instag using the given opt argument.
 */
static void load_instag(void)
{
	int ret;
	gcry_error_t err;

	ret = access(opt_instag_path, R_OK);
	if (ret < 0) {
		fail("Instag file %s is not readable", opt_instag_path);
		return;
	}

	err = otrl_instag_read(user_state, opt_instag_path);
	OK(err == GPG_ERR_NO_ERROR, "Loading instag from given file");
}

/*
 * Load private key file using the given opt argument.
 */
static void load_key(void)
{
	int ret;
	gcry_error_t err;

	ret = access(opt_key_path, R_OK);
	if (ret < 0) {
		fail("Key file %s is not readable", opt_key_path);
		return;
	}

	err = otrl_privkey_read(user_state, opt_key_path);
	OK(err == GPG_ERR_NO_ERROR, "Loading key from given file");
}

/*
 * Load private key fingerprint file using the given opt argument.
 */
static void load_key_fp(void)
{
	int ret;
	gcry_error_t err;

	ret = access(opt_key_fp_path, R_OK);
	if (ret < 0) {
		fail("Key fingerprints file %s is not readable", opt_key_fp_path);
		return;
	}

	err = otrl_privkey_read_fingerprints(user_state, opt_key_fp_path, NULL,
			NULL);
	OK(err == GPG_ERR_NO_ERROR, "Loading key fingerprints from given file");
}

static int create_unix_socket(const char *pathname,
		struct sockaddr_un *sun)
{
	int sock, ret;

	/* Create both Unix socket. */
	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		ret = -errno;
		perror("Unix socket");
		goto error;
	}

    memset(sun, 0, sizeof(struct sockaddr_un));
	sun->sun_family = AF_UNIX;
	strncpy(sun->sun_path, pathname, sizeof(sun->sun_path));
	sun->sun_path[sizeof(sun->sun_path) - 1] = '\0';

	ret = bind(sock, (struct sockaddr *) sun, sizeof(struct sockaddr_un));
	if (ret < 0) {
		perror("bind unix sock");
		goto error;
	}

	ret = listen(sock, 10);
	if (ret < 0) {
		perror("listen unix sock");
		goto error;
	}

	return sock;
error:
	return ret;
}

/*
 * Bootstrap client by initializing the OTR library and creating an OTR user
 * state.
 *
 * Return 0 on success else a negative value on error.
 */
static int init_client(void)
{
	int ret;

	/* Init libgcrypt threading system. */
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

	/* Init OTR library. */
	OTRL_INIT;
	OK(1, "OTR library initialization done.");

	user_state = otrl_userstate_create();
	OK(user_state, "OTR userstate creation done.");
	if (!user_state) {
		fail("Out of memory on userstate create");
		ret = -ENOMEM;
		goto error;
	}

	/* Seed the prng. */
	srand(time(NULL));

	/* Cleanup Unix socket file before creating them. */
	unlink(unix_sock_alice_path);
	unlink(unix_sock_bob_path);

	alice_sock = create_unix_socket(unix_sock_alice_path, &alice_sun);
	bob_sock = create_unix_socket(unix_sock_bob_path, &bob_sun);
	if (alice_sock < 0 || bob_sock < 0) {
		ret = -EINVAL;
		goto error;
	}

	return 0;

error:
	return ret;
}

static void sighandler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		cleanup();
		break;
	default:
		break;
	}
}

/*
 * main entry point.
 */
int main(int argc, char **argv)
{
	int ret, opt;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		perror("sigemptyset");
		goto error;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;

	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		perror("sigaction");
		goto error;
	}
	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		perror("sigaction");
		goto error;
	}

	while ((opt = getopt_long(argc, argv, "+i:k:f:t:m:d", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i':
			opt_instag_path = strdup(optarg);
			break;
		case 'k':
			opt_key_path = strdup(optarg);
			break;
		case 'f':
			opt_key_fp_path = strdup(optarg);
			break;
		case 't':
			timeout_max = atoi(optarg);
			break;
		case 'm':
			opt_max_num_msg = atoi(optarg);
			break;
		case 'd':
			opt_disconnect = 1;
			break;
		default:
			goto error;
		}
	}

	if (!opt_key_path) {
		fail("No key file, failing");
		goto error;
	}

	plan_no_plan();

	/* Running OTR tests. */
	ret = init_client();
	if (ret < 0) {
		goto error;
	}

	if (opt_instag_path) {
		load_instag();
	}
	if (opt_key_fp_path) {
		load_key_fp();
	}
	load_key();

	run();

	return 0;

error:
	return -1;
}
