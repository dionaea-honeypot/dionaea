/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_CONNECTION_H
#define HAVE_CONNECTION_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdint.h>

//#include <linux/if.h>
#include <ev.h>
#include <glib.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "protocol.h"
#include "refcount.h"
#include "node_info.h"

typedef void (*event_fn)(struct connection *con);

#define SSL_TMP_KEY_RSA_512  (0)
#define SSL_TMP_KEY_RSA_1024 (1)
#define SSL_TMP_KEY_DH_512   (2)
#define SSL_TMP_KEY_DH_1024  (3)
#define SSL_TMP_KEY_MAX      (4)

#define CONOFF(x)							((void *)x - sizeof(struct connection))
#define CONOFF_IO_IN(x)  					((struct connection *)(((void *)x) - offsetof (struct connection, events.io_in)))
#define CONOFF_IO_OUT(x) 					((struct connection *)(((void *)x) - offsetof (struct connection, events.io_out)))
#define CONOFF_LISTEN_TIMEOUT(x) 			((struct connection *)(((void *)x) - offsetof (struct connection, events.listen_timeout)))
#define CONOFF_CONNECTING_TIMEOUT(x) 		((struct connection *)(((void *)x) - offsetof (struct connection, events.connecting_timeout)))
#define CONOFF_SUSTAIN_TIMEOUT(x)			((struct connection *)(((void *)x) - offsetof (struct connection, events.sustain_timeout)))
#define CONOFF_IDLE_TIMEOUT(x) 				((struct connection *)(((void *)x) - offsetof (struct connection, events.idle_timeout)))
#define CONOFF_DNS_TIMEOUT(x) 				((struct connection *)(((void *)x) - offsetof (struct connection, events.dns_timeout)))
#define CONOFF_HANDSHAKE_TIMEOUT(x) 		((struct connection *)(((void *)x) - offsetof (struct connection, events.handshake_timeout)))
#define CONOFF_CLOSE_TIMEOUT(x) 			((struct connection *)(((void *)x) - offsetof (struct connection, events.close_timeout)))
#define CONOFF_RECONNECT_TIMEOUT(x) 		((struct connection *)(((void *)x) - offsetof (struct connection, events.reconnect_timeout)))
#define CONOFF_THROTTLE_IO_IN_TIMEOUT(x) 	((struct connection *)(((void *)x) - offsetof (struct connection, events.throttle_io_in_timeout)))
#define CONOFF_THROTTLE_IO_OUT_TIMEOUT(x) 	((struct connection *)(((void *)x) - offsetof (struct connection, events.throttle_io_out_timeout)))
#define CONOFF_FREE(x)						((struct connection *)(((void *)x) - offsetof (struct connection, events.free)))

struct ev_loop;
struct ev_io;
struct ev_timer;
struct ev_loop;


enum connection_transport
{
	connection_transport_udp,
	connection_transport_tcp,
	connection_transport_tls,
	connection_transport_dtls,
	connection_transport_io,
};

enum connection_type
{
	connection_type_none,
	connection_type_accept,
	connection_type_bind,
	connection_type_connect,
	connection_type_listen,
};

enum connection_state
{
	connection_state_none,
	connection_state_resolve,
	connection_state_connecting,
	connection_state_handshake,
	connection_state_established,
	connection_state_shutdown,
	connection_state_close,
	connection_state_reconnect,
};

struct connection;


struct udp_packet
{
	struct sockaddr_storage from;
	struct sockaddr_storage to;
	GString *data;
};

struct connection_throttle
{
	double max_bytes_per_second;
	double interval_bytes;
	double interval_start;
	double last_throttle;
	double interval_stop;
	double sleep_adjust;
};

struct connection_accounting
{
	double    bytes;
	double    limit;
};

struct connection_stats
{
	struct connection_accounting accounting;
	struct connection_throttle throttle;
};


struct connection_stats_info
{
	struct timeval start;
	struct connection_stats io_in, io_out;
};


struct connection
{
	enum connection_transport trans;
	struct node_info local;
	struct node_info remote;

	enum connection_type type;
	enum connection_state state;

	union
	{
		struct
		{
			GList *io_in;
			GList *io_out;
			union
			{
				struct
				{
					GHashTable *peers;
				}server;
				struct
				{
					struct connection *parent;
				}client;
			}type;
		} udp;

		struct
		{
			GString *io_in;
			GString *io_out;

		} tcp;

		struct
		{
			event_fn ev_read;
			event_fn ev_write;
			void *data;
		} io;

		struct
		{
			const SSL_METHOD      *meth;
			SSL_CTX         *ctx;
			SSL *ssl;

			GString *io_in;
			GString *io_out;
			GString *io_out_again;
			uint32_t io_out_again_size;

			unsigned long ssl_error;
			char ssl_error_string[256];

			void           *pTmpKeys[SSL_TMP_KEY_MAX];
		} tls;
		struct
		{
			const SSL_METHOD	*meth;
			SSL_CTX				*ctx;
			SSL *ssl;
			BIO *reading;
			BIO *writing;
			unsigned long ssl_error;
			char ssl_error_string[256];
			GList *io_out;
			union
			{
				struct
				{
					GHashTable *peers;
#define DTLS_COOKIE_SECRET_LENGTH 16
					unsigned char cookie_secret[DTLS_COOKIE_SECRET_LENGTH];
				}server;
				struct
				{
					struct connection *parent;
					int flags;
#define DTLS_HAS_SEEN_THE_COOKIE (1<<0)
				}client;
			}type;
		} dtls;
	}transport;

	struct connection_stats_info stats;

	struct protocol protocol;


	int socket;

	struct
	{
		struct ev_io io_in;
		struct ev_io io_out;
		struct ev_timer listen_timeout;	// tcp listen
		struct ev_timer connecting_timeout;	// tcp-connect, ssl-connect
		struct ev_timer sustain_timeout; // tcp&ssl (connect&accept)
		struct ev_timer idle_timeout; // tcp&ssl (connect&accept)
		struct ev_timer dns_timeout;
		struct ev_timer handshake_timeout; // ssl connect & accept

		struct ev_timer close_timeout; // ssl connect & accept
		struct ev_timer reconnect_timeout; // reconnect after this period, if 0., directly
		struct ev_timer throttle_io_in_timeout;
		struct ev_timer throttle_io_out_timeout;
		struct ev_timer free;
	}events;

	/**
	 * associate this socket with some specific data
	 * which is not protocol related
	 */
	void *data;

	struct processor_data *processor_data;
	struct refcount refcount;
	unsigned int flags;
};

enum connection_flags
{
	connection_busy_sending = 0,
	connection_busy_close = 1
};

#define connection_flag_set(c, fl)     (c)->flags |= 1 << (fl)
#define connection_flag_toggle(c, fl)  (c)->flags ^= 1 << (fl)
#define connection_flag_unset(c, fl)   (c)->flags &= ~(1 << (fl))
#define connection_flag_isset(c, fl)   ((c)->flags & ( 1 << (fl)))


void init_dh_params(void);
bool mkcert(SSL_CTX *);

void connection_stop(struct connection *con);
const char *connection_strerror(enum connection_error error);
void connection_process(struct connection *con);

struct connection *connection_new(enum connection_transport type);
void connection_free(struct connection *con);
void connection_free_cb(struct ev_loop *loop, struct ev_timer *w, int revents, bool report_incident);
void connection_free_report_cb(EV_P_ struct ev_timer *, int);

bool connection_node_set_local(struct connection *);
bool connection_node_set_remote(struct connection *);

void connection_set_nonblocking(struct connection *con);
void connection_set_blocking(struct connection *con);

bool connection_bind(struct connection* con, const char* addr, uint16_t port, const char* iface_scope);
bool connection_listen(struct connection *con, int len);
void connection_connect(struct connection* con, const char* addr, uint16_t port, const char* iface_scope);
void connection_connect_next_addr(struct connection *con);
void connection_close(struct connection *con);
void connection_close_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void connection_reconnect(struct connection *con);
void connection_established(struct connection *con);

double connection_stats_speed_get(struct connection_stats *throttle_info);
double connection_stats_speed_limit_get(struct connection_stats *throttle_info);
void connection_stats_speed_limit_set(struct connection_stats *throttle_info, double limit);

double connection_stats_accounting_get(struct connection_stats *throttle_info);
double connection_stats_accounting_limit_get(struct connection_stats *throttle_info);
void connection_stats_accounting_limit_set(struct connection_stats *throttle_info, double limit);
bool connection_stats_accounting_limit_exceeded(struct connection_stats *stats);
void connection_throttle_io_in_set(struct connection *con, uint32_t max_bytes_per_second);
void connection_throttle_io_out_set(struct connection *con, uint32_t max_bytes_per_second);

int connection_throttle(struct connection *con, struct connection_throttle *thr);
void connection_throttle_update(struct connection *con, struct connection_throttle *thr, int bytes);

void connection_throttle_io_in_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void connection_throttle_io_out_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void connection_throttle_reset(struct connection_throttle *thr);

void connection_send(struct connection *con, const void *data, uint32_t size);
void connection_send_string(struct connection *con, const char *str);

void connection_set_type(struct connection *con, enum connection_type type);
void connection_set_state(struct connection *con, enum connection_state state);

void connection_listen_timeout_set(struct connection *con, double timeout_interval_nms);
double connection_listen_timeout_get(struct connection *con);
void connection_listen_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

void connection_sustain_timeout_set(struct connection *con, double timeout_interval_ms);
double connection_sustain_timeout_get(struct connection *con);
void connection_sustain_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

void connection_idle_timeout_set(struct connection *con, double timeout_interval_ms);
double connection_idle_timeout_get(struct connection *con);
void connection_idle_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

void connection_handshake_timeout_set(struct connection *con, double timeout_interval_ms);
double connection_handshake_timeout_get(struct connection *con);

void connection_connecting_timeout_set(struct connection *con, double timeout_interval_ms);
double connection_connecting_timeout_get(struct connection *con);
void connection_connecting_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

void connection_reconnect_timeout_set(struct connection *con, double timeout_interval_ms);
double connection_reconnect_timeout_get(struct connection *con);
void connection_reconnect_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

void connection_disconnect(struct connection *con);

void connection_tcp_accept_cb (struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tcp_connecting_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tcp_io_in_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tcp_io_out_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tcp_disconnect(struct connection *con);

void connection_udp_io_in_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_udp_io_out_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_udp_disconnect(struct connection *con);
ssize_t recvfromto(int, void *, size_t, int, const struct sockaddr *, socklen_t *, const struct sockaddr *, socklen_t *);
void _connection_send_packets(struct connection *, int, GList **);

void connection_tls_accept_cb (struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tls_handshake_again_cb (struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tls_handshake_again_timeout_cb (struct ev_loop *loop, struct ev_timer *w, int revents);
void connection_tls_connecting_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tls_io_in_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tls_io_out_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tls_shutdown_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_tls_disconnect(struct connection *con);
void connection_tls_error(struct connection *con);
bool connection_tls_set_certificate(struct connection *con, const char *path);
bool connection_tls_set_key(struct connection *con, const char *path, int type);
bool connection_tls_mkcert(struct connection *con);


guint connection_addrs_hash(gconstpointer key);
gboolean connection_addrs_cmp(gconstpointer a, gconstpointer b);
int dtls_generate_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
int dtls_verify_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int cookie_len);
#else
int dtls_verify_cookie_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);
#endif
void connection_dtls_accept_again(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_dtls_connect_again(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_dtls_io_in_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_dtls_io_out_cb(struct ev_loop *loop, struct ev_io *w, int revents);
void connection_dtls_error(struct connection *con);
void connection_dtls_drain_bio(struct connection *con);
bool connection_dtls_mkcert(struct connection *con);


bool connection_transport_from_string(const char *type_str, enum connection_transport *type);
const char *connection_transport_to_string(enum connection_transport trans);

const char *connection_state_to_string(enum connection_state state);
const char *connection_type_to_string(enum connection_type type);

struct dns_ctx;
void connection_connect_resolve(struct connection *con);
void connection_connect_resolve_action(struct connection *con);
void connection_dns_resolve_cancel(struct connection *con);
void connection_connect_resolve_a_cb(struct dns_ctx *ctx, void *result, void *data);
void connection_connect_resolve_aaaa_cb(struct dns_ctx *ctx, void *result, void *data);

void connection_protocol_set(struct connection *con, struct protocol *proto);
void *connection_protocol_ctx_get(struct connection *con);
void connection_protocol_ctx_set(struct connection *con, void *data);
bool bind_local(struct connection *con);

int connection_ref(struct connection *con);
int connection_unref(struct connection *con);
#endif
