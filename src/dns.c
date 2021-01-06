/*
 * Name server resolution
 *
 * Copyright 2020 Haproxy Technologies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

#include <haproxy/action.h>
#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/channel.h>
#include <haproxy/check.h>
#include <haproxy/cli.h>
#include <haproxy/dgram.h>
#include <haproxy/dns.h>
#include <haproxy/errors.h>
#include <haproxy/fd.h>
#include <haproxy/log.h>


/* Opens an UDP socket on the namesaver's IP/Port, if required. Returns 0 on
 * success, -1 otherwise.
 */
static int dns_connect_nameserver(struct dns_nameserver *ns)
{
	if (ns->dgram) {
		struct dgram_conn *dgram = ns->dgram;
		int fd;

		/* Already connected */
		if (dgram->t.sock.fd != -1)
			return 0;

		/* Create an UDP socket and connect it on the nameserver's IP/Port */
		if ((fd = socket(ns->dgram->addr.to.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			send_log(NULL, LOG_WARNING,
				 "DNS : resolvers '%s': can't create socket for nameserver '%s'.\n",
				 ns->counters->pid, ns->id);
			return -1;
		}
		if (connect(fd, (struct sockaddr*)&ns->dgram->addr.to, get_addr_len(&ns->dgram->addr.to)) == -1) {
			send_log(NULL, LOG_WARNING,
				 "DNS : resolvers '%s': can't connect socket for nameserver '%s'.\n",
				 ns->counters->id, ns->id);
			close(fd);
			return -1;
		}

		/* Make the socket non blocking */
		fcntl(fd, F_SETFL, O_NONBLOCK);

		/* Add the fd in the fd list and update its parameters */
		dgram->t.sock.fd = fd;
		fd_insert(fd, dgram, dgram_fd_handler, MAX_THREADS_MASK);
		fd_want_recv(fd);
	}
	return 0;
}

/* Sends a message to a name server
 * It returns message length on success
 * or -1 in error case
 * 0 is returned in case of EAGAIN 
 */
int dns_send_nameserver(struct dns_nameserver *ns, void *buf, size_t len)
{
	int ret;

	if (ns->dgram) {
		int fd = ns->dgram->t.sock.fd;

		if (fd == -1) {
			if (dns_connect_nameserver(ns) == -1)
				return -1;
			fd = ns->dgram->t.sock.fd;
		}

		ret = send(fd, buf, len, 0);
		if (ret < 0) {
			if (errno == EAGAIN)
				return 0;
			
			fd_delete(fd);
			close(fd);
			ns->dgram->t.sock.fd = -1;
		}
	}

	return ret;
}

/* Receives a dns message
 * Returns message length
 * 0 is returned if no more message available
 * -1 in error case
 */
ssize_t dns_recv_nameserver(struct dns_nameserver *ns, void *data, size_t size)
{
        ssize_t ret = -1;

	if (ns->dgram) {
		int fd = ns->dgram->t.sock.fd;

		if (fd == -1)
			return -1;

		if ((ret = recv(fd, data, size, 0)) < 0) {
			if (errno == EAGAIN)
				return 0;
			fd_delete(fd);
			close(fd);
			ns->dgram->t.sock.fd = -1;
			return -1;
		}
	}

	return ret;
}

static void dns_resolve_recv(struct dgram_conn *dgram)
{
	struct dns_nameserver *ns;
	struct resolvers  *resolvers;
	struct resolv_resolution *res;
	struct resolv_query_item *query;
	unsigned char  buf[DNS_MAX_UDP_MESSAGE + 1];
	unsigned char *bufend;
	int fd, buflen, dns_resp;
	int max_answer_records;
	unsigned short query_id;
	struct eb32_node *eb;
	struct resolv_requester *req;

	fd = dgram->t.sock.fd;

	/* check if ready for reading */
	if (!fd_recv_ready(fd))
		return;

	/* no need to go further if we can't retrieve the nameserver */
	if ((ns = dgram->owner) == NULL) {
		_HA_ATOMIC_AND(&fdtab[fd].ev, ~(FD_POLL_HUP|FD_POLL_ERR));
		fd_stop_recv(fd);
		return;
	}

	if (ns->process_responses(ns) <= 0) {
		/* FIXME : for now we consider EAGAIN only, but at
		 * least we purge sticky errors that would cause us to
		 * be called in loops.
		 */
		_HA_ATOMIC_AND(&fdtab[fd].ev, ~(FD_POLL_HUP|FD_POLL_ERR));
		fd_cant_recv(fd);
	}
}

/* Called when a dns network socket is ready to send data */
static void dns_resolve_send(struct dgram_conn *dgram)
{
	int fd;

	fd = dgram->t.sock.fd;

	/* check if ready for sending */
	if (!fd_send_ready(fd))
		return;

	/* we don't want/need to be waked up any more for sending */
	fd_stop_send(fd);

}

/* proto_udp callback functions for a DNS resolution */
struct dgram_data_cb dns_dgram_cb = {
	.recv = dns_resolve_recv,
	.send = dns_resolve_send,
};

int dns_dgram_init(struct dns_nameserver *ns, struct sockaddr_storage *sk)
{
	struct dgram_conn *dgram;

	 if ((dgram = calloc(1, sizeof(*dgram))) == NULL)
		return -1;

	/* Leave dgram partially initialized, no FD attached for
	 * now. */
	dgram->owner     = ns;
	dgram->data      = &dns_dgram_cb;
	dgram->t.sock.fd = -1;
	dgram->addr.to = *sk;
	ns->dgram = dgram;

	return 0;
}

