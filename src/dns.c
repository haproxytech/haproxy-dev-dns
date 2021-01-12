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
#include <haproxy/ring.h>
#include <haproxy/stream.h>
#include <haproxy/stream_interface.h>

static THREAD_LOCAL char tmp_dns_buf[DNS_TCP_MSG_MAX_SIZE];

DECLARE_STATIC_POOL(dns_session_pool, "dns_session", sizeof(struct dns_session));
DECLARE_STATIC_POOL(dns_query_pool, "dns_query", sizeof(struct dns_query));

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
	int ret = -1;

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
	else if (ns->stream) {
		struct ist myist;

		myist.ptr = buf;
		myist.len = len;
                ret = ring_write(ns->stream->ring_req, DNS_TCP_MSG_MAX_SIZE, NULL, 0, &myist, 1);
		if (ret) {
			task_wakeup(ns->stream->task_req, TASK_WOKEN_MSG);
			return ret;
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
	else if (ns->stream) {
		struct dns_stream_server *dss = ns->stream;
		struct ring *ring = dss->ring_rsp;
		struct buffer *buf = &ring->buf;
		uint64_t msg_len;
		size_t len, cnt, ofs;

		HA_SPIN_LOCK(DNS_LOCK, &dss->lock);

		ofs = dss->ofs_rsp;

		HA_RWLOCK_RDLOCK(DNS_LOCK, &ring->lock);

		/* explanation for the initialization below: it would be better to do
		 * this in the parsing function but this would occasionally result in
		 * dropped events because we'd take a reference on the oldest message
		 * and keep it while being scheduled. Thus instead let's take it the
		 * first time we enter here so that we have a chance to pass many
		 * existing messages before grabbing a reference to a location. This
		 * value cannot be produced after initialization.
		 */
		if (unlikely(ofs == ~0)) {
			ofs = 0;

			HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
			ofs += ring->ofs;
		}

		/* we were already there, adjust the offset to be relative to
		 * the buffer's head and remove us from the counter.
		 */
		ofs -= ring->ofs;
		BUG_ON(ofs >= buf->size);
		HA_ATOMIC_SUB(b_peek(buf, ofs), 1);

		if (ofs + 1 >= b_data(buf)) {
			HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
			ofs += ring->ofs;
			dss->ofs_rsp= ofs;
			HA_RWLOCK_RDUNLOCK(DNS_LOCK, &ring->lock);
			HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
			return 0;
		}

		cnt = 1;
		len = b_peek_varint(buf, ofs + cnt, &msg_len);
		if (!len) {
			HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
			ofs += ring->ofs;
			dss->ofs_rsp= ofs;
			HA_RWLOCK_RDUNLOCK(DNS_LOCK, &ring->lock);
			HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
			return 0;
		}

		cnt += len;
		BUG_ON(msg_len + ofs + cnt + 1 > b_data(buf));

		ret = b_getblk(buf, data, msg_len < size ? msg_len : size, ofs + cnt);

		ofs += cnt + ret;
		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
		dss->ofs_rsp= ofs;
		HA_RWLOCK_RDUNLOCK(DNS_LOCK, &ring->lock);
		HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
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

/*
 * IO Handler to handle message push to dns tcp server
 */
static void dns_session_io_handler(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct dns_session *ds = appctx->ctx.sft.ptr;
	struct ring *ring = &ds->ring;
	struct buffer *buf = &ring->buf;
	uint64_t msg_len;
	int available_room;
	size_t len, cnt, ofs;
	int ret = 0;

	/* if stopping was requested, close immediately */
	if (unlikely(stopping))
		goto close;

	/* for rex because it seems reset to timeout
	 * and we don't want expire on this case
	 * with a syslog server
	 */
	si_oc(si)->rex = TICK_ETERNITY;
	/* rto should not change but it seems the case */
	si_oc(si)->rto = TICK_ETERNITY;

	/* an error was detected */
	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		goto close;

	/* con closed by server side */
	if ((si_oc(si)->flags & CF_SHUTW))
		goto close;

	/* if the connection is not established, inform the stream that we want
	 * to be notified whenever the connection completes.
	 */
	if (si_opposite(si)->state < SI_ST_EST) {
		si_cant_get(si);
		si_rx_conn_blk(si);
		si_rx_endp_more(si);
		return;
	}

	HA_SPIN_LOCK(DNS_LOCK, &ds->lock);
	if (appctx != ds->appctx) {
		HA_SPIN_UNLOCK(DNS_LOCK, &ds->lock);
		goto close;
	}
	ofs = ds->ofs;

	HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &ring->lock);
	LIST_DEL_INIT(&appctx->wait_entry);
	HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);

	HA_RWLOCK_RDLOCK(LOGSRV_LOCK, &ring->lock);

	/* explanation for the initialization below: it would be better to do
	 * this in the parsing function but this would occasionally result in
	 * dropped events because we'd take a reference on the oldest message
	 * and keep it while being scheduled. Thus instead let's take it the
	 * first time we enter here so that we have a chance to pass many
	 * existing messages before grabbing a reference to a location. This
	 * value cannot be produced after initialization.
	 */
	if (unlikely(ofs == ~0)) {
		ofs = 0;

		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
	}

	/* in this loop, ofs always points to the counter byte that precedes
	 * the message so that we can take our reference there if we have to
	 * stop before the end (ret=0).
	 */
	if (si_opposite(si)->state == SI_ST_EST) {
		/* we were already there, adjust the offset to be relative to
		 * the buffer's head and remove us from the counter.
		 */
		ofs -= ring->ofs;
		BUG_ON(ofs >= buf->size);
		HA_ATOMIC_SUB(b_peek(buf, ofs), 1);

		ret = 1;
		while (ofs + 1 < b_data(buf)) {
			struct dns_query *query;
			uint16_t original_qid;
			uint16_t new_qid;

			cnt = 1;
			len = b_peek_varint(buf, ofs + cnt, &msg_len);
			if (!len)
				break;
			cnt += len;
			BUG_ON(msg_len + ofs + cnt + 1 > b_data(buf));

			/* retrieve available room on output channel */
			available_room = channel_recv_max(si_ic(si));

			/* tx_msg_offset null means we are at the start of a new message */
			if (!ds->tx_msg_offset) {
				uint16_t slen;

				/* check if there is enough room to put message len and query id */
				if (available_room < sizeof(slen) + sizeof(new_qid)) {
					si_rx_room_blk(si);
					ret = 0;
					break;
				}

				/* put msg len into then channel */
				slen = (uint16_t)msg_len;
				slen = htons(slen);
				ci_putblk(si_ic(si), (char *)&slen, sizeof(slen));
				available_room -= sizeof(slen);

				/* backup original query id */
				len = b_getblk(buf, (char *)&original_qid, sizeof(original_qid), ofs + cnt);
				/* generates new query id */
				new_qid = ++ds->query_counter;
				new_qid = htons(new_qid);

				/* put new query id into the channel */
				ci_putblk(si_ic(si), (char *)&new_qid, sizeof(new_qid));
				available_room -= sizeof(new_qid);

				/* keep query id mapping */
				query = pool_alloc(dns_query_pool);
				if (query) {
					query->qid.key = new_qid;
					query->original_qid = original_qid;
					eb32_insert(&ds->query_ids, &query->qid);
				}

				/* update the tx_offset to handle output in 16k streams */
				ds->tx_msg_offset = sizeof(original_qid);

			}

			/* check if it remains available room on output chan */
			if (unlikely(!available_room)) {
				si_rx_room_blk(si);
				ret = 0;
				break;
			}

			chunk_reset(&trash);
			if ((msg_len - ds->tx_msg_offset) > available_room) {
				/* remaining msg data is too large to be written in output channel at one time */

				len = b_getblk(buf, trash.area, available_room, ofs + cnt + ds->tx_msg_offset);

				/* update offset to complete mesg forwarding later */
				ds->tx_msg_offset += len;
			}
			else {
				/* remaining msg data can be written in output channel at one time */
				len = b_getblk(buf, trash.area, msg_len - ds->tx_msg_offset, ofs + cnt + ds->tx_msg_offset);

				/* reset tx_msg_offset to mark forward fully processed */
				ds->tx_msg_offset = 0;
			}
			trash.data += len;

			ci_putchk(si_ic(si), &trash);

			if (ds->tx_msg_offset) {
				/* msg was not fully processed, we must aware to drain pending data */

				si_rx_room_blk(si);
				ret = 0;
				break;
			}
			ds->queued_slots--;
			/* switch to next message */
			ofs += cnt + msg_len;
		}

		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
		ds->ofs = ofs;
	}
	HA_RWLOCK_RDUNLOCK(LOGSRV_LOCK, &ring->lock);

	if (ret) {
		/* let's be woken up once new data arrive */
		HA_RWLOCK_WRLOCK(LOGSRV_LOCK, &ring->lock);
		LIST_ADDQ(&ring->waiters, &appctx->wait_entry);
		HA_RWLOCK_WRUNLOCK(LOGSRV_LOCK, &ring->lock);
		si_rx_endp_done(si);
	}

	while (1) {
		uint16_t query_id;
		struct eb32_node *eb;
		struct dns_query *query;
		int getblock;

		if (ds->rx_msg.len && ds->rx_msg.len == ds->rx_msg.offset) {
			struct ist myist;

			myist.ptr = ds->rx_msg.buf;
			myist.len = ds->rx_msg.len;
			if (ring_write(ds->dss->ring_rsp, DNS_TCP_MSG_MAX_SIZE, NULL, 0, &myist, 1) <= 0) {
				/* no enough room into rx ring, we retry later */
				break;
			}
			ds->rx_msg.len = ds->rx_msg.offset = 0;

			/* we need to lock dss, but we dont want
			 * dead lock so we firstly release
			 * dns_session lock */
			HA_SPIN_UNLOCK(DNS_LOCK, &ds->lock);

			/* we lock both dss and session lock */
			HA_SPIN_LOCK(DNS_LOCK, &ds->dss->lock);
			HA_SPIN_LOCK(DNS_LOCK, &ds->lock);

			/* update used slots */
			ds->used_slots--;
			LIST_DEL(&ds->list);
			if (ds->used_slots)
				LIST_ADD(&ds->dss->actv_sess, &ds->list);
			else
				LIST_ADDQ(&ds->dss->actv_sess, &ds->list);

			/* awake task handling the response */
			task_wakeup(ds->dss->task_rsp, TASK_WOKEN_INIT);

			/* we can release dss but we keep lock on session
		 	 * until the end */
			HA_SPIN_UNLOCK(DNS_LOCK, &ds->dss->lock);
		}

		if (co_data(si_oc(si)) < 2)
			break;

		co_getblk(si_oc(si), (char *)&msg_len, 2, 0);

		co_skip(si_oc(si), 2);

		ds->rx_msg.len = ntohs(msg_len);

		if (co_data(si_oc(si)) + ds->rx_msg.offset < ds->rx_msg.len) {
			/* message only partially available */
			co_getblk(si_oc(si), ds->rx_msg.buf + ds->rx_msg.offset, co_data(si_oc(si)), 0);
			ds->rx_msg.offset += co_data(si_oc(si));
			co_skip(si_oc(si), co_data(si_oc(si)));
			break;
		}
		else {
			/* message will be fully available */
			co_getblk(si_oc(si), ds->rx_msg.buf + ds->rx_msg.offset, ds->rx_msg.len - ds->rx_msg.offset, 0);
			ds->rx_msg.offset = ds->rx_msg.len;
			co_skip(si_oc(si), ds->rx_msg.len - ds->rx_msg.offset);

			/* remap query id to original */
			memcpy(&query_id, ds->rx_msg.buf, sizeof(query_id));
			eb = eb32_lookup(&ds->query_ids, query_id);
			if (!eb) {
				/* reset len and offset to mark message as consumed */
				ds->rx_msg.len = ds->rx_msg.offset = 0;
				continue;
			}
			query = eb32_entry(eb, struct dns_query, qid);
			eb32_delete(&query->qid);
			memcpy(ds->rx_msg.buf, &query->original_qid, sizeof(query->original_qid));
			pool_free(dns_query_pool, query);
		}	
	}
incomplete:
	HA_SPIN_UNLOCK(DNS_LOCK, &ds->lock);
	return;
close:
	si_shutw(si);
	si_shutr(si);
	si_ic(si)->flags |= CF_READ_NULL;
}


/*
 * Function to release a DNS tcp session
 */
static void dns_session_release(struct appctx *appctx)
{
	struct dns_session *ds = appctx->ctx.sft.ptr;

	if (!ds)
		return;

	HA_SPIN_LOCK(DNS_LOCK, &ds->dss->lock);
	HA_SPIN_LOCK(DNS_LOCK, &ds->lock);
	if (ds->appctx == appctx) {
		/* We do not call ring_appctx_detach here
		 * because we want to keep readers couters
		 * to retry a con with a different appctx*/
		HA_RWLOCK_WRLOCK(DNS_LOCK, &ds->ring.lock);
		LIST_DEL_INIT(&appctx->wait_entry);
		HA_RWLOCK_WRUNLOCK(DNS_LOCK, &ds->ring.lock);
		ds->appctx = NULL;
		LIST_DEL(&ds->list);
		LIST_ADD(&ds->dss->rlse_sess, &ds->list);
		task_wakeup(ds->dss->task_req, TASK_WOKEN_MSG);
	}
	HA_SPIN_UNLOCK(DNS_LOCK, &ds->lock);
	HA_SPIN_UNLOCK(DNS_LOCK, &ds->dss->lock);
}

/* DNS tcp session applet */
static struct applet dns_session_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<STRMDNS>", /* used for logging */
	.fct = dns_session_io_handler,
	.release = dns_session_release,
};

/*
 * Function used to create an appctx for a DNS session
 */
static struct appctx *dns_session_create(struct dns_session *ds)
{
	struct appctx *appctx;
	struct session *sess;
	struct stream *s;
	struct applet *applet = &dns_session_applet;

	appctx = appctx_new(applet, tid_bit);
	if (!appctx)
		goto out_close;

	appctx->ctx.sft.ptr = (void *)ds;

	sess = session_new(ds->dss->srv->proxy, NULL, &appctx->obj_type);
	if (!sess) {
		ha_alert("out of memory in peer_session_create().\n");
		goto out_free_appctx;
	}

	if ((s = stream_new(sess, &appctx->obj_type, &BUF_NULL)) == NULL) {
		ha_alert("Failed to initialize stream in peer_session_create().\n");
		goto out_free_sess;
	}


	s->target = &ds->dss->srv->obj_type;
	if (!sockaddr_alloc(&s->target_addr, &ds->dss->srv->addr, sizeof(ds->dss->srv->addr)))
		goto out_free_strm;
	s->flags = SF_ASSIGNED|SF_ADDR_SET;
	s->si[1].flags |= SI_FL_NOLINGER;

	s->do_log = NULL;
	s->uniq_id = 0;

	s->res.flags |= CF_READ_DONTWAIT;
	/* for rto and rex to eternity to not expire on idle recv:
	 * We are using a syslog server.
	 */
	s->res.rto = TICK_ETERNITY;
	s->res.rex = TICK_ETERNITY;
	ds->appctx = appctx;
	task_wakeup(s->task, TASK_WOKEN_INIT);
	return appctx;

	/* Error unrolling */
 out_free_strm:
	LIST_DEL(&s->list);
	pool_free(pool_head_stream, s);
 out_free_sess:
	session_free(sess);
 out_free_appctx:
	appctx_free(appctx);
 out_close:
	return NULL;
}

/*
 * Task used to consume pending messages from nameserver ring
 * and forward them to dns_session ring.
 * Note: If no slot found a new dns_session is allocated
 */
static struct task *dns_process_req(struct task *t, void *context, unsigned short state)
{
	struct dns_nameserver *ns = (struct dns_nameserver *)context;
	struct dns_stream_server *dss = ns->stream;
	struct ring *ring = dss->ring_req;
	struct buffer *buf = &ring->buf;
	uint64_t msg_len;
	size_t len, cnt, ofs;
	struct dns_session *ds, *ads;
	HA_SPIN_LOCK(DNS_LOCK, &dss->lock);

	list_for_each_entry_safe(ds, ads, &dss->rlse_sess, list) {
		LIST_DEL(&ds->list);
		HA_SPIN_LOCK(DNS_LOCK, &ds->lock);
		if (ds->queued_slots) {
			/* there is pending queued messages
			 * We try a re-connect
			 */
			ds->rx_msg.offset = ds->rx_msg.len = 0;
			/* here the ofs and the attached counter
			 * are keep unchanged
			*/
			ds->appctx = dns_session_create(ds);
			ds->used_slots = ds->queued_slots;
			if (ds->used_slots >= DNS_STREAM_MAX_SLOTS)
				LIST_ADD(&dss->full_sess, &ds->list);
			else
				LIST_ADD(&dss->actv_sess, &ds->list);
			HA_SPIN_UNLOCK(DNS_LOCK, &ds->lock);
			continue;
		}
		/* session has no pending messages, it may be an idle
		 * timeout session
		 */
		HA_SPIN_UNLOCK(DNS_LOCK, &ds->lock);
		pool_free(dns_session_pool, ds);

	}
	ofs = dss->ofs_req;

	HA_RWLOCK_RDLOCK(DNS_LOCK, &ring->lock);

	/* explanation for the initialization below: it would be better to do
	 * this in the parsing function but this would occasionally result in
	 * dropped events because we'd take a reference on the oldest message
	 * and keep it while being scheduled. Thus instead let's take it the
	 * first time we enter here so that we have a chance to pass many
	 * existing messages before grabbing a reference to a location. This
	 * value cannot be produced after initialization.
	 */
	if (unlikely(ofs == ~0)) {
		ofs = 0;
		HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
		ofs += ring->ofs;
	}

	/* we were already there, adjust the offset to be relative to
	 * the buffer's head and remove us from the counter.
	 */
	ofs -= ring->ofs;
	BUG_ON(ofs >= buf->size);
	HA_ATOMIC_SUB(b_peek(buf, ofs), 1);

	while (ofs + 1 < b_data(buf)) {
		struct ist myist;

		cnt = 1;
		len = b_peek_varint(buf, ofs + cnt, &msg_len);
		if (!len)
			break;
		cnt += len;
		BUG_ON(msg_len + ofs + cnt + 1 > b_data(buf));
		if (unlikely(msg_len > sizeof(tmp_dns_buf))) {
			/* too large a message to ever fit, let's skip it */
			ofs += cnt + msg_len;
			continue;
		}

		len = b_getblk(buf, tmp_dns_buf, msg_len, ofs + cnt);

		myist.ptr = tmp_dns_buf;
		myist.len = len;

		ads = NULL;
		list_for_each_entry(ds, &dss->actv_sess, list) {
			if (ring_write(&ds->ring, DNS_TCP_MSG_MAX_SIZE, NULL, 0, &myist, 1) > 0) {
				HA_SPIN_LOCK(DNS_LOCK, &ds->lock);
				ds->used_slots++;
				ds->queued_slots++;
				LIST_DEL(&ds->list);
				if (ds->used_slots >= DNS_STREAM_MAX_SLOTS)
					LIST_ADD(&dss->full_sess, &ds->list);
				else
					LIST_ADD(&dss->actv_sess, &ds->list);
				HA_SPIN_UNLOCK(DNS_LOCK, &ds->lock);
				ads = ds;
				break;
			}
		}

		/* we didn't find a session avalaible with large enough room */
		if (!ads) {
			/* allocate a new session */
			ads = pool_alloc(dns_session_pool);
			if (ads) {
				ring_init(&ads->ring, ads->tx_ring_area, sizeof(ads->tx_ring_area));
				ads->ofs = ~0;
				ads->dss = dss;
				ds->rx_msg.offset = ds->rx_msg.len = 0;
				LIST_INIT(&ads->list);
				HA_SPIN_INIT(&ads->lock);
				HA_SPIN_LOCK(DNS_LOCK, &ads->lock);
				ads->appctx = dns_session_create(ads);
				ring_attach(&ads->ring);
				/* ring is empty so this ring_write should never fail */
				ring_write(&ads->ring, DNS_TCP_MSG_MAX_SIZE, NULL, 0, &myist, 1);
				ads->used_slots++;
				ads->queued_slots++;
				LIST_ADD(&dss->actv_sess, &ads->list);
				HA_SPIN_UNLOCK(DNS_LOCK, &ads->lock);
			}
		}

		ofs += cnt + len;
	}

	HA_ATOMIC_ADD(b_peek(buf, ofs), 1);
	ofs += ring->ofs;
	dss->ofs_req = ofs;
	HA_RWLOCK_RDUNLOCK(DNS_LOCK, &ring->lock);


	HA_SPIN_UNLOCK(DNS_LOCK, &dss->lock);
	return t;
}

/*
 * Task used to consume response
 * Note: upper layer callback is called
 */
static struct task *dns_process_rsp(struct task *t, void *context, unsigned short state)
{
	struct dns_nameserver *ns = (struct dns_nameserver *)context;

	ns->process_responses(ns);

	return t;
}

/* Function used to initialize an TCP nameserver */
int dns_stream_init(struct dns_nameserver *ns, struct server *srv)
{
	struct dns_stream_server *dss = NULL;
	int err_code;

        dss = calloc(1, sizeof(*dss));
        if (!dss) {
		ha_alert("memory allocation error initializing dns tcp server '%s'.\n", srv->id);
		         err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	dss->srv = srv;

	dss->ofs_req = ~0; /* init ring offset */
	dss->ring_req = ring_new(1 + 1 + varint_bytes(DNS_TCP_MSG_MAX_SIZE) + DNS_TCP_MSG_MAX_SIZE);
	if (!dss->ring_req) {
		ha_alert("memory allocation error initializing the ring for dns tcp server '%s'.\n", srv->id);
		         err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	/* Create the task associated to the resolver target handling conns */
	if ((dss->task_req = task_new(MAX_THREADS_MASK)) == NULL) {
		ha_alert("memory allocation error initializing the ring for dns tcp server '%s'.\n", srv->id);
		         err_code |= (ERR_ALERT|ERR_ABORT);
		goto out;
	}

	/* Update task's parameters */
	dss->task_req->process = dns_process_req;
	dss->task_req->context = ns;

	/* attach the task as reader */
	if (!ring_attach(dss->ring_req)) {
		/* mark server attached to the ring */
		ha_alert("server '%s' sets too many watchers > 255 on ring.\n", srv->id);
		         err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	dss->ofs_rsp = ~0; /* init ring offset */
	dss->ring_rsp = ring_new(1 + 1 + varint_bytes(DNS_TCP_MSG_MAX_SIZE) + DNS_TCP_MSG_MAX_SIZE);
	if (!dss->ring_rsp) {
		ha_alert("memory allocation error initializing the ring for dns tcp server '%s'.\n", srv->id);
		         err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}
	/* Create the task associated to the resolver target handling conns */
	if ((dss->task_rsp = task_new(MAX_THREADS_MASK)) == NULL) {
		ha_alert("memory allocation error initializing the ring for dns tcp server '%s'.\n", srv->id);
		         err_code |= (ERR_ALERT|ERR_ABORT);
		goto out;
	}

	/* Update task's parameters */
	dss->task_rsp->process = dns_process_rsp;
	dss->task_rsp->context = ns;

	/* attach the task as reader */
	if (!ring_attach(dss->ring_rsp)) {
		/* mark server attached to the ring */
		ha_alert("server '%s' sets too many watchers > 255 on ring.\n", srv->id);
		         err_code |= ERR_ALERT | ERR_FATAL;
		goto out;
	}

	LIST_INIT(&dss->rlse_sess);
	LIST_INIT(&dss->actv_sess);
	LIST_INIT(&dss->full_sess);
	HA_SPIN_INIT(&dss->lock);
	ns->stream = dss;
	return 0;
out:
	if (dss && dss->task_rsp)
		task_destroy(dss->task_rsp);
	if (dss && dss->ring_rsp)
		ring_free(dss->ring_rsp);
	if (dss && dss->task_req)
		task_destroy(dss->task_req);
	if (dss && dss->ring_req)
		ring_free(dss->ring_req);

	free(dss);
	return -1;
}
