/*
 * include/haproxy/dns-t.h
 * This file provides structures and types for DNS.
 *
 * Copyright (C) 2014 Baptiste Assmann <bedis9@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_DNS_T_H
#define _HAPROXY_DNS_T_H

#include <import/eb32tree.h>

#include <haproxy/connection-t.h>
#include <haproxy/dgram-t.h>
#include <haproxy/obj_type-t.h>
#include <haproxy/stats-t.h>
#include <haproxy/task-t.h>
#include <haproxy/thread.h>

/* DNS header size */
#define DNS_HEADER_SIZE  ((int)sizeof(struct dns_header))

/* DNS request or response header structure */
struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));

/* short structure to describe a DNS question */
/* NOTE: big endian structure */
struct dns_question {
	unsigned short qtype;   /* question type */
	unsigned short qclass;  /* query class */
} __attribute__ ((packed));


/* NOTE: big endian structure */
struct dns_additional_record {
	uint8_t  name;             /* domain name, must be 0 (RFC 6891) */
	uint16_t type;             /* record type DNS_RTYPE_OPT (41) */
	uint16_t udp_payload_size; /* maximum size accepted for the response */
	uint32_t extension;        /* extended rcode and flags, not used for now */
	uint16_t data_length;      /* data length */
/* as of today, we don't support yet edns options, that said I already put a
 * placeholder here for this purpose. We may need to define a dns_option_record
 * structure which itself should point to different type of data, based on the
 * extension set (client subnet, tcp keepalive, etc...)*/
} __attribute__ ((packed));

struct dns_counters {
	char *id;
	char *pid;
	long long sent;         /* - queries sent */
	long long snd_error;    /* - sending errors */
	long long valid;        /* - valid response */
	long long update;       /* - valid response used to update server's IP */
	long long cname;        /* - CNAME response requiring new resolution */
	long long cname_error;  /* - error when resolving CNAMEs */
	long long any_err;      /* - void response (usually because ANY qtype) */
	long long nx;           /* - NX response */
	long long timeout;      /* - queries which reached timeout */
	long long refused;      /* - queries refused */
	long long other;        /* - other type of response */
	long long invalid;      /* - malformed DNS response */
	long long too_big;      /* - too big response */
	long long outdated;     /* - outdated response (server slower than the other ones) */
	long long truncated;    /* - truncated response */;
};

/* Structure describing a name server used during name resolution.
 * A name server belongs to a resolvers section.
 */
struct dns_nameserver {
	char *id;                       /* nameserver unique identifier */
	void *parent;
	struct {
		const char *file;       /* file where the section appears */
		int         line;       /* line where the section appears */
	} conf;                         /* config information */

	int (*process_responses)(struct dns_nameserver *ns); /* callback used to process responses */
	struct dgram_conn      *dgram;  /* transport layer */

	EXTRA_COUNTERS(extra_counters);
	struct dns_counters *counters;

	struct list list;               /* nameserver chained list */
};

#endif /* _HAPROXY_DNS_T_H */
