/*
 * include/haproxy/dns.h
 * This file provides functions related to DNS protocol
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

#ifndef _HAPROXY_DNS_H
#define _HAPROXY_DNS_H

#include <haproxy/action-t.h>
#include <haproxy/dns-t.h>

extern struct list sec_resolvers;
extern unsigned int resolv_failed_resolutions;

struct resolvers *find_resolvers_by_id(const char *id);
struct resolv_srvrq *find_srvrq_by_name(const char *name, struct proxy *px);
struct resolv_srvrq *new_resolv_srvrq(struct server *srv, char *fqdn);

int resolv_str_to_dn_label(const char *str, int str_len, char *dn, int dn_len);
int resolv_dn_label_to_str(const char *dn, int dn_len, char *str, int str_len);

int resolv_hostname_validation(const char *string, char **err);
int resolv_get_ip_from_response(struct resolv_response *r_res,
                             struct resolv_options *resolv_opts, void *currentip,
                             short currentip_sin_family,
                             void **newip, short *newip_sin_family,
                             void *owner);

int resolv_link_resolution(void *requester, int requester_type, int requester_locked);
void resolv_unlink_resolution(struct resolv_requester *requester);
void resolv_trigger_resolution(struct resolv_requester *requester);
enum act_parse_ret resolv_parse_do_resolve(const char **args, int *orig_arg, struct proxy *px, struct act_rule *rule, char **err);
int check_action_do_resolve(struct act_rule *rule, struct proxy *px, char **err);

int stats_dump_dns(struct stream_interface *si,
                   struct field *stats, size_t stats_count,
                   struct list *stat_modules);
void dns_stats_clear_counters(int clrall, struct list *stat_modules);
int dns_allocate_counters(struct list *stat_modules);
int dns_dgram_init(struct dns_nameserver *ns, struct sockaddr_storage *sk);

#endif // _HAPROXY_DNS_H
