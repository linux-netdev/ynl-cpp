/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_RT_ROUTE_GEN_H
#define _LINUX_RT_ROUTE_GEN_H

#include <linux/types.h>
#include <stdlib.h>
#include <string.h>

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <array>

#include "ynl.hpp"

#include <linux/rtnetlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_rt_route_family();

/* Enums */
std::string_view rt_route_op_str(int op);
std::string_view rt_route_rtm_type_str(int value);

/* Common nested types */
struct rt_route_metrics {
	std::optional<__u32> lock;
	std::optional<__u32> mtu;
	std::optional<__u32> window;
	std::optional<__u32> rtt;
	std::optional<__u32> rttvar;
	std::optional<__u32> ssthresh;
	std::optional<__u32> cwnd;
	std::optional<__u32> advmss;
	std::optional<__u32> reordering;
	std::optional<__u32> hoplimit;
	std::optional<__u32> initcwnd;
	std::optional<__u32> features;
	std::optional<__u32> rto_min;
	std::optional<__u32> initrwnd;
	std::optional<__u32> quickack;
	std::string cc_algo;
	std::optional<__u32> fastopen_no_cookie;
};

/* ============== RTM_GETROUTE ============== */
/* RTM_GETROUTE - do */
struct rt_route_getroute_req {
	__u16 _nlmsg_flags;

	struct rtmsg _hdr;

	std::vector<__u8> src;
	std::vector<__u8> dst;
	std::optional<__u32> iif;
	std::optional<__u32> oif;
	std::optional<__u8> ip_proto;
	std::optional<__u16> sport;
	std::optional<__u16> dport;
	std::optional<__u32> mark;
	std::optional<__u32> uid;
	std::optional<__u32> flowlabel /* big-endian */;
};

struct rt_route_getroute_rsp {
	struct rtmsg _hdr;

	std::vector<__u8> dst;
	std::vector<__u8> src;
	std::optional<__u32> iif;
	std::optional<__u32> oif;
	std::vector<__u8> gateway;
	std::optional<__u32> priority;
	std::vector<__u8> prefsrc;
	std::optional<rt_route_metrics> metrics;
	std::vector<__u8> multipath;
	std::optional<__u32> flow;
	std::optional<struct rta_cacheinfo> cacheinfo;
	std::optional<__u32> table;
	std::optional<__u32> mark;
	std::vector<__u8> mfc_stats;
	std::vector<__u8> via;
	std::vector<__u8> newdst;
	std::optional<__u8> pref;
	std::optional<__u16> encap_type;
	std::vector<__u8> encap;
	std::optional<__u32> expires;
	std::vector<__u8> pad;
	std::optional<__u32> uid;
	std::optional<__u8> ttl_propagate;
	std::optional<__u8> ip_proto;
	std::optional<__u16> sport;
	std::optional<__u16> dport;
	std::optional<__u32> nh_id;
	std::optional<__u32> flowlabel /* big-endian */;
};

/*
 * Dump route information.
 */
std::unique_ptr<rt_route_getroute_rsp>
rt_route_getroute(ynl_cpp::ynl_socket& ys, rt_route_getroute_req& req);

/* RTM_GETROUTE - dump */
struct rt_route_getroute_req_dump {
	struct rtmsg _hdr;
};

struct rt_route_getroute_list {
	std::list<rt_route_getroute_rsp> objs;
};

std::unique_ptr<rt_route_getroute_list>
rt_route_getroute_dump(ynl_cpp::ynl_socket& ys,
		       rt_route_getroute_req_dump& req);

/* ============== RTM_NEWROUTE ============== */
/* RTM_NEWROUTE - do */
struct rt_route_newroute_req {
	__u16 _nlmsg_flags;

	struct rtmsg _hdr;

	std::vector<__u8> dst;
	std::vector<__u8> src;
	std::optional<__u32> iif;
	std::optional<__u32> oif;
	std::vector<__u8> gateway;
	std::optional<__u32> priority;
	std::vector<__u8> prefsrc;
	std::optional<rt_route_metrics> metrics;
	std::vector<__u8> multipath;
	std::optional<__u32> flow;
	std::optional<struct rta_cacheinfo> cacheinfo;
	std::optional<__u32> table;
	std::optional<__u32> mark;
	std::vector<__u8> mfc_stats;
	std::vector<__u8> via;
	std::vector<__u8> newdst;
	std::optional<__u8> pref;
	std::optional<__u16> encap_type;
	std::vector<__u8> encap;
	std::optional<__u32> expires;
	std::vector<__u8> pad;
	std::optional<__u32> uid;
	std::optional<__u8> ttl_propagate;
	std::optional<__u8> ip_proto;
	std::optional<__u16> sport;
	std::optional<__u16> dport;
	std::optional<__u32> nh_id;
	std::optional<__u32> flowlabel /* big-endian */;
};

/*
 * Create a new route
 */
int rt_route_newroute(ynl_cpp::ynl_socket& ys, rt_route_newroute_req& req);

/* ============== RTM_DELROUTE ============== */
/* RTM_DELROUTE - do */
struct rt_route_delroute_req {
	__u16 _nlmsg_flags;

	struct rtmsg _hdr;

	std::vector<__u8> dst;
	std::vector<__u8> src;
	std::optional<__u32> iif;
	std::optional<__u32> oif;
	std::vector<__u8> gateway;
	std::optional<__u32> priority;
	std::vector<__u8> prefsrc;
	std::optional<rt_route_metrics> metrics;
	std::vector<__u8> multipath;
	std::optional<__u32> flow;
	std::optional<struct rta_cacheinfo> cacheinfo;
	std::optional<__u32> table;
	std::optional<__u32> mark;
	std::vector<__u8> mfc_stats;
	std::vector<__u8> via;
	std::vector<__u8> newdst;
	std::optional<__u8> pref;
	std::optional<__u16> encap_type;
	std::vector<__u8> encap;
	std::optional<__u32> expires;
	std::vector<__u8> pad;
	std::optional<__u32> uid;
	std::optional<__u8> ttl_propagate;
	std::optional<__u8> ip_proto;
	std::optional<__u16> sport;
	std::optional<__u16> dport;
	std::optional<__u32> nh_id;
	std::optional<__u32> flowlabel /* big-endian */;
};

/*
 * Delete an existing route
 */
int rt_route_delroute(ynl_cpp::ynl_socket& ys, rt_route_delroute_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_RT_ROUTE_GEN_H */
