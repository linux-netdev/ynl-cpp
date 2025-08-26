/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_RT_NEIGH_GEN_H
#define _LINUX_RT_NEIGH_GEN_H

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
const struct ynl_family& get_ynl_rt_neigh_family();

/* Enums */
std::string_view rt_neigh_op_str(int op);
std::string_view rt_neigh_nud_state_str(int value);
std::string_view rt_neigh_ntf_flags_str(int value);
std::string_view rt_neigh_ntf_ext_flags_str(int value);
std::string_view rt_neigh_rtm_type_str(int value);

/* Common nested types */
struct rt_neigh_ndtpa_attrs {
	std::optional<__u32> ifindex;
	std::optional<__u32> refcnt;
	std::optional<__u64> reachable_time;
	std::optional<__u64> base_reachable_time;
	std::optional<__u64> retrans_time;
	std::optional<__u64> gc_staletime;
	std::optional<__u64> delay_probe_time;
	std::optional<__u32> queue_len;
	std::optional<__u32> app_probes;
	std::optional<__u32> ucast_probes;
	std::optional<__u32> mcast_probes;
	std::optional<__u64> anycast_delay;
	std::optional<__u64> proxy_delay;
	std::optional<__u32> proxy_qlen;
	std::optional<__u64> locktime;
	std::optional<__u32> queue_lenbytes;
	std::optional<__u32> mcast_reprobes;
	std::optional<__u64> interval_probe_time_ms;
};

/* ============== RTM_NEWNEIGH ============== */
/* RTM_NEWNEIGH - do */
struct rt_neigh_newneigh_req {
	__u16 _nlmsg_flags;

	struct ndmsg _hdr;

	std::vector<__u8> dst;
	std::vector<__u8> lladdr;
	std::optional<__u32> probes;
	std::optional<__u16> vlan;
	std::optional<__u16> port;
	std::optional<__u32> vni;
	std::optional<__u32> ifindex;
	std::optional<__u32> master;
	std::optional<__u8> protocol;
	std::optional<__u32> nh_id;
	std::optional<__u32> flags_ext;
	std::vector<__u8> fdb_ext_attrs;
};

/*
 * Add new neighbour entry
 */
int rt_neigh_newneigh(ynl_cpp::ynl_socket& ys, rt_neigh_newneigh_req& req);

/* ============== RTM_DELNEIGH ============== */
/* RTM_DELNEIGH - do */
struct rt_neigh_delneigh_req {
	__u16 _nlmsg_flags;

	struct ndmsg _hdr;

	std::vector<__u8> dst;
	std::optional<__u32> ifindex;
};

/*
 * Remove an existing neighbour entry
 */
int rt_neigh_delneigh(ynl_cpp::ynl_socket& ys, rt_neigh_delneigh_req& req);

/* ============== RTM_GETNEIGH ============== */
/* RTM_GETNEIGH - do */
struct rt_neigh_getneigh_req {
	__u16 _nlmsg_flags;

	struct ndmsg _hdr;

	std::vector<__u8> dst;
};

struct rt_neigh_getneigh_rsp {
	struct ndmsg _hdr;

	std::vector<__u8> dst;
	std::vector<__u8> lladdr;
	std::optional<__u32> probes;
	std::optional<__u16> vlan;
	std::optional<__u16> port;
	std::optional<__u32> vni;
	std::optional<__u32> ifindex;
	std::optional<__u32> master;
	std::optional<__u8> protocol;
	std::optional<__u32> nh_id;
	std::optional<__u32> flags_ext;
	std::vector<__u8> fdb_ext_attrs;
};

/*
 * Get or dump neighbour entries
 */
std::unique_ptr<rt_neigh_getneigh_rsp>
rt_neigh_getneigh(ynl_cpp::ynl_socket& ys, rt_neigh_getneigh_req& req);

/* RTM_GETNEIGH - dump */
struct rt_neigh_getneigh_req_dump {
	struct ndmsg _hdr;

	std::optional<__u32> ifindex;
	std::optional<__u32> master;
};

struct rt_neigh_getneigh_list {
	std::list<rt_neigh_getneigh_rsp> objs;
};

std::unique_ptr<rt_neigh_getneigh_list>
rt_neigh_getneigh_dump(ynl_cpp::ynl_socket& ys,
		       rt_neigh_getneigh_req_dump& req);

/* RTM_GETNEIGH - notify */
struct rt_neigh_getneigh_ntf {
};

/* ============== RTM_GETNEIGHTBL ============== */
/* RTM_GETNEIGHTBL - dump */
struct rt_neigh_getneightbl_req {
	struct ndtmsg _hdr;
};

struct rt_neigh_getneightbl_rsp {
	struct ndtmsg _hdr;

	std::string name;
	std::optional<__u32> thresh1;
	std::optional<__u32> thresh2;
	std::optional<__u32> thresh3;
	std::optional<struct ndt_config> config;
	std::optional<rt_neigh_ndtpa_attrs> parms;
	std::optional<struct ndt_stats> stats;
	std::optional<__u64> gc_interval;
};

struct rt_neigh_getneightbl_list {
	std::list<rt_neigh_getneightbl_rsp> objs;
};

std::unique_ptr<rt_neigh_getneightbl_list>
rt_neigh_getneightbl_dump(ynl_cpp::ynl_socket& ys,
			  rt_neigh_getneightbl_req& req);

/* ============== RTM_SETNEIGHTBL ============== */
/* RTM_SETNEIGHTBL - do */
struct rt_neigh_setneightbl_req {
	__u16 _nlmsg_flags;

	struct ndtmsg _hdr;

	std::string name;
	std::optional<__u32> thresh1;
	std::optional<__u32> thresh2;
	std::optional<__u32> thresh3;
	std::optional<rt_neigh_ndtpa_attrs> parms;
	std::optional<__u64> gc_interval;
};

/*
 * Set neighbour tables
 */
int rt_neigh_setneightbl(ynl_cpp::ynl_socket& ys,
			 rt_neigh_setneightbl_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_RT_NEIGH_GEN_H */
