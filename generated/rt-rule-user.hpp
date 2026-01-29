/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_RT_RULE_GEN_H
#define _LINUX_RT_RULE_GEN_H

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

#include <linux/fib_rules.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_rt_rule_family();

/* Enums */
std::string_view rt_rule_op_str(int op);
std::string_view rt_rule_fr_act_str(int value);

/* Common nested types */
/* ============== RTM_NEWRULE ============== */
/* RTM_NEWRULE - do */
struct rt_rule_newrule_req {
	__u16 _nlmsg_flags;

	struct fib_rule_hdr _hdr;

	std::string iifname;
	std::string oifname;
	std::optional<__u32> priority;
	std::optional<__u32> fwmark;
	std::optional<__u32> flow;
	std::optional<__u64> tun_id;
	std::optional<__u32> fwmask;
	std::optional<__u32> table;
	std::optional<__u32> suppress_prefixlen;
	std::optional<__u32> suppress_ifgroup;
	std::optional<__u32> goto_;
	std::optional<__u8> l3mdev;
	std::optional<struct fib_rule_uid_range> uid_range;
	std::optional<__u8> protocol;
	std::optional<__u8> ip_proto;
	std::optional<struct fib_rule_port_range> sport_range;
	std::optional<struct fib_rule_port_range> dport_range;
	std::optional<__u8> dscp;
	std::optional<__u32> flowlabel /* big-endian */;
	std::optional<__u32> flowlabel_mask /* big-endian */;
	std::optional<__u16> sport_mask;
	std::optional<__u16> dport_mask;
	std::optional<__u8> dscp_mask;
};

/*
 * Add new FIB rule
 */
int rt_rule_newrule(ynl_cpp::ynl_socket& ys, rt_rule_newrule_req& req);

/* ============== RTM_DELRULE ============== */
/* RTM_DELRULE - do */
struct rt_rule_delrule_req {
	__u16 _nlmsg_flags;

	struct fib_rule_hdr _hdr;

	std::string iifname;
	std::string oifname;
	std::optional<__u32> priority;
	std::optional<__u32> fwmark;
	std::optional<__u32> flow;
	std::optional<__u64> tun_id;
	std::optional<__u32> fwmask;
	std::optional<__u32> table;
	std::optional<__u32> suppress_prefixlen;
	std::optional<__u32> suppress_ifgroup;
	std::optional<__u32> goto_;
	std::optional<__u8> l3mdev;
	std::optional<struct fib_rule_uid_range> uid_range;
	std::optional<__u8> protocol;
	std::optional<__u8> ip_proto;
	std::optional<struct fib_rule_port_range> sport_range;
	std::optional<struct fib_rule_port_range> dport_range;
	std::optional<__u8> dscp;
	std::optional<__u32> flowlabel /* big-endian */;
	std::optional<__u32> flowlabel_mask /* big-endian */;
	std::optional<__u16> sport_mask;
	std::optional<__u16> dport_mask;
	std::optional<__u8> dscp_mask;
};

/*
 * Remove an existing FIB rule
 */
int rt_rule_delrule(ynl_cpp::ynl_socket& ys, rt_rule_delrule_req& req);

/* ============== RTM_GETRULE ============== */
/* RTM_GETRULE - dump */
struct rt_rule_getrule_req {
	struct fib_rule_hdr _hdr;
};

struct rt_rule_getrule_rsp {
	struct fib_rule_hdr _hdr;

	std::string iifname;
	std::string oifname;
	std::optional<__u32> priority;
	std::optional<__u32> fwmark;
	std::optional<__u32> flow;
	std::optional<__u64> tun_id;
	std::optional<__u32> fwmask;
	std::optional<__u32> table;
	std::optional<__u32> suppress_prefixlen;
	std::optional<__u32> suppress_ifgroup;
	std::optional<__u32> goto_;
	std::optional<__u8> l3mdev;
	std::optional<struct fib_rule_uid_range> uid_range;
	std::optional<__u8> protocol;
	std::optional<__u8> ip_proto;
	std::optional<struct fib_rule_port_range> sport_range;
	std::optional<struct fib_rule_port_range> dport_range;
	std::optional<__u8> dscp;
	std::optional<__u32> flowlabel /* big-endian */;
	std::optional<__u32> flowlabel_mask /* big-endian */;
	std::optional<__u16> sport_mask;
	std::optional<__u16> dport_mask;
	std::optional<__u8> dscp_mask;
};

struct rt_rule_getrule_list {
	std::list<rt_rule_getrule_rsp> objs;
};

std::unique_ptr<rt_rule_getrule_list>
rt_rule_getrule_dump(ynl_cpp::ynl_socket& ys, rt_rule_getrule_req& req);

/* RTM_GETRULE - notify */
struct rt_rule_getrule_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	rt_rule_getrule_rsp obj __attribute__((aligned(8)));
};

} //namespace ynl_cpp
#endif /* _LINUX_RT_RULE_GEN_H */
