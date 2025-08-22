/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_NLCTRL_GEN_H
#define _LINUX_NLCTRL_GEN_H

#include <linux/types.h>
#include <stdlib.h>
#include <string.h>

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ynl.hpp"

#include <linux/genetlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_nlctrl_family();

/* Enums */
std::string_view nlctrl_op_str(int op);
std::string_view nlctrl_op_flags_str(int value);
std::string_view nlctrl_attr_type_str(netlink_attribute_type value);

/* Common nested types */
struct nlctrl_op_attrs {
	std::optional<__u32> idx;
	std::optional<__u32> id;
	std::optional<__u32> flags;
};

struct nlctrl_mcast_group_attrs {
	std::optional<__u32> idx;
	std::string name;
	std::optional<__u32> id;
};

struct nlctrl_policy_attrs {
	std::optional<__u32> attr_id;
	std::optional<__u32> policy_id;
	std::optional<enum netlink_attribute_type> type;
	std::optional<__s64> min_value_s;
	std::optional<__s64> max_value_s;
	std::optional<__u64> min_value_u;
	std::optional<__u64> max_value_u;
	std::optional<__u32> min_length;
	std::optional<__u32> max_length;
	std::optional<__u32> policy_idx;
	std::optional<__u32> policy_maxtype;
	std::optional<__u32> bitfield32_mask;
	std::optional<__u64> mask;
};

struct nlctrl_op_policy_attrs {
	std::optional<__u32> op_id;
	std::optional<__u32> do_;
	std::optional<__u32> dump;
};

/* ============== CTRL_CMD_GETFAMILY ============== */
/* CTRL_CMD_GETFAMILY - do */
struct nlctrl_getfamily_req {
	std::string family_name;
};

struct nlctrl_getfamily_rsp {
	std::optional<__u16> family_id;
	std::string family_name;
	std::optional<__u32> hdrsize;
	std::optional<__u32> maxattr;
	std::vector<nlctrl_mcast_group_attrs> mcast_groups;
	std::vector<nlctrl_op_attrs> ops;
	std::optional<__u32> version;
};

/*
 * Get / dump genetlink families
 */
std::unique_ptr<nlctrl_getfamily_rsp>
nlctrl_getfamily(ynl_cpp::ynl_socket& ys, nlctrl_getfamily_req& req);

/* CTRL_CMD_GETFAMILY - dump */
struct nlctrl_getfamily_list {
	std::list<nlctrl_getfamily_rsp> objs;
};

std::unique_ptr<nlctrl_getfamily_list>
nlctrl_getfamily_dump(ynl_cpp::ynl_socket& ys);

/* ============== CTRL_CMD_GETPOLICY ============== */
/* CTRL_CMD_GETPOLICY - dump */
struct nlctrl_getpolicy_req_dump {
	std::string family_name;
	std::optional<__u16> family_id;
	std::optional<__u32> op;
};

struct nlctrl_getpolicy_rsp_dump {
	std::optional<__u16> family_id;
	std::optional<nlctrl_op_policy_attrs> op_policy;
	std::optional<nlctrl_policy_attrs> policy;
};

struct nlctrl_getpolicy_rsp_list {
	std::list<nlctrl_getpolicy_rsp_dump> objs;
};

std::unique_ptr<nlctrl_getpolicy_rsp_list>
nlctrl_getpolicy_dump(ynl_cpp::ynl_socket& ys, nlctrl_getpolicy_req_dump& req);

} //namespace ynl_cpp
#endif /* _LINUX_NLCTRL_GEN_H */
