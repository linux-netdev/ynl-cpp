/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_MPTCP_PM_GEN_H
#define _LINUX_MPTCP_PM_GEN_H

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

#include <linux/mptcp_pm.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_mptcp_pm_family();

/* Enums */
std::string_view mptcp_pm_op_str(int op);
std::string_view mptcp_pm_event_type_str(mptcp_event_type value);

/* Common nested types */
struct mptcp_pm_address {
	std::optional<__u16> family;
	std::optional<__u8> id;
	std::optional<__u32> addr4 /* big-endian */;
	std::vector<__u8> addr6;
	std::optional<__u16> port;
	std::optional<__u32> flags;
	std::optional<__s32> if_idx;
};

/* ============== MPTCP_PM_CMD_ADD_ADDR ============== */
/* MPTCP_PM_CMD_ADD_ADDR - do */
struct mptcp_pm_add_addr_req {
	std::optional<mptcp_pm_address> addr;
};

/*
 * Add endpoint
 */
int mptcp_pm_add_addr(ynl_cpp::ynl_socket& ys, mptcp_pm_add_addr_req& req);

/* ============== MPTCP_PM_CMD_DEL_ADDR ============== */
/* MPTCP_PM_CMD_DEL_ADDR - do */
struct mptcp_pm_del_addr_req {
	std::optional<mptcp_pm_address> addr;
};

/*
 * Delete endpoint
 */
int mptcp_pm_del_addr(ynl_cpp::ynl_socket& ys, mptcp_pm_del_addr_req& req);

/* ============== MPTCP_PM_CMD_GET_ADDR ============== */
/* MPTCP_PM_CMD_GET_ADDR - do */
struct mptcp_pm_get_addr_req {
	std::optional<mptcp_pm_address> addr;
	std::optional<__u32> token;
};

struct mptcp_pm_get_addr_rsp {
	std::optional<mptcp_pm_address> addr;
};

/*
 * Get endpoint information
 */
std::unique_ptr<mptcp_pm_get_addr_rsp>
mptcp_pm_get_addr(ynl_cpp::ynl_socket& ys, mptcp_pm_get_addr_req& req);

/* MPTCP_PM_CMD_GET_ADDR - dump */
struct mptcp_pm_get_addr_list {
	std::list<mptcp_pm_get_addr_rsp> objs;
};

std::unique_ptr<mptcp_pm_get_addr_list>
mptcp_pm_get_addr_dump(ynl_cpp::ynl_socket& ys);

/* ============== MPTCP_PM_CMD_FLUSH_ADDRS ============== */
/* MPTCP_PM_CMD_FLUSH_ADDRS - do */
struct mptcp_pm_flush_addrs_req {
	std::optional<mptcp_pm_address> addr;
};

/*
 * Flush addresses
 */
int mptcp_pm_flush_addrs(ynl_cpp::ynl_socket& ys,
			 mptcp_pm_flush_addrs_req& req);

/* ============== MPTCP_PM_CMD_SET_LIMITS ============== */
/* MPTCP_PM_CMD_SET_LIMITS - do */
struct mptcp_pm_set_limits_req {
	std::optional<__u32> rcv_add_addrs;
	std::optional<__u32> subflows;
};

/*
 * Set protocol limits
 */
int mptcp_pm_set_limits(ynl_cpp::ynl_socket& ys, mptcp_pm_set_limits_req& req);

/* ============== MPTCP_PM_CMD_GET_LIMITS ============== */
/* MPTCP_PM_CMD_GET_LIMITS - do */
struct mptcp_pm_get_limits_req {
	std::optional<__u32> rcv_add_addrs;
	std::optional<__u32> subflows;
};

struct mptcp_pm_get_limits_rsp {
	std::optional<__u32> rcv_add_addrs;
	std::optional<__u32> subflows;
};

/*
 * Get protocol limits
 */
std::unique_ptr<mptcp_pm_get_limits_rsp>
mptcp_pm_get_limits(ynl_cpp::ynl_socket& ys, mptcp_pm_get_limits_req& req);

/* ============== MPTCP_PM_CMD_SET_FLAGS ============== */
/* MPTCP_PM_CMD_SET_FLAGS - do */
struct mptcp_pm_set_flags_req {
	std::optional<mptcp_pm_address> addr;
	std::optional<__u32> token;
	std::optional<mptcp_pm_address> addr_remote;
};

/*
 * Change endpoint flags
 */
int mptcp_pm_set_flags(ynl_cpp::ynl_socket& ys, mptcp_pm_set_flags_req& req);

/* ============== MPTCP_PM_CMD_ANNOUNCE ============== */
/* MPTCP_PM_CMD_ANNOUNCE - do */
struct mptcp_pm_announce_req {
	std::optional<mptcp_pm_address> addr;
	std::optional<__u32> token;
};

/*
 * Announce new address
 */
int mptcp_pm_announce(ynl_cpp::ynl_socket& ys, mptcp_pm_announce_req& req);

/* ============== MPTCP_PM_CMD_REMOVE ============== */
/* MPTCP_PM_CMD_REMOVE - do */
struct mptcp_pm_remove_req {
	std::optional<__u32> token;
	std::optional<__u8> loc_id;
};

/*
 * Announce removal
 */
int mptcp_pm_remove(ynl_cpp::ynl_socket& ys, mptcp_pm_remove_req& req);

/* ============== MPTCP_PM_CMD_SUBFLOW_CREATE ============== */
/* MPTCP_PM_CMD_SUBFLOW_CREATE - do */
struct mptcp_pm_subflow_create_req {
	std::optional<mptcp_pm_address> addr;
	std::optional<__u32> token;
	std::optional<mptcp_pm_address> addr_remote;
};

/*
 * Create subflow
 */
int mptcp_pm_subflow_create(ynl_cpp::ynl_socket& ys,
			    mptcp_pm_subflow_create_req& req);

/* ============== MPTCP_PM_CMD_SUBFLOW_DESTROY ============== */
/* MPTCP_PM_CMD_SUBFLOW_DESTROY - do */
struct mptcp_pm_subflow_destroy_req {
	std::optional<mptcp_pm_address> addr;
	std::optional<__u32> token;
	std::optional<mptcp_pm_address> addr_remote;
};

/*
 * Destroy subflow
 */
int mptcp_pm_subflow_destroy(ynl_cpp::ynl_socket& ys,
			     mptcp_pm_subflow_destroy_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_MPTCP_PM_GEN_H */
