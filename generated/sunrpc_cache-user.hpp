/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_SUNRPC_GEN_H
#define _LINUX_SUNRPC_GEN_H

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

#include <linux/sunrpc_netlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_sunrpc_family();

/* Enums */
std::string_view sunrpc_op_str(int op);
std::string_view sunrpc_cache_type_str(sunrpc_cache_type value);

/* Common nested types */
struct sunrpc_ip_map {
	std::optional<__u64> seqno;
	std::string class_;
	std::string addr;
	std::string domain;
	bool negative{};
	std::optional<__u64> expiry;
};

struct sunrpc_unix_gid {
	std::optional<__u64> seqno;
	std::optional<__u32> uid;
	std::vector<__u32> gids;
	bool negative{};
	std::optional<__u64> expiry;
};

/* ============== SUNRPC_CMD_IP_MAP_GET_REQS ============== */
/* SUNRPC_CMD_IP_MAP_GET_REQS - dump */
struct sunrpc_ip_map_get_reqs_rsp {
	std::vector<sunrpc_ip_map> requests;
};

struct sunrpc_ip_map_get_reqs_list {
	std::list<sunrpc_ip_map_get_reqs_rsp> objs;
};

std::unique_ptr<sunrpc_ip_map_get_reqs_list>
sunrpc_ip_map_get_reqs_dump(ynl_cpp::ynl_socket& ys);

/* ============== SUNRPC_CMD_IP_MAP_SET_REQS ============== */
/* SUNRPC_CMD_IP_MAP_SET_REQS - do */
struct sunrpc_ip_map_set_reqs_req {
	std::vector<sunrpc_ip_map> requests;
};

/*
 * Respond to one or more ip_map requests
 */
int sunrpc_ip_map_set_reqs(ynl_cpp::ynl_socket& ys,
			   sunrpc_ip_map_set_reqs_req& req);

/* ============== SUNRPC_CMD_UNIX_GID_GET_REQS ============== */
/* SUNRPC_CMD_UNIX_GID_GET_REQS - dump */
struct sunrpc_unix_gid_get_reqs_rsp {
	std::vector<sunrpc_unix_gid> requests;
};

struct sunrpc_unix_gid_get_reqs_list {
	std::list<sunrpc_unix_gid_get_reqs_rsp> objs;
};

std::unique_ptr<sunrpc_unix_gid_get_reqs_list>
sunrpc_unix_gid_get_reqs_dump(ynl_cpp::ynl_socket& ys);

/* ============== SUNRPC_CMD_UNIX_GID_SET_REQS ============== */
/* SUNRPC_CMD_UNIX_GID_SET_REQS - do */
struct sunrpc_unix_gid_set_reqs_req {
	std::vector<sunrpc_unix_gid> requests;
};

/*
 * Respond to one or more unix_gid requests
 */
int sunrpc_unix_gid_set_reqs(ynl_cpp::ynl_socket& ys,
			     sunrpc_unix_gid_set_reqs_req& req);

/* ============== SUNRPC_CMD_CACHE_FLUSH ============== */
/* SUNRPC_CMD_CACHE_FLUSH - do */
struct sunrpc_cache_flush_req {
	std::optional<__u32> mask;
};

/*
 * Flush sunrpc caches (ip_map and/or unix_gid)
 */
int sunrpc_cache_flush(ynl_cpp::ynl_socket& ys, sunrpc_cache_flush_req& req);

/* SUNRPC_CMD_CACHE_NOTIFY - event */
struct sunrpc_cache_notify_rsp {
	std::optional<__u32> cache_type;
};

struct sunrpc_cache_notify {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	sunrpc_cache_notify_rsp obj __attribute__((aligned(8)));
};

} //namespace ynl_cpp
#endif /* _LINUX_SUNRPC_GEN_H */
