/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_NFSD_GEN_H
#define _LINUX_NFSD_GEN_H

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

#include <linux/nfsd_netlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_nfsd_family();

/* Enums */
std::string_view nfsd_op_str(int op);

/* Common nested types */
struct nfsd_version {
	std::optional<__u32> major;
	std::optional<__u32> minor;
	bool enabled{};
};

struct nfsd_sock {
	std::vector<__u8> addr;
	std::string transport_name;
};

/* ============== NFSD_CMD_RPC_STATUS_GET ============== */
/* NFSD_CMD_RPC_STATUS_GET - dump */
struct nfsd_rpc_status_get_rsp_dump {
	std::optional<__u32> xid /* big-endian */;
	std::optional<__u32> flags;
	std::optional<__u32> prog;
	std::optional<__u8> version;
	std::optional<__u32> proc;
	std::optional<__s64> service_time;
	std::optional<__u32> saddr4 /* big-endian */;
	std::optional<__u32> daddr4 /* big-endian */;
	std::vector<__u8> saddr6;
	std::vector<__u8> daddr6;
	std::optional<__u16> sport /* big-endian */;
	std::optional<__u16> dport /* big-endian */;
	std::vector<__u32> compound_ops;
};

struct nfsd_rpc_status_get_rsp_list {
	std::list<nfsd_rpc_status_get_rsp_dump> objs;
};

std::unique_ptr<nfsd_rpc_status_get_rsp_list>
nfsd_rpc_status_get_dump(ynl_cpp::ynl_socket& ys);

/* ============== NFSD_CMD_THREADS_SET ============== */
/* NFSD_CMD_THREADS_SET - do */
struct nfsd_threads_set_req {
	std::vector<__u32> threads;
	std::optional<__u32> gracetime;
	std::optional<__u32> leasetime;
	std::string scope;
};

/*
 * set the number of running threads
 */
int nfsd_threads_set(ynl_cpp::ynl_socket& ys, nfsd_threads_set_req& req);

/* ============== NFSD_CMD_THREADS_GET ============== */
/* NFSD_CMD_THREADS_GET - do */

struct nfsd_threads_get_rsp {
	std::vector<__u32> threads;
	std::optional<__u32> gracetime;
	std::optional<__u32> leasetime;
	std::string scope;
};

/*
 * get the number of running threads
 */
std::unique_ptr<nfsd_threads_get_rsp>
nfsd_threads_get(ynl_cpp::ynl_socket& ys);

/* ============== NFSD_CMD_VERSION_SET ============== */
/* NFSD_CMD_VERSION_SET - do */
struct nfsd_version_set_req {
	std::vector<nfsd_version> version;
};

/*
 * set nfs enabled versions
 */
int nfsd_version_set(ynl_cpp::ynl_socket& ys, nfsd_version_set_req& req);

/* ============== NFSD_CMD_VERSION_GET ============== */
/* NFSD_CMD_VERSION_GET - do */

struct nfsd_version_get_rsp {
	std::vector<nfsd_version> version;
};

/*
 * get nfs enabled versions
 */
std::unique_ptr<nfsd_version_get_rsp>
nfsd_version_get(ynl_cpp::ynl_socket& ys);

/* ============== NFSD_CMD_LISTENER_SET ============== */
/* NFSD_CMD_LISTENER_SET - do */
struct nfsd_listener_set_req {
	std::vector<nfsd_sock> addr;
};

/*
 * set nfs running sockets
 */
int nfsd_listener_set(ynl_cpp::ynl_socket& ys, nfsd_listener_set_req& req);

/* ============== NFSD_CMD_LISTENER_GET ============== */
/* NFSD_CMD_LISTENER_GET - do */

struct nfsd_listener_get_rsp {
	std::vector<nfsd_sock> addr;
};

/*
 * get nfs running listeners
 */
std::unique_ptr<nfsd_listener_get_rsp>
nfsd_listener_get(ynl_cpp::ynl_socket& ys);

/* ============== NFSD_CMD_POOL_MODE_SET ============== */
/* NFSD_CMD_POOL_MODE_SET - do */
struct nfsd_pool_mode_set_req {
	std::string mode;
};

/*
 * set the current server pool-mode
 */
int nfsd_pool_mode_set(ynl_cpp::ynl_socket& ys, nfsd_pool_mode_set_req& req);

/* ============== NFSD_CMD_POOL_MODE_GET ============== */
/* NFSD_CMD_POOL_MODE_GET - do */

struct nfsd_pool_mode_get_rsp {
	std::string mode;
	std::optional<__u32> npools;
};

/*
 * get info about server pool-mode
 */
std::unique_ptr<nfsd_pool_mode_get_rsp>
nfsd_pool_mode_get(ynl_cpp::ynl_socket& ys);

} //namespace ynl_cpp
#endif /* _LINUX_NFSD_GEN_H */
