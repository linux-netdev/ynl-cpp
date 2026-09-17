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
#include <array>

#include "ynl.hpp"

#include <linux/nfsd_netlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_nfsd_family();

/* Enums */
std::string_view nfsd_op_str(int op);
std::string_view nfsd_cache_type_str(nfsd_cache_type value);
std::string_view nfsd_export_flags_str(nfsd_export_flags value);
std::string_view nfsd_xprtsec_mode_str(nfsd_xprtsec_mode value);

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

struct nfsd_expkey {
	std::optional<__u64> seqno;
	std::string client;
	std::optional<__u8> fsidtype;
	std::vector<__u8> fsid;
	bool negative{};
	std::optional<__u64> expiry;
	std::string path;
};

struct nfsd_server_proc_entry {
	std::optional<__u32> op;
	std::optional<__u64> count;
};

struct nfsd_auth_flavor {
	std::optional<__u32> pseudoflavor;
	std::optional<__u32> flags;
};

struct nfsd_fslocation {
	std::string host;
	std::string path;
};

struct nfsd_fslocations {
	std::vector<nfsd_fslocation> location;
};

struct nfsd_svc_export {
	std::optional<__u64> seqno;
	std::string client;
	std::string path;
	bool negative{};
	std::optional<__u64> expiry;
	std::optional<__u32> anon_uid;
	std::optional<__u32> anon_gid;
	std::optional<nfsd_fslocations> fslocations;
	std::vector<__u8> uuid;
	std::vector<nfsd_auth_flavor> secinfo;
	std::vector<__u32> xprtsec;
	std::optional<__u32> flags;
	std::optional<__s32> fsid;
};

/* ============== NFSD_CMD_RPC_STATUS_GET ============== */
/* NFSD_CMD_RPC_STATUS_GET - dump */
struct nfsd_rpc_status_get_rsp {
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

struct nfsd_rpc_status_get_list {
	std::list<nfsd_rpc_status_get_rsp> objs;
};

std::unique_ptr<nfsd_rpc_status_get_list>
nfsd_rpc_status_get_dump(ynl_cpp::ynl_socket& ys);

/* ============== NFSD_CMD_THREADS_SET ============== */
/* NFSD_CMD_THREADS_SET - do */
struct nfsd_threads_set_req {
	std::vector<__u32> threads;
	std::optional<__u32> gracetime;
	std::optional<__u32> leasetime;
	std::string scope;
	std::optional<__u32> min_threads;
	std::vector<__u8> fh_key;
};

/*
 * set the maximum number of running threads
 */
int nfsd_threads_set(ynl_cpp::ynl_socket& ys, nfsd_threads_set_req& req);

/* ============== NFSD_CMD_THREADS_GET ============== */
/* NFSD_CMD_THREADS_GET - do */

struct nfsd_threads_get_rsp {
	std::vector<__u32> threads;
	std::optional<__u32> gracetime;
	std::optional<__u32> leasetime;
	std::string scope;
	std::optional<__u32> min_threads;
};

/*
 * get the maximum number of running threads
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

/* ============== NFSD_CMD_SVC_EXPORT_GET_REQS ============== */
/* NFSD_CMD_SVC_EXPORT_GET_REQS - dump */
struct nfsd_svc_export_get_reqs_rsp {
	std::vector<nfsd_svc_export> requests;
};

struct nfsd_svc_export_get_reqs_list {
	std::list<nfsd_svc_export_get_reqs_rsp> objs;
};

std::unique_ptr<nfsd_svc_export_get_reqs_list>
nfsd_svc_export_get_reqs_dump(ynl_cpp::ynl_socket& ys);

/* ============== NFSD_CMD_SVC_EXPORT_SET_REQS ============== */
/* NFSD_CMD_SVC_EXPORT_SET_REQS - do */
struct nfsd_svc_export_set_reqs_req {
	std::vector<nfsd_svc_export> requests;
};

/*
 * Respond to one or more svc_export requests
 */
int nfsd_svc_export_set_reqs(ynl_cpp::ynl_socket& ys,
			     nfsd_svc_export_set_reqs_req& req);

/* ============== NFSD_CMD_EXPKEY_GET_REQS ============== */
/* NFSD_CMD_EXPKEY_GET_REQS - dump */
struct nfsd_expkey_get_reqs_rsp {
	std::vector<nfsd_expkey> requests;
};

struct nfsd_expkey_get_reqs_list {
	std::list<nfsd_expkey_get_reqs_rsp> objs;
};

std::unique_ptr<nfsd_expkey_get_reqs_list>
nfsd_expkey_get_reqs_dump(ynl_cpp::ynl_socket& ys);

/* ============== NFSD_CMD_EXPKEY_SET_REQS ============== */
/* NFSD_CMD_EXPKEY_SET_REQS - do */
struct nfsd_expkey_set_reqs_req {
	std::vector<nfsd_expkey> requests;
};

/*
 * Respond to one or more expkey requests
 */
int nfsd_expkey_set_reqs(ynl_cpp::ynl_socket& ys,
			 nfsd_expkey_set_reqs_req& req);

/* ============== NFSD_CMD_CACHE_FLUSH ============== */
/* NFSD_CMD_CACHE_FLUSH - do */
struct nfsd_cache_flush_req {
	std::optional<__u32> mask;
};

/*
 * Flush nfsd caches (svc_export and/or expkey)
 */
int nfsd_cache_flush(ynl_cpp::ynl_socket& ys, nfsd_cache_flush_req& req);

/* ============== NFSD_CMD_UNLOCK_IP ============== */
/* NFSD_CMD_UNLOCK_IP - do */
struct nfsd_unlock_ip_req {
	std::vector<__u8> address;
};

/*
 * release NLM locks held by an IP address
 */
int nfsd_unlock_ip(ynl_cpp::ynl_socket& ys, nfsd_unlock_ip_req& req);

/* ============== NFSD_CMD_UNLOCK_FILESYSTEM ============== */
/* NFSD_CMD_UNLOCK_FILESYSTEM - do */
struct nfsd_unlock_filesystem_req {
	std::string path;
};

/*
 * revoke NFS state under a filesystem path
 */
int nfsd_unlock_filesystem(ynl_cpp::ynl_socket& ys,
			   nfsd_unlock_filesystem_req& req);

/* ============== NFSD_CMD_UNLOCK_EXPORT ============== */
/* NFSD_CMD_UNLOCK_EXPORT - do */
struct nfsd_unlock_export_req {
	std::string path;
};

/*
 * Revoke NFSv4 state acquired through exports of a given path. Unlike unlock-filesystem, which operates at superblock granularity, this command targets only state associated with a specific export path. Userspace (exportfs -u) sends this after removing the last client for a path so the underlying filesystem can be unmounted.
 */
int nfsd_unlock_export(ynl_cpp::ynl_socket& ys, nfsd_unlock_export_req& req);

/* ============== NFSD_CMD_SERVER_STATS_GET ============== */
/* NFSD_CMD_SERVER_STATS_GET - dump */
struct nfsd_server_stats_get_rsp {
	std::optional<__u64> rc_hits;
	std::optional<__u64> rc_misses;
	std::optional<__u64> rc_nocache;
	std::optional<__u64> fh_stale;
	std::optional<__u64> io_read;
	std::optional<__u64> io_write;
	std::optional<__u32> netcnt;
	std::optional<__u32> netudpcnt;
	std::optional<__u32> nettcpcnt;
	std::optional<__u32> nettcpconn;
	std::optional<__u32> rpccnt;
	std::optional<__u32> rpcbadfmt;
	std::optional<__u32> rpcbadauth;
	std::optional<__u32> rpcbadclnt;
	std::vector<nfsd_server_proc_entry> proc2_ops;
	std::vector<nfsd_server_proc_entry> proc3_ops;
	std::vector<nfsd_server_proc_entry> proc4_ops;
	std::vector<nfsd_server_proc_entry> proc4ops_ops;
	std::vector<nfsd_server_proc_entry> proc4cb_ops;
};

struct nfsd_server_stats_get_list {
	std::list<nfsd_server_stats_get_rsp> objs;
};

std::unique_ptr<nfsd_server_stats_get_list>
nfsd_server_stats_get_dump(ynl_cpp::ynl_socket& ys);

/* NFSD_CMD_CACHE_NOTIFY - event */
struct nfsd_cache_notify_rsp {
	std::optional<__u32> cache_type;
};

struct nfsd_cache_notify {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	nfsd_cache_notify_rsp obj __attribute__((aligned(8)));
};

} //namespace ynl_cpp
#endif /* _LINUX_NFSD_GEN_H */
