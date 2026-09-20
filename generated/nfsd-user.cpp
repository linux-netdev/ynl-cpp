// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "nfsd-user.hpp"

#include <array>

#include <linux/nfsd_netlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, NFSD_CMD_SERVER_STATS_GET + 1> nfsd_op_strmap = []() {
	std::array<std::string_view, NFSD_CMD_SERVER_STATS_GET + 1> arr{};
	arr[NFSD_CMD_RPC_STATUS_GET] = "rpc-status-get";
	arr[NFSD_CMD_THREADS_SET] = "threads-set";
	arr[NFSD_CMD_THREADS_GET] = "threads-get";
	arr[NFSD_CMD_VERSION_SET] = "version-set";
	arr[NFSD_CMD_VERSION_GET] = "version-get";
	arr[NFSD_CMD_LISTENER_SET] = "listener-set";
	arr[NFSD_CMD_LISTENER_GET] = "listener-get";
	arr[NFSD_CMD_POOL_MODE_SET] = "pool-mode-set";
	arr[NFSD_CMD_POOL_MODE_GET] = "pool-mode-get";
	arr[NFSD_CMD_CACHE_NOTIFY] = "cache-notify";
	arr[NFSD_CMD_SVC_EXPORT_GET_REQS] = "svc-export-get-reqs";
	arr[NFSD_CMD_SVC_EXPORT_SET_REQS] = "svc-export-set-reqs";
	arr[NFSD_CMD_EXPKEY_GET_REQS] = "expkey-get-reqs";
	arr[NFSD_CMD_EXPKEY_SET_REQS] = "expkey-set-reqs";
	arr[NFSD_CMD_CACHE_FLUSH] = "cache-flush";
	arr[NFSD_CMD_UNLOCK_IP] = "unlock-ip";
	arr[NFSD_CMD_UNLOCK_FILESYSTEM] = "unlock-filesystem";
	arr[NFSD_CMD_UNLOCK_EXPORT] = "unlock-export";
	arr[NFSD_CMD_SERVER_STATS_GET] = "server-stats-get";
	return arr;
} ();

std::string_view nfsd_op_str(int op)
{
	if ((int)op < 0 || (int)op >= (int)(nfsd_op_strmap.size())) {
		return "";
	}
	return nfsd_op_strmap[op];
}

static constexpr std::array<std::string_view, 1 + 1> nfsd_cache_type_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "svc_export";
	arr[1] = "expkey";
	return arr;
} ();

std::string_view nfsd_cache_type_str(nfsd_cache_type value)
{
	value = (nfsd_cache_type)(ffs(value) - 1);
	if (value < 0 || value >= (int)(nfsd_cache_type_strmap.size())) {
		return "";
	}
	return nfsd_cache_type_strmap[value];
}

static constexpr std::array<std::string_view, 17 + 1> nfsd_export_flags_strmap = []() {
	std::array<std::string_view, 17 + 1> arr{};
	arr[0] = "readonly";
	arr[1] = "insecure-port";
	arr[2] = "rootsquash";
	arr[3] = "allsquash";
	arr[4] = "async";
	arr[5] = "gathered-writes";
	arr[6] = "noreaddirplus";
	arr[7] = "security-label";
	arr[8] = "sign-fh";
	arr[9] = "nohide";
	arr[10] = "nosubtreecheck";
	arr[11] = "noauthnlm";
	arr[12] = "msnfs";
	arr[13] = "fsid";
	arr[14] = "crossmount";
	arr[15] = "noacl";
	arr[16] = "v4root";
	arr[17] = "pnfs";
	return arr;
} ();

std::string_view nfsd_export_flags_str(nfsd_export_flags value)
{
	value = (nfsd_export_flags)(ffs(value) - 1);
	if (value < 0 || value >= (int)(nfsd_export_flags_strmap.size())) {
		return "";
	}
	return nfsd_export_flags_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> nfsd_xprtsec_mode_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "none";
	arr[1] = "tls";
	arr[2] = "mtls";
	return arr;
} ();

std::string_view nfsd_xprtsec_mode_str(nfsd_xprtsec_mode value)
{
	value = (nfsd_xprtsec_mode)(ffs(value) - 1);
	if (value < 0 || value >= (int)(nfsd_xprtsec_mode_strmap.size())) {
		return "";
	}
	return nfsd_xprtsec_mode_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,NFSD_A_VERSION_MAX + 1> nfsd_version_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_VERSION_MAX + 1> arr{};
	arr[NFSD_A_VERSION_MAJOR].name = "major";
	arr[NFSD_A_VERSION_MAJOR].type = YNL_PT_U32;
	arr[NFSD_A_VERSION_MINOR].name = "minor";
	arr[NFSD_A_VERSION_MINOR].type = YNL_PT_U32;
	arr[NFSD_A_VERSION_ENABLED].name = "enabled";
	arr[NFSD_A_VERSION_ENABLED].type = YNL_PT_FLAG;
	return arr;
} ();

struct ynl_policy_nest nfsd_version_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_VERSION_MAX),
	.table = nfsd_version_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_SOCK_MAX + 1> nfsd_sock_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_SOCK_MAX + 1> arr{};
	arr[NFSD_A_SOCK_ADDR].name = "addr";
	arr[NFSD_A_SOCK_ADDR].type = YNL_PT_BINARY;
	arr[NFSD_A_SOCK_TRANSPORT_NAME].name = "transport-name";
	arr[NFSD_A_SOCK_TRANSPORT_NAME].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest nfsd_sock_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_SOCK_MAX),
	.table = nfsd_sock_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_EXPKEY_MAX + 1> nfsd_expkey_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_EXPKEY_MAX + 1> arr{};
	arr[NFSD_A_EXPKEY_SEQNO].name = "seqno";
	arr[NFSD_A_EXPKEY_SEQNO].type = YNL_PT_U64;
	arr[NFSD_A_EXPKEY_CLIENT].name = "client";
	arr[NFSD_A_EXPKEY_CLIENT].type  = YNL_PT_NUL_STR;
	arr[NFSD_A_EXPKEY_FSIDTYPE].name = "fsidtype";
	arr[NFSD_A_EXPKEY_FSIDTYPE].type = YNL_PT_U8;
	arr[NFSD_A_EXPKEY_FSID].name = "fsid";
	arr[NFSD_A_EXPKEY_FSID].type = YNL_PT_BINARY;
	arr[NFSD_A_EXPKEY_NEGATIVE].name = "negative";
	arr[NFSD_A_EXPKEY_NEGATIVE].type = YNL_PT_FLAG;
	arr[NFSD_A_EXPKEY_EXPIRY].name = "expiry";
	arr[NFSD_A_EXPKEY_EXPIRY].type = YNL_PT_U64;
	arr[NFSD_A_EXPKEY_PATH].name = "path";
	arr[NFSD_A_EXPKEY_PATH].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest nfsd_expkey_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_EXPKEY_MAX),
	.table = nfsd_expkey_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_SERVER_PROC_ENTRY_MAX + 1> nfsd_server_proc_entry_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_SERVER_PROC_ENTRY_MAX + 1> arr{};
	arr[NFSD_A_SERVER_PROC_ENTRY_OP].name = "op";
	arr[NFSD_A_SERVER_PROC_ENTRY_OP].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_PROC_ENTRY_COUNT].name = "count";
	arr[NFSD_A_SERVER_PROC_ENTRY_COUNT].type = YNL_PT_U64;
	arr[NFSD_A_SERVER_PROC_ENTRY_PAD].name = "pad";
	arr[NFSD_A_SERVER_PROC_ENTRY_PAD].type = YNL_PT_IGNORE;
	return arr;
} ();

struct ynl_policy_nest nfsd_server_proc_entry_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_SERVER_PROC_ENTRY_MAX),
	.table = nfsd_server_proc_entry_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_AUTH_FLAVOR_MAX + 1> nfsd_auth_flavor_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_AUTH_FLAVOR_MAX + 1> arr{};
	arr[NFSD_A_AUTH_FLAVOR_PSEUDOFLAVOR].name = "pseudoflavor";
	arr[NFSD_A_AUTH_FLAVOR_PSEUDOFLAVOR].type = YNL_PT_U32;
	arr[NFSD_A_AUTH_FLAVOR_FLAGS].name = "flags";
	arr[NFSD_A_AUTH_FLAVOR_FLAGS].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nfsd_auth_flavor_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_AUTH_FLAVOR_MAX),
	.table = nfsd_auth_flavor_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_FSLOCATION_MAX + 1> nfsd_fslocation_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_FSLOCATION_MAX + 1> arr{};
	arr[NFSD_A_FSLOCATION_HOST].name = "host";
	arr[NFSD_A_FSLOCATION_HOST].type  = YNL_PT_NUL_STR;
	arr[NFSD_A_FSLOCATION_PATH].name = "path";
	arr[NFSD_A_FSLOCATION_PATH].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest nfsd_fslocation_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_FSLOCATION_MAX),
	.table = nfsd_fslocation_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_FSLOCATIONS_MAX + 1> nfsd_fslocations_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_FSLOCATIONS_MAX + 1> arr{};
	arr[NFSD_A_FSLOCATIONS_LOCATION].name = "location";
	arr[NFSD_A_FSLOCATIONS_LOCATION].type = YNL_PT_NEST;
	arr[NFSD_A_FSLOCATIONS_LOCATION].nest = &nfsd_fslocation_nest;
	return arr;
} ();

struct ynl_policy_nest nfsd_fslocations_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_FSLOCATIONS_MAX),
	.table = nfsd_fslocations_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_SVC_EXPORT_MAX + 1> nfsd_svc_export_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_SVC_EXPORT_MAX + 1> arr{};
	arr[NFSD_A_SVC_EXPORT_SEQNO].name = "seqno";
	arr[NFSD_A_SVC_EXPORT_SEQNO].type = YNL_PT_U64;
	arr[NFSD_A_SVC_EXPORT_CLIENT].name = "client";
	arr[NFSD_A_SVC_EXPORT_CLIENT].type  = YNL_PT_NUL_STR;
	arr[NFSD_A_SVC_EXPORT_PATH].name = "path";
	arr[NFSD_A_SVC_EXPORT_PATH].type  = YNL_PT_NUL_STR;
	arr[NFSD_A_SVC_EXPORT_NEGATIVE].name = "negative";
	arr[NFSD_A_SVC_EXPORT_NEGATIVE].type = YNL_PT_FLAG;
	arr[NFSD_A_SVC_EXPORT_EXPIRY].name = "expiry";
	arr[NFSD_A_SVC_EXPORT_EXPIRY].type = YNL_PT_U64;
	arr[NFSD_A_SVC_EXPORT_ANON_UID].name = "anon-uid";
	arr[NFSD_A_SVC_EXPORT_ANON_UID].type = YNL_PT_U32;
	arr[NFSD_A_SVC_EXPORT_ANON_GID].name = "anon-gid";
	arr[NFSD_A_SVC_EXPORT_ANON_GID].type = YNL_PT_U32;
	arr[NFSD_A_SVC_EXPORT_FSLOCATIONS].name = "fslocations";
	arr[NFSD_A_SVC_EXPORT_FSLOCATIONS].type = YNL_PT_NEST;
	arr[NFSD_A_SVC_EXPORT_FSLOCATIONS].nest = &nfsd_fslocations_nest;
	arr[NFSD_A_SVC_EXPORT_UUID].name = "uuid";
	arr[NFSD_A_SVC_EXPORT_UUID].type = YNL_PT_BINARY;
	arr[NFSD_A_SVC_EXPORT_SECINFO].name = "secinfo";
	arr[NFSD_A_SVC_EXPORT_SECINFO].type = YNL_PT_NEST;
	arr[NFSD_A_SVC_EXPORT_SECINFO].nest = &nfsd_auth_flavor_nest;
	arr[NFSD_A_SVC_EXPORT_XPRTSEC].name = "xprtsec";
	arr[NFSD_A_SVC_EXPORT_XPRTSEC].type = YNL_PT_U32;
	arr[NFSD_A_SVC_EXPORT_FLAGS].name = "flags";
	arr[NFSD_A_SVC_EXPORT_FLAGS].type = YNL_PT_U32;
	arr[NFSD_A_SVC_EXPORT_FSID].name = "fsid";
	arr[NFSD_A_SVC_EXPORT_FSID].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nfsd_svc_export_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_SVC_EXPORT_MAX),
	.table = nfsd_svc_export_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_RPC_STATUS_MAX + 1> nfsd_rpc_status_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_RPC_STATUS_MAX + 1> arr{};
	arr[NFSD_A_RPC_STATUS_XID].name = "xid";
	arr[NFSD_A_RPC_STATUS_XID].type = YNL_PT_U32;
	arr[NFSD_A_RPC_STATUS_FLAGS].name = "flags";
	arr[NFSD_A_RPC_STATUS_FLAGS].type = YNL_PT_U32;
	arr[NFSD_A_RPC_STATUS_PROG].name = "prog";
	arr[NFSD_A_RPC_STATUS_PROG].type = YNL_PT_U32;
	arr[NFSD_A_RPC_STATUS_VERSION].name = "version";
	arr[NFSD_A_RPC_STATUS_VERSION].type = YNL_PT_U8;
	arr[NFSD_A_RPC_STATUS_PROC].name = "proc";
	arr[NFSD_A_RPC_STATUS_PROC].type = YNL_PT_U32;
	arr[NFSD_A_RPC_STATUS_SERVICE_TIME].name = "service-time";
	arr[NFSD_A_RPC_STATUS_SERVICE_TIME].type = YNL_PT_U64;
	arr[NFSD_A_RPC_STATUS_PAD].name = "pad";
	arr[NFSD_A_RPC_STATUS_PAD].type = YNL_PT_IGNORE;
	arr[NFSD_A_RPC_STATUS_SADDR4].name = "saddr4";
	arr[NFSD_A_RPC_STATUS_SADDR4].type = YNL_PT_U32;
	arr[NFSD_A_RPC_STATUS_DADDR4].name = "daddr4";
	arr[NFSD_A_RPC_STATUS_DADDR4].type = YNL_PT_U32;
	arr[NFSD_A_RPC_STATUS_SADDR6].name = "saddr6";
	arr[NFSD_A_RPC_STATUS_SADDR6].type = YNL_PT_BINARY;
	arr[NFSD_A_RPC_STATUS_DADDR6].name = "daddr6";
	arr[NFSD_A_RPC_STATUS_DADDR6].type = YNL_PT_BINARY;
	arr[NFSD_A_RPC_STATUS_SPORT].name = "sport";
	arr[NFSD_A_RPC_STATUS_SPORT].type = YNL_PT_U16;
	arr[NFSD_A_RPC_STATUS_DPORT].name = "dport";
	arr[NFSD_A_RPC_STATUS_DPORT].type = YNL_PT_U16;
	arr[NFSD_A_RPC_STATUS_COMPOUND_OPS].name = "compound-ops";
	arr[NFSD_A_RPC_STATUS_COMPOUND_OPS].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nfsd_rpc_status_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_RPC_STATUS_MAX),
	.table = nfsd_rpc_status_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_SERVER_MAX + 1> nfsd_server_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_SERVER_MAX + 1> arr{};
	arr[NFSD_A_SERVER_THREADS].name = "threads";
	arr[NFSD_A_SERVER_THREADS].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_GRACETIME].name = "gracetime";
	arr[NFSD_A_SERVER_GRACETIME].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_LEASETIME].name = "leasetime";
	arr[NFSD_A_SERVER_LEASETIME].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_SCOPE].name = "scope";
	arr[NFSD_A_SERVER_SCOPE].type  = YNL_PT_NUL_STR;
	arr[NFSD_A_SERVER_MIN_THREADS].name = "min-threads";
	arr[NFSD_A_SERVER_MIN_THREADS].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_FH_KEY].name = "fh-key";
	arr[NFSD_A_SERVER_FH_KEY].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest nfsd_server_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_SERVER_MAX),
	.table = nfsd_server_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_SERVER_PROTO_MAX + 1> nfsd_server_proto_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_SERVER_PROTO_MAX + 1> arr{};
	arr[NFSD_A_SERVER_PROTO_VERSION].name = "version";
	arr[NFSD_A_SERVER_PROTO_VERSION].type = YNL_PT_NEST;
	arr[NFSD_A_SERVER_PROTO_VERSION].nest = &nfsd_version_nest;
	return arr;
} ();

struct ynl_policy_nest nfsd_server_proto_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_SERVER_PROTO_MAX),
	.table = nfsd_server_proto_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_SERVER_SOCK_MAX + 1> nfsd_server_sock_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_SERVER_SOCK_MAX + 1> arr{};
	arr[NFSD_A_SERVER_SOCK_ADDR].name = "addr";
	arr[NFSD_A_SERVER_SOCK_ADDR].type = YNL_PT_NEST;
	arr[NFSD_A_SERVER_SOCK_ADDR].nest = &nfsd_sock_nest;
	return arr;
} ();

struct ynl_policy_nest nfsd_server_sock_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_SERVER_SOCK_MAX),
	.table = nfsd_server_sock_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_POOL_MODE_MAX + 1> nfsd_pool_mode_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_POOL_MODE_MAX + 1> arr{};
	arr[NFSD_A_POOL_MODE_MODE].name = "mode";
	arr[NFSD_A_POOL_MODE_MODE].type  = YNL_PT_NUL_STR;
	arr[NFSD_A_POOL_MODE_NPOOLS].name = "npools";
	arr[NFSD_A_POOL_MODE_NPOOLS].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nfsd_pool_mode_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_POOL_MODE_MAX),
	.table = nfsd_pool_mode_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_CACHE_NOTIFY_MAX + 1> nfsd_cache_notify_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_CACHE_NOTIFY_MAX + 1> arr{};
	arr[NFSD_A_CACHE_NOTIFY_CACHE_TYPE].name = "cache-type";
	arr[NFSD_A_CACHE_NOTIFY_CACHE_TYPE].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nfsd_cache_notify_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_CACHE_NOTIFY_MAX),
	.table = nfsd_cache_notify_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_SVC_EXPORT_REQS_MAX + 1> nfsd_svc_export_reqs_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_SVC_EXPORT_REQS_MAX + 1> arr{};
	arr[NFSD_A_SVC_EXPORT_REQS_REQUESTS].name = "requests";
	arr[NFSD_A_SVC_EXPORT_REQS_REQUESTS].type = YNL_PT_NEST;
	arr[NFSD_A_SVC_EXPORT_REQS_REQUESTS].nest = &nfsd_svc_export_nest;
	return arr;
} ();

struct ynl_policy_nest nfsd_svc_export_reqs_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_SVC_EXPORT_REQS_MAX),
	.table = nfsd_svc_export_reqs_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_EXPKEY_REQS_MAX + 1> nfsd_expkey_reqs_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_EXPKEY_REQS_MAX + 1> arr{};
	arr[NFSD_A_EXPKEY_REQS_REQUESTS].name = "requests";
	arr[NFSD_A_EXPKEY_REQS_REQUESTS].type = YNL_PT_NEST;
	arr[NFSD_A_EXPKEY_REQS_REQUESTS].nest = &nfsd_expkey_nest;
	return arr;
} ();

struct ynl_policy_nest nfsd_expkey_reqs_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_EXPKEY_REQS_MAX),
	.table = nfsd_expkey_reqs_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_CACHE_FLUSH_MAX + 1> nfsd_cache_flush_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_CACHE_FLUSH_MAX + 1> arr{};
	arr[NFSD_A_CACHE_FLUSH_MASK].name = "mask";
	arr[NFSD_A_CACHE_FLUSH_MASK].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nfsd_cache_flush_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_CACHE_FLUSH_MAX),
	.table = nfsd_cache_flush_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_UNLOCK_IP_MAX + 1> nfsd_unlock_ip_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_UNLOCK_IP_MAX + 1> arr{};
	arr[NFSD_A_UNLOCK_IP_ADDRESS].name = "address";
	arr[NFSD_A_UNLOCK_IP_ADDRESS].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest nfsd_unlock_ip_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_UNLOCK_IP_MAX),
	.table = nfsd_unlock_ip_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_UNLOCK_FILESYSTEM_MAX + 1> nfsd_unlock_filesystem_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_UNLOCK_FILESYSTEM_MAX + 1> arr{};
	arr[NFSD_A_UNLOCK_FILESYSTEM_PATH].name = "path";
	arr[NFSD_A_UNLOCK_FILESYSTEM_PATH].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest nfsd_unlock_filesystem_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_UNLOCK_FILESYSTEM_MAX),
	.table = nfsd_unlock_filesystem_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_UNLOCK_EXPORT_MAX + 1> nfsd_unlock_export_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_UNLOCK_EXPORT_MAX + 1> arr{};
	arr[NFSD_A_UNLOCK_EXPORT_PATH].name = "path";
	arr[NFSD_A_UNLOCK_EXPORT_PATH].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest nfsd_unlock_export_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_UNLOCK_EXPORT_MAX),
	.table = nfsd_unlock_export_policy.data(),
};

static std::array<ynl_policy_attr,NFSD_A_SERVER_STATS_MAX + 1> nfsd_server_stats_policy = []() {
	std::array<ynl_policy_attr,NFSD_A_SERVER_STATS_MAX + 1> arr{};
	arr[NFSD_A_SERVER_STATS_RC_HITS].name = "rc-hits";
	arr[NFSD_A_SERVER_STATS_RC_HITS].type = YNL_PT_U64;
	arr[NFSD_A_SERVER_STATS_RC_MISSES].name = "rc-misses";
	arr[NFSD_A_SERVER_STATS_RC_MISSES].type = YNL_PT_U64;
	arr[NFSD_A_SERVER_STATS_RC_NOCACHE].name = "rc-nocache";
	arr[NFSD_A_SERVER_STATS_RC_NOCACHE].type = YNL_PT_U64;
	arr[NFSD_A_SERVER_STATS_PAD].name = "pad";
	arr[NFSD_A_SERVER_STATS_PAD].type = YNL_PT_IGNORE;
	arr[NFSD_A_SERVER_STATS_FH_STALE].name = "fh-stale";
	arr[NFSD_A_SERVER_STATS_FH_STALE].type = YNL_PT_U64;
	arr[NFSD_A_SERVER_STATS_IO_READ].name = "io-read";
	arr[NFSD_A_SERVER_STATS_IO_READ].type = YNL_PT_U64;
	arr[NFSD_A_SERVER_STATS_IO_WRITE].name = "io-write";
	arr[NFSD_A_SERVER_STATS_IO_WRITE].type = YNL_PT_U64;
	arr[NFSD_A_SERVER_STATS_NETCNT].name = "netcnt";
	arr[NFSD_A_SERVER_STATS_NETCNT].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_STATS_NETUDPCNT].name = "netudpcnt";
	arr[NFSD_A_SERVER_STATS_NETUDPCNT].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_STATS_NETTCPCNT].name = "nettcpcnt";
	arr[NFSD_A_SERVER_STATS_NETTCPCNT].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_STATS_NETTCPCONN].name = "nettcpconn";
	arr[NFSD_A_SERVER_STATS_NETTCPCONN].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_STATS_RPCCNT].name = "rpccnt";
	arr[NFSD_A_SERVER_STATS_RPCCNT].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_STATS_RPCBADFMT].name = "rpcbadfmt";
	arr[NFSD_A_SERVER_STATS_RPCBADFMT].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_STATS_RPCBADAUTH].name = "rpcbadauth";
	arr[NFSD_A_SERVER_STATS_RPCBADAUTH].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_STATS_RPCBADCLNT].name = "rpcbadclnt";
	arr[NFSD_A_SERVER_STATS_RPCBADCLNT].type = YNL_PT_U32;
	arr[NFSD_A_SERVER_STATS_PROC2_OPS].name = "proc2-ops";
	arr[NFSD_A_SERVER_STATS_PROC2_OPS].type = YNL_PT_NEST;
	arr[NFSD_A_SERVER_STATS_PROC2_OPS].nest = &nfsd_server_proc_entry_nest;
	arr[NFSD_A_SERVER_STATS_PROC3_OPS].name = "proc3-ops";
	arr[NFSD_A_SERVER_STATS_PROC3_OPS].type = YNL_PT_NEST;
	arr[NFSD_A_SERVER_STATS_PROC3_OPS].nest = &nfsd_server_proc_entry_nest;
	arr[NFSD_A_SERVER_STATS_PROC4_OPS].name = "proc4-ops";
	arr[NFSD_A_SERVER_STATS_PROC4_OPS].type = YNL_PT_NEST;
	arr[NFSD_A_SERVER_STATS_PROC4_OPS].nest = &nfsd_server_proc_entry_nest;
	arr[NFSD_A_SERVER_STATS_PROC4OPS_OPS].name = "proc4ops-ops";
	arr[NFSD_A_SERVER_STATS_PROC4OPS_OPS].type = YNL_PT_NEST;
	arr[NFSD_A_SERVER_STATS_PROC4OPS_OPS].nest = &nfsd_server_proc_entry_nest;
	arr[NFSD_A_SERVER_STATS_PROC4CB_OPS].name = "proc4cb-ops";
	arr[NFSD_A_SERVER_STATS_PROC4CB_OPS].type = YNL_PT_NEST;
	arr[NFSD_A_SERVER_STATS_PROC4CB_OPS].nest = &nfsd_server_proc_entry_nest;
	return arr;
} ();

struct ynl_policy_nest nfsd_server_stats_nest = {
	.max_attr = static_cast<unsigned int>(NFSD_A_SERVER_STATS_MAX),
	.table = nfsd_server_stats_policy.data(),
};

/* Common nested types */
int nfsd_version_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     const nfsd_version&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.major.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_VERSION_MAJOR, obj.major.value());
	}
	if (obj.minor.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_VERSION_MINOR, obj.minor.value());
	}
	if (obj.enabled) {
		ynl_attr_put(nlh, NFSD_A_VERSION_ENABLED, NULL, 0);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int nfsd_version_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	nfsd_version *dst = (nfsd_version *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_VERSION_MAJOR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->major = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_VERSION_MINOR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->minor = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_VERSION_ENABLED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int nfsd_sock_put(struct nlmsghdr *nlh, unsigned int attr_type,
		  const nfsd_sock&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.addr.size() > 0) {
		ynl_attr_put(nlh, NFSD_A_SOCK_ADDR, obj.addr.data(), obj.addr.size());
	}
	if (obj.transport_name.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_SOCK_TRANSPORT_NAME, obj.transport_name.data());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int nfsd_sock_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	nfsd_sock *dst = (nfsd_sock *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SOCK_ADDR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->addr.assign(data, data + len);
		} else if (type == NFSD_A_SOCK_TRANSPORT_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->transport_name.assign(ynl_attr_get_str(attr));
		}
	}

	return 0;
}

int nfsd_expkey_put(struct nlmsghdr *nlh, unsigned int attr_type,
		    const nfsd_expkey&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.seqno.has_value()) {
		ynl_attr_put_u64(nlh, NFSD_A_EXPKEY_SEQNO, obj.seqno.value());
	}
	if (obj.client.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_EXPKEY_CLIENT, obj.client.data());
	}
	if (obj.fsidtype.has_value()) {
		ynl_attr_put_u8(nlh, NFSD_A_EXPKEY_FSIDTYPE, obj.fsidtype.value());
	}
	if (obj.fsid.size() > 0) {
		ynl_attr_put(nlh, NFSD_A_EXPKEY_FSID, obj.fsid.data(), obj.fsid.size());
	}
	if (obj.negative) {
		ynl_attr_put(nlh, NFSD_A_EXPKEY_NEGATIVE, NULL, 0);
	}
	if (obj.expiry.has_value()) {
		ynl_attr_put_u64(nlh, NFSD_A_EXPKEY_EXPIRY, obj.expiry.value());
	}
	if (obj.path.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_EXPKEY_PATH, obj.path.data());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int nfsd_expkey_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	nfsd_expkey *dst = (nfsd_expkey *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_EXPKEY_SEQNO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->seqno = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_EXPKEY_CLIENT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->client.assign(ynl_attr_get_str(attr));
		} else if (type == NFSD_A_EXPKEY_FSIDTYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fsidtype = (__u8)ynl_attr_get_u8(attr);
		} else if (type == NFSD_A_EXPKEY_FSID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->fsid.assign(data, data + len);
		} else if (type == NFSD_A_EXPKEY_NEGATIVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NFSD_A_EXPKEY_EXPIRY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->expiry = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_EXPKEY_PATH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->path.assign(ynl_attr_get_str(attr));
		}
	}

	return 0;
}

int nfsd_server_proc_entry_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	nfsd_server_proc_entry *dst = (nfsd_server_proc_entry *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SERVER_PROC_ENTRY_OP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->op = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_PROC_ENTRY_COUNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->count = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int nfsd_auth_flavor_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 const nfsd_auth_flavor&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.pseudoflavor.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_AUTH_FLAVOR_PSEUDOFLAVOR, obj.pseudoflavor.value());
	}
	if (obj.flags.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_AUTH_FLAVOR_FLAGS, obj.flags.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int nfsd_auth_flavor_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	nfsd_auth_flavor *dst = (nfsd_auth_flavor *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_AUTH_FLAVOR_PSEUDOFLAVOR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->pseudoflavor = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_AUTH_FLAVOR_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int nfsd_fslocation_put(struct nlmsghdr *nlh, unsigned int attr_type,
			const nfsd_fslocation&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.host.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_FSLOCATION_HOST, obj.host.data());
	}
	if (obj.path.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_FSLOCATION_PATH, obj.path.data());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int nfsd_fslocation_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	nfsd_fslocation *dst = (nfsd_fslocation *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_FSLOCATION_HOST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->host.assign(ynl_attr_get_str(attr));
		} else if (type == NFSD_A_FSLOCATION_PATH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->path.assign(ynl_attr_get_str(attr));
		}
	}

	return 0;
}

int nfsd_fslocations_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 const nfsd_fslocations&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (unsigned int i = 0; i < obj.location.size(); i++) {
		nfsd_fslocation_put(nlh, NFSD_A_FSLOCATIONS_LOCATION, obj.location[i]);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int nfsd_fslocations_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	nfsd_fslocations *dst = (nfsd_fslocations *)yarg->data;
	unsigned int n_location = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->location.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (fslocations.location)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_FSLOCATIONS_LOCATION) {
			n_location++;
		}
	}

	if (n_location) {
		dst->location.resize(n_location);
		i = 0;
		parg.rsp_policy = &nfsd_fslocation_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == NFSD_A_FSLOCATIONS_LOCATION) {
				parg.data = &dst->location[i];
				if (nfsd_fslocation_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int nfsd_svc_export_put(struct nlmsghdr *nlh, unsigned int attr_type,
			const nfsd_svc_export&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.seqno.has_value()) {
		ynl_attr_put_u64(nlh, NFSD_A_SVC_EXPORT_SEQNO, obj.seqno.value());
	}
	if (obj.client.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_SVC_EXPORT_CLIENT, obj.client.data());
	}
	if (obj.path.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_SVC_EXPORT_PATH, obj.path.data());
	}
	if (obj.negative) {
		ynl_attr_put(nlh, NFSD_A_SVC_EXPORT_NEGATIVE, NULL, 0);
	}
	if (obj.expiry.has_value()) {
		ynl_attr_put_u64(nlh, NFSD_A_SVC_EXPORT_EXPIRY, obj.expiry.value());
	}
	if (obj.anon_uid.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_SVC_EXPORT_ANON_UID, obj.anon_uid.value());
	}
	if (obj.anon_gid.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_SVC_EXPORT_ANON_GID, obj.anon_gid.value());
	}
	if (obj.fslocations.has_value()) {
		nfsd_fslocations_put(nlh, NFSD_A_SVC_EXPORT_FSLOCATIONS, obj.fslocations.value());
	}
	if (obj.uuid.size() > 0) {
		ynl_attr_put(nlh, NFSD_A_SVC_EXPORT_UUID, obj.uuid.data(), obj.uuid.size());
	}
	for (unsigned int i = 0; i < obj.secinfo.size(); i++) {
		nfsd_auth_flavor_put(nlh, NFSD_A_SVC_EXPORT_SECINFO, obj.secinfo[i]);
	}
	for (unsigned int i = 0; i < obj.xprtsec.size(); i++) {
		ynl_attr_put_u32(nlh, NFSD_A_SVC_EXPORT_XPRTSEC, obj.xprtsec[i]);
	}
	if (obj.flags.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_SVC_EXPORT_FLAGS, obj.flags.value());
	}
	if (obj.fsid.has_value()) {
		ynl_attr_put_s32(nlh, NFSD_A_SVC_EXPORT_FSID, obj.fsid.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int nfsd_svc_export_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	nfsd_svc_export *dst = (nfsd_svc_export *)yarg->data;
	unsigned int n_secinfo = 0;
	unsigned int n_xprtsec = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->secinfo.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (svc-export.secinfo)");
	}
	if (dst->xprtsec.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (svc-export.xprtsec)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SVC_EXPORT_SEQNO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->seqno = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_SVC_EXPORT_CLIENT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->client.assign(ynl_attr_get_str(attr));
		} else if (type == NFSD_A_SVC_EXPORT_PATH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->path.assign(ynl_attr_get_str(attr));
		} else if (type == NFSD_A_SVC_EXPORT_NEGATIVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NFSD_A_SVC_EXPORT_EXPIRY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->expiry = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_SVC_EXPORT_ANON_UID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->anon_uid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SVC_EXPORT_ANON_GID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->anon_gid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SVC_EXPORT_FSLOCATIONS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &nfsd_fslocations_nest;
			parg.data = &dst->fslocations.emplace();
			if (nfsd_fslocations_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NFSD_A_SVC_EXPORT_UUID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->uuid.assign(data, data + len);
		} else if (type == NFSD_A_SVC_EXPORT_SECINFO) {
			n_secinfo++;
		} else if (type == NFSD_A_SVC_EXPORT_XPRTSEC) {
			n_xprtsec++;
		} else if (type == NFSD_A_SVC_EXPORT_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SVC_EXPORT_FSID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fsid = (__s32)ynl_attr_get_s32(attr);
		}
	}

	if (n_secinfo) {
		dst->secinfo.resize(n_secinfo);
		i = 0;
		parg.rsp_policy = &nfsd_auth_flavor_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == NFSD_A_SVC_EXPORT_SECINFO) {
				parg.data = &dst->secinfo[i];
				if (nfsd_auth_flavor_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}
	if (n_xprtsec) {
		dst->xprtsec.resize(n_xprtsec);
		i = 0;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == NFSD_A_SVC_EXPORT_XPRTSEC) {
				dst->xprtsec[i] = ynl_attr_get_u32(attr);
				i++;
			}
		}
	}

	return 0;
}

/* ============== NFSD_CMD_RPC_STATUS_GET ============== */
/* NFSD_CMD_RPC_STATUS_GET - dump */
int nfsd_rpc_status_get_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	unsigned int n_compound_ops = 0;
	nfsd_rpc_status_get_rsp *dst;
	const struct nlattr *attr;
	int i;

	dst = (nfsd_rpc_status_get_rsp*)yarg->data;

	if (dst->compound_ops.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (rpc-status.compound-ops)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_RPC_STATUS_XID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->xid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_PROG) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->prog = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_VERSION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->version = (__u8)ynl_attr_get_u8(attr);
		} else if (type == NFSD_A_RPC_STATUS_PROC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->proc = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_SERVICE_TIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->service_time = (__s64)ynl_attr_get_s64(attr);
		} else if (type == NFSD_A_RPC_STATUS_SADDR4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->saddr4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_DADDR4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->daddr4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_RPC_STATUS_SADDR6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->saddr6.assign(data, data + len);
		} else if (type == NFSD_A_RPC_STATUS_DADDR6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->daddr6.assign(data, data + len);
		} else if (type == NFSD_A_RPC_STATUS_SPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == NFSD_A_RPC_STATUS_DPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == NFSD_A_RPC_STATUS_COMPOUND_OPS) {
			n_compound_ops++;
		}
	}

	if (n_compound_ops) {
		dst->compound_ops.resize(n_compound_ops);
		i = 0;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_RPC_STATUS_COMPOUND_OPS) {
				dst->compound_ops[i] = ynl_attr_get_u32(attr);
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nfsd_rpc_status_get_list>
nfsd_rpc_status_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<nfsd_rpc_status_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nfsd_rpc_status_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<nfsd_rpc_status_get_list*>(arg)->objs.emplace_back());};
	yds.cb = nfsd_rpc_status_get_rsp_parse;
	yds.rsp_cmd = NFSD_CMD_RPC_STATUS_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_RPC_STATUS_GET, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== NFSD_CMD_THREADS_SET ============== */
/* NFSD_CMD_THREADS_SET - do */
int nfsd_threads_set(ynl_cpp::ynl_socket& ys, nfsd_threads_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_THREADS_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_server_nest;

	for (unsigned int i = 0; i < req.threads.size(); i++) {
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_THREADS, req.threads[i]);
	}
	if (req.gracetime.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_GRACETIME, req.gracetime.value());
	}
	if (req.leasetime.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_LEASETIME, req.leasetime.value());
	}
	if (req.scope.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_SERVER_SCOPE, req.scope.data());
	}
	if (req.min_threads.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_MIN_THREADS, req.min_threads.value());
	}
	if (req.fh_key.size() > 0) {
		ynl_attr_put(nlh, NFSD_A_SERVER_FH_KEY, req.fh_key.data(), req.fh_key.size());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_THREADS_GET ============== */
/* NFSD_CMD_THREADS_GET - do */
int nfsd_threads_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	unsigned int n_threads = 0;
	nfsd_threads_get_rsp *dst;
	const struct nlattr *attr;
	int i;

	dst = (nfsd_threads_get_rsp*)yarg->data;

	if (dst->threads.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (server.threads)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SERVER_THREADS) {
			n_threads++;
		} else if (type == NFSD_A_SERVER_GRACETIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gracetime = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_LEASETIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->leasetime = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_SCOPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->scope.assign(ynl_attr_get_str(attr));
		} else if (type == NFSD_A_SERVER_MIN_THREADS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->min_threads = (__u32)ynl_attr_get_u32(attr);
		}
	}

	if (n_threads) {
		dst->threads.resize(n_threads);
		i = 0;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_THREADS) {
				dst->threads[i] = ynl_attr_get_u32(attr);
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nfsd_threads_get_rsp> nfsd_threads_get(ynl_cpp::ynl_socket& ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<nfsd_threads_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_THREADS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_server_nest;
	yrs.yarg.rsp_policy = &nfsd_server_nest;

	rsp.reset(new nfsd_threads_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = nfsd_threads_get_rsp_parse;
	yrs.rsp_cmd = NFSD_CMD_THREADS_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== NFSD_CMD_VERSION_SET ============== */
/* NFSD_CMD_VERSION_SET - do */
int nfsd_version_set(ynl_cpp::ynl_socket& ys, nfsd_version_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_VERSION_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_server_proto_nest;

	for (unsigned int i = 0; i < req.version.size(); i++) {
		nfsd_version_put(nlh, NFSD_A_SERVER_PROTO_VERSION, req.version[i]);
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_VERSION_GET ============== */
/* NFSD_CMD_VERSION_GET - do */
int nfsd_version_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	unsigned int n_version = 0;
	nfsd_version_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = (nfsd_version_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->version.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (server-proto.version)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SERVER_PROTO_VERSION) {
			n_version++;
		}
	}

	if (n_version) {
		dst->version.resize(n_version);
		i = 0;
		parg.rsp_policy = &nfsd_version_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_PROTO_VERSION) {
				parg.data = &dst->version[i];
				if (nfsd_version_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nfsd_version_get_rsp> nfsd_version_get(ynl_cpp::ynl_socket& ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<nfsd_version_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_VERSION_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_server_proto_nest;
	yrs.yarg.rsp_policy = &nfsd_server_proto_nest;

	rsp.reset(new nfsd_version_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = nfsd_version_get_rsp_parse;
	yrs.rsp_cmd = NFSD_CMD_VERSION_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== NFSD_CMD_LISTENER_SET ============== */
/* NFSD_CMD_LISTENER_SET - do */
int nfsd_listener_set(ynl_cpp::ynl_socket& ys, nfsd_listener_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_LISTENER_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_server_sock_nest;

	for (unsigned int i = 0; i < req.addr.size(); i++) {
		nfsd_sock_put(nlh, NFSD_A_SERVER_SOCK_ADDR, req.addr[i]);
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_LISTENER_GET ============== */
/* NFSD_CMD_LISTENER_GET - do */
int nfsd_listener_get_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	nfsd_listener_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_addr = 0;
	int i;

	dst = (nfsd_listener_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->addr.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (server-sock.addr)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SERVER_SOCK_ADDR) {
			n_addr++;
		}
	}

	if (n_addr) {
		dst->addr.resize(n_addr);
		i = 0;
		parg.rsp_policy = &nfsd_sock_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_SOCK_ADDR) {
				parg.data = &dst->addr[i];
				if (nfsd_sock_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nfsd_listener_get_rsp>
nfsd_listener_get(ynl_cpp::ynl_socket& ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<nfsd_listener_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_LISTENER_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_server_sock_nest;
	yrs.yarg.rsp_policy = &nfsd_server_sock_nest;

	rsp.reset(new nfsd_listener_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = nfsd_listener_get_rsp_parse;
	yrs.rsp_cmd = NFSD_CMD_LISTENER_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== NFSD_CMD_POOL_MODE_SET ============== */
/* NFSD_CMD_POOL_MODE_SET - do */
int nfsd_pool_mode_set(ynl_cpp::ynl_socket& ys, nfsd_pool_mode_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_POOL_MODE_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_pool_mode_nest;

	if (req.mode.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_POOL_MODE_MODE, req.mode.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_POOL_MODE_GET ============== */
/* NFSD_CMD_POOL_MODE_GET - do */
int nfsd_pool_mode_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	nfsd_pool_mode_get_rsp *dst;
	const struct nlattr *attr;

	dst = (nfsd_pool_mode_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_POOL_MODE_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mode.assign(ynl_attr_get_str(attr));
		} else if (type == NFSD_A_POOL_MODE_NPOOLS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->npools = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nfsd_pool_mode_get_rsp>
nfsd_pool_mode_get(ynl_cpp::ynl_socket& ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<nfsd_pool_mode_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_POOL_MODE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_pool_mode_nest;
	yrs.yarg.rsp_policy = &nfsd_pool_mode_nest;

	rsp.reset(new nfsd_pool_mode_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = nfsd_pool_mode_get_rsp_parse;
	yrs.rsp_cmd = NFSD_CMD_POOL_MODE_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== NFSD_CMD_SVC_EXPORT_GET_REQS ============== */
/* NFSD_CMD_SVC_EXPORT_GET_REQS - dump */
int nfsd_svc_export_get_reqs_rsp_parse(const struct nlmsghdr *nlh,
				       struct ynl_parse_arg *yarg)
{
	nfsd_svc_export_get_reqs_rsp *dst;
	unsigned int n_requests = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = (nfsd_svc_export_get_reqs_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->requests.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (svc-export-reqs.requests)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SVC_EXPORT_REQS_REQUESTS) {
			n_requests++;
		}
	}

	if (n_requests) {
		dst->requests.resize(n_requests);
		i = 0;
		parg.rsp_policy = &nfsd_svc_export_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SVC_EXPORT_REQS_REQUESTS) {
				parg.data = &dst->requests[i];
				if (nfsd_svc_export_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nfsd_svc_export_get_reqs_list>
nfsd_svc_export_get_reqs_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<nfsd_svc_export_get_reqs_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nfsd_svc_export_reqs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<nfsd_svc_export_get_reqs_list*>(arg)->objs.emplace_back());};
	yds.cb = nfsd_svc_export_get_reqs_rsp_parse;
	yds.rsp_cmd = NFSD_CMD_SVC_EXPORT_GET_REQS;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_SVC_EXPORT_GET_REQS, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== NFSD_CMD_SVC_EXPORT_SET_REQS ============== */
/* NFSD_CMD_SVC_EXPORT_SET_REQS - do */
int nfsd_svc_export_set_reqs(ynl_cpp::ynl_socket& ys,
			     nfsd_svc_export_set_reqs_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_SVC_EXPORT_SET_REQS, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_svc_export_reqs_nest;

	for (unsigned int i = 0; i < req.requests.size(); i++) {
		nfsd_svc_export_put(nlh, NFSD_A_SVC_EXPORT_REQS_REQUESTS, req.requests[i]);
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_EXPKEY_GET_REQS ============== */
/* NFSD_CMD_EXPKEY_GET_REQS - dump */
int nfsd_expkey_get_reqs_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	nfsd_expkey_get_reqs_rsp *dst;
	unsigned int n_requests = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = (nfsd_expkey_get_reqs_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->requests.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (expkey-reqs.requests)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_EXPKEY_REQS_REQUESTS) {
			n_requests++;
		}
	}

	if (n_requests) {
		dst->requests.resize(n_requests);
		i = 0;
		parg.rsp_policy = &nfsd_expkey_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_EXPKEY_REQS_REQUESTS) {
				parg.data = &dst->requests[i];
				if (nfsd_expkey_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nfsd_expkey_get_reqs_list>
nfsd_expkey_get_reqs_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<nfsd_expkey_get_reqs_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nfsd_expkey_reqs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<nfsd_expkey_get_reqs_list*>(arg)->objs.emplace_back());};
	yds.cb = nfsd_expkey_get_reqs_rsp_parse;
	yds.rsp_cmd = NFSD_CMD_EXPKEY_GET_REQS;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_EXPKEY_GET_REQS, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== NFSD_CMD_EXPKEY_SET_REQS ============== */
/* NFSD_CMD_EXPKEY_SET_REQS - do */
int nfsd_expkey_set_reqs(ynl_cpp::ynl_socket& ys,
			 nfsd_expkey_set_reqs_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_EXPKEY_SET_REQS, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_expkey_reqs_nest;

	for (unsigned int i = 0; i < req.requests.size(); i++) {
		nfsd_expkey_put(nlh, NFSD_A_EXPKEY_REQS_REQUESTS, req.requests[i]);
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_CACHE_FLUSH ============== */
/* NFSD_CMD_CACHE_FLUSH - do */
int nfsd_cache_flush(ynl_cpp::ynl_socket& ys, nfsd_cache_flush_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_CACHE_FLUSH, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_cache_flush_nest;

	if (req.mask.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_CACHE_FLUSH_MASK, req.mask.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_UNLOCK_IP ============== */
/* NFSD_CMD_UNLOCK_IP - do */
int nfsd_unlock_ip(ynl_cpp::ynl_socket& ys, nfsd_unlock_ip_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_UNLOCK_IP, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_unlock_ip_nest;

	if (req.address.size() > 0) {
		ynl_attr_put(nlh, NFSD_A_UNLOCK_IP_ADDRESS, req.address.data(), req.address.size());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_UNLOCK_FILESYSTEM ============== */
/* NFSD_CMD_UNLOCK_FILESYSTEM - do */
int nfsd_unlock_filesystem(ynl_cpp::ynl_socket& ys,
			   nfsd_unlock_filesystem_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_UNLOCK_FILESYSTEM, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_unlock_filesystem_nest;

	if (req.path.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_UNLOCK_FILESYSTEM_PATH, req.path.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_UNLOCK_EXPORT ============== */
/* NFSD_CMD_UNLOCK_EXPORT - do */
int nfsd_unlock_export(ynl_cpp::ynl_socket& ys, nfsd_unlock_export_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_UNLOCK_EXPORT, 1);
	((struct ynl_sock*)ys)->req_policy = &nfsd_unlock_export_nest;

	if (req.path.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_UNLOCK_EXPORT_PATH, req.path.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NFSD_CMD_SERVER_STATS_GET ============== */
/* NFSD_CMD_SERVER_STATS_GET - dump */
int nfsd_server_stats_get_rsp_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	unsigned int n_proc4ops_ops = 0;
	nfsd_server_stats_get_rsp *dst;
	unsigned int n_proc4cb_ops = 0;
	unsigned int n_proc2_ops = 0;
	unsigned int n_proc3_ops = 0;
	unsigned int n_proc4_ops = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = (nfsd_server_stats_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->proc2_ops.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (server-stats.proc2-ops)");
	}
	if (dst->proc3_ops.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (server-stats.proc3-ops)");
	}
	if (dst->proc4_ops.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (server-stats.proc4-ops)");
	}
	if (dst->proc4cb_ops.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (server-stats.proc4cb-ops)");
	}
	if (dst->proc4ops_ops.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (server-stats.proc4ops-ops)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_SERVER_STATS_RC_HITS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rc_hits = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_SERVER_STATS_RC_MISSES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rc_misses = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_SERVER_STATS_RC_NOCACHE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rc_nocache = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_SERVER_STATS_FH_STALE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fh_stale = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_SERVER_STATS_IO_READ) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->io_read = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_SERVER_STATS_IO_WRITE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->io_write = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NFSD_A_SERVER_STATS_NETCNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->netcnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_STATS_NETUDPCNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->netudpcnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_STATS_NETTCPCNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->nettcpcnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_STATS_NETTCPCONN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->nettcpconn = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_STATS_RPCCNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rpccnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_STATS_RPCBADFMT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rpcbadfmt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_STATS_RPCBADAUTH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rpcbadauth = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_STATS_RPCBADCLNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rpcbadclnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NFSD_A_SERVER_STATS_PROC2_OPS) {
			n_proc2_ops++;
		} else if (type == NFSD_A_SERVER_STATS_PROC3_OPS) {
			n_proc3_ops++;
		} else if (type == NFSD_A_SERVER_STATS_PROC4_OPS) {
			n_proc4_ops++;
		} else if (type == NFSD_A_SERVER_STATS_PROC4OPS_OPS) {
			n_proc4ops_ops++;
		} else if (type == NFSD_A_SERVER_STATS_PROC4CB_OPS) {
			n_proc4cb_ops++;
		}
	}

	if (n_proc2_ops) {
		dst->proc2_ops.resize(n_proc2_ops);
		i = 0;
		parg.rsp_policy = &nfsd_server_proc_entry_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_STATS_PROC2_OPS) {
				parg.data = &dst->proc2_ops[i];
				if (nfsd_server_proc_entry_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}
	if (n_proc3_ops) {
		dst->proc3_ops.resize(n_proc3_ops);
		i = 0;
		parg.rsp_policy = &nfsd_server_proc_entry_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_STATS_PROC3_OPS) {
				parg.data = &dst->proc3_ops[i];
				if (nfsd_server_proc_entry_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}
	if (n_proc4_ops) {
		dst->proc4_ops.resize(n_proc4_ops);
		i = 0;
		parg.rsp_policy = &nfsd_server_proc_entry_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_STATS_PROC4_OPS) {
				parg.data = &dst->proc4_ops[i];
				if (nfsd_server_proc_entry_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}
	if (n_proc4cb_ops) {
		dst->proc4cb_ops.resize(n_proc4cb_ops);
		i = 0;
		parg.rsp_policy = &nfsd_server_proc_entry_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_STATS_PROC4CB_OPS) {
				parg.data = &dst->proc4cb_ops[i];
				if (nfsd_server_proc_entry_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}
	if (n_proc4ops_ops) {
		dst->proc4ops_ops.resize(n_proc4ops_ops);
		i = 0;
		parg.rsp_policy = &nfsd_server_proc_entry_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == NFSD_A_SERVER_STATS_PROC4OPS_OPS) {
				parg.data = &dst->proc4ops_ops[i];
				if (nfsd_server_proc_entry_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nfsd_server_stats_get_list>
nfsd_server_stats_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<nfsd_server_stats_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nfsd_server_stats_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<nfsd_server_stats_get_list*>(arg)->objs.emplace_back());};
	yds.cb = nfsd_server_stats_get_rsp_parse;
	yds.rsp_cmd = NFSD_CMD_SERVER_STATS_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, NFSD_CMD_SERVER_STATS_GET, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* NFSD_CMD_CACHE_NOTIFY - event */
int nfsd_cache_notify_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	nfsd_cache_notify_rsp *dst;
	const struct nlattr *attr;

	dst = (nfsd_cache_notify_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NFSD_A_CACHE_NOTIFY_CACHE_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cache_type = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

static void nfsd_cache_notify_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<nfsd_cache_notify*>(ntf);
	typed_ntf->obj.~nfsd_cache_notify_rsp();
	free(ntf);
}

static constexpr std::array<ynl_ntf_info, NFSD_CMD_CACHE_NOTIFY + 1> nfsd_ntf_info = []() {
	std::array<ynl_ntf_info, NFSD_CMD_CACHE_NOTIFY + 1> arr{};
	arr[NFSD_CMD_CACHE_NOTIFY].policy		= &nfsd_cache_notify_nest;
	arr[NFSD_CMD_CACHE_NOTIFY].cb		= nfsd_cache_notify_rsp_parse;
	arr[NFSD_CMD_CACHE_NOTIFY].alloc_sz	= sizeof(nfsd_cache_notify);
	arr[NFSD_CMD_CACHE_NOTIFY].free		= nfsd_cache_notify_free;
	return arr;
} ();

const struct ynl_family ynl_nfsd_family =  {
	.name		= "nfsd",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= nfsd_ntf_info.data(),
	.ntf_info_size	= nfsd_ntf_info.size(),
};
const struct ynl_family& get_ynl_nfsd_family() {
	return ynl_nfsd_family;
};
} //namespace ynl_cpp
