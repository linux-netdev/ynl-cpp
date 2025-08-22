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
static constexpr std::array<std::string_view, NFSD_CMD_POOL_MODE_GET + 1> nfsd_op_strmap = []() {
	std::array<std::string_view, NFSD_CMD_POOL_MODE_GET + 1> arr{};
	arr[NFSD_CMD_RPC_STATUS_GET] = "rpc-status-get";
	arr[NFSD_CMD_THREADS_SET] = "threads-set";
	arr[NFSD_CMD_THREADS_GET] = "threads-get";
	arr[NFSD_CMD_VERSION_SET] = "version-set";
	arr[NFSD_CMD_VERSION_GET] = "version-get";
	arr[NFSD_CMD_LISTENER_SET] = "listener-set";
	arr[NFSD_CMD_LISTENER_GET] = "listener-get";
	arr[NFSD_CMD_POOL_MODE_SET] = "pool-mode-set";
	arr[NFSD_CMD_POOL_MODE_GET] = "pool-mode-get";
	return arr;
} ();

std::string_view nfsd_op_str(int op)
{
	if (op < 0 || op >= (int)(nfsd_op_strmap.size())) {
		return "";
	}
	return nfsd_op_strmap[op];
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

/* ============== NFSD_CMD_RPC_STATUS_GET ============== */
/* NFSD_CMD_RPC_STATUS_GET - dump */
int nfsd_rpc_status_get_rsp_dump_parse(const struct nlmsghdr *nlh,
				       struct ynl_parse_arg *yarg)
{
	nfsd_rpc_status_get_rsp_dump *dst;
	unsigned int n_compound_ops = 0;
	const struct nlattr *attr;
	int i;

	dst = (nfsd_rpc_status_get_rsp_dump*)yarg->data;

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

std::unique_ptr<nfsd_rpc_status_get_rsp_list>
nfsd_rpc_status_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<nfsd_rpc_status_get_rsp_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nfsd_rpc_status_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<nfsd_rpc_status_get_rsp_list*>(arg)->objs.emplace_back());};
	yds.cb = nfsd_rpc_status_get_rsp_dump_parse;
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

	for (unsigned int i = 0; i < req.threads.size(); i++)
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_THREADS, req.threads[i]);
	if (req.gracetime.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_GRACETIME, req.gracetime.value());
	}
	if (req.leasetime.has_value()) {
		ynl_attr_put_u32(nlh, NFSD_A_SERVER_LEASETIME, req.leasetime.value());
	}
	if (req.scope.size() > 0) {
		ynl_attr_put_str(nlh, NFSD_A_SERVER_SCOPE, req.scope.data());
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

	for (unsigned int i = 0; i < req.version.size(); i++)
		nfsd_version_put(nlh, NFSD_A_SERVER_PROTO_VERSION, req.version[i]);

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

	for (unsigned int i = 0; i < req.addr.size(); i++)
		nfsd_sock_put(nlh, NFSD_A_SERVER_SOCK_ADDR, req.addr[i]);

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

const struct ynl_family ynl_nfsd_family =  {
	.name		= "nfsd",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_nfsd_family() {
	return ynl_nfsd_family;
};
} //namespace ynl_cpp
