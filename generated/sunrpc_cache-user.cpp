// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "sunrpc_cache-user.hpp"

#include <array>

#include <linux/sunrpc_netlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, SUNRPC_CMD_CACHE_FLUSH + 1> sunrpc_op_strmap = []() {
	std::array<std::string_view, SUNRPC_CMD_CACHE_FLUSH + 1> arr{};
	arr[SUNRPC_CMD_CACHE_NOTIFY] = "cache-notify";
	arr[SUNRPC_CMD_IP_MAP_GET_REQS] = "ip-map-get-reqs";
	arr[SUNRPC_CMD_IP_MAP_SET_REQS] = "ip-map-set-reqs";
	arr[SUNRPC_CMD_UNIX_GID_GET_REQS] = "unix-gid-get-reqs";
	arr[SUNRPC_CMD_UNIX_GID_SET_REQS] = "unix-gid-set-reqs";
	arr[SUNRPC_CMD_CACHE_FLUSH] = "cache-flush";
	return arr;
} ();

std::string_view sunrpc_op_str(int op)
{
	if (op < 0 || op >= (int)(sunrpc_op_strmap.size())) {
		return "";
	}
	return sunrpc_op_strmap[op];
}

static constexpr std::array<std::string_view, 1 + 1> sunrpc_cache_type_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "ip_map";
	arr[1] = "unix_gid";
	return arr;
} ();

std::string_view sunrpc_cache_type_str(sunrpc_cache_type value)
{
	value = (sunrpc_cache_type)(ffs(value) - 1);
	if (value < 0 || value >= (int)(sunrpc_cache_type_strmap.size())) {
		return "";
	}
	return sunrpc_cache_type_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,SUNRPC_A_IP_MAP_MAX + 1> sunrpc_ip_map_policy = []() {
	std::array<ynl_policy_attr,SUNRPC_A_IP_MAP_MAX + 1> arr{};
	arr[SUNRPC_A_IP_MAP_SEQNO].name = "seqno";
	arr[SUNRPC_A_IP_MAP_SEQNO].type = YNL_PT_U64;
	arr[SUNRPC_A_IP_MAP_CLASS].name = "class";
	arr[SUNRPC_A_IP_MAP_CLASS].type  = YNL_PT_NUL_STR;
	arr[SUNRPC_A_IP_MAP_ADDR].name = "addr";
	arr[SUNRPC_A_IP_MAP_ADDR].type  = YNL_PT_NUL_STR;
	arr[SUNRPC_A_IP_MAP_DOMAIN].name = "domain";
	arr[SUNRPC_A_IP_MAP_DOMAIN].type  = YNL_PT_NUL_STR;
	arr[SUNRPC_A_IP_MAP_NEGATIVE].name = "negative";
	arr[SUNRPC_A_IP_MAP_NEGATIVE].type = YNL_PT_FLAG;
	arr[SUNRPC_A_IP_MAP_EXPIRY].name = "expiry";
	arr[SUNRPC_A_IP_MAP_EXPIRY].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest sunrpc_ip_map_nest = {
	.max_attr = static_cast<unsigned int>(SUNRPC_A_IP_MAP_MAX),
	.table = sunrpc_ip_map_policy.data(),
};

static std::array<ynl_policy_attr,SUNRPC_A_UNIX_GID_MAX + 1> sunrpc_unix_gid_policy = []() {
	std::array<ynl_policy_attr,SUNRPC_A_UNIX_GID_MAX + 1> arr{};
	arr[SUNRPC_A_UNIX_GID_SEQNO].name = "seqno";
	arr[SUNRPC_A_UNIX_GID_SEQNO].type = YNL_PT_U64;
	arr[SUNRPC_A_UNIX_GID_UID].name = "uid";
	arr[SUNRPC_A_UNIX_GID_UID].type = YNL_PT_U32;
	arr[SUNRPC_A_UNIX_GID_GIDS].name = "gids";
	arr[SUNRPC_A_UNIX_GID_GIDS].type = YNL_PT_U32;
	arr[SUNRPC_A_UNIX_GID_NEGATIVE].name = "negative";
	arr[SUNRPC_A_UNIX_GID_NEGATIVE].type = YNL_PT_FLAG;
	arr[SUNRPC_A_UNIX_GID_EXPIRY].name = "expiry";
	arr[SUNRPC_A_UNIX_GID_EXPIRY].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest sunrpc_unix_gid_nest = {
	.max_attr = static_cast<unsigned int>(SUNRPC_A_UNIX_GID_MAX),
	.table = sunrpc_unix_gid_policy.data(),
};

static std::array<ynl_policy_attr,SUNRPC_A_CACHE_NOTIFY_MAX + 1> sunrpc_cache_notify_policy = []() {
	std::array<ynl_policy_attr,SUNRPC_A_CACHE_NOTIFY_MAX + 1> arr{};
	arr[SUNRPC_A_CACHE_NOTIFY_CACHE_TYPE].name = "cache-type";
	arr[SUNRPC_A_CACHE_NOTIFY_CACHE_TYPE].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest sunrpc_cache_notify_nest = {
	.max_attr = static_cast<unsigned int>(SUNRPC_A_CACHE_NOTIFY_MAX),
	.table = sunrpc_cache_notify_policy.data(),
};

static std::array<ynl_policy_attr,SUNRPC_A_IP_MAP_REQS_MAX + 1> sunrpc_ip_map_reqs_policy = []() {
	std::array<ynl_policy_attr,SUNRPC_A_IP_MAP_REQS_MAX + 1> arr{};
	arr[SUNRPC_A_IP_MAP_REQS_REQUESTS].name = "requests";
	arr[SUNRPC_A_IP_MAP_REQS_REQUESTS].type = YNL_PT_NEST;
	arr[SUNRPC_A_IP_MAP_REQS_REQUESTS].nest = &sunrpc_ip_map_nest;
	return arr;
} ();

struct ynl_policy_nest sunrpc_ip_map_reqs_nest = {
	.max_attr = static_cast<unsigned int>(SUNRPC_A_IP_MAP_REQS_MAX),
	.table = sunrpc_ip_map_reqs_policy.data(),
};

static std::array<ynl_policy_attr,SUNRPC_A_UNIX_GID_REQS_MAX + 1> sunrpc_unix_gid_reqs_policy = []() {
	std::array<ynl_policy_attr,SUNRPC_A_UNIX_GID_REQS_MAX + 1> arr{};
	arr[SUNRPC_A_UNIX_GID_REQS_REQUESTS].name = "requests";
	arr[SUNRPC_A_UNIX_GID_REQS_REQUESTS].type = YNL_PT_NEST;
	arr[SUNRPC_A_UNIX_GID_REQS_REQUESTS].nest = &sunrpc_unix_gid_nest;
	return arr;
} ();

struct ynl_policy_nest sunrpc_unix_gid_reqs_nest = {
	.max_attr = static_cast<unsigned int>(SUNRPC_A_UNIX_GID_REQS_MAX),
	.table = sunrpc_unix_gid_reqs_policy.data(),
};

static std::array<ynl_policy_attr,SUNRPC_A_CACHE_FLUSH_MAX + 1> sunrpc_cache_flush_policy = []() {
	std::array<ynl_policy_attr,SUNRPC_A_CACHE_FLUSH_MAX + 1> arr{};
	arr[SUNRPC_A_CACHE_FLUSH_MASK].name = "mask";
	arr[SUNRPC_A_CACHE_FLUSH_MASK].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest sunrpc_cache_flush_nest = {
	.max_attr = static_cast<unsigned int>(SUNRPC_A_CACHE_FLUSH_MAX),
	.table = sunrpc_cache_flush_policy.data(),
};

/* Common nested types */
int sunrpc_ip_map_put(struct nlmsghdr *nlh, unsigned int attr_type,
		      const sunrpc_ip_map&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.seqno.has_value()) {
		ynl_attr_put_u64(nlh, SUNRPC_A_IP_MAP_SEQNO, obj.seqno.value());
	}
	if (obj.class_.size() > 0) {
		ynl_attr_put_str(nlh, SUNRPC_A_IP_MAP_CLASS, obj.class_.data());
	}
	if (obj.addr.size() > 0) {
		ynl_attr_put_str(nlh, SUNRPC_A_IP_MAP_ADDR, obj.addr.data());
	}
	if (obj.domain.size() > 0) {
		ynl_attr_put_str(nlh, SUNRPC_A_IP_MAP_DOMAIN, obj.domain.data());
	}
	if (obj.negative) {
		ynl_attr_put(nlh, SUNRPC_A_IP_MAP_NEGATIVE, NULL, 0);
	}
	if (obj.expiry.has_value()) {
		ynl_attr_put_u64(nlh, SUNRPC_A_IP_MAP_EXPIRY, obj.expiry.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int sunrpc_ip_map_parse(struct ynl_parse_arg *yarg,
			const struct nlattr *nested)
{
	sunrpc_ip_map *dst = (sunrpc_ip_map *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == SUNRPC_A_IP_MAP_SEQNO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->seqno = (__u64)ynl_attr_get_u64(attr);
		} else if (type == SUNRPC_A_IP_MAP_CLASS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->class_.assign(ynl_attr_get_str(attr));
		} else if (type == SUNRPC_A_IP_MAP_ADDR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->addr.assign(ynl_attr_get_str(attr));
		} else if (type == SUNRPC_A_IP_MAP_DOMAIN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->domain.assign(ynl_attr_get_str(attr));
		} else if (type == SUNRPC_A_IP_MAP_NEGATIVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == SUNRPC_A_IP_MAP_EXPIRY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->expiry = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int sunrpc_unix_gid_put(struct nlmsghdr *nlh, unsigned int attr_type,
			const sunrpc_unix_gid&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.seqno.has_value()) {
		ynl_attr_put_u64(nlh, SUNRPC_A_UNIX_GID_SEQNO, obj.seqno.value());
	}
	if (obj.uid.has_value()) {
		ynl_attr_put_u32(nlh, SUNRPC_A_UNIX_GID_UID, obj.uid.value());
	}
	for (unsigned int i = 0; i < obj.gids.size(); i++) {
		ynl_attr_put_u32(nlh, SUNRPC_A_UNIX_GID_GIDS, obj.gids[i]);
	}
	if (obj.negative) {
		ynl_attr_put(nlh, SUNRPC_A_UNIX_GID_NEGATIVE, NULL, 0);
	}
	if (obj.expiry.has_value()) {
		ynl_attr_put_u64(nlh, SUNRPC_A_UNIX_GID_EXPIRY, obj.expiry.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int sunrpc_unix_gid_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	sunrpc_unix_gid *dst = (sunrpc_unix_gid *)yarg->data;
	const struct nlattr *attr;
	unsigned int n_gids = 0;
	int i;

	if (dst->gids.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (unix-gid.gids)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == SUNRPC_A_UNIX_GID_SEQNO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->seqno = (__u64)ynl_attr_get_u64(attr);
		} else if (type == SUNRPC_A_UNIX_GID_UID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->uid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == SUNRPC_A_UNIX_GID_GIDS) {
			n_gids++;
		} else if (type == SUNRPC_A_UNIX_GID_NEGATIVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == SUNRPC_A_UNIX_GID_EXPIRY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->expiry = (__u64)ynl_attr_get_u64(attr);
		}
	}

	if (n_gids) {
		dst->gids.resize(n_gids);
		i = 0;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == SUNRPC_A_UNIX_GID_GIDS) {
				dst->gids[i] = ynl_attr_get_u32(attr);
				i++;
			}
		}
	}

	return 0;
}

/* ============== SUNRPC_CMD_IP_MAP_GET_REQS ============== */
/* SUNRPC_CMD_IP_MAP_GET_REQS - dump */
int sunrpc_ip_map_get_reqs_rsp_parse(const struct nlmsghdr *nlh,
				     struct ynl_parse_arg *yarg)
{
	sunrpc_ip_map_get_reqs_rsp *dst;
	unsigned int n_requests = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = (sunrpc_ip_map_get_reqs_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->requests.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (ip-map-reqs.requests)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == SUNRPC_A_IP_MAP_REQS_REQUESTS) {
			n_requests++;
		}
	}

	if (n_requests) {
		dst->requests.resize(n_requests);
		i = 0;
		parg.rsp_policy = &sunrpc_ip_map_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == SUNRPC_A_IP_MAP_REQS_REQUESTS) {
				parg.data = &dst->requests[i];
				if (sunrpc_ip_map_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<sunrpc_ip_map_get_reqs_list>
sunrpc_ip_map_get_reqs_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<sunrpc_ip_map_get_reqs_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &sunrpc_ip_map_reqs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<sunrpc_ip_map_get_reqs_list*>(arg)->objs.emplace_back());};
	yds.cb = sunrpc_ip_map_get_reqs_rsp_parse;
	yds.rsp_cmd = SUNRPC_CMD_IP_MAP_GET_REQS;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, SUNRPC_CMD_IP_MAP_GET_REQS, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== SUNRPC_CMD_IP_MAP_SET_REQS ============== */
/* SUNRPC_CMD_IP_MAP_SET_REQS - do */
int sunrpc_ip_map_set_reqs(ynl_cpp::ynl_socket& ys,
			   sunrpc_ip_map_set_reqs_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, SUNRPC_CMD_IP_MAP_SET_REQS, 1);
	((struct ynl_sock*)ys)->req_policy = &sunrpc_ip_map_reqs_nest;

	for (unsigned int i = 0; i < req.requests.size(); i++) {
		sunrpc_ip_map_put(nlh, SUNRPC_A_IP_MAP_REQS_REQUESTS, req.requests[i]);
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== SUNRPC_CMD_UNIX_GID_GET_REQS ============== */
/* SUNRPC_CMD_UNIX_GID_GET_REQS - dump */
int sunrpc_unix_gid_get_reqs_rsp_parse(const struct nlmsghdr *nlh,
				       struct ynl_parse_arg *yarg)
{
	sunrpc_unix_gid_get_reqs_rsp *dst;
	unsigned int n_requests = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = (sunrpc_unix_gid_get_reqs_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->requests.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (unix-gid-reqs.requests)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == SUNRPC_A_UNIX_GID_REQS_REQUESTS) {
			n_requests++;
		}
	}

	if (n_requests) {
		dst->requests.resize(n_requests);
		i = 0;
		parg.rsp_policy = &sunrpc_unix_gid_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == SUNRPC_A_UNIX_GID_REQS_REQUESTS) {
				parg.data = &dst->requests[i];
				if (sunrpc_unix_gid_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<sunrpc_unix_gid_get_reqs_list>
sunrpc_unix_gid_get_reqs_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<sunrpc_unix_gid_get_reqs_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &sunrpc_unix_gid_reqs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<sunrpc_unix_gid_get_reqs_list*>(arg)->objs.emplace_back());};
	yds.cb = sunrpc_unix_gid_get_reqs_rsp_parse;
	yds.rsp_cmd = SUNRPC_CMD_UNIX_GID_GET_REQS;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, SUNRPC_CMD_UNIX_GID_GET_REQS, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== SUNRPC_CMD_UNIX_GID_SET_REQS ============== */
/* SUNRPC_CMD_UNIX_GID_SET_REQS - do */
int sunrpc_unix_gid_set_reqs(ynl_cpp::ynl_socket& ys,
			     sunrpc_unix_gid_set_reqs_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, SUNRPC_CMD_UNIX_GID_SET_REQS, 1);
	((struct ynl_sock*)ys)->req_policy = &sunrpc_unix_gid_reqs_nest;

	for (unsigned int i = 0; i < req.requests.size(); i++) {
		sunrpc_unix_gid_put(nlh, SUNRPC_A_UNIX_GID_REQS_REQUESTS, req.requests[i]);
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== SUNRPC_CMD_CACHE_FLUSH ============== */
/* SUNRPC_CMD_CACHE_FLUSH - do */
int sunrpc_cache_flush(ynl_cpp::ynl_socket& ys, sunrpc_cache_flush_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, SUNRPC_CMD_CACHE_FLUSH, 1);
	((struct ynl_sock*)ys)->req_policy = &sunrpc_cache_flush_nest;

	if (req.mask.has_value()) {
		ynl_attr_put_u32(nlh, SUNRPC_A_CACHE_FLUSH_MASK, req.mask.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* SUNRPC_CMD_CACHE_NOTIFY - event */
int sunrpc_cache_notify_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	sunrpc_cache_notify_rsp *dst;
	const struct nlattr *attr;

	dst = (sunrpc_cache_notify_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == SUNRPC_A_CACHE_NOTIFY_CACHE_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cache_type = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

static void sunrpc_cache_notify_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<sunrpc_cache_notify*>(ntf);
	typed_ntf->obj.~sunrpc_cache_notify_rsp();
	free(ntf);
}

static constexpr std::array<ynl_ntf_info, SUNRPC_CMD_CACHE_NOTIFY + 1> sunrpc_ntf_info = []() {
	std::array<ynl_ntf_info, SUNRPC_CMD_CACHE_NOTIFY + 1> arr{};
	arr[SUNRPC_CMD_CACHE_NOTIFY].policy		= &sunrpc_cache_notify_nest;
	arr[SUNRPC_CMD_CACHE_NOTIFY].cb		= sunrpc_cache_notify_rsp_parse;
	arr[SUNRPC_CMD_CACHE_NOTIFY].alloc_sz	= sizeof(sunrpc_cache_notify);
	arr[SUNRPC_CMD_CACHE_NOTIFY].free		= sunrpc_cache_notify_free;
	return arr;
} ();

const struct ynl_family ynl_sunrpc_family =  {
	.name		= "sunrpc",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= sunrpc_ntf_info.data(),
	.ntf_info_size	= sunrpc_ntf_info.size(),
};
const struct ynl_family& get_ynl_sunrpc_family() {
	return ynl_sunrpc_family;
};
} //namespace ynl_cpp
