// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "net_shaper-user.hpp"

#include <array>

#include <linux/net_shaper.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, NET_SHAPER_CMD_CAP_GET + 1> net_shaper_op_strmap = []() {
	std::array<std::string_view, NET_SHAPER_CMD_CAP_GET + 1> arr{};
	arr[NET_SHAPER_CMD_GET] = "get";
	arr[NET_SHAPER_CMD_SET] = "set";
	arr[NET_SHAPER_CMD_DELETE] = "delete";
	arr[NET_SHAPER_CMD_GROUP] = "group";
	arr[NET_SHAPER_CMD_CAP_GET] = "cap-get";
	return arr;
} ();

std::string_view net_shaper_op_str(int op)
{
	if (op < 0 || op >= (int)(net_shaper_op_strmap.size())) {
		return "";
	}
	return net_shaper_op_strmap[op];
}

static constexpr std::array<std::string_view, 3 + 1> net_shaper_scope_strmap = []() {
	std::array<std::string_view, 3 + 1> arr{};
	arr[0] = "unspec";
	arr[1] = "netdev";
	arr[2] = "queue";
	arr[3] = "node";
	return arr;
} ();

std::string_view net_shaper_scope_str(net_shaper_scope value)
{
	if (value < 0 || value >= (int)(net_shaper_scope_strmap.size())) {
		return "";
	}
	return net_shaper_scope_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> net_shaper_metric_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "bps";
	arr[1] = "pps";
	return arr;
} ();

std::string_view net_shaper_metric_str(net_shaper_metric value)
{
	if (value < 0 || value >= (int)(net_shaper_metric_strmap.size())) {
		return "";
	}
	return net_shaper_metric_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,NET_SHAPER_A_HANDLE_MAX + 1> net_shaper_handle_policy = []() {
	std::array<ynl_policy_attr,NET_SHAPER_A_HANDLE_MAX + 1> arr{};
	arr[NET_SHAPER_A_HANDLE_SCOPE].name = "scope";
	arr[NET_SHAPER_A_HANDLE_SCOPE].type = YNL_PT_U32;
	arr[NET_SHAPER_A_HANDLE_ID].name = "id";
	arr[NET_SHAPER_A_HANDLE_ID].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest net_shaper_handle_nest = {
	.max_attr = static_cast<unsigned int>(NET_SHAPER_A_HANDLE_MAX),
	.table = net_shaper_handle_policy.data(),
};

static std::array<ynl_policy_attr,NET_SHAPER_A_MAX + 1> net_shaper_leaf_info_policy = []() {
	std::array<ynl_policy_attr,NET_SHAPER_A_MAX + 1> arr{};
	arr[NET_SHAPER_A_HANDLE].name = "handle";
	arr[NET_SHAPER_A_HANDLE].type = YNL_PT_NEST;
	arr[NET_SHAPER_A_HANDLE].nest = &net_shaper_handle_nest;
	arr[NET_SHAPER_A_PRIORITY].name = "priority";
	arr[NET_SHAPER_A_PRIORITY].type = YNL_PT_U32;
	arr[NET_SHAPER_A_WEIGHT].name = "weight";
	arr[NET_SHAPER_A_WEIGHT].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest net_shaper_leaf_info_nest = {
	.max_attr = static_cast<unsigned int>(NET_SHAPER_A_MAX),
	.table = net_shaper_leaf_info_policy.data(),
};

static std::array<ynl_policy_attr,NET_SHAPER_A_MAX + 1> net_shaper_net_shaper_policy = []() {
	std::array<ynl_policy_attr,NET_SHAPER_A_MAX + 1> arr{};
	arr[NET_SHAPER_A_HANDLE].name = "handle";
	arr[NET_SHAPER_A_HANDLE].type = YNL_PT_NEST;
	arr[NET_SHAPER_A_HANDLE].nest = &net_shaper_handle_nest;
	arr[NET_SHAPER_A_METRIC].name = "metric";
	arr[NET_SHAPER_A_METRIC].type = YNL_PT_U32;
	arr[NET_SHAPER_A_BW_MIN].name = "bw-min";
	arr[NET_SHAPER_A_BW_MIN].type = YNL_PT_UINT;
	arr[NET_SHAPER_A_BW_MAX].name = "bw-max";
	arr[NET_SHAPER_A_BW_MAX].type = YNL_PT_UINT;
	arr[NET_SHAPER_A_BURST].name = "burst";
	arr[NET_SHAPER_A_BURST].type = YNL_PT_UINT;
	arr[NET_SHAPER_A_PRIORITY].name = "priority";
	arr[NET_SHAPER_A_PRIORITY].type = YNL_PT_U32;
	arr[NET_SHAPER_A_WEIGHT].name = "weight";
	arr[NET_SHAPER_A_WEIGHT].type = YNL_PT_U32;
	arr[NET_SHAPER_A_IFINDEX].name = "ifindex";
	arr[NET_SHAPER_A_IFINDEX].type = YNL_PT_U32;
	arr[NET_SHAPER_A_PARENT].name = "parent";
	arr[NET_SHAPER_A_PARENT].type = YNL_PT_NEST;
	arr[NET_SHAPER_A_PARENT].nest = &net_shaper_handle_nest;
	arr[NET_SHAPER_A_LEAVES].name = "leaves";
	arr[NET_SHAPER_A_LEAVES].type = YNL_PT_NEST;
	arr[NET_SHAPER_A_LEAVES].nest = &net_shaper_leaf_info_nest;
	return arr;
} ();

struct ynl_policy_nest net_shaper_net_shaper_nest = {
	.max_attr = static_cast<unsigned int>(NET_SHAPER_A_MAX),
	.table = net_shaper_net_shaper_policy.data(),
};

static std::array<ynl_policy_attr,NET_SHAPER_A_CAPS_MAX + 1> net_shaper_caps_policy = []() {
	std::array<ynl_policy_attr,NET_SHAPER_A_CAPS_MAX + 1> arr{};
	arr[NET_SHAPER_A_CAPS_IFINDEX].name = "ifindex";
	arr[NET_SHAPER_A_CAPS_IFINDEX].type = YNL_PT_U32;
	arr[NET_SHAPER_A_CAPS_SCOPE].name = "scope";
	arr[NET_SHAPER_A_CAPS_SCOPE].type = YNL_PT_U32;
	arr[NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS].name = "support-metric-bps";
	arr[NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS].type = YNL_PT_FLAG;
	arr[NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS].name = "support-metric-pps";
	arr[NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS].type = YNL_PT_FLAG;
	arr[NET_SHAPER_A_CAPS_SUPPORT_NESTING].name = "support-nesting";
	arr[NET_SHAPER_A_CAPS_SUPPORT_NESTING].type = YNL_PT_FLAG;
	arr[NET_SHAPER_A_CAPS_SUPPORT_BW_MIN].name = "support-bw-min";
	arr[NET_SHAPER_A_CAPS_SUPPORT_BW_MIN].type = YNL_PT_FLAG;
	arr[NET_SHAPER_A_CAPS_SUPPORT_BW_MAX].name = "support-bw-max";
	arr[NET_SHAPER_A_CAPS_SUPPORT_BW_MAX].type = YNL_PT_FLAG;
	arr[NET_SHAPER_A_CAPS_SUPPORT_BURST].name = "support-burst";
	arr[NET_SHAPER_A_CAPS_SUPPORT_BURST].type = YNL_PT_FLAG;
	arr[NET_SHAPER_A_CAPS_SUPPORT_PRIORITY].name = "support-priority";
	arr[NET_SHAPER_A_CAPS_SUPPORT_PRIORITY].type = YNL_PT_FLAG;
	arr[NET_SHAPER_A_CAPS_SUPPORT_WEIGHT].name = "support-weight";
	arr[NET_SHAPER_A_CAPS_SUPPORT_WEIGHT].type = YNL_PT_FLAG;
	return arr;
} ();

struct ynl_policy_nest net_shaper_caps_nest = {
	.max_attr = static_cast<unsigned int>(NET_SHAPER_A_CAPS_MAX),
	.table = net_shaper_caps_policy.data(),
};

/* Common nested types */
int net_shaper_handle_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  const net_shaper_handle&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.scope.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_HANDLE_SCOPE, obj.scope.value());
	}
	if (obj.id.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_HANDLE_ID, obj.id.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int net_shaper_handle_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	net_shaper_handle *dst = (net_shaper_handle *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NET_SHAPER_A_HANDLE_SCOPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->scope = (enum net_shaper_scope)ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_HANDLE_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int net_shaper_leaf_info_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     const net_shaper_leaf_info&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.handle.has_value()) {
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, obj.handle.value());
	}
	if (obj.priority.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_PRIORITY, obj.priority.value());
	}
	if (obj.weight.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_WEIGHT, obj.weight.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

/* ============== NET_SHAPER_CMD_GET ============== */
/* NET_SHAPER_CMD_GET - do */
int net_shaper_get_rsp_parse(const struct nlmsghdr *nlh,
			     struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	net_shaper_get_rsp *dst;

	dst = (net_shaper_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NET_SHAPER_A_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_PARENT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &net_shaper_handle_nest;
			parg.data = &dst->parent.emplace();
			if (net_shaper_handle_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NET_SHAPER_A_HANDLE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &net_shaper_handle_nest;
			parg.data = &dst->handle.emplace();
			if (net_shaper_handle_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NET_SHAPER_A_METRIC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->metric = (enum net_shaper_metric)ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_BW_MIN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bw_min = (__u64)ynl_attr_get_uint(attr);
		} else if (type == NET_SHAPER_A_BW_MAX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bw_max = (__u64)ynl_attr_get_uint(attr);
		} else if (type == NET_SHAPER_A_BURST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->burst = (__u64)ynl_attr_get_uint(attr);
		} else if (type == NET_SHAPER_A_PRIORITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->priority = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_WEIGHT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->weight = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<net_shaper_get_rsp>
net_shaper_get(ynl_cpp::ynl_socket& ys, net_shaper_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<net_shaper_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NET_SHAPER_CMD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &net_shaper_net_shaper_nest;
	yrs.yarg.rsp_policy = &net_shaper_net_shaper_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req.ifindex.value());
	}
	if (req.handle.has_value()) {
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, req.handle.value());
	}

	rsp.reset(new net_shaper_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = net_shaper_get_rsp_parse;
	yrs.rsp_cmd = NET_SHAPER_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* NET_SHAPER_CMD_GET - dump */
std::unique_ptr<net_shaper_get_list>
net_shaper_get_dump(ynl_cpp::ynl_socket& ys, net_shaper_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<net_shaper_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &net_shaper_net_shaper_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<net_shaper_get_list*>(arg)->objs.emplace_back());};
	yds.cb = net_shaper_get_rsp_parse;
	yds.rsp_cmd = NET_SHAPER_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, NET_SHAPER_CMD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &net_shaper_net_shaper_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req.ifindex.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== NET_SHAPER_CMD_SET ============== */
/* NET_SHAPER_CMD_SET - do */
int net_shaper_set(ynl_cpp::ynl_socket& ys, net_shaper_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NET_SHAPER_CMD_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &net_shaper_net_shaper_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req.ifindex.value());
	}
	if (req.handle.has_value()) {
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, req.handle.value());
	}
	if (req.metric.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_METRIC, req.metric.value());
	}
	if (req.bw_min.has_value()) {
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BW_MIN, req.bw_min.value());
	}
	if (req.bw_max.has_value()) {
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BW_MAX, req.bw_max.value());
	}
	if (req.burst.has_value()) {
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BURST, req.burst.value());
	}
	if (req.priority.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_PRIORITY, req.priority.value());
	}
	if (req.weight.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_WEIGHT, req.weight.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NET_SHAPER_CMD_DELETE ============== */
/* NET_SHAPER_CMD_DELETE - do */
int net_shaper_delete(ynl_cpp::ynl_socket& ys, net_shaper_delete_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NET_SHAPER_CMD_DELETE, 1);
	((struct ynl_sock*)ys)->req_policy = &net_shaper_net_shaper_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req.ifindex.value());
	}
	if (req.handle.has_value()) {
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, req.handle.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== NET_SHAPER_CMD_GROUP ============== */
/* NET_SHAPER_CMD_GROUP - do */
int net_shaper_group_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	net_shaper_group_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (net_shaper_group_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NET_SHAPER_A_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_HANDLE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &net_shaper_handle_nest;
			parg.data = &dst->handle.emplace();
			if (net_shaper_handle_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<net_shaper_group_rsp>
net_shaper_group(ynl_cpp::ynl_socket& ys, net_shaper_group_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<net_shaper_group_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NET_SHAPER_CMD_GROUP, 1);
	((struct ynl_sock*)ys)->req_policy = &net_shaper_net_shaper_nest;
	yrs.yarg.rsp_policy = &net_shaper_net_shaper_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_IFINDEX, req.ifindex.value());
	}
	if (req.parent.has_value()) {
		net_shaper_handle_put(nlh, NET_SHAPER_A_PARENT, req.parent.value());
	}
	if (req.handle.has_value()) {
		net_shaper_handle_put(nlh, NET_SHAPER_A_HANDLE, req.handle.value());
	}
	if (req.metric.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_METRIC, req.metric.value());
	}
	if (req.bw_min.has_value()) {
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BW_MIN, req.bw_min.value());
	}
	if (req.bw_max.has_value()) {
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BW_MAX, req.bw_max.value());
	}
	if (req.burst.has_value()) {
		ynl_attr_put_uint(nlh, NET_SHAPER_A_BURST, req.burst.value());
	}
	if (req.priority.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_PRIORITY, req.priority.value());
	}
	if (req.weight.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_WEIGHT, req.weight.value());
	}
	for (unsigned int i = 0; i < req.leaves.size(); i++)
		net_shaper_leaf_info_put(nlh, NET_SHAPER_A_LEAVES, req.leaves[i]);

	rsp.reset(new net_shaper_group_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = net_shaper_group_rsp_parse;
	yrs.rsp_cmd = NET_SHAPER_CMD_GROUP;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== NET_SHAPER_CMD_CAP_GET ============== */
/* NET_SHAPER_CMD_CAP_GET - do */
int net_shaper_cap_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	net_shaper_cap_get_rsp *dst;
	const struct nlattr *attr;

	dst = (net_shaper_cap_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NET_SHAPER_A_CAPS_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_CAPS_SCOPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->scope = (enum net_shaper_scope)ynl_attr_get_u32(attr);
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_NESTING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_BW_MIN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_BW_MAX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_BURST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_PRIORITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NET_SHAPER_A_CAPS_SUPPORT_WEIGHT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<net_shaper_cap_get_rsp>
net_shaper_cap_get(ynl_cpp::ynl_socket& ys, net_shaper_cap_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<net_shaper_cap_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, NET_SHAPER_CMD_CAP_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &net_shaper_caps_nest;
	yrs.yarg.rsp_policy = &net_shaper_caps_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_CAPS_IFINDEX, req.ifindex.value());
	}
	if (req.scope.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_CAPS_SCOPE, req.scope.value());
	}

	rsp.reset(new net_shaper_cap_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = net_shaper_cap_get_rsp_parse;
	yrs.rsp_cmd = NET_SHAPER_CMD_CAP_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* NET_SHAPER_CMD_CAP_GET - dump */
std::unique_ptr<net_shaper_cap_get_list>
net_shaper_cap_get_dump(ynl_cpp::ynl_socket& ys,
			net_shaper_cap_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<net_shaper_cap_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &net_shaper_caps_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<net_shaper_cap_get_list*>(arg)->objs.emplace_back());};
	yds.cb = net_shaper_cap_get_rsp_parse;
	yds.rsp_cmd = NET_SHAPER_CMD_CAP_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, NET_SHAPER_CMD_CAP_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &net_shaper_caps_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NET_SHAPER_A_CAPS_IFINDEX, req.ifindex.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

const struct ynl_family ynl_net_shaper_family =  {
	.name		= "net_shaper",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_net_shaper_family() {
	return ynl_net_shaper_family;
};
} //namespace ynl_cpp
