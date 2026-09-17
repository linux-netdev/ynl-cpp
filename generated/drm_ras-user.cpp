// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "drm_ras-user.hpp"

#include <array>

#include <drm/drm_ras.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, DRM_RAS_CMD_CLEAR_ERROR_COUNTER + 1> drm_ras_op_strmap = []() {
	std::array<std::string_view, DRM_RAS_CMD_CLEAR_ERROR_COUNTER + 1> arr{};
	arr[DRM_RAS_CMD_LIST_NODES] = "list-nodes";
	arr[DRM_RAS_CMD_GET_ERROR_COUNTER] = "get-error-counter";
	arr[DRM_RAS_CMD_CLEAR_ERROR_COUNTER] = "clear-error-counter";
	return arr;
} ();

std::string_view drm_ras_op_str(int op)
{
	if (op < 0 || op >= (int)(drm_ras_op_strmap.size())) {
		return "";
	}
	return drm_ras_op_strmap[op];
}

static constexpr std::array<std::string_view, 1 + 1> drm_ras_node_type_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[1] = "error-counter";
	return arr;
} ();

std::string_view drm_ras_node_type_str(drm_ras_node_type value)
{
	if (value < 0 || value >= (int)(drm_ras_node_type_strmap.size())) {
		return "";
	}
	return drm_ras_node_type_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,DRM_RAS_A_NODE_ATTRS_MAX + 1> drm_ras_node_attrs_policy = []() {
	std::array<ynl_policy_attr,DRM_RAS_A_NODE_ATTRS_MAX + 1> arr{};
	arr[DRM_RAS_A_NODE_ATTRS_NODE_ID].name = "node-id";
	arr[DRM_RAS_A_NODE_ATTRS_NODE_ID].type = YNL_PT_U32;
	arr[DRM_RAS_A_NODE_ATTRS_DEVICE_NAME].name = "device-name";
	arr[DRM_RAS_A_NODE_ATTRS_DEVICE_NAME].type  = YNL_PT_NUL_STR;
	arr[DRM_RAS_A_NODE_ATTRS_NODE_NAME].name = "node-name";
	arr[DRM_RAS_A_NODE_ATTRS_NODE_NAME].type  = YNL_PT_NUL_STR;
	arr[DRM_RAS_A_NODE_ATTRS_NODE_TYPE].name = "node-type";
	arr[DRM_RAS_A_NODE_ATTRS_NODE_TYPE].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest drm_ras_node_attrs_nest = {
	.max_attr = static_cast<unsigned int>(DRM_RAS_A_NODE_ATTRS_MAX),
	.table = drm_ras_node_attrs_policy.data(),
};

static std::array<ynl_policy_attr,DRM_RAS_A_ERROR_COUNTER_ATTRS_MAX + 1> drm_ras_error_counter_attrs_policy = []() {
	std::array<ynl_policy_attr,DRM_RAS_A_ERROR_COUNTER_ATTRS_MAX + 1> arr{};
	arr[DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID].name = "node-id";
	arr[DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID].type = YNL_PT_U32;
	arr[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID].name = "error-id";
	arr[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID].type = YNL_PT_U32;
	arr[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_NAME].name = "error-name";
	arr[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_NAME].type  = YNL_PT_NUL_STR;
	arr[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_VALUE].name = "error-value";
	arr[DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_VALUE].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest drm_ras_error_counter_attrs_nest = {
	.max_attr = static_cast<unsigned int>(DRM_RAS_A_ERROR_COUNTER_ATTRS_MAX),
	.table = drm_ras_error_counter_attrs_policy.data(),
};

/* Common nested types */
/* ============== DRM_RAS_CMD_LIST_NODES ============== */
/* DRM_RAS_CMD_LIST_NODES - dump */
int drm_ras_list_nodes_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	drm_ras_list_nodes_rsp *dst;
	const struct nlattr *attr;

	dst = (drm_ras_list_nodes_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DRM_RAS_A_NODE_ATTRS_NODE_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->node_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DRM_RAS_A_NODE_ATTRS_DEVICE_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->device_name.assign(ynl_attr_get_str(attr));
		} else if (type == DRM_RAS_A_NODE_ATTRS_NODE_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->node_name.assign(ynl_attr_get_str(attr));
		} else if (type == DRM_RAS_A_NODE_ATTRS_NODE_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->node_type = (enum drm_ras_node_type)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<drm_ras_list_nodes_list>
drm_ras_list_nodes_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<drm_ras_list_nodes_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &drm_ras_node_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<drm_ras_list_nodes_list*>(arg)->objs.emplace_back());};
	yds.cb = drm_ras_list_nodes_rsp_parse;
	yds.rsp_cmd = DRM_RAS_CMD_LIST_NODES;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DRM_RAS_CMD_LIST_NODES, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DRM_RAS_CMD_GET_ERROR_COUNTER ============== */
/* DRM_RAS_CMD_GET_ERROR_COUNTER - do */
int drm_ras_get_error_counter_rsp_parse(const struct nlmsghdr *nlh,
					struct ynl_parse_arg *yarg)
{
	drm_ras_get_error_counter_rsp *dst;
	const struct nlattr *attr;

	dst = (drm_ras_get_error_counter_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->error_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->error_name.assign(ynl_attr_get_str(attr));
		} else if (type == DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_VALUE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->error_value = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<drm_ras_get_error_counter_rsp>
drm_ras_get_error_counter(ynl_cpp::ynl_socket& ys,
			  drm_ras_get_error_counter_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<drm_ras_get_error_counter_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DRM_RAS_CMD_GET_ERROR_COUNTER, 1);
	((struct ynl_sock*)ys)->req_policy = &drm_ras_error_counter_attrs_nest;
	yrs.yarg.rsp_policy = &drm_ras_error_counter_attrs_nest;

	if (req.node_id.has_value()) {
		ynl_attr_put_u32(nlh, DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID, req.node_id.value());
	}
	if (req.error_id.has_value()) {
		ynl_attr_put_u32(nlh, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID, req.error_id.value());
	}

	rsp.reset(new drm_ras_get_error_counter_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = drm_ras_get_error_counter_rsp_parse;
	yrs.rsp_cmd = DRM_RAS_CMD_GET_ERROR_COUNTER;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DRM_RAS_CMD_GET_ERROR_COUNTER - dump */
std::unique_ptr<drm_ras_get_error_counter_list>
drm_ras_get_error_counter_dump(ynl_cpp::ynl_socket& ys,
			       drm_ras_get_error_counter_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<drm_ras_get_error_counter_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &drm_ras_error_counter_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<drm_ras_get_error_counter_list*>(arg)->objs.emplace_back());};
	yds.cb = drm_ras_get_error_counter_rsp_parse;
	yds.rsp_cmd = DRM_RAS_CMD_GET_ERROR_COUNTER;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DRM_RAS_CMD_GET_ERROR_COUNTER, 1);
	((struct ynl_sock*)ys)->req_policy = &drm_ras_error_counter_attrs_nest;

	if (req.node_id.has_value()) {
		ynl_attr_put_u32(nlh, DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID, req.node_id.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DRM_RAS_CMD_CLEAR_ERROR_COUNTER ============== */
/* DRM_RAS_CMD_CLEAR_ERROR_COUNTER - do */
int drm_ras_clear_error_counter(ynl_cpp::ynl_socket& ys,
				drm_ras_clear_error_counter_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DRM_RAS_CMD_CLEAR_ERROR_COUNTER, 1);
	((struct ynl_sock*)ys)->req_policy = &drm_ras_error_counter_attrs_nest;

	if (req.node_id.has_value()) {
		ynl_attr_put_u32(nlh, DRM_RAS_A_ERROR_COUNTER_ATTRS_NODE_ID, req.node_id.value());
	}
	if (req.error_id.has_value()) {
		ynl_attr_put_u32(nlh, DRM_RAS_A_ERROR_COUNTER_ATTRS_ERROR_ID, req.error_id.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

const struct ynl_family ynl_drm_ras_family =  {
	.name		= "drm_ras",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_drm_ras_family() {
	return ynl_drm_ras_family;
};
} //namespace ynl_cpp
