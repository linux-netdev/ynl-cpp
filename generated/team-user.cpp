// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "team-user.hpp"

#include <array>

#include <linux/if_team.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, TEAM_CMD_PORT_LIST_GET + 1> team_op_strmap = []() {
	std::array<std::string_view, TEAM_CMD_PORT_LIST_GET + 1> arr{};
	arr[TEAM_CMD_OPTIONS_SET] = "options-set";
	arr[TEAM_CMD_OPTIONS_GET] = "options-get";
	arr[TEAM_CMD_PORT_LIST_GET] = "port-list-get";
	return arr;
} ();

std::string_view team_op_str(int op)
{
	if (op < 0 || op >= (int)(team_op_strmap.size())) {
		return "";
	}
	return team_op_strmap[op];
}

/* Policies */
static std::array<ynl_policy_attr,TEAM_ATTR_OPTION_MAX + 1> team_attr_option_policy = []() {
	std::array<ynl_policy_attr,TEAM_ATTR_OPTION_MAX + 1> arr{};
	arr[TEAM_ATTR_OPTION_UNSPEC].name = "unspec";
	arr[TEAM_ATTR_OPTION_UNSPEC].type = YNL_PT_REJECT;
	arr[TEAM_ATTR_OPTION_NAME].name = "name";
	arr[TEAM_ATTR_OPTION_NAME].type  = YNL_PT_NUL_STR;
	arr[TEAM_ATTR_OPTION_CHANGED].name = "changed";
	arr[TEAM_ATTR_OPTION_CHANGED].type = YNL_PT_FLAG;
	arr[TEAM_ATTR_OPTION_TYPE].name = "type";
	arr[TEAM_ATTR_OPTION_TYPE].type = YNL_PT_U8;
	arr[TEAM_ATTR_OPTION_DATA].name = "data";
	arr[TEAM_ATTR_OPTION_DATA].type = YNL_PT_BINARY;
	arr[TEAM_ATTR_OPTION_REMOVED].name = "removed";
	arr[TEAM_ATTR_OPTION_REMOVED].type = YNL_PT_FLAG;
	arr[TEAM_ATTR_OPTION_PORT_IFINDEX].name = "port-ifindex";
	arr[TEAM_ATTR_OPTION_PORT_IFINDEX].type = YNL_PT_U32;
	arr[TEAM_ATTR_OPTION_ARRAY_INDEX].name = "array-index";
	arr[TEAM_ATTR_OPTION_ARRAY_INDEX].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest team_attr_option_nest = {
	.max_attr = static_cast<unsigned int>(TEAM_ATTR_OPTION_MAX),
	.table = team_attr_option_policy.data(),
};

static std::array<ynl_policy_attr,TEAM_ATTR_PORT_MAX + 1> team_attr_port_policy = []() {
	std::array<ynl_policy_attr,TEAM_ATTR_PORT_MAX + 1> arr{};
	arr[TEAM_ATTR_PORT_UNSPEC].name = "unspec";
	arr[TEAM_ATTR_PORT_UNSPEC].type = YNL_PT_REJECT;
	arr[TEAM_ATTR_PORT_IFINDEX].name = "ifindex";
	arr[TEAM_ATTR_PORT_IFINDEX].type = YNL_PT_U32;
	arr[TEAM_ATTR_PORT_CHANGED].name = "changed";
	arr[TEAM_ATTR_PORT_CHANGED].type = YNL_PT_FLAG;
	arr[TEAM_ATTR_PORT_LINKUP].name = "linkup";
	arr[TEAM_ATTR_PORT_LINKUP].type = YNL_PT_FLAG;
	arr[TEAM_ATTR_PORT_SPEED].name = "speed";
	arr[TEAM_ATTR_PORT_SPEED].type = YNL_PT_U32;
	arr[TEAM_ATTR_PORT_DUPLEX].name = "duplex";
	arr[TEAM_ATTR_PORT_DUPLEX].type = YNL_PT_U8;
	arr[TEAM_ATTR_PORT_REMOVED].name = "removed";
	arr[TEAM_ATTR_PORT_REMOVED].type = YNL_PT_FLAG;
	return arr;
} ();

struct ynl_policy_nest team_attr_port_nest = {
	.max_attr = static_cast<unsigned int>(TEAM_ATTR_PORT_MAX),
	.table = team_attr_port_policy.data(),
};

static std::array<ynl_policy_attr,TEAM_ATTR_ITEM_OPTION_MAX + 1> team_item_option_policy = []() {
	std::array<ynl_policy_attr,TEAM_ATTR_ITEM_OPTION_MAX + 1> arr{};
	arr[TEAM_ATTR_ITEM_OPTION_UNSPEC].name = "option-unspec";
	arr[TEAM_ATTR_ITEM_OPTION_UNSPEC].type = YNL_PT_REJECT;
	arr[TEAM_ATTR_ITEM_OPTION].name = "option";
	arr[TEAM_ATTR_ITEM_OPTION].type = YNL_PT_NEST;
	arr[TEAM_ATTR_ITEM_OPTION].nest = &team_attr_option_nest;
	return arr;
} ();

struct ynl_policy_nest team_item_option_nest = {
	.max_attr = static_cast<unsigned int>(TEAM_ATTR_ITEM_OPTION_MAX),
	.table = team_item_option_policy.data(),
};

static std::array<ynl_policy_attr,TEAM_ATTR_ITEM_PORT_MAX + 1> team_item_port_policy = []() {
	std::array<ynl_policy_attr,TEAM_ATTR_ITEM_PORT_MAX + 1> arr{};
	arr[TEAM_ATTR_ITEM_PORT_UNSPEC].name = "port-unspec";
	arr[TEAM_ATTR_ITEM_PORT_UNSPEC].type = YNL_PT_REJECT;
	arr[TEAM_ATTR_ITEM_PORT].name = "port";
	arr[TEAM_ATTR_ITEM_PORT].type = YNL_PT_NEST;
	arr[TEAM_ATTR_ITEM_PORT].nest = &team_attr_port_nest;
	return arr;
} ();

struct ynl_policy_nest team_item_port_nest = {
	.max_attr = static_cast<unsigned int>(TEAM_ATTR_ITEM_PORT_MAX),
	.table = team_item_port_policy.data(),
};

static std::array<ynl_policy_attr,TEAM_ATTR_MAX + 1> team_policy = []() {
	std::array<ynl_policy_attr,TEAM_ATTR_MAX + 1> arr{};
	arr[TEAM_ATTR_UNSPEC].name = "unspec";
	arr[TEAM_ATTR_UNSPEC].type = YNL_PT_REJECT;
	arr[TEAM_ATTR_TEAM_IFINDEX].name = "team-ifindex";
	arr[TEAM_ATTR_TEAM_IFINDEX].type = YNL_PT_U32;
	arr[TEAM_ATTR_LIST_OPTION].name = "list-option";
	arr[TEAM_ATTR_LIST_OPTION].type = YNL_PT_NEST;
	arr[TEAM_ATTR_LIST_OPTION].nest = &team_item_option_nest;
	arr[TEAM_ATTR_LIST_PORT].name = "list-port";
	arr[TEAM_ATTR_LIST_PORT].type = YNL_PT_NEST;
	arr[TEAM_ATTR_LIST_PORT].nest = &team_item_port_nest;
	return arr;
} ();

struct ynl_policy_nest team_nest = {
	.max_attr = static_cast<unsigned int>(TEAM_ATTR_MAX),
	.table = team_policy.data(),
};

/* Common nested types */
int team_attr_option_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 const team_attr_option&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.name.size() > 0) {
		ynl_attr_put_str(nlh, TEAM_ATTR_OPTION_NAME, obj.name.data());
	}
	if (obj.changed) {
		ynl_attr_put(nlh, TEAM_ATTR_OPTION_CHANGED, NULL, 0);
	}
	if (obj.type.has_value()) {
		ynl_attr_put_u8(nlh, TEAM_ATTR_OPTION_TYPE, obj.type.value());
	}
	if (obj.data.size() > 0) {
		ynl_attr_put(nlh, TEAM_ATTR_OPTION_DATA, obj.data.data(), obj.data.size());
	}
	if (obj.removed) {
		ynl_attr_put(nlh, TEAM_ATTR_OPTION_REMOVED, NULL, 0);
	}
	if (obj.port_ifindex.has_value()) {
		ynl_attr_put_u32(nlh, TEAM_ATTR_OPTION_PORT_IFINDEX, obj.port_ifindex.value());
	}
	if (obj.array_index.has_value()) {
		ynl_attr_put_u32(nlh, TEAM_ATTR_OPTION_ARRAY_INDEX, obj.array_index.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int team_attr_option_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	team_attr_option *dst = (team_attr_option *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_OPTION_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->name.assign(ynl_attr_get_str(attr));
		} else if (type == TEAM_ATTR_OPTION_CHANGED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == TEAM_ATTR_OPTION_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->type = (__u8)ynl_attr_get_u8(attr);
		} else if (type == TEAM_ATTR_OPTION_DATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->data.assign(data, data + len);
		} else if (type == TEAM_ATTR_OPTION_REMOVED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == TEAM_ATTR_OPTION_PORT_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_OPTION_ARRAY_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->array_index = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int team_attr_port_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	team_attr_port *dst = (team_attr_port *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_PORT_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_PORT_CHANGED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == TEAM_ATTR_PORT_LINKUP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == TEAM_ATTR_PORT_SPEED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->speed = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_PORT_DUPLEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->duplex = (__u8)ynl_attr_get_u8(attr);
		} else if (type == TEAM_ATTR_PORT_REMOVED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int team_item_option_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 const team_item_option&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.option.has_value()) {
		team_attr_option_put(nlh, TEAM_ATTR_ITEM_OPTION, obj.option.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int team_item_option_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	team_item_option *dst = (team_item_option *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_ITEM_OPTION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &team_attr_option_nest;
			parg.data = &dst->option.emplace();
			if (team_attr_option_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int team_item_port_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	team_item_port *dst = (team_item_port *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_ITEM_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &team_attr_port_nest;
			parg.data = &dst->port.emplace();
			if (team_attr_port_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

/* ============== TEAM_CMD_NOOP ============== */
/* TEAM_CMD_NOOP - do */
int team_noop_rsp_parse(const struct nlmsghdr *nlh, struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	team_noop_rsp *dst;

	dst = (team_noop_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_TEAM_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->team_ifindex = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<team_noop_rsp> team_noop(ynl_cpp::ynl_socket& ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<team_noop_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, TEAM_CMD_NOOP, 1);
	((struct ynl_sock*)ys)->req_policy = &team_nest;
	yrs.yarg.rsp_policy = &team_nest;

	rsp.reset(new team_noop_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = team_noop_rsp_parse;
	yrs.rsp_cmd = TEAM_CMD_NOOP;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== TEAM_CMD_OPTIONS_SET ============== */
/* TEAM_CMD_OPTIONS_SET - do */
int team_options_set_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	team_options_set_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (team_options_set_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_TEAM_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->team_ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_LIST_OPTION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &team_item_option_nest;
			parg.data = &dst->list_option.emplace();
			if (team_item_option_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<team_options_set_rsp>
team_options_set(ynl_cpp::ynl_socket& ys, team_options_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<team_options_set_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, TEAM_CMD_OPTIONS_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &team_nest;
	yrs.yarg.rsp_policy = &team_nest;

	if (req.team_ifindex.has_value()) {
		ynl_attr_put_u32(nlh, TEAM_ATTR_TEAM_IFINDEX, req.team_ifindex.value());
	}
	if (req.list_option.has_value()) {
		team_item_option_put(nlh, TEAM_ATTR_LIST_OPTION, req.list_option.value());
	}

	rsp.reset(new team_options_set_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = team_options_set_rsp_parse;
	yrs.rsp_cmd = TEAM_CMD_OPTIONS_SET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== TEAM_CMD_OPTIONS_GET ============== */
/* TEAM_CMD_OPTIONS_GET - do */
int team_options_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	team_options_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (team_options_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_TEAM_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->team_ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_LIST_OPTION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &team_item_option_nest;
			parg.data = &dst->list_option.emplace();
			if (team_item_option_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<team_options_get_rsp>
team_options_get(ynl_cpp::ynl_socket& ys, team_options_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<team_options_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, TEAM_CMD_OPTIONS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &team_nest;
	yrs.yarg.rsp_policy = &team_nest;

	if (req.team_ifindex.has_value()) {
		ynl_attr_put_u32(nlh, TEAM_ATTR_TEAM_IFINDEX, req.team_ifindex.value());
	}

	rsp.reset(new team_options_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = team_options_get_rsp_parse;
	yrs.rsp_cmd = TEAM_CMD_OPTIONS_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== TEAM_CMD_PORT_LIST_GET ============== */
/* TEAM_CMD_PORT_LIST_GET - do */
int team_port_list_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	team_port_list_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (team_port_list_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TEAM_ATTR_TEAM_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->team_ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TEAM_ATTR_LIST_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &team_item_port_nest;
			parg.data = &dst->list_port.emplace();
			if (team_item_port_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<team_port_list_get_rsp>
team_port_list_get(ynl_cpp::ynl_socket& ys, team_port_list_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<team_port_list_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, TEAM_CMD_PORT_LIST_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &team_nest;
	yrs.yarg.rsp_policy = &team_nest;

	if (req.team_ifindex.has_value()) {
		ynl_attr_put_u32(nlh, TEAM_ATTR_TEAM_IFINDEX, req.team_ifindex.value());
	}

	rsp.reset(new team_port_list_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = team_port_list_get_rsp_parse;
	yrs.rsp_cmd = TEAM_CMD_PORT_LIST_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

const struct ynl_family ynl_team_family =  {
	.name		= "team",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_team_family() {
	return ynl_team_family;
};
} //namespace ynl_cpp
