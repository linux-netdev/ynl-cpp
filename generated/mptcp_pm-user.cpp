// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "mptcp_pm-user.hpp"

#include <array>

#include <linux/mptcp_pm.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, MPTCP_PM_CMD_SUBFLOW_DESTROY + 1> mptcp_pm_op_strmap = []() {
	std::array<std::string_view, MPTCP_PM_CMD_SUBFLOW_DESTROY + 1> arr{};
	arr[MPTCP_PM_CMD_ADD_ADDR] = "add-addr";
	arr[MPTCP_PM_CMD_DEL_ADDR] = "del-addr";
	arr[MPTCP_PM_CMD_GET_ADDR] = "get-addr";
	arr[MPTCP_PM_CMD_FLUSH_ADDRS] = "flush-addrs";
	arr[MPTCP_PM_CMD_SET_LIMITS] = "set-limits";
	arr[MPTCP_PM_CMD_GET_LIMITS] = "get-limits";
	arr[MPTCP_PM_CMD_SET_FLAGS] = "set-flags";
	arr[MPTCP_PM_CMD_ANNOUNCE] = "announce";
	arr[MPTCP_PM_CMD_REMOVE] = "remove";
	arr[MPTCP_PM_CMD_SUBFLOW_CREATE] = "subflow-create";
	arr[MPTCP_PM_CMD_SUBFLOW_DESTROY] = "subflow-destroy";
	return arr;
} ();

std::string_view mptcp_pm_op_str(int op)
{
	if (op < 0 || op >= (int)(mptcp_pm_op_strmap.size())) {
		return "";
	}
	return mptcp_pm_op_strmap[op];
}

static constexpr std::array<std::string_view, 16 + 1> mptcp_pm_event_type_strmap = []() {
	std::array<std::string_view, 16 + 1> arr{};
	arr[0] = "unspec";
	arr[1] = "created";
	arr[2] = "established";
	arr[3] = "closed";
	arr[6] = "announced";
	arr[7] = "removed";
	arr[10] = "sub-established";
	arr[11] = "sub-closed";
	arr[13] = "sub-priority";
	arr[15] = "listener-created";
	arr[16] = "listener-closed";
	return arr;
} ();

std::string_view mptcp_pm_event_type_str(mptcp_event_type value)
{
	if (value < 0 || value >= (int)(mptcp_pm_event_type_strmap.size())) {
		return "";
	}
	return mptcp_pm_event_type_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,MPTCP_PM_ADDR_ATTR_MAX + 1> mptcp_pm_address_policy = []() {
	std::array<ynl_policy_attr,MPTCP_PM_ADDR_ATTR_MAX + 1> arr{};
	arr[MPTCP_PM_ADDR_ATTR_UNSPEC].name = "unspec";
	arr[MPTCP_PM_ADDR_ATTR_UNSPEC].type = YNL_PT_REJECT;
	arr[MPTCP_PM_ADDR_ATTR_FAMILY].name = "family";
	arr[MPTCP_PM_ADDR_ATTR_FAMILY].type = YNL_PT_U16;
	arr[MPTCP_PM_ADDR_ATTR_ID].name = "id";
	arr[MPTCP_PM_ADDR_ATTR_ID].type = YNL_PT_U8;
	arr[MPTCP_PM_ADDR_ATTR_ADDR4].name = "addr4";
	arr[MPTCP_PM_ADDR_ATTR_ADDR4].type = YNL_PT_U32;
	arr[MPTCP_PM_ADDR_ATTR_ADDR6].name = "addr6";
	arr[MPTCP_PM_ADDR_ATTR_ADDR6].type = YNL_PT_BINARY;
	arr[MPTCP_PM_ADDR_ATTR_PORT].name = "port";
	arr[MPTCP_PM_ADDR_ATTR_PORT].type = YNL_PT_U16;
	arr[MPTCP_PM_ADDR_ATTR_FLAGS].name = "flags";
	arr[MPTCP_PM_ADDR_ATTR_FLAGS].type = YNL_PT_U32;
	arr[MPTCP_PM_ADDR_ATTR_IF_IDX].name = "if-idx";
	arr[MPTCP_PM_ADDR_ATTR_IF_IDX].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest mptcp_pm_address_nest = {
	.max_attr = static_cast<unsigned int>(MPTCP_PM_ADDR_ATTR_MAX),
	.table = mptcp_pm_address_policy.data(),
};

static std::array<ynl_policy_attr,MPTCP_PM_ENDPOINT_MAX + 1> mptcp_pm_endpoint_policy = []() {
	std::array<ynl_policy_attr,MPTCP_PM_ENDPOINT_MAX + 1> arr{};
	arr[MPTCP_PM_ENDPOINT_ADDR].name = "addr";
	arr[MPTCP_PM_ENDPOINT_ADDR].type = YNL_PT_NEST;
	arr[MPTCP_PM_ENDPOINT_ADDR].nest = &mptcp_pm_address_nest;
	return arr;
} ();

struct ynl_policy_nest mptcp_pm_endpoint_nest = {
	.max_attr = static_cast<unsigned int>(MPTCP_PM_ENDPOINT_MAX),
	.table = mptcp_pm_endpoint_policy.data(),
};

static std::array<ynl_policy_attr,MPTCP_PM_ATTR_MAX + 1> mptcp_pm_attr_policy = []() {
	std::array<ynl_policy_attr,MPTCP_PM_ATTR_MAX + 1> arr{};
	arr[MPTCP_PM_ATTR_UNSPEC].name = "unspec";
	arr[MPTCP_PM_ATTR_UNSPEC].type = YNL_PT_REJECT;
	arr[MPTCP_PM_ATTR_ADDR].name = "addr";
	arr[MPTCP_PM_ATTR_ADDR].type = YNL_PT_NEST;
	arr[MPTCP_PM_ATTR_ADDR].nest = &mptcp_pm_address_nest;
	arr[MPTCP_PM_ATTR_RCV_ADD_ADDRS].name = "rcv-add-addrs";
	arr[MPTCP_PM_ATTR_RCV_ADD_ADDRS].type = YNL_PT_U32;
	arr[MPTCP_PM_ATTR_SUBFLOWS].name = "subflows";
	arr[MPTCP_PM_ATTR_SUBFLOWS].type = YNL_PT_U32;
	arr[MPTCP_PM_ATTR_TOKEN].name = "token";
	arr[MPTCP_PM_ATTR_TOKEN].type = YNL_PT_U32;
	arr[MPTCP_PM_ATTR_LOC_ID].name = "loc-id";
	arr[MPTCP_PM_ATTR_LOC_ID].type = YNL_PT_U8;
	arr[MPTCP_PM_ATTR_ADDR_REMOTE].name = "addr-remote";
	arr[MPTCP_PM_ATTR_ADDR_REMOTE].type = YNL_PT_NEST;
	arr[MPTCP_PM_ATTR_ADDR_REMOTE].nest = &mptcp_pm_address_nest;
	return arr;
} ();

struct ynl_policy_nest mptcp_pm_attr_nest = {
	.max_attr = static_cast<unsigned int>(MPTCP_PM_ATTR_MAX),
	.table = mptcp_pm_attr_policy.data(),
};

/* Common nested types */
int mptcp_pm_address_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 const mptcp_pm_address&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.family.has_value()) {
		ynl_attr_put_u16(nlh, MPTCP_PM_ADDR_ATTR_FAMILY, obj.family.value());
	}
	if (obj.id.has_value()) {
		ynl_attr_put_u8(nlh, MPTCP_PM_ADDR_ATTR_ID, obj.id.value());
	}
	if (obj.addr4.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ADDR_ATTR_ADDR4, obj.addr4.value());
	}
	if (obj.addr6.size() > 0) {
		ynl_attr_put(nlh, MPTCP_PM_ADDR_ATTR_ADDR6, obj.addr6.data(), obj.addr6.size());
	}
	if (obj.port.has_value()) {
		ynl_attr_put_u16(nlh, MPTCP_PM_ADDR_ATTR_PORT, obj.port.value());
	}
	if (obj.flags.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ADDR_ATTR_FLAGS, obj.flags.value());
	}
	if (obj.if_idx.has_value()) {
		ynl_attr_put_s32(nlh, MPTCP_PM_ADDR_ATTR_IF_IDX, obj.if_idx.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int mptcp_pm_address_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	mptcp_pm_address *dst = (mptcp_pm_address *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == MPTCP_PM_ADDR_ATTR_FAMILY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->family = (__u16)ynl_attr_get_u16(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u8)ynl_attr_get_u8(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_ADDR4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->addr4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_ADDR6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->addr6.assign(data, data + len);
		} else if (type == MPTCP_PM_ADDR_ATTR_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		} else if (type == MPTCP_PM_ADDR_ATTR_IF_IDX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->if_idx = (__s32)ynl_attr_get_s32(attr);
		}
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_ADD_ADDR ============== */
/* MPTCP_PM_CMD_ADD_ADDR - do */
int mptcp_pm_add_addr(ynl_cpp::ynl_socket& ys, mptcp_pm_add_addr_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_ADD_ADDR, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_endpoint_nest;

	if (req.addr.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ENDPOINT_ADDR, req.addr.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_DEL_ADDR ============== */
/* MPTCP_PM_CMD_DEL_ADDR - do */
int mptcp_pm_del_addr(ynl_cpp::ynl_socket& ys, mptcp_pm_del_addr_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_DEL_ADDR, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_endpoint_nest;

	if (req.addr.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ENDPOINT_ADDR, req.addr.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_GET_ADDR ============== */
/* MPTCP_PM_CMD_GET_ADDR - do */
int mptcp_pm_get_addr_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	mptcp_pm_get_addr_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (mptcp_pm_get_addr_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == MPTCP_PM_ATTR_ADDR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &mptcp_pm_address_nest;
			parg.data = &dst->addr.emplace();
			if (mptcp_pm_address_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<mptcp_pm_get_addr_rsp>
mptcp_pm_get_addr(ynl_cpp::ynl_socket& ys, mptcp_pm_get_addr_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<mptcp_pm_get_addr_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_GET_ADDR, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_attr_nest;
	yrs.yarg.rsp_policy = &mptcp_pm_attr_nest;

	if (req.addr.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, req.addr.value());
	}
	if (req.token.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req.token.value());
	}

	rsp.reset(new mptcp_pm_get_addr_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = mptcp_pm_get_addr_rsp_parse;
	yrs.rsp_cmd = MPTCP_PM_CMD_GET_ADDR;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* MPTCP_PM_CMD_GET_ADDR - dump */
std::unique_ptr<mptcp_pm_get_addr_list>
mptcp_pm_get_addr_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<mptcp_pm_get_addr_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &mptcp_pm_attr_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<mptcp_pm_get_addr_list*>(arg)->objs.emplace_back());};
	yds.cb = mptcp_pm_get_addr_rsp_parse;
	yds.rsp_cmd = MPTCP_PM_CMD_GET_ADDR;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_GET_ADDR, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== MPTCP_PM_CMD_FLUSH_ADDRS ============== */
/* MPTCP_PM_CMD_FLUSH_ADDRS - do */
int mptcp_pm_flush_addrs(ynl_cpp::ynl_socket& ys,
			 mptcp_pm_flush_addrs_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_FLUSH_ADDRS, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_endpoint_nest;

	if (req.addr.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ENDPOINT_ADDR, req.addr.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_SET_LIMITS ============== */
/* MPTCP_PM_CMD_SET_LIMITS - do */
int mptcp_pm_set_limits(ynl_cpp::ynl_socket& ys, mptcp_pm_set_limits_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_SET_LIMITS, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_attr_nest;

	if (req.rcv_add_addrs.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_RCV_ADD_ADDRS, req.rcv_add_addrs.value());
	}
	if (req.subflows.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_SUBFLOWS, req.subflows.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_GET_LIMITS ============== */
/* MPTCP_PM_CMD_GET_LIMITS - do */
int mptcp_pm_get_limits_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	mptcp_pm_get_limits_rsp *dst;
	const struct nlattr *attr;

	dst = (mptcp_pm_get_limits_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == MPTCP_PM_ATTR_RCV_ADD_ADDRS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rcv_add_addrs = (__u32)ynl_attr_get_u32(attr);
		} else if (type == MPTCP_PM_ATTR_SUBFLOWS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->subflows = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<mptcp_pm_get_limits_rsp>
mptcp_pm_get_limits(ynl_cpp::ynl_socket& ys, mptcp_pm_get_limits_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<mptcp_pm_get_limits_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_GET_LIMITS, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_attr_nest;
	yrs.yarg.rsp_policy = &mptcp_pm_attr_nest;

	if (req.rcv_add_addrs.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_RCV_ADD_ADDRS, req.rcv_add_addrs.value());
	}
	if (req.subflows.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_SUBFLOWS, req.subflows.value());
	}

	rsp.reset(new mptcp_pm_get_limits_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = mptcp_pm_get_limits_rsp_parse;
	yrs.rsp_cmd = MPTCP_PM_CMD_GET_LIMITS;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== MPTCP_PM_CMD_SET_FLAGS ============== */
/* MPTCP_PM_CMD_SET_FLAGS - do */
int mptcp_pm_set_flags(ynl_cpp::ynl_socket& ys, mptcp_pm_set_flags_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_SET_FLAGS, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_attr_nest;

	if (req.addr.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, req.addr.value());
	}
	if (req.token.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req.token.value());
	}
	if (req.addr_remote.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR_REMOTE, req.addr_remote.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_ANNOUNCE ============== */
/* MPTCP_PM_CMD_ANNOUNCE - do */
int mptcp_pm_announce(ynl_cpp::ynl_socket& ys, mptcp_pm_announce_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_ANNOUNCE, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_attr_nest;

	if (req.addr.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, req.addr.value());
	}
	if (req.token.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req.token.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_REMOVE ============== */
/* MPTCP_PM_CMD_REMOVE - do */
int mptcp_pm_remove(ynl_cpp::ynl_socket& ys, mptcp_pm_remove_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_REMOVE, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_attr_nest;

	if (req.token.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req.token.value());
	}
	if (req.loc_id.has_value()) {
		ynl_attr_put_u8(nlh, MPTCP_PM_ATTR_LOC_ID, req.loc_id.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_SUBFLOW_CREATE ============== */
/* MPTCP_PM_CMD_SUBFLOW_CREATE - do */
int mptcp_pm_subflow_create(ynl_cpp::ynl_socket& ys,
			    mptcp_pm_subflow_create_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_SUBFLOW_CREATE, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_attr_nest;

	if (req.addr.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, req.addr.value());
	}
	if (req.token.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req.token.value());
	}
	if (req.addr_remote.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR_REMOTE, req.addr_remote.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== MPTCP_PM_CMD_SUBFLOW_DESTROY ============== */
/* MPTCP_PM_CMD_SUBFLOW_DESTROY - do */
int mptcp_pm_subflow_destroy(ynl_cpp::ynl_socket& ys,
			     mptcp_pm_subflow_destroy_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, MPTCP_PM_CMD_SUBFLOW_DESTROY, 1);
	((struct ynl_sock*)ys)->req_policy = &mptcp_pm_attr_nest;

	if (req.addr.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR, req.addr.value());
	}
	if (req.token.has_value()) {
		ynl_attr_put_u32(nlh, MPTCP_PM_ATTR_TOKEN, req.token.value());
	}
	if (req.addr_remote.has_value()) {
		mptcp_pm_address_put(nlh, MPTCP_PM_ATTR_ADDR_REMOTE, req.addr_remote.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

const struct ynl_family ynl_mptcp_pm_family =  {
	.name		= "mptcp_pm",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_mptcp_pm_family() {
	return ynl_mptcp_pm_family;
};
} //namespace ynl_cpp
