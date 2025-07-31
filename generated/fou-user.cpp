// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "fou-user.hpp"

#include <array>

#include <linux/fou.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, FOU_CMD_GET + 1> fou_op_strmap = []() {
	std::array<std::string_view, FOU_CMD_GET + 1> arr{};
	arr[FOU_CMD_ADD] = "add";
	arr[FOU_CMD_DEL] = "del";
	arr[FOU_CMD_GET] = "get";
	return arr;
} ();

std::string_view fou_op_str(int op)
{
	if (op < 0 || op >= (int)(fou_op_strmap.size()))
		return "";
	return fou_op_strmap[op];
}

static constexpr std::array<std::string_view, 2 + 1> fou_encap_type_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "unspec";
	arr[1] = "direct";
	arr[2] = "gue";
	return arr;
} ();

std::string_view fou_encap_type_str(int value)
{
	if (value < 0 || value >= (int)(fou_encap_type_strmap.size()))
		return "";
	return fou_encap_type_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,FOU_ATTR_MAX + 1> fou_policy = []() {
	std::array<ynl_policy_attr,FOU_ATTR_MAX + 1> arr{};
	arr[FOU_ATTR_UNSPEC].name = "unspec";
	arr[FOU_ATTR_UNSPEC].type = YNL_PT_REJECT;
	arr[FOU_ATTR_PORT].name = "port";
	arr[FOU_ATTR_PORT].type = YNL_PT_U16;
	arr[FOU_ATTR_AF].name = "af";
	arr[FOU_ATTR_AF].type = YNL_PT_U8;
	arr[FOU_ATTR_IPPROTO].name = "ipproto";
	arr[FOU_ATTR_IPPROTO].type = YNL_PT_U8;
	arr[FOU_ATTR_TYPE].name = "type";
	arr[FOU_ATTR_TYPE].type = YNL_PT_U8;
	arr[FOU_ATTR_REMCSUM_NOPARTIAL].name = "remcsum-nopartial";
	arr[FOU_ATTR_REMCSUM_NOPARTIAL].type = YNL_PT_FLAG;
	arr[FOU_ATTR_LOCAL_V4].name = "local-v4";
	arr[FOU_ATTR_LOCAL_V4].type = YNL_PT_U32;
	arr[FOU_ATTR_LOCAL_V6].name = "local-v6";
	arr[FOU_ATTR_LOCAL_V6].type = YNL_PT_BINARY;
	arr[FOU_ATTR_PEER_V4].name = "peer-v4";
	arr[FOU_ATTR_PEER_V4].type = YNL_PT_U32;
	arr[FOU_ATTR_PEER_V6].name = "peer-v6";
	arr[FOU_ATTR_PEER_V6].type = YNL_PT_BINARY;
	arr[FOU_ATTR_PEER_PORT].name = "peer-port";
	arr[FOU_ATTR_PEER_PORT].type = YNL_PT_U16;
	arr[FOU_ATTR_IFINDEX].name = "ifindex";
	arr[FOU_ATTR_IFINDEX].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest fou_nest = {
	.max_attr = static_cast<unsigned int>(FOU_ATTR_MAX),
	.table = fou_policy.data(),
};

/* Common nested types */
/* ============== FOU_CMD_ADD ============== */
/* FOU_CMD_ADD - do */
int fou_add(ynl_cpp::ynl_socket& ys, fou_add_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, FOU_CMD_ADD, 1);
	((struct ynl_sock*)ys)->req_policy = &fou_nest;

	if (req.port.has_value())
		ynl_attr_put_u16(nlh, FOU_ATTR_PORT, req.port.value());
	if (req.ipproto.has_value())
		ynl_attr_put_u8(nlh, FOU_ATTR_IPPROTO, req.ipproto.value());
	if (req.type.has_value())
		ynl_attr_put_u8(nlh, FOU_ATTR_TYPE, req.type.value());
	if (req.remcsum_nopartial)
		ynl_attr_put(nlh, FOU_ATTR_REMCSUM_NOPARTIAL, NULL, 0);
	if (req.local_v4.has_value())
		ynl_attr_put_u32(nlh, FOU_ATTR_LOCAL_V4, req.local_v4.value());
	if (req.peer_v4.has_value())
		ynl_attr_put_u32(nlh, FOU_ATTR_PEER_V4, req.peer_v4.value());
	if (req.local_v6.size() > 0)
		ynl_attr_put(nlh, FOU_ATTR_LOCAL_V6, req.local_v6.data(), req.local_v6.size());
	if (req.peer_v6.size() > 0)
		ynl_attr_put(nlh, FOU_ATTR_PEER_V6, req.peer_v6.data(), req.peer_v6.size());
	if (req.peer_port.has_value())
		ynl_attr_put_u16(nlh, FOU_ATTR_PEER_PORT, req.peer_port.value());
	if (req.ifindex.has_value())
		ynl_attr_put_s32(nlh, FOU_ATTR_IFINDEX, req.ifindex.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== FOU_CMD_DEL ============== */
/* FOU_CMD_DEL - do */
int fou_del(ynl_cpp::ynl_socket& ys, fou_del_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, FOU_CMD_DEL, 1);
	((struct ynl_sock*)ys)->req_policy = &fou_nest;

	if (req.af.has_value())
		ynl_attr_put_u8(nlh, FOU_ATTR_AF, req.af.value());
	if (req.ifindex.has_value())
		ynl_attr_put_s32(nlh, FOU_ATTR_IFINDEX, req.ifindex.value());
	if (req.port.has_value())
		ynl_attr_put_u16(nlh, FOU_ATTR_PORT, req.port.value());
	if (req.peer_port.has_value())
		ynl_attr_put_u16(nlh, FOU_ATTR_PEER_PORT, req.peer_port.value());
	if (req.local_v4.has_value())
		ynl_attr_put_u32(nlh, FOU_ATTR_LOCAL_V4, req.local_v4.value());
	if (req.peer_v4.has_value())
		ynl_attr_put_u32(nlh, FOU_ATTR_PEER_V4, req.peer_v4.value());
	if (req.local_v6.size() > 0)
		ynl_attr_put(nlh, FOU_ATTR_LOCAL_V6, req.local_v6.data(), req.local_v6.size());
	if (req.peer_v6.size() > 0)
		ynl_attr_put(nlh, FOU_ATTR_PEER_V6, req.peer_v6.data(), req.peer_v6.size());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== FOU_CMD_GET ============== */
/* FOU_CMD_GET - do */
int fou_get_rsp_parse(const struct nlmsghdr *nlh, struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	fou_get_rsp *dst;

	dst = (fou_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == FOU_ATTR_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == FOU_ATTR_IPPROTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->ipproto = (__u8)ynl_attr_get_u8(attr);
		} else if (type == FOU_ATTR_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->type = (__u8)ynl_attr_get_u8(attr);
		} else if (type == FOU_ATTR_REMCSUM_NOPARTIAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == FOU_ATTR_LOCAL_V4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->local_v4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FOU_ATTR_PEER_V4) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->peer_v4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FOU_ATTR_LOCAL_V6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->local_v6.assign(data, data + len);
		} else if (type == FOU_ATTR_PEER_V6) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->peer_v6.assign(data, data + len);
		} else if (type == FOU_ATTR_PEER_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->peer_port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == FOU_ATTR_IFINDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->ifindex = (__s32)ynl_attr_get_s32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<fou_get_rsp> fou_get(ynl_cpp::ynl_socket& ys, fou_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<fou_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, FOU_CMD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &fou_nest;
	yrs.yarg.rsp_policy = &fou_nest;

	if (req.af.has_value())
		ynl_attr_put_u8(nlh, FOU_ATTR_AF, req.af.value());
	if (req.ifindex.has_value())
		ynl_attr_put_s32(nlh, FOU_ATTR_IFINDEX, req.ifindex.value());
	if (req.port.has_value())
		ynl_attr_put_u16(nlh, FOU_ATTR_PORT, req.port.value());
	if (req.peer_port.has_value())
		ynl_attr_put_u16(nlh, FOU_ATTR_PEER_PORT, req.peer_port.value());
	if (req.local_v4.has_value())
		ynl_attr_put_u32(nlh, FOU_ATTR_LOCAL_V4, req.local_v4.value());
	if (req.peer_v4.has_value())
		ynl_attr_put_u32(nlh, FOU_ATTR_PEER_V4, req.peer_v4.value());
	if (req.local_v6.size() > 0)
		ynl_attr_put(nlh, FOU_ATTR_LOCAL_V6, req.local_v6.data(), req.local_v6.size());
	if (req.peer_v6.size() > 0)
		ynl_attr_put(nlh, FOU_ATTR_PEER_V6, req.peer_v6.data(), req.peer_v6.size());

	rsp.reset(new fou_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = fou_get_rsp_parse;
	yrs.rsp_cmd = FOU_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* FOU_CMD_GET - dump */
std::unique_ptr<fou_get_list> fou_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<fou_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &fou_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<fou_get_list*>(arg)->objs.emplace_back());};
	yds.cb = fou_get_rsp_parse;
	yds.rsp_cmd = FOU_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, FOU_CMD_GET, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

const struct ynl_family ynl_fou_family =  {
	.name		= "fou",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_fou_family() {
	return ynl_fou_family;
};
} //namespace ynl_cpp
