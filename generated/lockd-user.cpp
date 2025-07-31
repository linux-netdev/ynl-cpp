// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "lockd-user.hpp"

#include <array>

#include <linux/lockd_netlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, LOCKD_CMD_SERVER_GET + 1> lockd_op_strmap = []() {
	std::array<std::string_view, LOCKD_CMD_SERVER_GET + 1> arr{};
	arr[LOCKD_CMD_SERVER_SET] = "server-set";
	arr[LOCKD_CMD_SERVER_GET] = "server-get";
	return arr;
} ();

std::string_view lockd_op_str(int op)
{
	if (op < 0 || op >= (int)(lockd_op_strmap.size()))
		return "";
	return lockd_op_strmap[op];
}

/* Policies */
static std::array<ynl_policy_attr,LOCKD_A_SERVER_MAX + 1> lockd_server_policy = []() {
	std::array<ynl_policy_attr,LOCKD_A_SERVER_MAX + 1> arr{};
	arr[LOCKD_A_SERVER_GRACETIME].name = "gracetime";
	arr[LOCKD_A_SERVER_GRACETIME].type = YNL_PT_U32;
	arr[LOCKD_A_SERVER_TCP_PORT].name = "tcp-port";
	arr[LOCKD_A_SERVER_TCP_PORT].type = YNL_PT_U16;
	arr[LOCKD_A_SERVER_UDP_PORT].name = "udp-port";
	arr[LOCKD_A_SERVER_UDP_PORT].type = YNL_PT_U16;
	return arr;
} ();

struct ynl_policy_nest lockd_server_nest = {
	.max_attr = static_cast<unsigned int>(LOCKD_A_SERVER_MAX),
	.table = lockd_server_policy.data(),
};

/* Common nested types */
/* ============== LOCKD_CMD_SERVER_SET ============== */
/* LOCKD_CMD_SERVER_SET - do */
int lockd_server_set(ynl_cpp::ynl_socket& ys, lockd_server_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, LOCKD_CMD_SERVER_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &lockd_server_nest;

	if (req.gracetime.has_value())
		ynl_attr_put_u32(nlh, LOCKD_A_SERVER_GRACETIME, req.gracetime.value());
	if (req.tcp_port.has_value())
		ynl_attr_put_u16(nlh, LOCKD_A_SERVER_TCP_PORT, req.tcp_port.value());
	if (req.udp_port.has_value())
		ynl_attr_put_u16(nlh, LOCKD_A_SERVER_UDP_PORT, req.udp_port.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== LOCKD_CMD_SERVER_GET ============== */
/* LOCKD_CMD_SERVER_GET - do */
int lockd_server_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	lockd_server_get_rsp *dst;
	const struct nlattr *attr;

	dst = (lockd_server_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == LOCKD_A_SERVER_GRACETIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->gracetime = (__u32)ynl_attr_get_u32(attr);
		} else if (type == LOCKD_A_SERVER_TCP_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tcp_port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == LOCKD_A_SERVER_UDP_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->udp_port = (__u16)ynl_attr_get_u16(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<lockd_server_get_rsp> lockd_server_get(ynl_cpp::ynl_socket& ys)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<lockd_server_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, LOCKD_CMD_SERVER_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &lockd_server_nest;
	yrs.yarg.rsp_policy = &lockd_server_nest;

	rsp.reset(new lockd_server_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = lockd_server_get_rsp_parse;
	yrs.rsp_cmd = LOCKD_CMD_SERVER_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

const struct ynl_family ynl_lockd_family =  {
	.name		= "lockd",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_lockd_family() {
	return ynl_lockd_family;
};
} //namespace ynl_cpp
