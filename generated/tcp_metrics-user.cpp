// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "tcp_metrics-user.hpp"

#include <array>

#include <linux/tcp_metrics.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, TCP_METRICS_CMD_DEL + 1> tcp_metrics_op_strmap = []() {
	std::array<std::string_view, TCP_METRICS_CMD_DEL + 1> arr{};
	arr[TCP_METRICS_CMD_GET] = "get";
	arr[TCP_METRICS_CMD_DEL] = "del";
	return arr;
} ();

std::string_view tcp_metrics_op_str(int op)
{
	if (op < 0 || op >= (int)(tcp_metrics_op_strmap.size())) {
		return "";
	}
	return tcp_metrics_op_strmap[op];
}

/* Policies */
static std::array<ynl_policy_attr,TCP_METRICS_A_METRICS_MAX + 1> tcp_metrics_metrics_policy = []() {
	std::array<ynl_policy_attr,TCP_METRICS_A_METRICS_MAX + 1> arr{};
	arr[TCP_METRICS_A_METRICS_RTT].name = "rtt";
	arr[TCP_METRICS_A_METRICS_RTT].type = YNL_PT_U32;
	arr[TCP_METRICS_A_METRICS_RTTVAR].name = "rttvar";
	arr[TCP_METRICS_A_METRICS_RTTVAR].type = YNL_PT_U32;
	arr[TCP_METRICS_A_METRICS_SSTHRESH].name = "ssthresh";
	arr[TCP_METRICS_A_METRICS_SSTHRESH].type = YNL_PT_U32;
	arr[TCP_METRICS_A_METRICS_CWND].name = "cwnd";
	arr[TCP_METRICS_A_METRICS_CWND].type = YNL_PT_U32;
	arr[TCP_METRICS_A_METRICS_REODERING].name = "reodering";
	arr[TCP_METRICS_A_METRICS_REODERING].type = YNL_PT_U32;
	arr[TCP_METRICS_A_METRICS_RTT_US].name = "rtt-us";
	arr[TCP_METRICS_A_METRICS_RTT_US].type = YNL_PT_U32;
	arr[TCP_METRICS_A_METRICS_RTTVAR_US].name = "rttvar-us";
	arr[TCP_METRICS_A_METRICS_RTTVAR_US].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest tcp_metrics_metrics_nest = {
	.max_attr = static_cast<unsigned int>(TCP_METRICS_A_METRICS_MAX),
	.table = tcp_metrics_metrics_policy.data(),
};

static std::array<ynl_policy_attr,TCP_METRICS_ATTR_MAX + 1> tcp_metrics_policy = []() {
	std::array<ynl_policy_attr,TCP_METRICS_ATTR_MAX + 1> arr{};
	arr[TCP_METRICS_ATTR_ADDR_IPV4].name = "addr-ipv4";
	arr[TCP_METRICS_ATTR_ADDR_IPV4].type = YNL_PT_U32;
	arr[TCP_METRICS_ATTR_ADDR_IPV6].name = "addr-ipv6";
	arr[TCP_METRICS_ATTR_ADDR_IPV6].type = YNL_PT_BINARY;
	arr[TCP_METRICS_ATTR_AGE].name = "age";
	arr[TCP_METRICS_ATTR_AGE].type = YNL_PT_U64;
	arr[TCP_METRICS_ATTR_TW_TSVAL].name = "tw-tsval";
	arr[TCP_METRICS_ATTR_TW_TSVAL].type = YNL_PT_U32;
	arr[TCP_METRICS_ATTR_TW_TS_STAMP].name = "tw-ts-stamp";
	arr[TCP_METRICS_ATTR_TW_TS_STAMP].type = YNL_PT_U32;
	arr[TCP_METRICS_ATTR_VALS].name = "vals";
	arr[TCP_METRICS_ATTR_VALS].type = YNL_PT_NEST;
	arr[TCP_METRICS_ATTR_VALS].nest = &tcp_metrics_metrics_nest;
	arr[TCP_METRICS_ATTR_FOPEN_MSS].name = "fopen-mss";
	arr[TCP_METRICS_ATTR_FOPEN_MSS].type = YNL_PT_U16;
	arr[TCP_METRICS_ATTR_FOPEN_SYN_DROPS].name = "fopen-syn-drops";
	arr[TCP_METRICS_ATTR_FOPEN_SYN_DROPS].type = YNL_PT_U16;
	arr[TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS].name = "fopen-syn-drop-ts";
	arr[TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS].type = YNL_PT_U64;
	arr[TCP_METRICS_ATTR_FOPEN_COOKIE].name = "fopen-cookie";
	arr[TCP_METRICS_ATTR_FOPEN_COOKIE].type = YNL_PT_BINARY;
	arr[TCP_METRICS_ATTR_SADDR_IPV4].name = "saddr-ipv4";
	arr[TCP_METRICS_ATTR_SADDR_IPV4].type = YNL_PT_U32;
	arr[TCP_METRICS_ATTR_SADDR_IPV6].name = "saddr-ipv6";
	arr[TCP_METRICS_ATTR_SADDR_IPV6].type = YNL_PT_BINARY;
	arr[TCP_METRICS_ATTR_PAD].name = "pad";
	arr[TCP_METRICS_ATTR_PAD].type = YNL_PT_IGNORE;
	return arr;
} ();

struct ynl_policy_nest tcp_metrics_nest = {
	.max_attr = static_cast<unsigned int>(TCP_METRICS_ATTR_MAX),
	.table = tcp_metrics_policy.data(),
};

/* Common nested types */
int tcp_metrics_metrics_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	tcp_metrics_metrics *dst = (tcp_metrics_metrics *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCP_METRICS_A_METRICS_RTT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rtt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_RTTVAR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rttvar = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_SSTHRESH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ssthresh = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_CWND) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cwnd = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_REODERING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->reodering = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_RTT_US) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rtt_us = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_A_METRICS_RTTVAR_US) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rttvar_us = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

/* ============== TCP_METRICS_CMD_GET ============== */
/* TCP_METRICS_CMD_GET - do */
int tcp_metrics_get_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	tcp_metrics_get_rsp *dst;

	dst = (tcp_metrics_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == TCP_METRICS_ATTR_ADDR_IPV4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->addr_ipv4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_ATTR_ADDR_IPV6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->addr_ipv6.assign(data, data + len);
		} else if (type == TCP_METRICS_ATTR_SADDR_IPV4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->saddr_ipv4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == TCP_METRICS_ATTR_SADDR_IPV6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->saddr_ipv6.assign(data, data + len);
		} else if (type == TCP_METRICS_ATTR_AGE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->age = (__u64)ynl_attr_get_u64(attr);
		} else if (type == TCP_METRICS_ATTR_VALS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &tcp_metrics_metrics_nest;
			parg.data = &dst->vals.emplace();
			if (tcp_metrics_metrics_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == TCP_METRICS_ATTR_FOPEN_MSS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fopen_mss = (__u16)ynl_attr_get_u16(attr);
		} else if (type == TCP_METRICS_ATTR_FOPEN_SYN_DROPS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fopen_syn_drops = (__u16)ynl_attr_get_u16(attr);
		} else if (type == TCP_METRICS_ATTR_FOPEN_SYN_DROP_TS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fopen_syn_drop_ts = (__u64)ynl_attr_get_u64(attr);
		} else if (type == TCP_METRICS_ATTR_FOPEN_COOKIE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->fopen_cookie.assign(data, data + len);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<tcp_metrics_get_rsp>
tcp_metrics_get(ynl_cpp::ynl_socket& ys, tcp_metrics_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<tcp_metrics_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, TCP_METRICS_CMD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &tcp_metrics_nest;
	yrs.yarg.rsp_policy = &tcp_metrics_nest;

	if (req.addr_ipv4.has_value()) {
		ynl_attr_put_u32(nlh, TCP_METRICS_ATTR_ADDR_IPV4, req.addr_ipv4.value());
	}
	if (req.addr_ipv6.size() > 0) {
		ynl_attr_put(nlh, TCP_METRICS_ATTR_ADDR_IPV6, req.addr_ipv6.data(), req.addr_ipv6.size());
	}
	if (req.saddr_ipv4.has_value()) {
		ynl_attr_put_u32(nlh, TCP_METRICS_ATTR_SADDR_IPV4, req.saddr_ipv4.value());
	}
	if (req.saddr_ipv6.size() > 0) {
		ynl_attr_put(nlh, TCP_METRICS_ATTR_SADDR_IPV6, req.saddr_ipv6.data(), req.saddr_ipv6.size());
	}

	rsp.reset(new tcp_metrics_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = tcp_metrics_get_rsp_parse;
	yrs.rsp_cmd = TCP_METRICS_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* TCP_METRICS_CMD_GET - dump */
std::unique_ptr<tcp_metrics_get_list>
tcp_metrics_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<tcp_metrics_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &tcp_metrics_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<tcp_metrics_get_list*>(arg)->objs.emplace_back());};
	yds.cb = tcp_metrics_get_rsp_parse;
	yds.rsp_cmd = TCP_METRICS_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, TCP_METRICS_CMD_GET, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== TCP_METRICS_CMD_DEL ============== */
/* TCP_METRICS_CMD_DEL - do */
int tcp_metrics_del(ynl_cpp::ynl_socket& ys, tcp_metrics_del_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, TCP_METRICS_CMD_DEL, 1);
	((struct ynl_sock*)ys)->req_policy = &tcp_metrics_nest;

	if (req.addr_ipv4.has_value()) {
		ynl_attr_put_u32(nlh, TCP_METRICS_ATTR_ADDR_IPV4, req.addr_ipv4.value());
	}
	if (req.addr_ipv6.size() > 0) {
		ynl_attr_put(nlh, TCP_METRICS_ATTR_ADDR_IPV6, req.addr_ipv6.data(), req.addr_ipv6.size());
	}
	if (req.saddr_ipv4.has_value()) {
		ynl_attr_put_u32(nlh, TCP_METRICS_ATTR_SADDR_IPV4, req.saddr_ipv4.value());
	}
	if (req.saddr_ipv6.size() > 0) {
		ynl_attr_put(nlh, TCP_METRICS_ATTR_SADDR_IPV6, req.saddr_ipv6.data(), req.saddr_ipv6.size());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

const struct ynl_family ynl_tcp_metrics_family =  {
	.name		= "tcp_metrics",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_tcp_metrics_family() {
	return ynl_tcp_metrics_family;
};
} //namespace ynl_cpp
