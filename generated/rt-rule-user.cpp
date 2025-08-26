// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "rt-rule-user.hpp"

#include <array>

#include <linux/fib_rules.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, 33 + 1> rt_rule_op_strmap = []() {
	std::array<std::string_view, 33 + 1> arr{};
	arr[33] = "delrule-ntf";
	arr[32] = "getrule";
	return arr;
} ();

std::string_view rt_rule_op_str(int op)
{
	if (op < 0 || op >= (int)(rt_rule_op_strmap.size())) {
		return "";
	}
	return rt_rule_op_strmap[op];
}

static constexpr std::array<std::string_view, 8 + 1> rt_rule_fr_act_strmap = []() {
	std::array<std::string_view, 8 + 1> arr{};
	arr[0] = "unspec";
	arr[1] = "to-tbl";
	arr[2] = "goto";
	arr[3] = "nop";
	arr[4] = "res3";
	arr[5] = "res4";
	arr[6] = "blackhole";
	arr[7] = "unreachable";
	arr[8] = "prohibit";
	return arr;
} ();

std::string_view rt_rule_fr_act_str(int value)
{
	if (value < 0 || value >= (int)(rt_rule_fr_act_strmap.size())) {
		return "";
	}
	return rt_rule_fr_act_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,FRA_MAX + 1> rt_rule_fib_rule_attrs_policy = []() {
	std::array<ynl_policy_attr,FRA_MAX + 1> arr{};
	arr[FRA_DST].name = "dst";
	arr[FRA_DST].type = YNL_PT_U32;
	arr[FRA_SRC].name = "src";
	arr[FRA_SRC].type = YNL_PT_U32;
	arr[FRA_IIFNAME].name = "iifname";
	arr[FRA_IIFNAME].type  = YNL_PT_NUL_STR;
	arr[FRA_GOTO].name = "goto";
	arr[FRA_GOTO].type = YNL_PT_U32;
	arr[FRA_UNUSED2].name = "unused2";
	arr[FRA_UNUSED2].type = YNL_PT_IGNORE;
	arr[FRA_PRIORITY].name = "priority";
	arr[FRA_PRIORITY].type = YNL_PT_U32;
	arr[FRA_UNUSED3].name = "unused3";
	arr[FRA_UNUSED3].type = YNL_PT_IGNORE;
	arr[FRA_UNUSED4].name = "unused4";
	arr[FRA_UNUSED4].type = YNL_PT_IGNORE;
	arr[FRA_UNUSED5].name = "unused5";
	arr[FRA_UNUSED5].type = YNL_PT_IGNORE;
	arr[FRA_FWMARK].name = "fwmark";
	arr[FRA_FWMARK].type = YNL_PT_U32;
	arr[FRA_FLOW].name = "flow";
	arr[FRA_FLOW].type = YNL_PT_U32;
	arr[FRA_TUN_ID].name = "tun-id";
	arr[FRA_TUN_ID].type = YNL_PT_U64;
	arr[FRA_SUPPRESS_IFGROUP].name = "suppress-ifgroup";
	arr[FRA_SUPPRESS_IFGROUP].type = YNL_PT_U32;
	arr[FRA_SUPPRESS_PREFIXLEN].name = "suppress-prefixlen";
	arr[FRA_SUPPRESS_PREFIXLEN].type = YNL_PT_U32;
	arr[FRA_TABLE].name = "table";
	arr[FRA_TABLE].type = YNL_PT_U32;
	arr[FRA_FWMASK].name = "fwmask";
	arr[FRA_FWMASK].type = YNL_PT_U32;
	arr[FRA_OIFNAME].name = "oifname";
	arr[FRA_OIFNAME].type  = YNL_PT_NUL_STR;
	arr[FRA_PAD].name = "pad";
	arr[FRA_PAD].type = YNL_PT_IGNORE;
	arr[FRA_L3MDEV].name = "l3mdev";
	arr[FRA_L3MDEV].type = YNL_PT_U8;
	arr[FRA_UID_RANGE].name = "uid-range";
	arr[FRA_UID_RANGE].type = YNL_PT_BINARY;
	arr[FRA_PROTOCOL].name = "protocol";
	arr[FRA_PROTOCOL].type = YNL_PT_U8;
	arr[FRA_IP_PROTO].name = "ip-proto";
	arr[FRA_IP_PROTO].type = YNL_PT_U8;
	arr[FRA_SPORT_RANGE].name = "sport-range";
	arr[FRA_SPORT_RANGE].type = YNL_PT_BINARY;
	arr[FRA_DPORT_RANGE].name = "dport-range";
	arr[FRA_DPORT_RANGE].type = YNL_PT_BINARY;
	arr[FRA_DSCP].name = "dscp";
	arr[FRA_DSCP].type = YNL_PT_U8;
	arr[FRA_FLOWLABEL].name = "flowlabel";
	arr[FRA_FLOWLABEL].type = YNL_PT_U32;
	arr[FRA_FLOWLABEL_MASK].name = "flowlabel-mask";
	arr[FRA_FLOWLABEL_MASK].type = YNL_PT_U32;
	arr[FRA_SPORT_MASK].name = "sport-mask";
	arr[FRA_SPORT_MASK].type = YNL_PT_U16;
	arr[FRA_DPORT_MASK].name = "dport-mask";
	arr[FRA_DPORT_MASK].type = YNL_PT_U16;
	arr[FRA_DSCP_MASK].name = "dscp-mask";
	arr[FRA_DSCP_MASK].type = YNL_PT_U8;
	return arr;
} ();

struct ynl_policy_nest rt_rule_fib_rule_attrs_nest = {
	.max_attr = static_cast<unsigned int>(FRA_MAX),
	.table = rt_rule_fib_rule_attrs_policy.data(),
};

/* Common nested types */
/* ============== RTM_NEWRULE ============== */
/* RTM_NEWRULE - do */
int rt_rule_newrule(ynl_cpp::ynl_socket& ys, rt_rule_newrule_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWRULE, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_rule_fib_rule_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.iifname.size() > 0) {
		ynl_attr_put_str(nlh, FRA_IIFNAME, req.iifname.data());
	}
	if (req.oifname.size() > 0) {
		ynl_attr_put_str(nlh, FRA_OIFNAME, req.oifname.data());
	}
	if (req.priority.has_value()) {
		ynl_attr_put_u32(nlh, FRA_PRIORITY, req.priority.value());
	}
	if (req.fwmark.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FWMARK, req.fwmark.value());
	}
	if (req.flow.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FLOW, req.flow.value());
	}
	if (req.tun_id.has_value()) {
		ynl_attr_put_u64(nlh, FRA_TUN_ID, req.tun_id.value());
	}
	if (req.fwmask.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FWMASK, req.fwmask.value());
	}
	if (req.table.has_value()) {
		ynl_attr_put_u32(nlh, FRA_TABLE, req.table.value());
	}
	if (req.suppress_prefixlen.has_value()) {
		ynl_attr_put_u32(nlh, FRA_SUPPRESS_PREFIXLEN, req.suppress_prefixlen.value());
	}
	if (req.suppress_ifgroup.has_value()) {
		ynl_attr_put_u32(nlh, FRA_SUPPRESS_IFGROUP, req.suppress_ifgroup.value());
	}
	if (req.goto_.has_value()) {
		ynl_attr_put_u32(nlh, FRA_GOTO, req.goto_.value());
	}
	if (req.l3mdev.has_value()) {
		ynl_attr_put_u8(nlh, FRA_L3MDEV, req.l3mdev.value());
	}
	if (req.uid_range) {
		ynl_attr_put(nlh, FRA_UID_RANGE, &*req.uid_range, sizeof(struct fib_rule_uid_range));
	}
	if (req.protocol.has_value()) {
		ynl_attr_put_u8(nlh, FRA_PROTOCOL, req.protocol.value());
	}
	if (req.ip_proto.has_value()) {
		ynl_attr_put_u8(nlh, FRA_IP_PROTO, req.ip_proto.value());
	}
	if (req.sport_range) {
		ynl_attr_put(nlh, FRA_SPORT_RANGE, &*req.sport_range, sizeof(struct fib_rule_port_range));
	}
	if (req.dport_range) {
		ynl_attr_put(nlh, FRA_DPORT_RANGE, &*req.dport_range, sizeof(struct fib_rule_port_range));
	}
	if (req.dscp.has_value()) {
		ynl_attr_put_u8(nlh, FRA_DSCP, req.dscp.value());
	}
	if (req.flowlabel.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FLOWLABEL, req.flowlabel.value());
	}
	if (req.flowlabel_mask.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FLOWLABEL_MASK, req.flowlabel_mask.value());
	}
	if (req.sport_mask.has_value()) {
		ynl_attr_put_u16(nlh, FRA_SPORT_MASK, req.sport_mask.value());
	}
	if (req.dport_mask.has_value()) {
		ynl_attr_put_u16(nlh, FRA_DPORT_MASK, req.dport_mask.value());
	}
	if (req.dscp_mask.has_value()) {
		ynl_attr_put_u8(nlh, FRA_DSCP_MASK, req.dscp_mask.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_DELRULE ============== */
/* RTM_DELRULE - do */
int rt_rule_delrule(ynl_cpp::ynl_socket& ys, rt_rule_delrule_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELRULE, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_rule_fib_rule_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.iifname.size() > 0) {
		ynl_attr_put_str(nlh, FRA_IIFNAME, req.iifname.data());
	}
	if (req.oifname.size() > 0) {
		ynl_attr_put_str(nlh, FRA_OIFNAME, req.oifname.data());
	}
	if (req.priority.has_value()) {
		ynl_attr_put_u32(nlh, FRA_PRIORITY, req.priority.value());
	}
	if (req.fwmark.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FWMARK, req.fwmark.value());
	}
	if (req.flow.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FLOW, req.flow.value());
	}
	if (req.tun_id.has_value()) {
		ynl_attr_put_u64(nlh, FRA_TUN_ID, req.tun_id.value());
	}
	if (req.fwmask.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FWMASK, req.fwmask.value());
	}
	if (req.table.has_value()) {
		ynl_attr_put_u32(nlh, FRA_TABLE, req.table.value());
	}
	if (req.suppress_prefixlen.has_value()) {
		ynl_attr_put_u32(nlh, FRA_SUPPRESS_PREFIXLEN, req.suppress_prefixlen.value());
	}
	if (req.suppress_ifgroup.has_value()) {
		ynl_attr_put_u32(nlh, FRA_SUPPRESS_IFGROUP, req.suppress_ifgroup.value());
	}
	if (req.goto_.has_value()) {
		ynl_attr_put_u32(nlh, FRA_GOTO, req.goto_.value());
	}
	if (req.l3mdev.has_value()) {
		ynl_attr_put_u8(nlh, FRA_L3MDEV, req.l3mdev.value());
	}
	if (req.uid_range) {
		ynl_attr_put(nlh, FRA_UID_RANGE, &*req.uid_range, sizeof(struct fib_rule_uid_range));
	}
	if (req.protocol.has_value()) {
		ynl_attr_put_u8(nlh, FRA_PROTOCOL, req.protocol.value());
	}
	if (req.ip_proto.has_value()) {
		ynl_attr_put_u8(nlh, FRA_IP_PROTO, req.ip_proto.value());
	}
	if (req.sport_range) {
		ynl_attr_put(nlh, FRA_SPORT_RANGE, &*req.sport_range, sizeof(struct fib_rule_port_range));
	}
	if (req.dport_range) {
		ynl_attr_put(nlh, FRA_DPORT_RANGE, &*req.dport_range, sizeof(struct fib_rule_port_range));
	}
	if (req.dscp.has_value()) {
		ynl_attr_put_u8(nlh, FRA_DSCP, req.dscp.value());
	}
	if (req.flowlabel.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FLOWLABEL, req.flowlabel.value());
	}
	if (req.flowlabel_mask.has_value()) {
		ynl_attr_put_u32(nlh, FRA_FLOWLABEL_MASK, req.flowlabel_mask.value());
	}
	if (req.sport_mask.has_value()) {
		ynl_attr_put_u16(nlh, FRA_SPORT_MASK, req.sport_mask.value());
	}
	if (req.dport_mask.has_value()) {
		ynl_attr_put_u16(nlh, FRA_DPORT_MASK, req.dport_mask.value());
	}
	if (req.dscp_mask.has_value()) {
		ynl_attr_put_u8(nlh, FRA_DSCP_MASK, req.dscp_mask.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_GETRULE ============== */
/* RTM_GETRULE - dump */
int rt_rule_getrule_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	rt_rule_getrule_rsp *dst;
	void *hdr;

	dst = (rt_rule_getrule_rsp*)yarg->data;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct fib_rule_hdr));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == FRA_IIFNAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->iifname.assign(ynl_attr_get_str(attr));
		} else if (type == FRA_OIFNAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->oifname.assign(ynl_attr_get_str(attr));
		} else if (type == FRA_PRIORITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->priority = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_FWMARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fwmark = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_FLOW) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flow = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_TUN_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tun_id = (__u64)ynl_attr_get_u64(attr);
		} else if (type == FRA_FWMASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fwmask = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_TABLE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->table = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_SUPPRESS_PREFIXLEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->suppress_prefixlen = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_SUPPRESS_IFGROUP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->suppress_ifgroup = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_GOTO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->goto_ = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_L3MDEV) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->l3mdev = (__u8)ynl_attr_get_u8(attr);
		} else if (type == FRA_UID_RANGE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct fib_rule_uid_range);
			dst->uid_range.emplace();
			memcpy(&*dst->uid_range, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == FRA_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->protocol = (__u8)ynl_attr_get_u8(attr);
		} else if (type == FRA_IP_PROTO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ip_proto = (__u8)ynl_attr_get_u8(attr);
		} else if (type == FRA_SPORT_RANGE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct fib_rule_port_range);
			dst->sport_range.emplace();
			memcpy(&*dst->sport_range, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == FRA_DPORT_RANGE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct fib_rule_port_range);
			dst->dport_range.emplace();
			memcpy(&*dst->dport_range, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == FRA_DSCP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dscp = (__u8)ynl_attr_get_u8(attr);
		} else if (type == FRA_FLOWLABEL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flowlabel = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_FLOWLABEL_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flowlabel_mask = (__u32)ynl_attr_get_u32(attr);
		} else if (type == FRA_SPORT_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sport_mask = (__u16)ynl_attr_get_u16(attr);
		} else if (type == FRA_DPORT_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dport_mask = (__u16)ynl_attr_get_u16(attr);
		} else if (type == FRA_DSCP_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dscp_mask = (__u8)ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<rt_rule_getrule_list>
rt_rule_getrule_dump(ynl_cpp::ynl_socket& ys, rt_rule_getrule_req& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<rt_rule_getrule_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_rule_fib_rule_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<rt_rule_getrule_list*>(arg)->objs.emplace_back());};
	yds.cb = rt_rule_getrule_rsp_parse;
	yds.rsp_cmd = 32;

	nlh = ynl_msg_start_dump(ys, RTM_GETRULE);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &rt_rule_fib_rule_attrs_nest;

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* RTM_GETRULE - notify */

static constexpr std::array<ynl_ntf_info, RTM_DELRULE + 1> rt_rule_ntf_info = []() {
	std::array<ynl_ntf_info, RTM_DELRULE + 1> arr{};
	arr[RTM_NEWRULE].policy		= &rt_rule_fib_rule_attrs_nest;
	arr[RTM_NEWRULE].cb		= rt_rule_getrule_rsp_parse;
	arr[RTM_DELRULE].policy		= &rt_rule_fib_rule_attrs_nest;
	arr[RTM_DELRULE].cb		= rt_rule_getrule_rsp_parse;
	return arr;
} ();

const struct ynl_family ynl_rt_rule_family =  {
	.name		= "rt_rule",
	.is_classic	= true,
	.classic_id	= 0,
	.hdr_len	= sizeof(struct fib_rule_hdr),
	.ntf_info	= rt_rule_ntf_info.data(),
	.ntf_info_size	= rt_rule_ntf_info.size(),
};
const struct ynl_family& get_ynl_rt_rule_family() {
	return ynl_rt_rule_family;
};
} //namespace ynl_cpp
