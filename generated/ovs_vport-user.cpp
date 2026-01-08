// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "ovs_vport-user.hpp"

#include <array>

#include <linux/openvswitch.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, OVS_VPORT_CMD_GET + 1> ovs_vport_op_strmap = []() {
	std::array<std::string_view, OVS_VPORT_CMD_GET + 1> arr{};
	arr[OVS_VPORT_CMD_NEW] = "new";
	arr[OVS_VPORT_CMD_DEL] = "del";
	arr[OVS_VPORT_CMD_GET] = "get";
	return arr;
} ();

std::string_view ovs_vport_op_str(int op)
{
	if (op < 0 || op >= (int)(ovs_vport_op_strmap.size())) {
		return "";
	}
	return ovs_vport_op_strmap[op];
}

static constexpr std::array<std::string_view, 5 + 1> ovs_vport_vport_type_strmap = []() {
	std::array<std::string_view, 5 + 1> arr{};
	arr[0] = "unspec";
	arr[1] = "netdev";
	arr[2] = "internal";
	arr[3] = "gre";
	arr[4] = "vxlan";
	arr[5] = "geneve";
	return arr;
} ();

std::string_view ovs_vport_vport_type_str(ovs_vport_type value)
{
	if (value < 0 || value >= (int)(ovs_vport_vport_type_strmap.size())) {
		return "";
	}
	return ovs_vport_vport_type_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,OVS_TUNNEL_ATTR_MAX + 1> ovs_vport_vport_options_policy = []() {
	std::array<ynl_policy_attr,OVS_TUNNEL_ATTR_MAX + 1> arr{};
	arr[OVS_TUNNEL_ATTR_DST_PORT].name = "dst-port";
	arr[OVS_TUNNEL_ATTR_DST_PORT].type = YNL_PT_U32;
	arr[OVS_TUNNEL_ATTR_EXTENSION].name = "extension";
	arr[OVS_TUNNEL_ATTR_EXTENSION].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest ovs_vport_vport_options_nest = {
	.max_attr = static_cast<unsigned int>(OVS_TUNNEL_ATTR_MAX),
	.table = ovs_vport_vport_options_policy.data(),
};

static std::array<ynl_policy_attr,OVS_VPORT_UPCALL_ATTR_MAX + 1> ovs_vport_upcall_stats_policy = []() {
	std::array<ynl_policy_attr,OVS_VPORT_UPCALL_ATTR_MAX + 1> arr{};
	arr[OVS_VPORT_UPCALL_ATTR_SUCCESS].name = "success";
	arr[OVS_VPORT_UPCALL_ATTR_SUCCESS].type = YNL_PT_U64;
	arr[OVS_VPORT_UPCALL_ATTR_FAIL].name = "fail";
	arr[OVS_VPORT_UPCALL_ATTR_FAIL].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest ovs_vport_upcall_stats_nest = {
	.max_attr = static_cast<unsigned int>(OVS_VPORT_UPCALL_ATTR_MAX),
	.table = ovs_vport_upcall_stats_policy.data(),
};

static std::array<ynl_policy_attr,OVS_VPORT_ATTR_MAX + 1> ovs_vport_vport_policy = []() {
	std::array<ynl_policy_attr,OVS_VPORT_ATTR_MAX + 1> arr{};
	arr[OVS_VPORT_ATTR_UNSPEC].name = "unspec";
	arr[OVS_VPORT_ATTR_UNSPEC].type = YNL_PT_REJECT;
	arr[OVS_VPORT_ATTR_PORT_NO].name = "port-no";
	arr[OVS_VPORT_ATTR_PORT_NO].type = YNL_PT_U32;
	arr[OVS_VPORT_ATTR_TYPE].name = "type";
	arr[OVS_VPORT_ATTR_TYPE].type = YNL_PT_U32;
	arr[OVS_VPORT_ATTR_NAME].name = "name";
	arr[OVS_VPORT_ATTR_NAME].type  = YNL_PT_NUL_STR;
	arr[OVS_VPORT_ATTR_OPTIONS].name = "options";
	arr[OVS_VPORT_ATTR_OPTIONS].type = YNL_PT_NEST;
	arr[OVS_VPORT_ATTR_OPTIONS].nest = &ovs_vport_vport_options_nest;
	arr[OVS_VPORT_ATTR_UPCALL_PID].name = "upcall-pid";
	arr[OVS_VPORT_ATTR_UPCALL_PID].type = YNL_PT_BINARY;
	arr[OVS_VPORT_ATTR_STATS].name = "stats";
	arr[OVS_VPORT_ATTR_STATS].type = YNL_PT_BINARY;
	arr[OVS_VPORT_ATTR_PAD].name = "pad";
	arr[OVS_VPORT_ATTR_PAD].type = YNL_PT_REJECT;
	arr[OVS_VPORT_ATTR_IFINDEX].name = "ifindex";
	arr[OVS_VPORT_ATTR_IFINDEX].type = YNL_PT_U32;
	arr[OVS_VPORT_ATTR_NETNSID].name = "netnsid";
	arr[OVS_VPORT_ATTR_NETNSID].type = YNL_PT_U32;
	arr[OVS_VPORT_ATTR_UPCALL_STATS].name = "upcall-stats";
	arr[OVS_VPORT_ATTR_UPCALL_STATS].type = YNL_PT_NEST;
	arr[OVS_VPORT_ATTR_UPCALL_STATS].nest = &ovs_vport_upcall_stats_nest;
	return arr;
} ();

struct ynl_policy_nest ovs_vport_vport_nest = {
	.max_attr = static_cast<unsigned int>(OVS_VPORT_ATTR_MAX),
	.table = ovs_vport_vport_policy.data(),
};

/* Common nested types */
int ovs_vport_vport_options_put(struct nlmsghdr *nlh, unsigned int attr_type,
				const ovs_vport_vport_options&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.dst_port.has_value()) {
		ynl_attr_put_u32(nlh, OVS_TUNNEL_ATTR_DST_PORT, obj.dst_port.value());
	}
	if (obj.extension.has_value()) {
		ynl_attr_put_u32(nlh, OVS_TUNNEL_ATTR_EXTENSION, obj.extension.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_vport_upcall_stats_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	ovs_vport_upcall_stats *dst = (ovs_vport_upcall_stats *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_VPORT_UPCALL_ATTR_SUCCESS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->success = (__u64)ynl_attr_get_u64(attr);
		} else if (type == OVS_VPORT_UPCALL_ATTR_FAIL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fail = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

/* ============== OVS_VPORT_CMD_NEW ============== */
/* OVS_VPORT_CMD_NEW - do */
int ovs_vport_new(ynl_cpp::ynl_socket& ys, ovs_vport_new_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVS_VPORT_CMD_NEW, 1);
	((struct ynl_sock*)ys)->req_policy = &ovs_vport_vport_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.name.size() > 0) {
		ynl_attr_put_str(nlh, OVS_VPORT_ATTR_NAME, req.name.data());
	}
	if (req.type.has_value()) {
		ynl_attr_put_u32(nlh, OVS_VPORT_ATTR_TYPE, req.type.value());
	}
	if (req.upcall_pid.size() > 0) {
		ynl_attr_put(nlh, OVS_VPORT_ATTR_UPCALL_PID, req.upcall_pid.data(), req.upcall_pid.size());
	}
	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVS_VPORT_ATTR_IFINDEX, req.ifindex.value());
	}
	if (req.options.has_value()) {
		ovs_vport_vport_options_put(nlh, OVS_VPORT_ATTR_OPTIONS, req.options.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== OVS_VPORT_CMD_DEL ============== */
/* OVS_VPORT_CMD_DEL - do */
int ovs_vport_del(ynl_cpp::ynl_socket& ys, ovs_vport_del_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVS_VPORT_CMD_DEL, 1);
	((struct ynl_sock*)ys)->req_policy = &ovs_vport_vport_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.port_no.has_value()) {
		ynl_attr_put_u32(nlh, OVS_VPORT_ATTR_PORT_NO, req.port_no.value());
	}
	if (req.type.has_value()) {
		ynl_attr_put_u32(nlh, OVS_VPORT_ATTR_TYPE, req.type.value());
	}
	if (req.name.size() > 0) {
		ynl_attr_put_str(nlh, OVS_VPORT_ATTR_NAME, req.name.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== OVS_VPORT_CMD_GET ============== */
/* OVS_VPORT_CMD_GET - do */
int ovs_vport_get_rsp_parse(const struct nlmsghdr *nlh,
			    struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ovs_vport_get_rsp *dst;
	void *hdr;

	dst = (ovs_vport_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));
	memcpy(&dst->_hdr, hdr, sizeof(struct ovs_header));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_VPORT_ATTR_PORT_NO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_no = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_VPORT_ATTR_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->type = (enum ovs_vport_type)ynl_attr_get_u32(attr);
		} else if (type == OVS_VPORT_ATTR_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->name.assign(ynl_attr_get_str(attr));
		} else if (type == OVS_VPORT_ATTR_UPCALL_PID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->upcall_pid.assign(data, data + len);
		} else if (type == OVS_VPORT_ATTR_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_vport_stats);
			dst->stats.emplace();
			memcpy(&*dst->stats, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_VPORT_ATTR_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_VPORT_ATTR_NETNSID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->netnsid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_VPORT_ATTR_UPCALL_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_vport_upcall_stats_nest;
			parg.data = &dst->upcall_stats.emplace();
			if (ovs_vport_upcall_stats_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ovs_vport_get_rsp>
ovs_vport_get(ynl_cpp::ynl_socket& ys, ovs_vport_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ovs_vport_get_rsp> rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVS_VPORT_CMD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ovs_vport_vport_nest;
	yrs.yarg.rsp_policy = &ovs_vport_vport_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.name.size() > 0) {
		ynl_attr_put_str(nlh, OVS_VPORT_ATTR_NAME, req.name.data());
	}

	rsp.reset(new ovs_vport_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ovs_vport_get_rsp_parse;
	yrs.rsp_cmd = OVS_VPORT_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* OVS_VPORT_CMD_GET - dump */
std::unique_ptr<ovs_vport_get_list>
ovs_vport_get_dump(ynl_cpp::ynl_socket& ys, ovs_vport_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<ovs_vport_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ovs_vport_vport_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<ovs_vport_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ovs_vport_get_rsp_parse;
	yds.rsp_cmd = OVS_VPORT_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, OVS_VPORT_CMD_GET, 1);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &ovs_vport_vport_nest;

	if (req.name.size() > 0) {
		ynl_attr_put_str(nlh, OVS_VPORT_ATTR_NAME, req.name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

const struct ynl_family ynl_ovs_vport_family =  {
	.name		= "ovs_vport",
	.hdr_len	= sizeof(struct genlmsghdr) + sizeof(struct ovs_header),
};
const struct ynl_family& get_ynl_ovs_vport_family() {
	return ynl_ovs_vport_family;
};
} //namespace ynl_cpp
