// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "ovs_datapath-user.hpp"

#include <array>

#include <linux/openvswitch.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, OVS_DP_CMD_DEL + 1> ovs_datapath_op_strmap = []() {
	std::array<std::string_view, OVS_DP_CMD_DEL + 1> arr{};
	arr[OVS_DP_CMD_GET] = "get";
	arr[OVS_DP_CMD_NEW] = "new";
	arr[OVS_DP_CMD_DEL] = "del";
	return arr;
} ();

std::string_view ovs_datapath_op_str(int op)
{
	if (op < 0 || op >= (int)(ovs_datapath_op_strmap.size())) {
		return "";
	}
	return ovs_datapath_op_strmap[op];
}

static constexpr std::array<std::string_view, 3 + 1> ovs_datapath_user_features_strmap = []() {
	std::array<std::string_view, 3 + 1> arr{};
	arr[0] = "unaligned";
	arr[1] = "vport-pids";
	arr[2] = "tc-recirc-sharing";
	arr[3] = "dispatch-upcall-per-cpu";
	return arr;
} ();

std::string_view ovs_datapath_user_features_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(ovs_datapath_user_features_strmap.size())) {
		return "";
	}
	return ovs_datapath_user_features_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,OVS_DP_ATTR_MAX + 1> ovs_datapath_datapath_policy = []() {
	std::array<ynl_policy_attr,OVS_DP_ATTR_MAX + 1> arr{};
	arr[OVS_DP_ATTR_NAME].name = "name";
	arr[OVS_DP_ATTR_NAME].type  = YNL_PT_NUL_STR;
	arr[OVS_DP_ATTR_UPCALL_PID].name = "upcall-pid";
	arr[OVS_DP_ATTR_UPCALL_PID].type = YNL_PT_U32;
	arr[OVS_DP_ATTR_STATS].name = "stats";
	arr[OVS_DP_ATTR_STATS].type = YNL_PT_BINARY;
	arr[OVS_DP_ATTR_MEGAFLOW_STATS].name = "megaflow-stats";
	arr[OVS_DP_ATTR_MEGAFLOW_STATS].type = YNL_PT_BINARY;
	arr[OVS_DP_ATTR_USER_FEATURES].name = "user-features";
	arr[OVS_DP_ATTR_USER_FEATURES].type = YNL_PT_U32;
	arr[OVS_DP_ATTR_PAD].name = "pad";
	arr[OVS_DP_ATTR_PAD].type = YNL_PT_REJECT;
	arr[OVS_DP_ATTR_MASKS_CACHE_SIZE].name = "masks-cache-size";
	arr[OVS_DP_ATTR_MASKS_CACHE_SIZE].type = YNL_PT_U32;
	arr[OVS_DP_ATTR_PER_CPU_PIDS].name = "per-cpu-pids";
	arr[OVS_DP_ATTR_PER_CPU_PIDS].type = YNL_PT_BINARY;
	arr[OVS_DP_ATTR_IFINDEX].name = "ifindex";
	arr[OVS_DP_ATTR_IFINDEX].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest ovs_datapath_datapath_nest = {
	.max_attr = static_cast<unsigned int>(OVS_DP_ATTR_MAX),
	.table = ovs_datapath_datapath_policy.data(),
};

/* Common nested types */
/* ============== OVS_DP_CMD_GET ============== */
/* OVS_DP_CMD_GET - do */
int ovs_datapath_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	ovs_datapath_get_rsp *dst;
	const struct nlattr *attr;
	void *hdr;

	dst = (ovs_datapath_get_rsp*)yarg->data;

	hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));
	memcpy(&dst->_hdr, hdr, sizeof(struct ovs_header));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_DP_ATTR_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->name.assign(ynl_attr_get_str(attr));
		} else if (type == OVS_DP_ATTR_UPCALL_PID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->upcall_pid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_DP_ATTR_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_dp_stats);
			dst->stats.emplace();
			memcpy(&*dst->stats, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_DP_ATTR_MEGAFLOW_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_dp_megaflow_stats);
			dst->megaflow_stats.emplace();
			memcpy(&*dst->megaflow_stats, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_DP_ATTR_USER_FEATURES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->user_features = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_DP_ATTR_MASKS_CACHE_SIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->masks_cache_size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_DP_ATTR_PER_CPU_PIDS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->per_cpu_pids.assign(data, data + len);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ovs_datapath_get_rsp>
ovs_datapath_get(ynl_cpp::ynl_socket& ys, ovs_datapath_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ovs_datapath_get_rsp> rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVS_DP_CMD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ovs_datapath_datapath_nest;
	yrs.yarg.rsp_policy = &ovs_datapath_datapath_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.name.size() > 0) {
		ynl_attr_put_str(nlh, OVS_DP_ATTR_NAME, req.name.data());
	}

	rsp.reset(new ovs_datapath_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ovs_datapath_get_rsp_parse;
	yrs.rsp_cmd = OVS_DP_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* OVS_DP_CMD_GET - dump */
std::unique_ptr<ovs_datapath_get_list>
ovs_datapath_get_dump(ynl_cpp::ynl_socket& ys, ovs_datapath_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<ovs_datapath_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ovs_datapath_datapath_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ovs_datapath_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ovs_datapath_get_rsp_parse;
	yds.rsp_cmd = OVS_DP_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, OVS_DP_CMD_GET, 1);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &ovs_datapath_datapath_nest;

	if (req.name.size() > 0) {
		ynl_attr_put_str(nlh, OVS_DP_ATTR_NAME, req.name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== OVS_DP_CMD_NEW ============== */
/* OVS_DP_CMD_NEW - do */
int ovs_datapath_new(ynl_cpp::ynl_socket& ys, ovs_datapath_new_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVS_DP_CMD_NEW, 1);
	((struct ynl_sock*)ys)->req_policy = &ovs_datapath_datapath_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.name.size() > 0) {
		ynl_attr_put_str(nlh, OVS_DP_ATTR_NAME, req.name.data());
	}
	if (req.upcall_pid.has_value()) {
		ynl_attr_put_u32(nlh, OVS_DP_ATTR_UPCALL_PID, req.upcall_pid.value());
	}
	if (req.user_features.has_value()) {
		ynl_attr_put_u32(nlh, OVS_DP_ATTR_USER_FEATURES, req.user_features.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== OVS_DP_CMD_DEL ============== */
/* OVS_DP_CMD_DEL - do */
int ovs_datapath_del(ynl_cpp::ynl_socket& ys, ovs_datapath_del_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVS_DP_CMD_DEL, 1);
	((struct ynl_sock*)ys)->req_policy = &ovs_datapath_datapath_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.name.size() > 0) {
		ynl_attr_put_str(nlh, OVS_DP_ATTR_NAME, req.name.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

const struct ynl_family ynl_ovs_datapath_family =  {
	.name		= "ovs_datapath",
	.hdr_len	= sizeof(struct genlmsghdr) + sizeof(struct ovs_header),
};
const struct ynl_family& get_ynl_ovs_datapath_family() {
	return ynl_ovs_datapath_family;
};
} //namespace ynl_cpp
