// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "ovs_packet-user.hpp"

#include <array>

#include <linux/openvswitch.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, OVS_PACKET_CMD_EXECUTE + 1> ovs_packet_op_strmap = []() {
	std::array<std::string_view, OVS_PACKET_CMD_EXECUTE + 1> arr{};
	arr[OVS_PACKET_CMD_MISS] = "miss";
	arr[OVS_PACKET_CMD_ACTION] = "action";
	arr[OVS_PACKET_CMD_EXECUTE] = "execute";
	return arr;
} ();

std::string_view ovs_packet_op_str(int op)
{
	if (op < 0 || op >= (int)(ovs_packet_op_strmap.size())) {
		return "";
	}
	return ovs_packet_op_strmap[op];
}

/* Policies */
static std::array<ynl_policy_attr,OVS_PACKET_ATTR_MAX + 1> ovs_packet_packet_policy = []() {
	std::array<ynl_policy_attr,OVS_PACKET_ATTR_MAX + 1> arr{};
	arr[OVS_PACKET_ATTR_PACKET].name = "packet";
	arr[OVS_PACKET_ATTR_PACKET].type = YNL_PT_BINARY;
	arr[OVS_PACKET_ATTR_KEY].name = "key";
	arr[OVS_PACKET_ATTR_KEY].type = YNL_PT_BINARY;
	arr[OVS_PACKET_ATTR_ACTIONS].name = "actions";
	arr[OVS_PACKET_ATTR_ACTIONS].type = YNL_PT_BINARY;
	arr[OVS_PACKET_ATTR_USERDATA].name = "userdata";
	arr[OVS_PACKET_ATTR_USERDATA].type = YNL_PT_BINARY;
	arr[OVS_PACKET_ATTR_EGRESS_TUN_KEY].name = "egress-tun-key";
	arr[OVS_PACKET_ATTR_EGRESS_TUN_KEY].type = YNL_PT_BINARY;
	arr[OVS_PACKET_ATTR_UNUSED1].name = "unused1";
	arr[OVS_PACKET_ATTR_UNUSED1].type = YNL_PT_REJECT;
	arr[OVS_PACKET_ATTR_UNUSED2].name = "unused2";
	arr[OVS_PACKET_ATTR_UNUSED2].type = YNL_PT_REJECT;
	arr[OVS_PACKET_ATTR_PROBE].name = "probe";
	arr[OVS_PACKET_ATTR_PROBE].type = YNL_PT_FLAG;
	arr[OVS_PACKET_ATTR_MRU].name = "mru";
	arr[OVS_PACKET_ATTR_MRU].type = YNL_PT_U16;
	arr[OVS_PACKET_ATTR_LEN].name = "len";
	arr[OVS_PACKET_ATTR_LEN].type = YNL_PT_U32;
	arr[OVS_PACKET_ATTR_HASH].name = "hash";
	arr[OVS_PACKET_ATTR_HASH].type = YNL_PT_U64;
	arr[OVS_PACKET_ATTR_UPCALL_PID].name = "upcall-pid";
	arr[OVS_PACKET_ATTR_UPCALL_PID].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest ovs_packet_packet_nest = {
	.max_attr = static_cast<unsigned int>(OVS_PACKET_ATTR_MAX),
	.table = ovs_packet_packet_policy.data(),
};

/* Common nested types */
/* ============== OVS_PACKET_CMD_EXECUTE ============== */
/* OVS_PACKET_CMD_EXECUTE - do */
int ovs_packet_execute(ynl_cpp::ynl_socket& ys, ovs_packet_execute_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVS_PACKET_CMD_EXECUTE, 1);
	((struct ynl_sock*)ys)->req_policy = &ovs_packet_packet_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.packet.size() > 0) {
		ynl_attr_put(nlh, OVS_PACKET_ATTR_PACKET, req.packet.data(), req.packet.size());
	}
	if (req.key.size() > 0) {
		ynl_attr_put(nlh, OVS_PACKET_ATTR_KEY, req.key.data(), req.key.size());
	}
	if (req.actions.size() > 0) {
		ynl_attr_put(nlh, OVS_PACKET_ATTR_ACTIONS, req.actions.data(), req.actions.size());
	}
	if (req.probe) {
		ynl_attr_put(nlh, OVS_PACKET_ATTR_PROBE, NULL, 0);
	}
	if (req.mru.has_value()) {
		ynl_attr_put_u16(nlh, OVS_PACKET_ATTR_MRU, req.mru.value());
	}
	if (req.hash.has_value()) {
		ynl_attr_put_u64(nlh, OVS_PACKET_ATTR_HASH, req.hash.value());
	}
	if (req.upcall_pid.has_value()) {
		ynl_attr_put_u32(nlh, OVS_PACKET_ATTR_UPCALL_PID, req.upcall_pid.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* OVS_PACKET_CMD_MISS - event */
int ovs_packet_miss_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	ovs_packet_miss_rsp *dst;
	void *hdr;

	dst = (ovs_packet_miss_rsp*)yarg->data;

	hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));
	memcpy(&dst->_hdr, hdr, sizeof(struct ovs_header));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_PACKET_ATTR_PACKET) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->packet.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->key.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_USERDATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->userdata.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_ACTIONS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->actions.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_EGRESS_TUN_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->egress_tun_key.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_MRU) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mru = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_PACKET_ATTR_LEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->len = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_PACKET_ATTR_HASH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->hash = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

static void ovs_packet_miss_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<ovs_packet_miss*>(ntf);
	typed_ntf->obj.~ovs_packet_miss_rsp();
	free(ntf);
}

/* OVS_PACKET_CMD_ACTION - event */
int ovs_packet_action_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	ovs_packet_action_rsp *dst;
	const struct nlattr *attr;
	void *hdr;

	dst = (ovs_packet_action_rsp*)yarg->data;

	hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));
	memcpy(&dst->_hdr, hdr, sizeof(struct ovs_header));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_PACKET_ATTR_PACKET) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->packet.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->key.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_USERDATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->userdata.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_ACTIONS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->actions.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_EGRESS_TUN_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->egress_tun_key.assign(data, data + len);
		} else if (type == OVS_PACKET_ATTR_MRU) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mru = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_PACKET_ATTR_LEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->len = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_PACKET_ATTR_HASH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->hash = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

static void ovs_packet_action_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<ovs_packet_action*>(ntf);
	typed_ntf->obj.~ovs_packet_action_rsp();
	free(ntf);
}

static constexpr std::array<ynl_ntf_info, OVS_PACKET_CMD_ACTION + 1> ovs_packet_ntf_info = []() {
	std::array<ynl_ntf_info, OVS_PACKET_CMD_ACTION + 1> arr{};
	arr[OVS_PACKET_CMD_MISS].policy		= &ovs_packet_packet_nest;
	arr[OVS_PACKET_CMD_MISS].cb		= ovs_packet_miss_rsp_parse;
	arr[OVS_PACKET_CMD_MISS].alloc_sz	= sizeof(ovs_packet_miss);
	arr[OVS_PACKET_CMD_MISS].free		= ovs_packet_miss_free;
	arr[OVS_PACKET_CMD_ACTION].policy		= &ovs_packet_packet_nest;
	arr[OVS_PACKET_CMD_ACTION].cb		= ovs_packet_action_rsp_parse;
	arr[OVS_PACKET_CMD_ACTION].alloc_sz	= sizeof(ovs_packet_action);
	arr[OVS_PACKET_CMD_ACTION].free		= ovs_packet_action_free;
	return arr;
} ();

const struct ynl_family ynl_ovs_packet_family =  {
	.name		= "ovs_packet",
	.hdr_len	= sizeof(struct genlmsghdr) + sizeof(struct ovs_header),
	.ntf_info	= ovs_packet_ntf_info.data(),
	.ntf_info_size	= ovs_packet_ntf_info.size(),
};
const struct ynl_family& get_ynl_ovs_packet_family() {
	return ynl_ovs_packet_family;
};
} //namespace ynl_cpp
