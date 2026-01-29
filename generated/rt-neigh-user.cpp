// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "rt-neigh-user.hpp"

#include <array>

#include <linux/rtnetlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, 64 + 1> rt_neigh_op_strmap = []() {
	std::array<std::string_view, 64 + 1> arr{};
	arr[29] = "delneigh-ntf";
	arr[28] = "newneigh-ntf";
	arr[64] = "getneightbl";
	return arr;
} ();

std::string_view rt_neigh_op_str(int op)
{
	if (op < 0 || op >= (int)(rt_neigh_op_strmap.size())) {
		return "";
	}
	return rt_neigh_op_strmap[op];
}

static constexpr std::array<std::string_view, 7 + 1> rt_neigh_nud_state_strmap = []() {
	std::array<std::string_view, 7 + 1> arr{};
	arr[0] = "incomplete";
	arr[1] = "reachable";
	arr[2] = "stale";
	arr[3] = "delay";
	arr[4] = "probe";
	arr[5] = "failed";
	arr[6] = "noarp";
	arr[7] = "permanent";
	return arr;
} ();

std::string_view rt_neigh_nud_state_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(rt_neigh_nud_state_strmap.size())) {
		return "";
	}
	return rt_neigh_nud_state_strmap[value];
}

static constexpr std::array<std::string_view, 7 + 1> rt_neigh_ntf_flags_strmap = []() {
	std::array<std::string_view, 7 + 1> arr{};
	arr[0] = "use";
	arr[1] = "self";
	arr[2] = "master";
	arr[3] = "proxy";
	arr[4] = "ext-learned";
	arr[5] = "offloaded";
	arr[6] = "sticky";
	arr[7] = "router";
	return arr;
} ();

std::string_view rt_neigh_ntf_flags_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(rt_neigh_ntf_flags_strmap.size())) {
		return "";
	}
	return rt_neigh_ntf_flags_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> rt_neigh_ntf_ext_flags_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "managed";
	arr[1] = "locked";
	arr[2] = "ext-validated";
	return arr;
} ();

std::string_view rt_neigh_ntf_ext_flags_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(rt_neigh_ntf_ext_flags_strmap.size())) {
		return "";
	}
	return rt_neigh_ntf_ext_flags_strmap[value];
}

static constexpr std::array<std::string_view, 11 + 1> rt_neigh_rtm_type_strmap = []() {
	std::array<std::string_view, 11 + 1> arr{};
	arr[0] = "unspec";
	arr[1] = "unicast";
	arr[2] = "local";
	arr[3] = "broadcast";
	arr[4] = "anycast";
	arr[5] = "multicast";
	arr[6] = "blackhole";
	arr[7] = "unreachable";
	arr[8] = "prohibit";
	arr[9] = "throw";
	arr[10] = "nat";
	arr[11] = "xresolve";
	return arr;
} ();

std::string_view rt_neigh_rtm_type_str(int value)
{
	if (value < 0 || value >= (int)(rt_neigh_rtm_type_strmap.size())) {
		return "";
	}
	return rt_neigh_rtm_type_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,NDTPA_MAX + 1> rt_neigh_ndtpa_attrs_policy = []() {
	std::array<ynl_policy_attr,NDTPA_MAX + 1> arr{};
	arr[NDTPA_IFINDEX].name = "ifindex";
	arr[NDTPA_IFINDEX].type = YNL_PT_U32;
	arr[NDTPA_REFCNT].name = "refcnt";
	arr[NDTPA_REFCNT].type = YNL_PT_U32;
	arr[NDTPA_REACHABLE_TIME].name = "reachable-time";
	arr[NDTPA_REACHABLE_TIME].type = YNL_PT_U64;
	arr[NDTPA_BASE_REACHABLE_TIME].name = "base-reachable-time";
	arr[NDTPA_BASE_REACHABLE_TIME].type = YNL_PT_U64;
	arr[NDTPA_RETRANS_TIME].name = "retrans-time";
	arr[NDTPA_RETRANS_TIME].type = YNL_PT_U64;
	arr[NDTPA_GC_STALETIME].name = "gc-staletime";
	arr[NDTPA_GC_STALETIME].type = YNL_PT_U64;
	arr[NDTPA_DELAY_PROBE_TIME].name = "delay-probe-time";
	arr[NDTPA_DELAY_PROBE_TIME].type = YNL_PT_U64;
	arr[NDTPA_QUEUE_LEN].name = "queue-len";
	arr[NDTPA_QUEUE_LEN].type = YNL_PT_U32;
	arr[NDTPA_APP_PROBES].name = "app-probes";
	arr[NDTPA_APP_PROBES].type = YNL_PT_U32;
	arr[NDTPA_UCAST_PROBES].name = "ucast-probes";
	arr[NDTPA_UCAST_PROBES].type = YNL_PT_U32;
	arr[NDTPA_MCAST_PROBES].name = "mcast-probes";
	arr[NDTPA_MCAST_PROBES].type = YNL_PT_U32;
	arr[NDTPA_ANYCAST_DELAY].name = "anycast-delay";
	arr[NDTPA_ANYCAST_DELAY].type = YNL_PT_U64;
	arr[NDTPA_PROXY_DELAY].name = "proxy-delay";
	arr[NDTPA_PROXY_DELAY].type = YNL_PT_U64;
	arr[NDTPA_PROXY_QLEN].name = "proxy-qlen";
	arr[NDTPA_PROXY_QLEN].type = YNL_PT_U32;
	arr[NDTPA_LOCKTIME].name = "locktime";
	arr[NDTPA_LOCKTIME].type = YNL_PT_U64;
	arr[NDTPA_QUEUE_LENBYTES].name = "queue-lenbytes";
	arr[NDTPA_QUEUE_LENBYTES].type = YNL_PT_U32;
	arr[NDTPA_MCAST_REPROBES].name = "mcast-reprobes";
	arr[NDTPA_MCAST_REPROBES].type = YNL_PT_U32;
	arr[NDTPA_PAD].name = "pad";
	arr[NDTPA_PAD].type = YNL_PT_IGNORE;
	arr[NDTPA_INTERVAL_PROBE_TIME_MS].name = "interval-probe-time-ms";
	arr[NDTPA_INTERVAL_PROBE_TIME_MS].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest rt_neigh_ndtpa_attrs_nest = {
	.max_attr = static_cast<unsigned int>(NDTPA_MAX),
	.table = rt_neigh_ndtpa_attrs_policy.data(),
};

static std::array<ynl_policy_attr,NDA_MAX + 1> rt_neigh_neighbour_attrs_policy = []() {
	std::array<ynl_policy_attr,NDA_MAX + 1> arr{};
	arr[NDA_UNSPEC].name = "unspec";
	arr[NDA_UNSPEC].type = YNL_PT_BINARY;
	arr[NDA_DST].name = "dst";
	arr[NDA_DST].type = YNL_PT_BINARY;
	arr[NDA_LLADDR].name = "lladdr";
	arr[NDA_LLADDR].type = YNL_PT_BINARY;
	arr[NDA_CACHEINFO].name = "cacheinfo";
	arr[NDA_CACHEINFO].type = YNL_PT_BINARY;
	arr[NDA_PROBES].name = "probes";
	arr[NDA_PROBES].type = YNL_PT_U32;
	arr[NDA_VLAN].name = "vlan";
	arr[NDA_VLAN].type = YNL_PT_U16;
	arr[NDA_PORT].name = "port";
	arr[NDA_PORT].type = YNL_PT_U16;
	arr[NDA_VNI].name = "vni";
	arr[NDA_VNI].type = YNL_PT_U32;
	arr[NDA_IFINDEX].name = "ifindex";
	arr[NDA_IFINDEX].type = YNL_PT_U32;
	arr[NDA_MASTER].name = "master";
	arr[NDA_MASTER].type = YNL_PT_U32;
	arr[NDA_LINK_NETNSID].name = "link-netnsid";
	arr[NDA_LINK_NETNSID].type = YNL_PT_U32;
	arr[NDA_SRC_VNI].name = "src-vni";
	arr[NDA_SRC_VNI].type = YNL_PT_U32;
	arr[NDA_PROTOCOL].name = "protocol";
	arr[NDA_PROTOCOL].type = YNL_PT_U8;
	arr[NDA_NH_ID].name = "nh-id";
	arr[NDA_NH_ID].type = YNL_PT_U32;
	arr[NDA_FDB_EXT_ATTRS].name = "fdb-ext-attrs";
	arr[NDA_FDB_EXT_ATTRS].type = YNL_PT_BINARY;
	arr[NDA_FLAGS_EXT].name = "flags-ext";
	arr[NDA_FLAGS_EXT].type = YNL_PT_U32;
	arr[NDA_NDM_STATE_MASK].name = "ndm-state-mask";
	arr[NDA_NDM_STATE_MASK].type = YNL_PT_U16;
	arr[NDA_NDM_FLAGS_MASK].name = "ndm-flags-mask";
	arr[NDA_NDM_FLAGS_MASK].type = YNL_PT_U8;
	return arr;
} ();

struct ynl_policy_nest rt_neigh_neighbour_attrs_nest = {
	.max_attr = static_cast<unsigned int>(NDA_MAX),
	.table = rt_neigh_neighbour_attrs_policy.data(),
};

static std::array<ynl_policy_attr,NDTA_MAX + 1> rt_neigh_ndt_attrs_policy = []() {
	std::array<ynl_policy_attr,NDTA_MAX + 1> arr{};
	arr[NDTA_NAME].name = "name";
	arr[NDTA_NAME].type  = YNL_PT_NUL_STR;
	arr[NDTA_THRESH1].name = "thresh1";
	arr[NDTA_THRESH1].type = YNL_PT_U32;
	arr[NDTA_THRESH2].name = "thresh2";
	arr[NDTA_THRESH2].type = YNL_PT_U32;
	arr[NDTA_THRESH3].name = "thresh3";
	arr[NDTA_THRESH3].type = YNL_PT_U32;
	arr[NDTA_CONFIG].name = "config";
	arr[NDTA_CONFIG].type = YNL_PT_BINARY;
	arr[NDTA_PARMS].name = "parms";
	arr[NDTA_PARMS].type = YNL_PT_NEST;
	arr[NDTA_PARMS].nest = &rt_neigh_ndtpa_attrs_nest;
	arr[NDTA_STATS].name = "stats";
	arr[NDTA_STATS].type = YNL_PT_BINARY;
	arr[NDTA_GC_INTERVAL].name = "gc-interval";
	arr[NDTA_GC_INTERVAL].type = YNL_PT_U64;
	arr[NDTA_PAD].name = "pad";
	arr[NDTA_PAD].type = YNL_PT_IGNORE;
	return arr;
} ();

struct ynl_policy_nest rt_neigh_ndt_attrs_nest = {
	.max_attr = static_cast<unsigned int>(NDTA_MAX),
	.table = rt_neigh_ndt_attrs_policy.data(),
};

/* Common nested types */
int rt_neigh_ndtpa_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     const rt_neigh_ndtpa_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NDTPA_IFINDEX, obj.ifindex.value());
	}
	if (obj.refcnt.has_value()) {
		ynl_attr_put_u32(nlh, NDTPA_REFCNT, obj.refcnt.value());
	}
	if (obj.reachable_time.has_value()) {
		ynl_attr_put_u64(nlh, NDTPA_REACHABLE_TIME, obj.reachable_time.value());
	}
	if (obj.base_reachable_time.has_value()) {
		ynl_attr_put_u64(nlh, NDTPA_BASE_REACHABLE_TIME, obj.base_reachable_time.value());
	}
	if (obj.retrans_time.has_value()) {
		ynl_attr_put_u64(nlh, NDTPA_RETRANS_TIME, obj.retrans_time.value());
	}
	if (obj.gc_staletime.has_value()) {
		ynl_attr_put_u64(nlh, NDTPA_GC_STALETIME, obj.gc_staletime.value());
	}
	if (obj.delay_probe_time.has_value()) {
		ynl_attr_put_u64(nlh, NDTPA_DELAY_PROBE_TIME, obj.delay_probe_time.value());
	}
	if (obj.queue_len.has_value()) {
		ynl_attr_put_u32(nlh, NDTPA_QUEUE_LEN, obj.queue_len.value());
	}
	if (obj.app_probes.has_value()) {
		ynl_attr_put_u32(nlh, NDTPA_APP_PROBES, obj.app_probes.value());
	}
	if (obj.ucast_probes.has_value()) {
		ynl_attr_put_u32(nlh, NDTPA_UCAST_PROBES, obj.ucast_probes.value());
	}
	if (obj.mcast_probes.has_value()) {
		ynl_attr_put_u32(nlh, NDTPA_MCAST_PROBES, obj.mcast_probes.value());
	}
	if (obj.anycast_delay.has_value()) {
		ynl_attr_put_u64(nlh, NDTPA_ANYCAST_DELAY, obj.anycast_delay.value());
	}
	if (obj.proxy_delay.has_value()) {
		ynl_attr_put_u64(nlh, NDTPA_PROXY_DELAY, obj.proxy_delay.value());
	}
	if (obj.proxy_qlen.has_value()) {
		ynl_attr_put_u32(nlh, NDTPA_PROXY_QLEN, obj.proxy_qlen.value());
	}
	if (obj.locktime.has_value()) {
		ynl_attr_put_u64(nlh, NDTPA_LOCKTIME, obj.locktime.value());
	}
	if (obj.queue_lenbytes.has_value()) {
		ynl_attr_put_u32(nlh, NDTPA_QUEUE_LENBYTES, obj.queue_lenbytes.value());
	}
	if (obj.mcast_reprobes.has_value()) {
		ynl_attr_put_u32(nlh, NDTPA_MCAST_REPROBES, obj.mcast_reprobes.value());
	}
	if (obj.interval_probe_time_ms.has_value()) {
		ynl_attr_put_u64(nlh, NDTPA_INTERVAL_PROBE_TIME_MS, obj.interval_probe_time_ms.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_neigh_ndtpa_attrs_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested)
{
	rt_neigh_ndtpa_attrs *dst = (rt_neigh_ndtpa_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NDTPA_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTPA_REFCNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->refcnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTPA_REACHABLE_TIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->reachable_time = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NDTPA_BASE_REACHABLE_TIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->base_reachable_time = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NDTPA_RETRANS_TIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->retrans_time = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NDTPA_GC_STALETIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gc_staletime = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NDTPA_DELAY_PROBE_TIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->delay_probe_time = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NDTPA_QUEUE_LEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->queue_len = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTPA_APP_PROBES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->app_probes = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTPA_UCAST_PROBES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ucast_probes = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTPA_MCAST_PROBES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_probes = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTPA_ANYCAST_DELAY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->anycast_delay = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NDTPA_PROXY_DELAY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->proxy_delay = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NDTPA_PROXY_QLEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->proxy_qlen = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTPA_LOCKTIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->locktime = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NDTPA_QUEUE_LENBYTES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->queue_lenbytes = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTPA_MCAST_REPROBES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_reprobes = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTPA_INTERVAL_PROBE_TIME_MS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->interval_probe_time_ms = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

/* ============== RTM_NEWNEIGH ============== */
/* RTM_NEWNEIGH - do */
int rt_neigh_newneigh(ynl_cpp::ynl_socket& ys, rt_neigh_newneigh_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWNEIGH, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_neigh_neighbour_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.dst.size() > 0) {
		ynl_attr_put(nlh, NDA_DST, req.dst.data(), req.dst.size());
	}
	if (req.lladdr.size() > 0) {
		ynl_attr_put(nlh, NDA_LLADDR, req.lladdr.data(), req.lladdr.size());
	}
	if (req.probes.has_value()) {
		ynl_attr_put_u32(nlh, NDA_PROBES, req.probes.value());
	}
	if (req.vlan.has_value()) {
		ynl_attr_put_u16(nlh, NDA_VLAN, req.vlan.value());
	}
	if (req.port.has_value()) {
		ynl_attr_put_u16(nlh, NDA_PORT, req.port.value());
	}
	if (req.vni.has_value()) {
		ynl_attr_put_u32(nlh, NDA_VNI, req.vni.value());
	}
	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NDA_IFINDEX, req.ifindex.value());
	}
	if (req.master.has_value()) {
		ynl_attr_put_u32(nlh, NDA_MASTER, req.master.value());
	}
	if (req.protocol.has_value()) {
		ynl_attr_put_u8(nlh, NDA_PROTOCOL, req.protocol.value());
	}
	if (req.nh_id.has_value()) {
		ynl_attr_put_u32(nlh, NDA_NH_ID, req.nh_id.value());
	}
	if (req.flags_ext.has_value()) {
		ynl_attr_put_u32(nlh, NDA_FLAGS_EXT, req.flags_ext.value());
	}
	if (req.fdb_ext_attrs.size() > 0) {
		ynl_attr_put(nlh, NDA_FDB_EXT_ATTRS, req.fdb_ext_attrs.data(), req.fdb_ext_attrs.size());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_DELNEIGH ============== */
/* RTM_DELNEIGH - do */
int rt_neigh_delneigh(ynl_cpp::ynl_socket& ys, rt_neigh_delneigh_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELNEIGH, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_neigh_neighbour_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.dst.size() > 0) {
		ynl_attr_put(nlh, NDA_DST, req.dst.data(), req.dst.size());
	}
	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NDA_IFINDEX, req.ifindex.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_GETNEIGH ============== */
/* RTM_GETNEIGH - do */
int rt_neigh_getneigh_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	rt_neigh_getneigh_rsp *dst;
	const struct nlattr *attr;
	void *hdr;

	dst = (rt_neigh_getneigh_rsp*)yarg->data;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ndmsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct ndmsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NDA_DST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->dst.assign(data, data + len);
		} else if (type == NDA_LLADDR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->lladdr.assign(data, data + len);
		} else if (type == NDA_PROBES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->probes = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDA_VLAN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vlan = (__u16)ynl_attr_get_u16(attr);
		} else if (type == NDA_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == NDA_VNI) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vni = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDA_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDA_MASTER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->master = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDA_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->protocol = (__u8)ynl_attr_get_u8(attr);
		} else if (type == NDA_NH_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->nh_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDA_FLAGS_EXT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags_ext = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDA_FDB_EXT_ATTRS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->fdb_ext_attrs.assign(data, data + len);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<rt_neigh_getneigh_rsp>
rt_neigh_getneigh(ynl_cpp::ynl_socket& ys, rt_neigh_getneigh_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<rt_neigh_getneigh_rsp> rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETNEIGH, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_neigh_neighbour_attrs_nest;
	yrs.yarg.rsp_policy = &rt_neigh_neighbour_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.dst.size() > 0) {
		ynl_attr_put(nlh, NDA_DST, req.dst.data(), req.dst.size());
	}

	rsp.reset(new rt_neigh_getneigh_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = rt_neigh_getneigh_rsp_parse;
	yrs.rsp_cmd = 28;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* RTM_GETNEIGH - dump */
std::unique_ptr<rt_neigh_getneigh_list>
rt_neigh_getneigh_dump(ynl_cpp::ynl_socket& ys,
		       rt_neigh_getneigh_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<rt_neigh_getneigh_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_neigh_neighbour_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<rt_neigh_getneigh_list*>(arg)->objs.emplace_back());};
	yds.cb = rt_neigh_getneigh_rsp_parse;
	yds.rsp_cmd = 28;

	nlh = ynl_msg_start_dump(ys, RTM_GETNEIGH);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &rt_neigh_neighbour_attrs_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, NDA_IFINDEX, req.ifindex.value());
	}
	if (req.master.has_value()) {
		ynl_attr_put_u32(nlh, NDA_MASTER, req.master.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* RTM_GETNEIGH - notify */
static void rt_neigh_getneigh_ntf_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<rt_neigh_getneigh_ntf*>(ntf);
	typed_ntf->obj.~rt_neigh_getneigh_rsp();
	free(ntf);
}

/* ============== RTM_GETNEIGHTBL ============== */
/* RTM_GETNEIGHTBL - dump */
int rt_neigh_getneightbl_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	rt_neigh_getneightbl_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	void *hdr;

	dst = (rt_neigh_getneightbl_rsp*)yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ndtmsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct ndtmsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NDTA_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->name.assign(ynl_attr_get_str(attr));
		} else if (type == NDTA_THRESH1) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->thresh1 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTA_THRESH2) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->thresh2 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTA_THRESH3) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->thresh3 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NDTA_CONFIG) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ndt_config);
			dst->config.emplace();
			memcpy(&*dst->config, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == NDTA_PARMS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_neigh_ndtpa_attrs_nest;
			parg.data = &dst->parms.emplace();
			if (rt_neigh_ndtpa_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == NDTA_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ndt_stats);
			dst->stats.emplace();
			memcpy(&*dst->stats, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == NDTA_GC_INTERVAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gc_interval = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<rt_neigh_getneightbl_list>
rt_neigh_getneightbl_dump(ynl_cpp::ynl_socket& ys,
			  rt_neigh_getneightbl_req& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<rt_neigh_getneightbl_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_neigh_ndt_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<rt_neigh_getneightbl_list*>(arg)->objs.emplace_back());};
	yds.cb = rt_neigh_getneightbl_rsp_parse;
	yds.rsp_cmd = 64;

	nlh = ynl_msg_start_dump(ys, RTM_GETNEIGHTBL);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &rt_neigh_ndt_attrs_nest;

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== RTM_SETNEIGHTBL ============== */
/* RTM_SETNEIGHTBL - do */
int rt_neigh_setneightbl(ynl_cpp::ynl_socket& ys,
			 rt_neigh_setneightbl_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_SETNEIGHTBL, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_neigh_ndt_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.name.size() > 0) {
		ynl_attr_put_str(nlh, NDTA_NAME, req.name.data());
	}
	if (req.thresh1.has_value()) {
		ynl_attr_put_u32(nlh, NDTA_THRESH1, req.thresh1.value());
	}
	if (req.thresh2.has_value()) {
		ynl_attr_put_u32(nlh, NDTA_THRESH2, req.thresh2.value());
	}
	if (req.thresh3.has_value()) {
		ynl_attr_put_u32(nlh, NDTA_THRESH3, req.thresh3.value());
	}
	if (req.parms.has_value()) {
		rt_neigh_ndtpa_attrs_put(nlh, NDTA_PARMS, req.parms.value());
	}
	if (req.gc_interval.has_value()) {
		ynl_attr_put_u64(nlh, NDTA_GC_INTERVAL, req.gc_interval.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

static constexpr std::array<ynl_ntf_info, RTM_DELNEIGH + 1> rt_neigh_ntf_info = []() {
	std::array<ynl_ntf_info, RTM_DELNEIGH + 1> arr{};
	arr[RTM_DELNEIGH].policy		= &rt_neigh_neighbour_attrs_nest;
	arr[RTM_DELNEIGH].cb		= rt_neigh_getneigh_rsp_parse;
	arr[RTM_DELNEIGH].alloc_sz	= sizeof(rt_neigh_getneigh_ntf);
	arr[RTM_DELNEIGH].free		= rt_neigh_getneigh_ntf_free;
	arr[RTM_NEWNEIGH].policy		= &rt_neigh_neighbour_attrs_nest;
	arr[RTM_NEWNEIGH].cb		= rt_neigh_getneigh_rsp_parse;
	arr[RTM_NEWNEIGH].alloc_sz	= sizeof(rt_neigh_getneigh_ntf);
	arr[RTM_NEWNEIGH].free		= rt_neigh_getneigh_ntf_free;
	return arr;
} ();

const struct ynl_family ynl_rt_neigh_family =  {
	.name		= "rt_neigh",
	.is_classic	= true,
	.classic_id	= 0,
	.ntf_info	= rt_neigh_ntf_info.data(),
	.ntf_info_size	= rt_neigh_ntf_info.size(),
};
const struct ynl_family& get_ynl_rt_neigh_family() {
	return ynl_rt_neigh_family;
};
} //namespace ynl_cpp
