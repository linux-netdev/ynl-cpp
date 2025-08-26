// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "rt-route-user.hpp"

#include <array>

#include <linux/rtnetlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, 24 + 1> rt_route_op_strmap = []() {
	std::array<std::string_view, 24 + 1> arr{};
	arr[24] = "getroute";
	return arr;
} ();

std::string_view rt_route_op_str(int op)
{
	if (op < 0 || op >= (int)(rt_route_op_strmap.size())) {
		return "";
	}
	return rt_route_op_strmap[op];
}

static constexpr std::array<std::string_view, 11 + 1> rt_route_rtm_type_strmap = []() {
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

std::string_view rt_route_rtm_type_str(int value)
{
	if (value < 0 || value >= (int)(rt_route_rtm_type_strmap.size())) {
		return "";
	}
	return rt_route_rtm_type_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,RTAX_MAX + 1> rt_route_metrics_policy = []() {
	std::array<ynl_policy_attr,RTAX_MAX + 1> arr{};
	arr[RTAX_UNSPEC].name = "unspec";
	arr[RTAX_UNSPEC].type = YNL_PT_REJECT;
	arr[RTAX_LOCK].name = "lock";
	arr[RTAX_LOCK].type = YNL_PT_U32;
	arr[RTAX_MTU].name = "mtu";
	arr[RTAX_MTU].type = YNL_PT_U32;
	arr[RTAX_WINDOW].name = "window";
	arr[RTAX_WINDOW].type = YNL_PT_U32;
	arr[RTAX_RTT].name = "rtt";
	arr[RTAX_RTT].type = YNL_PT_U32;
	arr[RTAX_RTTVAR].name = "rttvar";
	arr[RTAX_RTTVAR].type = YNL_PT_U32;
	arr[RTAX_SSTHRESH].name = "ssthresh";
	arr[RTAX_SSTHRESH].type = YNL_PT_U32;
	arr[RTAX_CWND].name = "cwnd";
	arr[RTAX_CWND].type = YNL_PT_U32;
	arr[RTAX_ADVMSS].name = "advmss";
	arr[RTAX_ADVMSS].type = YNL_PT_U32;
	arr[RTAX_REORDERING].name = "reordering";
	arr[RTAX_REORDERING].type = YNL_PT_U32;
	arr[RTAX_HOPLIMIT].name = "hoplimit";
	arr[RTAX_HOPLIMIT].type = YNL_PT_U32;
	arr[RTAX_INITCWND].name = "initcwnd";
	arr[RTAX_INITCWND].type = YNL_PT_U32;
	arr[RTAX_FEATURES].name = "features";
	arr[RTAX_FEATURES].type = YNL_PT_U32;
	arr[RTAX_RTO_MIN].name = "rto-min";
	arr[RTAX_RTO_MIN].type = YNL_PT_U32;
	arr[RTAX_INITRWND].name = "initrwnd";
	arr[RTAX_INITRWND].type = YNL_PT_U32;
	arr[RTAX_QUICKACK].name = "quickack";
	arr[RTAX_QUICKACK].type = YNL_PT_U32;
	arr[RTAX_CC_ALGO].name = "cc-algo";
	arr[RTAX_CC_ALGO].type  = YNL_PT_NUL_STR;
	arr[RTAX_FASTOPEN_NO_COOKIE].name = "fastopen-no-cookie";
	arr[RTAX_FASTOPEN_NO_COOKIE].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_route_metrics_nest = {
	.max_attr = static_cast<unsigned int>(RTAX_MAX),
	.table = rt_route_metrics_policy.data(),
};

static std::array<ynl_policy_attr,RTA_MAX + 1> rt_route_route_attrs_policy = []() {
	std::array<ynl_policy_attr,RTA_MAX + 1> arr{};
	arr[RTA_DST].name = "dst";
	arr[RTA_DST].type = YNL_PT_BINARY;
	arr[RTA_SRC].name = "src";
	arr[RTA_SRC].type = YNL_PT_BINARY;
	arr[RTA_IIF].name = "iif";
	arr[RTA_IIF].type = YNL_PT_U32;
	arr[RTA_OIF].name = "oif";
	arr[RTA_OIF].type = YNL_PT_U32;
	arr[RTA_GATEWAY].name = "gateway";
	arr[RTA_GATEWAY].type = YNL_PT_BINARY;
	arr[RTA_PRIORITY].name = "priority";
	arr[RTA_PRIORITY].type = YNL_PT_U32;
	arr[RTA_PREFSRC].name = "prefsrc";
	arr[RTA_PREFSRC].type = YNL_PT_BINARY;
	arr[RTA_METRICS].name = "metrics";
	arr[RTA_METRICS].type = YNL_PT_NEST;
	arr[RTA_METRICS].nest = &rt_route_metrics_nest;
	arr[RTA_MULTIPATH].name = "multipath";
	arr[RTA_MULTIPATH].type = YNL_PT_BINARY;
	arr[RTA_PROTOINFO].name = "protoinfo";
	arr[RTA_PROTOINFO].type = YNL_PT_BINARY;
	arr[RTA_FLOW].name = "flow";
	arr[RTA_FLOW].type = YNL_PT_U32;
	arr[RTA_CACHEINFO].name = "cacheinfo";
	arr[RTA_CACHEINFO].type = YNL_PT_BINARY;
	arr[RTA_SESSION].name = "session";
	arr[RTA_SESSION].type = YNL_PT_BINARY;
	arr[RTA_MP_ALGO].name = "mp-algo";
	arr[RTA_MP_ALGO].type = YNL_PT_BINARY;
	arr[RTA_TABLE].name = "table";
	arr[RTA_TABLE].type = YNL_PT_U32;
	arr[RTA_MARK].name = "mark";
	arr[RTA_MARK].type = YNL_PT_U32;
	arr[RTA_MFC_STATS].name = "mfc-stats";
	arr[RTA_MFC_STATS].type = YNL_PT_BINARY;
	arr[RTA_VIA].name = "via";
	arr[RTA_VIA].type = YNL_PT_BINARY;
	arr[RTA_NEWDST].name = "newdst";
	arr[RTA_NEWDST].type = YNL_PT_BINARY;
	arr[RTA_PREF].name = "pref";
	arr[RTA_PREF].type = YNL_PT_U8;
	arr[RTA_ENCAP_TYPE].name = "encap-type";
	arr[RTA_ENCAP_TYPE].type = YNL_PT_U16;
	arr[RTA_ENCAP].name = "encap";
	arr[RTA_ENCAP].type = YNL_PT_BINARY;
	arr[RTA_EXPIRES].name = "expires";
	arr[RTA_EXPIRES].type = YNL_PT_U32;
	arr[RTA_PAD].name = "pad";
	arr[RTA_PAD].type = YNL_PT_BINARY;
	arr[RTA_UID].name = "uid";
	arr[RTA_UID].type = YNL_PT_U32;
	arr[RTA_TTL_PROPAGATE].name = "ttl-propagate";
	arr[RTA_TTL_PROPAGATE].type = YNL_PT_U8;
	arr[RTA_IP_PROTO].name = "ip-proto";
	arr[RTA_IP_PROTO].type = YNL_PT_U8;
	arr[RTA_SPORT].name = "sport";
	arr[RTA_SPORT].type = YNL_PT_U16;
	arr[RTA_DPORT].name = "dport";
	arr[RTA_DPORT].type = YNL_PT_U16;
	arr[RTA_NH_ID].name = "nh-id";
	arr[RTA_NH_ID].type = YNL_PT_U32;
	arr[RTA_FLOWLABEL].name = "flowlabel";
	arr[RTA_FLOWLABEL].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_route_route_attrs_nest = {
	.max_attr = static_cast<unsigned int>(RTA_MAX),
	.table = rt_route_route_attrs_policy.data(),
};

/* Common nested types */
int rt_route_metrics_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 const rt_route_metrics&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.lock.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_LOCK, obj.lock.value());
	}
	if (obj.mtu.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_MTU, obj.mtu.value());
	}
	if (obj.window.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_WINDOW, obj.window.value());
	}
	if (obj.rtt.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_RTT, obj.rtt.value());
	}
	if (obj.rttvar.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_RTTVAR, obj.rttvar.value());
	}
	if (obj.ssthresh.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_SSTHRESH, obj.ssthresh.value());
	}
	if (obj.cwnd.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_CWND, obj.cwnd.value());
	}
	if (obj.advmss.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_ADVMSS, obj.advmss.value());
	}
	if (obj.reordering.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_REORDERING, obj.reordering.value());
	}
	if (obj.hoplimit.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_HOPLIMIT, obj.hoplimit.value());
	}
	if (obj.initcwnd.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_INITCWND, obj.initcwnd.value());
	}
	if (obj.features.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_FEATURES, obj.features.value());
	}
	if (obj.rto_min.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_RTO_MIN, obj.rto_min.value());
	}
	if (obj.initrwnd.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_INITRWND, obj.initrwnd.value());
	}
	if (obj.quickack.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_QUICKACK, obj.quickack.value());
	}
	if (obj.cc_algo.size() > 0) {
		ynl_attr_put_str(nlh, RTAX_CC_ALGO, obj.cc_algo.data());
	}
	if (obj.fastopen_no_cookie.has_value()) {
		ynl_attr_put_u32(nlh, RTAX_FASTOPEN_NO_COOKIE, obj.fastopen_no_cookie.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_route_metrics_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	rt_route_metrics *dst = (rt_route_metrics *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == RTAX_LOCK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->lock = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_MTU) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mtu = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_WINDOW) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->window = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_RTT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rtt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_RTTVAR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rttvar = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_SSTHRESH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ssthresh = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_CWND) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cwnd = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_ADVMSS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->advmss = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_REORDERING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->reordering = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_HOPLIMIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->hoplimit = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_INITCWND) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->initcwnd = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_FEATURES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->features = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_RTO_MIN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rto_min = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_INITRWND) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->initrwnd = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_QUICKACK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->quickack = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTAX_CC_ALGO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cc_algo.assign(ynl_attr_get_str(attr));
		} else if (type == RTAX_FASTOPEN_NO_COOKIE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fastopen_no_cookie = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

/* ============== RTM_GETROUTE ============== */
/* RTM_GETROUTE - do */
int rt_route_getroute_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	rt_route_getroute_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	void *hdr;

	dst = (rt_route_getroute_rsp*)yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct rtmsg));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == RTA_DST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->dst.assign(data, data + len);
		} else if (type == RTA_SRC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->src.assign(data, data + len);
		} else if (type == RTA_IIF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->iif = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTA_OIF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->oif = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTA_GATEWAY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->gateway.assign(data, data + len);
		} else if (type == RTA_PRIORITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->priority = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTA_PREFSRC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->prefsrc.assign(data, data + len);
		} else if (type == RTA_METRICS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_route_metrics_nest;
			parg.data = &dst->metrics.emplace();
			if (rt_route_metrics_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == RTA_MULTIPATH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->multipath.assign(data, data + len);
		} else if (type == RTA_FLOW) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flow = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTA_CACHEINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct rta_cacheinfo);
			dst->cacheinfo.emplace();
			memcpy(&*dst->cacheinfo, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == RTA_TABLE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->table = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTA_MARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mark = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTA_MFC_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->mfc_stats.assign(data, data + len);
		} else if (type == RTA_VIA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->via.assign(data, data + len);
		} else if (type == RTA_NEWDST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->newdst.assign(data, data + len);
		} else if (type == RTA_PREF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->pref = (__u8)ynl_attr_get_u8(attr);
		} else if (type == RTA_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_type = (__u16)ynl_attr_get_u16(attr);
		} else if (type == RTA_ENCAP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->encap.assign(data, data + len);
		} else if (type == RTA_EXPIRES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->expires = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTA_PAD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->pad.assign(data, data + len);
		} else if (type == RTA_UID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->uid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTA_TTL_PROPAGATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ttl_propagate = (__u8)ynl_attr_get_u8(attr);
		} else if (type == RTA_IP_PROTO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ip_proto = (__u8)ynl_attr_get_u8(attr);
		} else if (type == RTA_SPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == RTA_DPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == RTA_NH_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->nh_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == RTA_FLOWLABEL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flowlabel = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<rt_route_getroute_rsp>
rt_route_getroute(ynl_cpp::ynl_socket& ys, rt_route_getroute_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<rt_route_getroute_rsp> rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETROUTE, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_route_route_attrs_nest;
	yrs.yarg.rsp_policy = &rt_route_route_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.src.size() > 0) {
		ynl_attr_put(nlh, RTA_SRC, req.src.data(), req.src.size());
	}
	if (req.dst.size() > 0) {
		ynl_attr_put(nlh, RTA_DST, req.dst.data(), req.dst.size());
	}
	if (req.iif.has_value()) {
		ynl_attr_put_u32(nlh, RTA_IIF, req.iif.value());
	}
	if (req.oif.has_value()) {
		ynl_attr_put_u32(nlh, RTA_OIF, req.oif.value());
	}
	if (req.ip_proto.has_value()) {
		ynl_attr_put_u8(nlh, RTA_IP_PROTO, req.ip_proto.value());
	}
	if (req.sport.has_value()) {
		ynl_attr_put_u16(nlh, RTA_SPORT, req.sport.value());
	}
	if (req.dport.has_value()) {
		ynl_attr_put_u16(nlh, RTA_DPORT, req.dport.value());
	}
	if (req.mark.has_value()) {
		ynl_attr_put_u32(nlh, RTA_MARK, req.mark.value());
	}
	if (req.uid.has_value()) {
		ynl_attr_put_u32(nlh, RTA_UID, req.uid.value());
	}
	if (req.flowlabel.has_value()) {
		ynl_attr_put_u32(nlh, RTA_FLOWLABEL, req.flowlabel.value());
	}

	rsp.reset(new rt_route_getroute_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = rt_route_getroute_rsp_parse;
	yrs.rsp_cmd = 24;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* RTM_GETROUTE - dump */
std::unique_ptr<rt_route_getroute_list>
rt_route_getroute_dump(ynl_cpp::ynl_socket& ys,
		       rt_route_getroute_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<rt_route_getroute_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_route_route_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<rt_route_getroute_list*>(arg)->objs.emplace_back());};
	yds.cb = rt_route_getroute_rsp_parse;
	yds.rsp_cmd = 24;

	nlh = ynl_msg_start_dump(ys, RTM_GETROUTE);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &rt_route_route_attrs_nest;

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== RTM_NEWROUTE ============== */
/* RTM_NEWROUTE - do */
int rt_route_newroute(ynl_cpp::ynl_socket& ys, rt_route_newroute_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWROUTE, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_route_route_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.dst.size() > 0) {
		ynl_attr_put(nlh, RTA_DST, req.dst.data(), req.dst.size());
	}
	if (req.src.size() > 0) {
		ynl_attr_put(nlh, RTA_SRC, req.src.data(), req.src.size());
	}
	if (req.iif.has_value()) {
		ynl_attr_put_u32(nlh, RTA_IIF, req.iif.value());
	}
	if (req.oif.has_value()) {
		ynl_attr_put_u32(nlh, RTA_OIF, req.oif.value());
	}
	if (req.gateway.size() > 0) {
		ynl_attr_put(nlh, RTA_GATEWAY, req.gateway.data(), req.gateway.size());
	}
	if (req.priority.has_value()) {
		ynl_attr_put_u32(nlh, RTA_PRIORITY, req.priority.value());
	}
	if (req.prefsrc.size() > 0) {
		ynl_attr_put(nlh, RTA_PREFSRC, req.prefsrc.data(), req.prefsrc.size());
	}
	if (req.metrics.has_value()) {
		rt_route_metrics_put(nlh, RTA_METRICS, req.metrics.value());
	}
	if (req.multipath.size() > 0) {
		ynl_attr_put(nlh, RTA_MULTIPATH, req.multipath.data(), req.multipath.size());
	}
	if (req.flow.has_value()) {
		ynl_attr_put_u32(nlh, RTA_FLOW, req.flow.value());
	}
	if (req.cacheinfo) {
		ynl_attr_put(nlh, RTA_CACHEINFO, &*req.cacheinfo, sizeof(struct rta_cacheinfo));
	}
	if (req.table.has_value()) {
		ynl_attr_put_u32(nlh, RTA_TABLE, req.table.value());
	}
	if (req.mark.has_value()) {
		ynl_attr_put_u32(nlh, RTA_MARK, req.mark.value());
	}
	if (req.mfc_stats.size() > 0) {
		ynl_attr_put(nlh, RTA_MFC_STATS, req.mfc_stats.data(), req.mfc_stats.size());
	}
	if (req.via.size() > 0) {
		ynl_attr_put(nlh, RTA_VIA, req.via.data(), req.via.size());
	}
	if (req.newdst.size() > 0) {
		ynl_attr_put(nlh, RTA_NEWDST, req.newdst.data(), req.newdst.size());
	}
	if (req.pref.has_value()) {
		ynl_attr_put_u8(nlh, RTA_PREF, req.pref.value());
	}
	if (req.encap_type.has_value()) {
		ynl_attr_put_u16(nlh, RTA_ENCAP_TYPE, req.encap_type.value());
	}
	if (req.encap.size() > 0) {
		ynl_attr_put(nlh, RTA_ENCAP, req.encap.data(), req.encap.size());
	}
	if (req.expires.has_value()) {
		ynl_attr_put_u32(nlh, RTA_EXPIRES, req.expires.value());
	}
	if (req.pad.size() > 0) {
		ynl_attr_put(nlh, RTA_PAD, req.pad.data(), req.pad.size());
	}
	if (req.uid.has_value()) {
		ynl_attr_put_u32(nlh, RTA_UID, req.uid.value());
	}
	if (req.ttl_propagate.has_value()) {
		ynl_attr_put_u8(nlh, RTA_TTL_PROPAGATE, req.ttl_propagate.value());
	}
	if (req.ip_proto.has_value()) {
		ynl_attr_put_u8(nlh, RTA_IP_PROTO, req.ip_proto.value());
	}
	if (req.sport.has_value()) {
		ynl_attr_put_u16(nlh, RTA_SPORT, req.sport.value());
	}
	if (req.dport.has_value()) {
		ynl_attr_put_u16(nlh, RTA_DPORT, req.dport.value());
	}
	if (req.nh_id.has_value()) {
		ynl_attr_put_u32(nlh, RTA_NH_ID, req.nh_id.value());
	}
	if (req.flowlabel.has_value()) {
		ynl_attr_put_u32(nlh, RTA_FLOWLABEL, req.flowlabel.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_DELROUTE ============== */
/* RTM_DELROUTE - do */
int rt_route_delroute(ynl_cpp::ynl_socket& ys, rt_route_delroute_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELROUTE, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_route_route_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.dst.size() > 0) {
		ynl_attr_put(nlh, RTA_DST, req.dst.data(), req.dst.size());
	}
	if (req.src.size() > 0) {
		ynl_attr_put(nlh, RTA_SRC, req.src.data(), req.src.size());
	}
	if (req.iif.has_value()) {
		ynl_attr_put_u32(nlh, RTA_IIF, req.iif.value());
	}
	if (req.oif.has_value()) {
		ynl_attr_put_u32(nlh, RTA_OIF, req.oif.value());
	}
	if (req.gateway.size() > 0) {
		ynl_attr_put(nlh, RTA_GATEWAY, req.gateway.data(), req.gateway.size());
	}
	if (req.priority.has_value()) {
		ynl_attr_put_u32(nlh, RTA_PRIORITY, req.priority.value());
	}
	if (req.prefsrc.size() > 0) {
		ynl_attr_put(nlh, RTA_PREFSRC, req.prefsrc.data(), req.prefsrc.size());
	}
	if (req.metrics.has_value()) {
		rt_route_metrics_put(nlh, RTA_METRICS, req.metrics.value());
	}
	if (req.multipath.size() > 0) {
		ynl_attr_put(nlh, RTA_MULTIPATH, req.multipath.data(), req.multipath.size());
	}
	if (req.flow.has_value()) {
		ynl_attr_put_u32(nlh, RTA_FLOW, req.flow.value());
	}
	if (req.cacheinfo) {
		ynl_attr_put(nlh, RTA_CACHEINFO, &*req.cacheinfo, sizeof(struct rta_cacheinfo));
	}
	if (req.table.has_value()) {
		ynl_attr_put_u32(nlh, RTA_TABLE, req.table.value());
	}
	if (req.mark.has_value()) {
		ynl_attr_put_u32(nlh, RTA_MARK, req.mark.value());
	}
	if (req.mfc_stats.size() > 0) {
		ynl_attr_put(nlh, RTA_MFC_STATS, req.mfc_stats.data(), req.mfc_stats.size());
	}
	if (req.via.size() > 0) {
		ynl_attr_put(nlh, RTA_VIA, req.via.data(), req.via.size());
	}
	if (req.newdst.size() > 0) {
		ynl_attr_put(nlh, RTA_NEWDST, req.newdst.data(), req.newdst.size());
	}
	if (req.pref.has_value()) {
		ynl_attr_put_u8(nlh, RTA_PREF, req.pref.value());
	}
	if (req.encap_type.has_value()) {
		ynl_attr_put_u16(nlh, RTA_ENCAP_TYPE, req.encap_type.value());
	}
	if (req.encap.size() > 0) {
		ynl_attr_put(nlh, RTA_ENCAP, req.encap.data(), req.encap.size());
	}
	if (req.expires.has_value()) {
		ynl_attr_put_u32(nlh, RTA_EXPIRES, req.expires.value());
	}
	if (req.pad.size() > 0) {
		ynl_attr_put(nlh, RTA_PAD, req.pad.data(), req.pad.size());
	}
	if (req.uid.has_value()) {
		ynl_attr_put_u32(nlh, RTA_UID, req.uid.value());
	}
	if (req.ttl_propagate.has_value()) {
		ynl_attr_put_u8(nlh, RTA_TTL_PROPAGATE, req.ttl_propagate.value());
	}
	if (req.ip_proto.has_value()) {
		ynl_attr_put_u8(nlh, RTA_IP_PROTO, req.ip_proto.value());
	}
	if (req.sport.has_value()) {
		ynl_attr_put_u16(nlh, RTA_SPORT, req.sport.value());
	}
	if (req.dport.has_value()) {
		ynl_attr_put_u16(nlh, RTA_DPORT, req.dport.value());
	}
	if (req.nh_id.has_value()) {
		ynl_attr_put_u32(nlh, RTA_NH_ID, req.nh_id.value());
	}
	if (req.flowlabel.has_value()) {
		ynl_attr_put_u32(nlh, RTA_FLOWLABEL, req.flowlabel.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

const struct ynl_family ynl_rt_route_family =  {
	.name		= "rt_route",
	.is_classic	= true,
	.classic_id	= 0,
	.hdr_len	= sizeof(struct rtmsg),
};
const struct ynl_family& get_ynl_rt_route_family() {
	return ynl_rt_route_family;
};
} //namespace ynl_cpp
