// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "rt-addr-user.hpp"

#include <array>

#include <linux/rtnetlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, RTM_GETMULTICAST + 1> rt_addr_op_strmap = []() {
	std::array<std::string_view, RTM_GETMULTICAST + 1> arr{};
	arr[20] = "getaddr";
	arr[RTM_GETMULTICAST] = "getmulticast";
	return arr;
} ();

std::string_view rt_addr_op_str(int op)
{
	if (op < 0 || op >= (int)(rt_addr_op_strmap.size())) {
		return "";
	}
	return rt_addr_op_strmap[op];
}

static constexpr std::array<std::string_view, 11 + 1> rt_addr_ifa_flags_strmap = []() {
	std::array<std::string_view, 11 + 1> arr{};
	arr[0] = "secondary";
	arr[1] = "nodad";
	arr[2] = "optimistic";
	arr[3] = "dadfailed";
	arr[4] = "homeaddress";
	arr[5] = "deprecated";
	arr[6] = "tentative";
	arr[7] = "permanent";
	arr[8] = "managetempaddr";
	arr[9] = "noprefixroute";
	arr[10] = "mcautojoin";
	arr[11] = "stable-privacy";
	return arr;
} ();

std::string_view rt_addr_ifa_flags_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(rt_addr_ifa_flags_strmap.size())) {
		return "";
	}
	return rt_addr_ifa_flags_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,IFA_MAX + 1> rt_addr_addr_attrs_policy = []() {
	std::array<ynl_policy_attr,IFA_MAX + 1> arr{};
	arr[IFA_ADDRESS].name = "address";
	arr[IFA_ADDRESS].type = YNL_PT_BINARY;
	arr[IFA_LOCAL].name = "local";
	arr[IFA_LOCAL].type = YNL_PT_BINARY;
	arr[IFA_LABEL].name = "label";
	arr[IFA_LABEL].type  = YNL_PT_NUL_STR;
	arr[IFA_BROADCAST].name = "broadcast";
	arr[IFA_BROADCAST].type = YNL_PT_BINARY;
	arr[IFA_ANYCAST].name = "anycast";
	arr[IFA_ANYCAST].type = YNL_PT_BINARY;
	arr[IFA_CACHEINFO].name = "cacheinfo";
	arr[IFA_CACHEINFO].type = YNL_PT_BINARY;
	arr[IFA_MULTICAST].name = "multicast";
	arr[IFA_MULTICAST].type = YNL_PT_BINARY;
	arr[IFA_FLAGS].name = "flags";
	arr[IFA_FLAGS].type = YNL_PT_U32;
	arr[IFA_RT_PRIORITY].name = "rt-priority";
	arr[IFA_RT_PRIORITY].type = YNL_PT_U32;
	arr[IFA_TARGET_NETNSID].name = "target-netnsid";
	arr[IFA_TARGET_NETNSID].type = YNL_PT_BINARY;
	arr[IFA_PROTO].name = "proto";
	arr[IFA_PROTO].type = YNL_PT_U8;
	return arr;
} ();

struct ynl_policy_nest rt_addr_addr_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFA_MAX),
	.table = rt_addr_addr_attrs_policy.data(),
};

/* Common nested types */
/* ============== RTM_NEWADDR ============== */
/* RTM_NEWADDR - do */
int rt_addr_newaddr(ynl_cpp::ynl_socket& ys, rt_addr_newaddr_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWADDR, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_addr_addr_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.address.size() > 0) {
		ynl_attr_put(nlh, IFA_ADDRESS, req.address.data(), req.address.size());
	}
	if (req.label.size() > 0) {
		ynl_attr_put_str(nlh, IFA_LABEL, req.label.data());
	}
	if (req.local.size() > 0) {
		ynl_attr_put(nlh, IFA_LOCAL, req.local.data(), req.local.size());
	}
	if (req.cacheinfo) {
		ynl_attr_put(nlh, IFA_CACHEINFO, &*req.cacheinfo, sizeof(struct ifa_cacheinfo));
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_DELADDR ============== */
/* RTM_DELADDR - do */
int rt_addr_deladdr(ynl_cpp::ynl_socket& ys, rt_addr_deladdr_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELADDR, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_addr_addr_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.address.size() > 0) {
		ynl_attr_put(nlh, IFA_ADDRESS, req.address.data(), req.address.size());
	}
	if (req.local.size() > 0) {
		ynl_attr_put(nlh, IFA_LOCAL, req.local.data(), req.local.size());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_GETADDR ============== */
/* RTM_GETADDR - dump */
int rt_addr_getaddr_rsp_dump_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	rt_addr_getaddr_rsp_dump *dst;
	const struct nlattr *attr;
	void *hdr;

	dst = (rt_addr_getaddr_rsp_dump*)yarg->data;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ifaddrmsg));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFA_ADDRESS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->address.assign(data, data + len);
		} else if (type == IFA_LABEL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->label.assign(ynl_attr_get_str(attr));
		} else if (type == IFA_LOCAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->local.assign(data, data + len);
		} else if (type == IFA_CACHEINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifa_cacheinfo);
			dst->cacheinfo.emplace();
			memcpy(&*dst->cacheinfo, ynl_attr_data(attr), std::min(struct_sz, len));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<rt_addr_getaddr_rsp_list>
rt_addr_getaddr_dump(ynl_cpp::ynl_socket& ys, rt_addr_getaddr_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<rt_addr_getaddr_rsp_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_addr_addr_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<rt_addr_getaddr_rsp_list*>(arg)->objs.emplace_back());};
	yds.cb = rt_addr_getaddr_rsp_dump_parse;
	yds.rsp_cmd = 20;

	nlh = ynl_msg_start_dump(ys, RTM_GETADDR);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &rt_addr_addr_attrs_nest;

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== RTM_GETMULTICAST ============== */
/* RTM_GETMULTICAST - do */
int rt_addr_getmulticast_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	rt_addr_getmulticast_rsp *dst;
	const struct nlattr *attr;
	void *hdr;

	dst = (rt_addr_getmulticast_rsp*)yarg->data;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ifaddrmsg));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFA_MULTICAST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->multicast.assign(data, data + len);
		} else if (type == IFA_CACHEINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifa_cacheinfo);
			dst->cacheinfo.emplace();
			memcpy(&*dst->cacheinfo, ynl_attr_data(attr), std::min(struct_sz, len));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<rt_addr_getmulticast_rsp>
rt_addr_getmulticast(ynl_cpp::ynl_socket& ys, rt_addr_getmulticast_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<rt_addr_getmulticast_rsp> rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETMULTICAST, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_addr_addr_attrs_nest;
	yrs.yarg.rsp_policy = &rt_addr_addr_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	rsp.reset(new rt_addr_getmulticast_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = rt_addr_getmulticast_rsp_parse;
	yrs.rsp_cmd = RTM_GETMULTICAST;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* RTM_GETMULTICAST - dump */
std::unique_ptr<rt_addr_getmulticast_list>
rt_addr_getmulticast_dump(ynl_cpp::ynl_socket& ys,
			  rt_addr_getmulticast_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<rt_addr_getmulticast_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_addr_addr_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<rt_addr_getmulticast_list*>(arg)->objs.emplace_back());};
	yds.cb = rt_addr_getmulticast_rsp_parse;
	yds.rsp_cmd = RTM_GETMULTICAST;

	nlh = ynl_msg_start_dump(ys, RTM_GETMULTICAST);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &rt_addr_addr_attrs_nest;

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

const struct ynl_family ynl_rt_addr_family =  {
	.name		= "rt_addr",
	.is_classic	= true,
	.classic_id	= 0,
	.hdr_len	= sizeof(struct ifaddrmsg),
};
const struct ynl_family& get_ynl_rt_addr_family() {
	return ynl_rt_addr_family;
};
} //namespace ynl_cpp
