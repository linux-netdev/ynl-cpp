/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_RT_ADDR_GEN_H
#define _LINUX_RT_ADDR_GEN_H

#include <linux/types.h>
#include <stdlib.h>
#include <string.h>

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <array>

#include "ynl.hpp"

#include <linux/rtnetlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_rt_addr_family();

/* Enums */
std::string_view rt_addr_op_str(int op);
std::string_view rt_addr_ifa_flags_str(int value);

/* Common nested types */
/* ============== RTM_NEWADDR ============== */
/* RTM_NEWADDR - do */
struct rt_addr_newaddr_req {
	__u16 _nlmsg_flags;

	struct ifaddrmsg _hdr;

	std::vector<__u8> address;
	std::string label;
	std::vector<__u8> local;
	std::optional<struct ifa_cacheinfo> cacheinfo;
};

/*
 * Add new address
 */
int rt_addr_newaddr(ynl_cpp::ynl_socket& ys, rt_addr_newaddr_req& req);

/* ============== RTM_DELADDR ============== */
/* RTM_DELADDR - do */
struct rt_addr_deladdr_req {
	__u16 _nlmsg_flags;

	struct ifaddrmsg _hdr;

	std::vector<__u8> address;
	std::vector<__u8> local;
};

/*
 * Remove address
 */
int rt_addr_deladdr(ynl_cpp::ynl_socket& ys, rt_addr_deladdr_req& req);

/* ============== RTM_GETADDR ============== */
/* RTM_GETADDR - dump */
struct rt_addr_getaddr_req {
	struct ifaddrmsg _hdr;
};

struct rt_addr_getaddr_rsp {
	struct ifaddrmsg _hdr;

	std::vector<__u8> address;
	std::string label;
	std::vector<__u8> local;
	std::optional<struct ifa_cacheinfo> cacheinfo;
};

struct rt_addr_getaddr_list {
	std::list<rt_addr_getaddr_rsp> objs;
};

std::unique_ptr<rt_addr_getaddr_list>
rt_addr_getaddr_dump(ynl_cpp::ynl_socket& ys, rt_addr_getaddr_req& req);

/* ============== RTM_GETMULTICAST ============== */
/* RTM_GETMULTICAST - do */
struct rt_addr_getmulticast_req {
	__u16 _nlmsg_flags;

	struct ifaddrmsg _hdr;
};

struct rt_addr_getmulticast_rsp {
	struct ifaddrmsg _hdr;

	std::vector<__u8> multicast;
	std::optional<__u32> mc_users;
	std::optional<struct ifa_cacheinfo> cacheinfo;
};

/*
 * Get / dump IPv4/IPv6 multicast addresses.
 */
std::unique_ptr<rt_addr_getmulticast_rsp>
rt_addr_getmulticast(ynl_cpp::ynl_socket& ys, rt_addr_getmulticast_req& req);

/* RTM_GETMULTICAST - dump */
struct rt_addr_getmulticast_req_dump {
	struct ifaddrmsg _hdr;
};

struct rt_addr_getmulticast_list {
	std::list<rt_addr_getmulticast_rsp> objs;
};

std::unique_ptr<rt_addr_getmulticast_list>
rt_addr_getmulticast_dump(ynl_cpp::ynl_socket& ys,
			  rt_addr_getmulticast_req_dump& req);

} //namespace ynl_cpp
#endif /* _LINUX_RT_ADDR_GEN_H */
