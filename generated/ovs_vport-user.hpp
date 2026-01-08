/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_OVS_VPORT_GEN_H
#define _LINUX_OVS_VPORT_GEN_H

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

#include <linux/openvswitch.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_ovs_vport_family();

/* Enums */
std::string_view ovs_vport_op_str(int op);
std::string_view ovs_vport_vport_type_str(ovs_vport_type value);

/* Common nested types */
struct ovs_vport_vport_options {
	std::optional<__u32> dst_port;
	std::optional<__u32> extension;
};

struct ovs_vport_upcall_stats {
	std::optional<__u64> success;
	std::optional<__u64> fail;
};

/* ============== OVS_VPORT_CMD_NEW ============== */
/* OVS_VPORT_CMD_NEW - do */
struct ovs_vport_new_req {
	struct ovs_header _hdr;

	std::string name;
	std::optional<enum ovs_vport_type> type;
	std::vector<__u8> upcall_pid;
	std::optional<__u32> ifindex;
	std::optional<ovs_vport_vport_options> options;
};

/*
 * Create a new OVS vport
 */
int ovs_vport_new(ynl_cpp::ynl_socket& ys, ovs_vport_new_req& req);

/* ============== OVS_VPORT_CMD_DEL ============== */
/* OVS_VPORT_CMD_DEL - do */
struct ovs_vport_del_req {
	struct ovs_header _hdr;

	std::optional<__u32> port_no;
	std::optional<enum ovs_vport_type> type;
	std::string name;
};

/*
 * Delete existing OVS vport from a data path
 */
int ovs_vport_del(ynl_cpp::ynl_socket& ys, ovs_vport_del_req& req);

/* ============== OVS_VPORT_CMD_GET ============== */
/* OVS_VPORT_CMD_GET - do */
struct ovs_vport_get_req {
	struct ovs_header _hdr;

	std::string name;
};

struct ovs_vport_get_rsp {
	struct ovs_header _hdr;

	std::optional<__u32> port_no;
	std::optional<enum ovs_vport_type> type;
	std::string name;
	std::vector<__u8> upcall_pid;
	std::optional<struct ovs_vport_stats> stats;
	std::optional<__u32> ifindex;
	std::optional<__u32> netnsid;
	std::optional<ovs_vport_upcall_stats> upcall_stats;
};

/*
 * Get / dump OVS vport configuration and state
 */
std::unique_ptr<ovs_vport_get_rsp>
ovs_vport_get(ynl_cpp::ynl_socket& ys, ovs_vport_get_req& req);

/* OVS_VPORT_CMD_GET - dump */
struct ovs_vport_get_req_dump {
	struct ovs_header _hdr;

	std::string name;
};

struct ovs_vport_get_list {
	std::list<ovs_vport_get_rsp> objs;
};

std::unique_ptr<ovs_vport_get_list>
ovs_vport_get_dump(ynl_cpp::ynl_socket& ys, ovs_vport_get_req_dump& req);

} //namespace ynl_cpp
#endif /* _LINUX_OVS_VPORT_GEN_H */
