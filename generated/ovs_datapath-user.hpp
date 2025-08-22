/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_OVS_DATAPATH_GEN_H
#define _LINUX_OVS_DATAPATH_GEN_H

#include <linux/types.h>
#include <stdlib.h>
#include <string.h>

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ynl.hpp"

#include <linux/openvswitch.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_ovs_datapath_family();

/* Enums */
std::string_view ovs_datapath_op_str(int op);
std::string_view ovs_datapath_user_features_str(int value);

/* Common nested types */
/* ============== OVS_DP_CMD_GET ============== */
/* OVS_DP_CMD_GET - do */
struct ovs_datapath_get_req {
	struct ovs_header _hdr;

	std::string name;
};

struct ovs_datapath_get_rsp {
	struct ovs_header _hdr;

	std::string name;
	std::optional<__u32> upcall_pid;
	std::optional<struct ovs_dp_stats> stats;
	std::optional<struct ovs_dp_megaflow_stats> megaflow_stats;
	std::optional<__u32> user_features;
	std::optional<__u32> masks_cache_size;
	std::vector<__u8> per_cpu_pids;
};

/*
 * Get / dump OVS data path configuration and state
 */
std::unique_ptr<ovs_datapath_get_rsp>
ovs_datapath_get(ynl_cpp::ynl_socket& ys, ovs_datapath_get_req& req);

/* OVS_DP_CMD_GET - dump */
struct ovs_datapath_get_req_dump {
	struct ovs_header _hdr;

	std::string name;
};

struct ovs_datapath_get_list {
	std::list<ovs_datapath_get_rsp> objs;
};

std::unique_ptr<ovs_datapath_get_list>
ovs_datapath_get_dump(ynl_cpp::ynl_socket& ys, ovs_datapath_get_req_dump& req);

/* ============== OVS_DP_CMD_NEW ============== */
/* OVS_DP_CMD_NEW - do */
struct ovs_datapath_new_req {
	struct ovs_header _hdr;

	std::string name;
	std::optional<__u32> upcall_pid;
	std::optional<__u32> user_features;
};

/*
 * Create new OVS data path
 */
int ovs_datapath_new(ynl_cpp::ynl_socket& ys, ovs_datapath_new_req& req);

/* ============== OVS_DP_CMD_DEL ============== */
/* OVS_DP_CMD_DEL - do */
struct ovs_datapath_del_req {
	struct ovs_header _hdr;

	std::string name;
};

/*
 * Delete existing OVS data path
 */
int ovs_datapath_del(ynl_cpp::ynl_socket& ys, ovs_datapath_del_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_OVS_DATAPATH_GEN_H */
