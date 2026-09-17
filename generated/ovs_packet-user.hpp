/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_OVS_PACKET_GEN_H
#define _LINUX_OVS_PACKET_GEN_H

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
const struct ynl_family& get_ynl_ovs_packet_family();

/* Enums */
std::string_view ovs_packet_op_str(int op);

/* Common nested types */
/* ============== OVS_PACKET_CMD_EXECUTE ============== */
/* OVS_PACKET_CMD_EXECUTE - do */
struct ovs_packet_execute_req {
	struct ovs_header _hdr;

	std::vector<__u8> packet;
	std::vector<__u8> key;
	std::vector<__u8> actions;
	bool probe{};
	std::optional<__u16> mru;
	std::optional<__u64> hash;
	std::optional<__u32> upcall_pid;
};

/*
 * Apply actions to a packet.
 */
int ovs_packet_execute(ynl_cpp::ynl_socket& ys, ovs_packet_execute_req& req);

/* OVS_PACKET_CMD_MISS - event */
struct ovs_packet_miss_rsp {
	struct ovs_header _hdr;

	std::vector<__u8> packet;
	std::vector<__u8> key;
	std::vector<__u8> userdata;
	std::vector<__u8> actions;
	std::vector<__u8> egress_tun_key;
	std::optional<__u16> mru;
	std::optional<__u32> len;
	std::optional<__u64> hash;
};

struct ovs_packet_miss {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ovs_packet_miss_rsp obj __attribute__((aligned(8)));
};

/* OVS_PACKET_CMD_ACTION - event */
struct ovs_packet_action_rsp {
	struct ovs_header _hdr;

	std::vector<__u8> packet;
	std::vector<__u8> key;
	std::vector<__u8> userdata;
	std::vector<__u8> actions;
	std::vector<__u8> egress_tun_key;
	std::optional<__u16> mru;
	std::optional<__u32> len;
	std::optional<__u64> hash;
};

struct ovs_packet_action {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ovs_packet_action_rsp obj __attribute__((aligned(8)));
};

} //namespace ynl_cpp
#endif /* _LINUX_OVS_PACKET_GEN_H */
