/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_OVS_FLOW_GEN_H
#define _LINUX_OVS_FLOW_GEN_H

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
const struct ynl_family& get_ynl_ovs_flow_family();

/* Enums */
std::string_view ovs_flow_op_str(int op);
std::string_view ovs_flow_ovs_frag_type_str(ovs_frag_type value);
std::string_view ovs_flow_ovs_ufid_flags_str(int value);
std::string_view ovs_flow_ovs_hash_alg_str(ovs_hash_alg value);
std::string_view ovs_flow_ct_state_flags_str(int value);

/* Common nested types */
struct ovs_flow_key_attrs;
struct ovs_flow_action_attrs;

struct ovs_flow_ovs_nsh_key_attrs {
	std::vector<__u8> base;
	std::vector<__u8> md1;
	std::vector<__u8> md2;
};

struct ovs_flow_userspace_attrs {
	std::optional<__u32> pid;
	std::vector<__u8> userdata;
	std::optional<__u32> egress_tun_port;
	bool actions{};
};

struct ovs_flow_psample_attrs {
	std::optional<__u32> group;
	std::vector<__u8> cookie;
};

struct ovs_flow_vxlan_ext_attrs {
	std::optional<__u32> gbp;
};

struct ovs_flow_nat_attrs {
	bool src{};
	bool dst{};
	std::vector<__u8> ip_min;
	std::vector<__u8> ip_max;
	std::optional<__u16> proto_min;
	std::optional<__u16> proto_max;
	bool persistent{};
	bool proto_hash{};
	bool proto_random{};
};

struct ovs_flow_tunnel_key_attrs {
	std::optional<__u64> id /* big-endian */;
	std::optional<__u32> ipv4_src /* big-endian */;
	std::optional<__u32> ipv4_dst /* big-endian */;
	std::optional<__u8> tos;
	std::optional<__u8> ttl;
	bool dont_fragment{};
	bool csum{};
	bool oam{};
	std::vector<__u8> geneve_opts;
	std::optional<__u16> tp_src /* big-endian */;
	std::optional<__u16> tp_dst /* big-endian */;
	std::optional<ovs_flow_vxlan_ext_attrs> vxlan_opts;
	std::vector<__u8> ipv6_src;
	std::vector<__u8> ipv6_dst;
	std::vector<__u8> pad;
	std::vector<__u8> erspan_opts;
	bool ipv4_info_bridge{};
};

struct ovs_flow_ct_attrs {
	bool commit{};
	std::optional<__u16> zone;
	std::vector<__u8> mark;
	std::vector<__u8> labels;
	std::string helper;
	std::optional<ovs_flow_nat_attrs> nat;
	bool force_commit{};
	std::optional<__u32> eventmask;
	std::string timeout;
};

struct ovs_flow_key_attrs {
	std::vector<ovs_flow_key_attrs> encap;
	std::optional<__u32> priority;
	std::optional<__u32> in_port;
	std::optional<struct ovs_key_ethernet> ethernet;
	std::optional<__u16> vlan /* big-endian */;
	std::optional<__u16> ethertype /* big-endian */;
	std::optional<struct ovs_key_ipv4> ipv4;
	std::optional<struct ovs_key_ipv6> ipv6;
	std::optional<struct ovs_key_tcp> tcp;
	std::optional<struct ovs_key_udp> udp;
	std::optional<struct ovs_key_icmp> icmp;
	std::optional<struct ovs_key_icmp> icmpv6;
	std::optional<struct ovs_key_arp> arp;
	std::optional<struct ovs_key_nd> nd;
	std::optional<__u32> skb_mark;
	std::optional<ovs_flow_tunnel_key_attrs> tunnel;
	std::optional<struct ovs_key_sctp> sctp;
	std::optional<__u16> tcp_flags /* big-endian */;
	std::optional<__u32> dp_hash;
	std::optional<__u32> recirc_id;
	std::optional<struct ovs_key_mpls> mpls;
	std::optional<__u32> ct_state;
	std::optional<__u16> ct_zone;
	std::optional<__u32> ct_mark;
	std::vector<__u8> ct_labels;
	std::optional<struct ovs_key_ct_tuple_ipv4> ct_orig_tuple_ipv4;
	std::vector<__u8> ct_orig_tuple_ipv6;
	std::optional<ovs_flow_ovs_nsh_key_attrs> nsh;
	std::optional<__u32> packet_type /* big-endian */;
	std::vector<__u8> nd_extensions;
	std::vector<__u8> tunnel_info;
	std::optional<struct ovs_key_ipv6_exthdrs> ipv6_exthdrs;
};

struct ovs_flow_sample_attrs {
	std::optional<__u32> probability;
	std::vector<ovs_flow_action_attrs> actions;
};

struct ovs_flow_check_pkt_len_attrs {
	std::optional<__u16> pkt_len;
	std::vector<ovs_flow_action_attrs> actions_if_greater;
	std::vector<ovs_flow_action_attrs> actions_if_less_equal;
};

struct ovs_flow_dec_ttl_attrs {
	std::vector<ovs_flow_action_attrs> action;
};

struct ovs_flow_action_attrs {
	std::optional<__u32> output;
	std::optional<ovs_flow_userspace_attrs> userspace;
	std::vector<ovs_flow_key_attrs> set;
	std::optional<struct ovs_action_push_vlan> push_vlan;
	bool pop_vlan{};
	std::optional<ovs_flow_sample_attrs> sample;
	std::optional<__u32> recirc;
	std::optional<struct ovs_action_hash> hash;
	std::optional<struct ovs_action_push_mpls> push_mpls;
	std::optional<__u16> pop_mpls /* big-endian */;
	std::vector<ovs_flow_key_attrs> set_masked;
	std::optional<ovs_flow_ct_attrs> ct;
	std::optional<__u32> trunc;
	std::vector<__u8> push_eth;
	bool pop_eth{};
	bool ct_clear{};
	std::optional<ovs_flow_ovs_nsh_key_attrs> push_nsh;
	bool pop_nsh{};
	std::optional<__u32> meter;
	std::vector<ovs_flow_action_attrs> clone;
	std::optional<ovs_flow_check_pkt_len_attrs> check_pkt_len;
	std::optional<struct ovs_action_add_mpls> add_mpls;
	std::optional<ovs_flow_dec_ttl_attrs> dec_ttl;
	std::optional<ovs_flow_psample_attrs> psample;
};

/* ============== OVS_FLOW_CMD_GET ============== */
/* OVS_FLOW_CMD_GET - do */
struct ovs_flow_get_req {
	struct ovs_header _hdr;

	std::optional<ovs_flow_key_attrs> key;
	std::vector<__u8> ufid;
	std::optional<__u32> ufid_flags;
};

struct ovs_flow_get_rsp {
	struct ovs_header _hdr;

	std::optional<ovs_flow_key_attrs> key;
	std::vector<__u8> ufid;
	std::optional<ovs_flow_key_attrs> mask;
	std::optional<struct ovs_flow_stats> stats;
	std::optional<ovs_flow_action_attrs> actions;
};

/*
 * Get / dump OVS flow configuration and state
 */
std::unique_ptr<ovs_flow_get_rsp>
ovs_flow_get(ynl_cpp::ynl_socket& ys, ovs_flow_get_req& req);

/* OVS_FLOW_CMD_GET - dump */
struct ovs_flow_get_req_dump {
	struct ovs_header _hdr;

	std::optional<ovs_flow_key_attrs> key;
	std::vector<__u8> ufid;
	std::optional<__u32> ufid_flags;
};

struct ovs_flow_get_list {
	std::list<ovs_flow_get_rsp> objs;
};

std::unique_ptr<ovs_flow_get_list>
ovs_flow_get_dump(ynl_cpp::ynl_socket& ys, ovs_flow_get_req_dump& req);

/* ============== OVS_FLOW_CMD_NEW ============== */
/* OVS_FLOW_CMD_NEW - do */
struct ovs_flow_new_req {
	struct ovs_header _hdr;

	std::optional<ovs_flow_key_attrs> key;
	std::vector<__u8> ufid;
	std::optional<ovs_flow_key_attrs> mask;
	std::optional<ovs_flow_action_attrs> actions;
};

/*
 * Create OVS flow configuration in a data path
 */
int ovs_flow_new(ynl_cpp::ynl_socket& ys, ovs_flow_new_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_OVS_FLOW_GEN_H */
