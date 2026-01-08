// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "ovs_flow-user.hpp"

#include <array>

#include <linux/openvswitch.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, OVS_FLOW_CMD_GET + 1> ovs_flow_op_strmap = []() {
	std::array<std::string_view, OVS_FLOW_CMD_GET + 1> arr{};
	arr[OVS_FLOW_CMD_GET] = "get";
	arr[OVS_FLOW_CMD_NEW] = "new";
	return arr;
} ();

std::string_view ovs_flow_op_str(int op)
{
	if (op < 0 || op >= (int)(ovs_flow_op_strmap.size())) {
		return "";
	}
	return ovs_flow_op_strmap[op];
}

static constexpr std::array<std::string_view, 255 + 1> ovs_flow_ovs_frag_type_strmap = []() {
	std::array<std::string_view, 255 + 1> arr{};
	arr[0] = "none";
	arr[1] = "first";
	arr[2] = "later";
	arr[255] = "any";
	return arr;
} ();

std::string_view ovs_flow_ovs_frag_type_str(ovs_frag_type value)
{
	if (value < 0 || value >= (int)(ovs_flow_ovs_frag_type_strmap.size())) {
		return "";
	}
	return ovs_flow_ovs_frag_type_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> ovs_flow_ovs_ufid_flags_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "omit-key";
	arr[1] = "omit-mask";
	arr[2] = "omit-actions";
	return arr;
} ();

std::string_view ovs_flow_ovs_ufid_flags_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(ovs_flow_ovs_ufid_flags_strmap.size())) {
		return "";
	}
	return ovs_flow_ovs_ufid_flags_strmap[value];
}

static constexpr std::array<std::string_view, 0 + 1> ovs_flow_ovs_hash_alg_strmap = []() {
	std::array<std::string_view, 0 + 1> arr{};
	arr[0] = "ovs-hash-alg-l4";
	return arr;
} ();

std::string_view ovs_flow_ovs_hash_alg_str(ovs_hash_alg value)
{
	if (value < 0 || value >= (int)(ovs_flow_ovs_hash_alg_strmap.size())) {
		return "";
	}
	return ovs_flow_ovs_hash_alg_strmap[value];
}

static constexpr std::array<std::string_view, 7 + 1> ovs_flow_ct_state_flags_strmap = []() {
	std::array<std::string_view, 7 + 1> arr{};
	arr[0] = "new";
	arr[1] = "established";
	arr[2] = "related";
	arr[3] = "reply-dir";
	arr[4] = "invalid";
	arr[5] = "tracked";
	arr[6] = "src-nat";
	arr[7] = "dst-nat";
	return arr;
} ();

std::string_view ovs_flow_ct_state_flags_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(ovs_flow_ct_state_flags_strmap.size())) {
		return "";
	}
	return ovs_flow_ct_state_flags_strmap[value];
}

/* Policies */
extern struct ynl_policy_nest ovs_flow_key_attrs_nest;
extern struct ynl_policy_nest ovs_flow_action_attrs_nest;

static std::array<ynl_policy_attr,OVS_NSH_KEY_ATTR_MAX + 1> ovs_flow_ovs_nsh_key_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_NSH_KEY_ATTR_MAX + 1> arr{};
	arr[OVS_NSH_KEY_ATTR_BASE].name = "base";
	arr[OVS_NSH_KEY_ATTR_BASE].type = YNL_PT_BINARY;
	arr[OVS_NSH_KEY_ATTR_MD1].name = "md1";
	arr[OVS_NSH_KEY_ATTR_MD1].type = YNL_PT_BINARY;
	arr[OVS_NSH_KEY_ATTR_MD2].name = "md2";
	arr[OVS_NSH_KEY_ATTR_MD2].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_ovs_nsh_key_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_NSH_KEY_ATTR_MAX),
	.table = ovs_flow_ovs_nsh_key_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_USERSPACE_ATTR_MAX + 1> ovs_flow_userspace_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_USERSPACE_ATTR_MAX + 1> arr{};
	arr[OVS_USERSPACE_ATTR_PID].name = "pid";
	arr[OVS_USERSPACE_ATTR_PID].type = YNL_PT_U32;
	arr[OVS_USERSPACE_ATTR_USERDATA].name = "userdata";
	arr[OVS_USERSPACE_ATTR_USERDATA].type = YNL_PT_BINARY;
	arr[OVS_USERSPACE_ATTR_EGRESS_TUN_PORT].name = "egress-tun-port";
	arr[OVS_USERSPACE_ATTR_EGRESS_TUN_PORT].type = YNL_PT_U32;
	arr[OVS_USERSPACE_ATTR_ACTIONS].name = "actions";
	arr[OVS_USERSPACE_ATTR_ACTIONS].type = YNL_PT_FLAG;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_userspace_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_USERSPACE_ATTR_MAX),
	.table = ovs_flow_userspace_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_PSAMPLE_ATTR_MAX + 1> ovs_flow_psample_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_PSAMPLE_ATTR_MAX + 1> arr{};
	arr[OVS_PSAMPLE_ATTR_GROUP].name = "group";
	arr[OVS_PSAMPLE_ATTR_GROUP].type = YNL_PT_U32;
	arr[OVS_PSAMPLE_ATTR_COOKIE].name = "cookie";
	arr[OVS_PSAMPLE_ATTR_COOKIE].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_psample_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_PSAMPLE_ATTR_MAX),
	.table = ovs_flow_psample_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_VXLAN_EXT_MAX + 1> ovs_flow_vxlan_ext_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_VXLAN_EXT_MAX + 1> arr{};
	arr[OVS_VXLAN_EXT_GBP].name = "gbp";
	arr[OVS_VXLAN_EXT_GBP].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_vxlan_ext_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_VXLAN_EXT_MAX),
	.table = ovs_flow_vxlan_ext_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_NAT_ATTR_MAX + 1> ovs_flow_nat_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_NAT_ATTR_MAX + 1> arr{};
	arr[OVS_NAT_ATTR_SRC].name = "src";
	arr[OVS_NAT_ATTR_SRC].type = YNL_PT_FLAG;
	arr[OVS_NAT_ATTR_DST].name = "dst";
	arr[OVS_NAT_ATTR_DST].type = YNL_PT_FLAG;
	arr[OVS_NAT_ATTR_IP_MIN].name = "ip-min";
	arr[OVS_NAT_ATTR_IP_MIN].type = YNL_PT_BINARY;
	arr[OVS_NAT_ATTR_IP_MAX].name = "ip-max";
	arr[OVS_NAT_ATTR_IP_MAX].type = YNL_PT_BINARY;
	arr[OVS_NAT_ATTR_PROTO_MIN].name = "proto-min";
	arr[OVS_NAT_ATTR_PROTO_MIN].type = YNL_PT_U16;
	arr[OVS_NAT_ATTR_PROTO_MAX].name = "proto-max";
	arr[OVS_NAT_ATTR_PROTO_MAX].type = YNL_PT_U16;
	arr[OVS_NAT_ATTR_PERSISTENT].name = "persistent";
	arr[OVS_NAT_ATTR_PERSISTENT].type = YNL_PT_FLAG;
	arr[OVS_NAT_ATTR_PROTO_HASH].name = "proto-hash";
	arr[OVS_NAT_ATTR_PROTO_HASH].type = YNL_PT_FLAG;
	arr[OVS_NAT_ATTR_PROTO_RANDOM].name = "proto-random";
	arr[OVS_NAT_ATTR_PROTO_RANDOM].type = YNL_PT_FLAG;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_nat_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_NAT_ATTR_MAX),
	.table = ovs_flow_nat_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_TUNNEL_KEY_ATTR_MAX + 1> ovs_flow_tunnel_key_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_TUNNEL_KEY_ATTR_MAX + 1> arr{};
	arr[OVS_TUNNEL_KEY_ATTR_ID].name = "id";
	arr[OVS_TUNNEL_KEY_ATTR_ID].type = YNL_PT_U64;
	arr[OVS_TUNNEL_KEY_ATTR_IPV4_SRC].name = "ipv4-src";
	arr[OVS_TUNNEL_KEY_ATTR_IPV4_SRC].type = YNL_PT_U32;
	arr[OVS_TUNNEL_KEY_ATTR_IPV4_DST].name = "ipv4-dst";
	arr[OVS_TUNNEL_KEY_ATTR_IPV4_DST].type = YNL_PT_U32;
	arr[OVS_TUNNEL_KEY_ATTR_TOS].name = "tos";
	arr[OVS_TUNNEL_KEY_ATTR_TOS].type = YNL_PT_U8;
	arr[OVS_TUNNEL_KEY_ATTR_TTL].name = "ttl";
	arr[OVS_TUNNEL_KEY_ATTR_TTL].type = YNL_PT_U8;
	arr[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT].name = "dont-fragment";
	arr[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT].type = YNL_PT_FLAG;
	arr[OVS_TUNNEL_KEY_ATTR_CSUM].name = "csum";
	arr[OVS_TUNNEL_KEY_ATTR_CSUM].type = YNL_PT_FLAG;
	arr[OVS_TUNNEL_KEY_ATTR_OAM].name = "oam";
	arr[OVS_TUNNEL_KEY_ATTR_OAM].type = YNL_PT_FLAG;
	arr[OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS].name = "geneve-opts";
	arr[OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS].type = YNL_PT_BINARY;
	arr[OVS_TUNNEL_KEY_ATTR_TP_SRC].name = "tp-src";
	arr[OVS_TUNNEL_KEY_ATTR_TP_SRC].type = YNL_PT_U16;
	arr[OVS_TUNNEL_KEY_ATTR_TP_DST].name = "tp-dst";
	arr[OVS_TUNNEL_KEY_ATTR_TP_DST].type = YNL_PT_U16;
	arr[OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS].name = "vxlan-opts";
	arr[OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS].type = YNL_PT_NEST;
	arr[OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS].nest = &ovs_flow_vxlan_ext_attrs_nest;
	arr[OVS_TUNNEL_KEY_ATTR_IPV6_SRC].name = "ipv6-src";
	arr[OVS_TUNNEL_KEY_ATTR_IPV6_SRC].type = YNL_PT_BINARY;
	arr[OVS_TUNNEL_KEY_ATTR_IPV6_DST].name = "ipv6-dst";
	arr[OVS_TUNNEL_KEY_ATTR_IPV6_DST].type = YNL_PT_BINARY;
	arr[OVS_TUNNEL_KEY_ATTR_PAD].name = "pad";
	arr[OVS_TUNNEL_KEY_ATTR_PAD].type = YNL_PT_BINARY;
	arr[OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS].name = "erspan-opts";
	arr[OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS].type = YNL_PT_BINARY;
	arr[OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE].name = "ipv4-info-bridge";
	arr[OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE].type = YNL_PT_FLAG;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_tunnel_key_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_TUNNEL_KEY_ATTR_MAX),
	.table = ovs_flow_tunnel_key_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_CT_ATTR_MAX + 1> ovs_flow_ct_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_CT_ATTR_MAX + 1> arr{};
	arr[OVS_CT_ATTR_COMMIT].name = "commit";
	arr[OVS_CT_ATTR_COMMIT].type = YNL_PT_FLAG;
	arr[OVS_CT_ATTR_ZONE].name = "zone";
	arr[OVS_CT_ATTR_ZONE].type = YNL_PT_U16;
	arr[OVS_CT_ATTR_MARK].name = "mark";
	arr[OVS_CT_ATTR_MARK].type = YNL_PT_BINARY;
	arr[OVS_CT_ATTR_LABELS].name = "labels";
	arr[OVS_CT_ATTR_LABELS].type = YNL_PT_BINARY;
	arr[OVS_CT_ATTR_HELPER].name = "helper";
	arr[OVS_CT_ATTR_HELPER].type  = YNL_PT_NUL_STR;
	arr[OVS_CT_ATTR_NAT].name = "nat";
	arr[OVS_CT_ATTR_NAT].type = YNL_PT_NEST;
	arr[OVS_CT_ATTR_NAT].nest = &ovs_flow_nat_attrs_nest;
	arr[OVS_CT_ATTR_FORCE_COMMIT].name = "force-commit";
	arr[OVS_CT_ATTR_FORCE_COMMIT].type = YNL_PT_FLAG;
	arr[OVS_CT_ATTR_EVENTMASK].name = "eventmask";
	arr[OVS_CT_ATTR_EVENTMASK].type = YNL_PT_U32;
	arr[OVS_CT_ATTR_TIMEOUT].name = "timeout";
	arr[OVS_CT_ATTR_TIMEOUT].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_ct_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_CT_ATTR_MAX),
	.table = ovs_flow_ct_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_KEY_ATTR_MAX + 1> ovs_flow_key_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_KEY_ATTR_MAX + 1> arr{};
	arr[OVS_KEY_ATTR_ENCAP].name = "encap";
	arr[OVS_KEY_ATTR_ENCAP].type = YNL_PT_NEST;
	arr[OVS_KEY_ATTR_ENCAP].nest = &ovs_flow_key_attrs_nest;
	arr[OVS_KEY_ATTR_PRIORITY].name = "priority";
	arr[OVS_KEY_ATTR_PRIORITY].type = YNL_PT_U32;
	arr[OVS_KEY_ATTR_IN_PORT].name = "in-port";
	arr[OVS_KEY_ATTR_IN_PORT].type = YNL_PT_U32;
	arr[OVS_KEY_ATTR_ETHERNET].name = "ethernet";
	arr[OVS_KEY_ATTR_ETHERNET].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_VLAN].name = "vlan";
	arr[OVS_KEY_ATTR_VLAN].type = YNL_PT_U16;
	arr[OVS_KEY_ATTR_ETHERTYPE].name = "ethertype";
	arr[OVS_KEY_ATTR_ETHERTYPE].type = YNL_PT_U16;
	arr[OVS_KEY_ATTR_IPV4].name = "ipv4";
	arr[OVS_KEY_ATTR_IPV4].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_IPV6].name = "ipv6";
	arr[OVS_KEY_ATTR_IPV6].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_TCP].name = "tcp";
	arr[OVS_KEY_ATTR_TCP].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_UDP].name = "udp";
	arr[OVS_KEY_ATTR_UDP].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_ICMP].name = "icmp";
	arr[OVS_KEY_ATTR_ICMP].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_ICMPV6].name = "icmpv6";
	arr[OVS_KEY_ATTR_ICMPV6].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_ARP].name = "arp";
	arr[OVS_KEY_ATTR_ARP].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_ND].name = "nd";
	arr[OVS_KEY_ATTR_ND].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_SKB_MARK].name = "skb-mark";
	arr[OVS_KEY_ATTR_SKB_MARK].type = YNL_PT_U32;
	arr[OVS_KEY_ATTR_TUNNEL].name = "tunnel";
	arr[OVS_KEY_ATTR_TUNNEL].type = YNL_PT_NEST;
	arr[OVS_KEY_ATTR_TUNNEL].nest = &ovs_flow_tunnel_key_attrs_nest;
	arr[OVS_KEY_ATTR_SCTP].name = "sctp";
	arr[OVS_KEY_ATTR_SCTP].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_TCP_FLAGS].name = "tcp-flags";
	arr[OVS_KEY_ATTR_TCP_FLAGS].type = YNL_PT_U16;
	arr[OVS_KEY_ATTR_DP_HASH].name = "dp-hash";
	arr[OVS_KEY_ATTR_DP_HASH].type = YNL_PT_U32;
	arr[OVS_KEY_ATTR_RECIRC_ID].name = "recirc-id";
	arr[OVS_KEY_ATTR_RECIRC_ID].type = YNL_PT_U32;
	arr[OVS_KEY_ATTR_MPLS].name = "mpls";
	arr[OVS_KEY_ATTR_MPLS].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_CT_STATE].name = "ct-state";
	arr[OVS_KEY_ATTR_CT_STATE].type = YNL_PT_U32;
	arr[OVS_KEY_ATTR_CT_ZONE].name = "ct-zone";
	arr[OVS_KEY_ATTR_CT_ZONE].type = YNL_PT_U16;
	arr[OVS_KEY_ATTR_CT_MARK].name = "ct-mark";
	arr[OVS_KEY_ATTR_CT_MARK].type = YNL_PT_U32;
	arr[OVS_KEY_ATTR_CT_LABELS].name = "ct-labels";
	arr[OVS_KEY_ATTR_CT_LABELS].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4].name = "ct-orig-tuple-ipv4";
	arr[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6].name = "ct-orig-tuple-ipv6";
	arr[OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_NSH].name = "nsh";
	arr[OVS_KEY_ATTR_NSH].type = YNL_PT_NEST;
	arr[OVS_KEY_ATTR_NSH].nest = &ovs_flow_ovs_nsh_key_attrs_nest;
	arr[OVS_KEY_ATTR_PACKET_TYPE].name = "packet-type";
	arr[OVS_KEY_ATTR_PACKET_TYPE].type = YNL_PT_U32;
	arr[OVS_KEY_ATTR_ND_EXTENSIONS].name = "nd-extensions";
	arr[OVS_KEY_ATTR_ND_EXTENSIONS].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_TUNNEL_INFO].name = "tunnel-info";
	arr[OVS_KEY_ATTR_TUNNEL_INFO].type = YNL_PT_BINARY;
	arr[OVS_KEY_ATTR_IPV6_EXTHDRS].name = "ipv6-exthdrs";
	arr[OVS_KEY_ATTR_IPV6_EXTHDRS].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_key_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_KEY_ATTR_MAX),
	.table = ovs_flow_key_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_SAMPLE_ATTR_MAX + 1> ovs_flow_sample_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_SAMPLE_ATTR_MAX + 1> arr{};
	arr[OVS_SAMPLE_ATTR_PROBABILITY].name = "probability";
	arr[OVS_SAMPLE_ATTR_PROBABILITY].type = YNL_PT_U32;
	arr[OVS_SAMPLE_ATTR_ACTIONS].name = "actions";
	arr[OVS_SAMPLE_ATTR_ACTIONS].type = YNL_PT_NEST;
	arr[OVS_SAMPLE_ATTR_ACTIONS].nest = &ovs_flow_action_attrs_nest;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_sample_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_SAMPLE_ATTR_MAX),
	.table = ovs_flow_sample_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_CHECK_PKT_LEN_ATTR_MAX + 1> ovs_flow_check_pkt_len_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_CHECK_PKT_LEN_ATTR_MAX + 1> arr{};
	arr[OVS_CHECK_PKT_LEN_ATTR_PKT_LEN].name = "pkt-len";
	arr[OVS_CHECK_PKT_LEN_ATTR_PKT_LEN].type = YNL_PT_U16;
	arr[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER].name = "actions-if-greater";
	arr[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER].type = YNL_PT_NEST;
	arr[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER].nest = &ovs_flow_action_attrs_nest;
	arr[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL].name = "actions-if-less-equal";
	arr[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL].type = YNL_PT_NEST;
	arr[OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL].nest = &ovs_flow_action_attrs_nest;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_check_pkt_len_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_CHECK_PKT_LEN_ATTR_MAX),
	.table = ovs_flow_check_pkt_len_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_DEC_TTL_ATTR_MAX + 1> ovs_flow_dec_ttl_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_DEC_TTL_ATTR_MAX + 1> arr{};
	arr[OVS_DEC_TTL_ATTR_ACTION].name = "action";
	arr[OVS_DEC_TTL_ATTR_ACTION].type = YNL_PT_NEST;
	arr[OVS_DEC_TTL_ATTR_ACTION].nest = &ovs_flow_action_attrs_nest;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_dec_ttl_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_DEC_TTL_ATTR_MAX),
	.table = ovs_flow_dec_ttl_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_ACTION_ATTR_MAX + 1> ovs_flow_action_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_ACTION_ATTR_MAX + 1> arr{};
	arr[OVS_ACTION_ATTR_OUTPUT].name = "output";
	arr[OVS_ACTION_ATTR_OUTPUT].type = YNL_PT_U32;
	arr[OVS_ACTION_ATTR_USERSPACE].name = "userspace";
	arr[OVS_ACTION_ATTR_USERSPACE].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_USERSPACE].nest = &ovs_flow_userspace_attrs_nest;
	arr[OVS_ACTION_ATTR_SET].name = "set";
	arr[OVS_ACTION_ATTR_SET].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_SET].nest = &ovs_flow_key_attrs_nest;
	arr[OVS_ACTION_ATTR_PUSH_VLAN].name = "push-vlan";
	arr[OVS_ACTION_ATTR_PUSH_VLAN].type = YNL_PT_BINARY;
	arr[OVS_ACTION_ATTR_POP_VLAN].name = "pop-vlan";
	arr[OVS_ACTION_ATTR_POP_VLAN].type = YNL_PT_FLAG;
	arr[OVS_ACTION_ATTR_SAMPLE].name = "sample";
	arr[OVS_ACTION_ATTR_SAMPLE].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_SAMPLE].nest = &ovs_flow_sample_attrs_nest;
	arr[OVS_ACTION_ATTR_RECIRC].name = "recirc";
	arr[OVS_ACTION_ATTR_RECIRC].type = YNL_PT_U32;
	arr[OVS_ACTION_ATTR_HASH].name = "hash";
	arr[OVS_ACTION_ATTR_HASH].type = YNL_PT_BINARY;
	arr[OVS_ACTION_ATTR_PUSH_MPLS].name = "push-mpls";
	arr[OVS_ACTION_ATTR_PUSH_MPLS].type = YNL_PT_BINARY;
	arr[OVS_ACTION_ATTR_POP_MPLS].name = "pop-mpls";
	arr[OVS_ACTION_ATTR_POP_MPLS].type = YNL_PT_U16;
	arr[OVS_ACTION_ATTR_SET_MASKED].name = "set-masked";
	arr[OVS_ACTION_ATTR_SET_MASKED].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_SET_MASKED].nest = &ovs_flow_key_attrs_nest;
	arr[OVS_ACTION_ATTR_CT].name = "ct";
	arr[OVS_ACTION_ATTR_CT].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_CT].nest = &ovs_flow_ct_attrs_nest;
	arr[OVS_ACTION_ATTR_TRUNC].name = "trunc";
	arr[OVS_ACTION_ATTR_TRUNC].type = YNL_PT_U32;
	arr[OVS_ACTION_ATTR_PUSH_ETH].name = "push-eth";
	arr[OVS_ACTION_ATTR_PUSH_ETH].type = YNL_PT_BINARY;
	arr[OVS_ACTION_ATTR_POP_ETH].name = "pop-eth";
	arr[OVS_ACTION_ATTR_POP_ETH].type = YNL_PT_FLAG;
	arr[OVS_ACTION_ATTR_CT_CLEAR].name = "ct-clear";
	arr[OVS_ACTION_ATTR_CT_CLEAR].type = YNL_PT_FLAG;
	arr[OVS_ACTION_ATTR_PUSH_NSH].name = "push-nsh";
	arr[OVS_ACTION_ATTR_PUSH_NSH].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_PUSH_NSH].nest = &ovs_flow_ovs_nsh_key_attrs_nest;
	arr[OVS_ACTION_ATTR_POP_NSH].name = "pop-nsh";
	arr[OVS_ACTION_ATTR_POP_NSH].type = YNL_PT_FLAG;
	arr[OVS_ACTION_ATTR_METER].name = "meter";
	arr[OVS_ACTION_ATTR_METER].type = YNL_PT_U32;
	arr[OVS_ACTION_ATTR_CLONE].name = "clone";
	arr[OVS_ACTION_ATTR_CLONE].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_CLONE].nest = &ovs_flow_action_attrs_nest;
	arr[OVS_ACTION_ATTR_CHECK_PKT_LEN].name = "check-pkt-len";
	arr[OVS_ACTION_ATTR_CHECK_PKT_LEN].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_CHECK_PKT_LEN].nest = &ovs_flow_check_pkt_len_attrs_nest;
	arr[OVS_ACTION_ATTR_ADD_MPLS].name = "add-mpls";
	arr[OVS_ACTION_ATTR_ADD_MPLS].type = YNL_PT_BINARY;
	arr[OVS_ACTION_ATTR_DEC_TTL].name = "dec-ttl";
	arr[OVS_ACTION_ATTR_DEC_TTL].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_DEC_TTL].nest = &ovs_flow_dec_ttl_attrs_nest;
	arr[OVS_ACTION_ATTR_PSAMPLE].name = "psample";
	arr[OVS_ACTION_ATTR_PSAMPLE].type = YNL_PT_NEST;
	arr[OVS_ACTION_ATTR_PSAMPLE].nest = &ovs_flow_psample_attrs_nest;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_action_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_ACTION_ATTR_MAX),
	.table = ovs_flow_action_attrs_policy.data(),
};

static std::array<ynl_policy_attr,OVS_FLOW_ATTR_MAX + 1> ovs_flow_flow_attrs_policy = []() {
	std::array<ynl_policy_attr,OVS_FLOW_ATTR_MAX + 1> arr{};
	arr[OVS_FLOW_ATTR_KEY].name = "key";
	arr[OVS_FLOW_ATTR_KEY].type = YNL_PT_NEST;
	arr[OVS_FLOW_ATTR_KEY].nest = &ovs_flow_key_attrs_nest;
	arr[OVS_FLOW_ATTR_ACTIONS].name = "actions";
	arr[OVS_FLOW_ATTR_ACTIONS].type = YNL_PT_NEST;
	arr[OVS_FLOW_ATTR_ACTIONS].nest = &ovs_flow_action_attrs_nest;
	arr[OVS_FLOW_ATTR_STATS].name = "stats";
	arr[OVS_FLOW_ATTR_STATS].type = YNL_PT_BINARY;
	arr[OVS_FLOW_ATTR_TCP_FLAGS].name = "tcp-flags";
	arr[OVS_FLOW_ATTR_TCP_FLAGS].type = YNL_PT_U8;
	arr[OVS_FLOW_ATTR_USED].name = "used";
	arr[OVS_FLOW_ATTR_USED].type = YNL_PT_U64;
	arr[OVS_FLOW_ATTR_CLEAR].name = "clear";
	arr[OVS_FLOW_ATTR_CLEAR].type = YNL_PT_FLAG;
	arr[OVS_FLOW_ATTR_MASK].name = "mask";
	arr[OVS_FLOW_ATTR_MASK].type = YNL_PT_NEST;
	arr[OVS_FLOW_ATTR_MASK].nest = &ovs_flow_key_attrs_nest;
	arr[OVS_FLOW_ATTR_PROBE].name = "probe";
	arr[OVS_FLOW_ATTR_PROBE].type = YNL_PT_BINARY;
	arr[OVS_FLOW_ATTR_UFID].name = "ufid";
	arr[OVS_FLOW_ATTR_UFID].type = YNL_PT_BINARY;
	arr[OVS_FLOW_ATTR_UFID_FLAGS].name = "ufid-flags";
	arr[OVS_FLOW_ATTR_UFID_FLAGS].type = YNL_PT_U32;
	arr[OVS_FLOW_ATTR_PAD].name = "pad";
	arr[OVS_FLOW_ATTR_PAD].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest ovs_flow_flow_attrs_nest = {
	.max_attr = static_cast<unsigned int>(OVS_FLOW_ATTR_MAX),
	.table = ovs_flow_flow_attrs_policy.data(),
};

/* Common nested types */
int ovs_flow_ovs_nsh_key_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   const ovs_flow_ovs_nsh_key_attrs&  obj);
int ovs_flow_ovs_nsh_key_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested);
int ovs_flow_userspace_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 const ovs_flow_userspace_attrs&  obj);
int ovs_flow_userspace_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested);
int ovs_flow_psample_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       const ovs_flow_psample_attrs&  obj);
int ovs_flow_psample_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested);
int ovs_flow_vxlan_ext_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 const ovs_flow_vxlan_ext_attrs&  obj);
int ovs_flow_vxlan_ext_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested);
int ovs_flow_nat_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   const ovs_flow_nat_attrs&  obj);
int ovs_flow_nat_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested);
int ovs_flow_tunnel_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  const ovs_flow_tunnel_key_attrs&  obj);
int ovs_flow_tunnel_key_attrs_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested);
int ovs_flow_ct_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  const ovs_flow_ct_attrs&  obj);
int ovs_flow_ct_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested);
int ovs_flow_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   const ovs_flow_key_attrs&  obj);
int ovs_flow_key_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested);
int ovs_flow_sample_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      const ovs_flow_sample_attrs&  obj);
int ovs_flow_sample_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested);
int ovs_flow_check_pkt_len_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     const ovs_flow_check_pkt_len_attrs&  obj);
int ovs_flow_check_pkt_len_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested);
int ovs_flow_dec_ttl_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       const ovs_flow_dec_ttl_attrs&  obj);
int ovs_flow_dec_ttl_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested);
int ovs_flow_action_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      const ovs_flow_action_attrs&  obj);
int ovs_flow_action_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested);

int ovs_flow_ovs_nsh_key_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   const ovs_flow_ovs_nsh_key_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.base.size() > 0) {
		ynl_attr_put(nlh, OVS_NSH_KEY_ATTR_BASE, obj.base.data(), obj.base.size());
	}
	if (obj.md1.size() > 0) {
		ynl_attr_put(nlh, OVS_NSH_KEY_ATTR_MD1, obj.md1.data(), obj.md1.size());
	}
	if (obj.md2.size() > 0) {
		ynl_attr_put(nlh, OVS_NSH_KEY_ATTR_MD2, obj.md2.data(), obj.md2.size());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_ovs_nsh_key_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	ovs_flow_ovs_nsh_key_attrs *dst = (ovs_flow_ovs_nsh_key_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_NSH_KEY_ATTR_BASE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->base.assign(data, data + len);
		} else if (type == OVS_NSH_KEY_ATTR_MD1) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->md1.assign(data, data + len);
		} else if (type == OVS_NSH_KEY_ATTR_MD2) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->md2.assign(data, data + len);
		}
	}

	return 0;
}

int ovs_flow_userspace_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 const ovs_flow_userspace_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.pid.has_value()) {
		ynl_attr_put_u32(nlh, OVS_USERSPACE_ATTR_PID, obj.pid.value());
	}
	if (obj.userdata.size() > 0) {
		ynl_attr_put(nlh, OVS_USERSPACE_ATTR_USERDATA, obj.userdata.data(), obj.userdata.size());
	}
	if (obj.egress_tun_port.has_value()) {
		ynl_attr_put_u32(nlh, OVS_USERSPACE_ATTR_EGRESS_TUN_PORT, obj.egress_tun_port.value());
	}
	if (obj.actions) {
		ynl_attr_put(nlh, OVS_USERSPACE_ATTR_ACTIONS, NULL, 0);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_userspace_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	ovs_flow_userspace_attrs *dst = (ovs_flow_userspace_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_USERSPACE_ATTR_PID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->pid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_USERSPACE_ATTR_USERDATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->userdata.assign(data, data + len);
		} else if (type == OVS_USERSPACE_ATTR_EGRESS_TUN_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->egress_tun_port = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_USERSPACE_ATTR_ACTIONS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int ovs_flow_psample_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       const ovs_flow_psample_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.group.has_value()) {
		ynl_attr_put_u32(nlh, OVS_PSAMPLE_ATTR_GROUP, obj.group.value());
	}
	if (obj.cookie.size() > 0) {
		ynl_attr_put(nlh, OVS_PSAMPLE_ATTR_COOKIE, obj.cookie.data(), obj.cookie.size());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_psample_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	ovs_flow_psample_attrs *dst = (ovs_flow_psample_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_PSAMPLE_ATTR_GROUP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->group = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_PSAMPLE_ATTR_COOKIE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->cookie.assign(data, data + len);
		}
	}

	return 0;
}

int ovs_flow_vxlan_ext_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 const ovs_flow_vxlan_ext_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.gbp.has_value()) {
		ynl_attr_put_u32(nlh, OVS_VXLAN_EXT_GBP, obj.gbp.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_vxlan_ext_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	ovs_flow_vxlan_ext_attrs *dst = (ovs_flow_vxlan_ext_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_VXLAN_EXT_GBP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gbp = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int ovs_flow_nat_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   const ovs_flow_nat_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.src) {
		ynl_attr_put(nlh, OVS_NAT_ATTR_SRC, NULL, 0);
	}
	if (obj.dst) {
		ynl_attr_put(nlh, OVS_NAT_ATTR_DST, NULL, 0);
	}
	if (obj.ip_min.size() > 0) {
		ynl_attr_put(nlh, OVS_NAT_ATTR_IP_MIN, obj.ip_min.data(), obj.ip_min.size());
	}
	if (obj.ip_max.size() > 0) {
		ynl_attr_put(nlh, OVS_NAT_ATTR_IP_MAX, obj.ip_max.data(), obj.ip_max.size());
	}
	if (obj.proto_min.has_value()) {
		ynl_attr_put_u16(nlh, OVS_NAT_ATTR_PROTO_MIN, obj.proto_min.value());
	}
	if (obj.proto_max.has_value()) {
		ynl_attr_put_u16(nlh, OVS_NAT_ATTR_PROTO_MAX, obj.proto_max.value());
	}
	if (obj.persistent) {
		ynl_attr_put(nlh, OVS_NAT_ATTR_PERSISTENT, NULL, 0);
	}
	if (obj.proto_hash) {
		ynl_attr_put(nlh, OVS_NAT_ATTR_PROTO_HASH, NULL, 0);
	}
	if (obj.proto_random) {
		ynl_attr_put(nlh, OVS_NAT_ATTR_PROTO_RANDOM, NULL, 0);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_nat_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	ovs_flow_nat_attrs *dst = (ovs_flow_nat_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_NAT_ATTR_SRC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_NAT_ATTR_DST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_NAT_ATTR_IP_MIN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->ip_min.assign(data, data + len);
		} else if (type == OVS_NAT_ATTR_IP_MAX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->ip_max.assign(data, data + len);
		} else if (type == OVS_NAT_ATTR_PROTO_MIN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->proto_min = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_NAT_ATTR_PROTO_MAX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->proto_max = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_NAT_ATTR_PERSISTENT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_NAT_ATTR_PROTO_HASH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_NAT_ATTR_PROTO_RANDOM) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int ovs_flow_tunnel_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  const ovs_flow_tunnel_key_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.id.has_value()) {
		ynl_attr_put_u64(nlh, OVS_TUNNEL_KEY_ATTR_ID, obj.id.value());
	}
	if (obj.ipv4_src.has_value()) {
		ynl_attr_put_u32(nlh, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, obj.ipv4_src.value());
	}
	if (obj.ipv4_dst.has_value()) {
		ynl_attr_put_u32(nlh, OVS_TUNNEL_KEY_ATTR_IPV4_DST, obj.ipv4_dst.value());
	}
	if (obj.tos.has_value()) {
		ynl_attr_put_u8(nlh, OVS_TUNNEL_KEY_ATTR_TOS, obj.tos.value());
	}
	if (obj.ttl.has_value()) {
		ynl_attr_put_u8(nlh, OVS_TUNNEL_KEY_ATTR_TTL, obj.ttl.value());
	}
	if (obj.dont_fragment) {
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT, NULL, 0);
	}
	if (obj.csum) {
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_CSUM, NULL, 0);
	}
	if (obj.oam) {
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_OAM, NULL, 0);
	}
	if (obj.geneve_opts.size() > 0) {
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS, obj.geneve_opts.data(), obj.geneve_opts.size());
	}
	if (obj.tp_src.has_value()) {
		ynl_attr_put_u16(nlh, OVS_TUNNEL_KEY_ATTR_TP_SRC, obj.tp_src.value());
	}
	if (obj.tp_dst.has_value()) {
		ynl_attr_put_u16(nlh, OVS_TUNNEL_KEY_ATTR_TP_DST, obj.tp_dst.value());
	}
	if (obj.vxlan_opts.has_value()) {
		ovs_flow_vxlan_ext_attrs_put(nlh, OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS, obj.vxlan_opts.value());
	}
	if (obj.ipv6_src.size() > 0) {
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_IPV6_SRC, obj.ipv6_src.data(), obj.ipv6_src.size());
	}
	if (obj.ipv6_dst.size() > 0) {
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_IPV6_DST, obj.ipv6_dst.data(), obj.ipv6_dst.size());
	}
	if (obj.pad.size() > 0) {
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_PAD, obj.pad.data(), obj.pad.size());
	}
	if (obj.erspan_opts.size() > 0) {
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS, obj.erspan_opts.data(), obj.erspan_opts.size());
	}
	if (obj.ipv4_info_bridge) {
		ynl_attr_put(nlh, OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE, NULL, 0);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_tunnel_key_attrs_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested)
{
	ovs_flow_tunnel_key_attrs *dst = (ovs_flow_tunnel_key_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_TUNNEL_KEY_ATTR_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u64)ynl_attr_get_u64(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV4_SRC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ipv4_src = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV4_DST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ipv4_dst = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_TOS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tos = (__u8)ynl_attr_get_u8(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_TTL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ttl = (__u8)ynl_attr_get_u8(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_TUNNEL_KEY_ATTR_CSUM) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_TUNNEL_KEY_ATTR_OAM) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->geneve_opts.assign(data, data + len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_TP_SRC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tp_src = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_TP_DST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tp_dst = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_vxlan_ext_attrs_nest;
			parg.data = &dst->vxlan_opts.emplace();
			if (ovs_flow_vxlan_ext_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV6_SRC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->ipv6_src.assign(data, data + len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV6_DST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->ipv6_dst.assign(data, data + len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_PAD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->pad.assign(data, data + len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->erspan_opts.assign(data, data + len);
		} else if (type == OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int ovs_flow_ct_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  const ovs_flow_ct_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.commit) {
		ynl_attr_put(nlh, OVS_CT_ATTR_COMMIT, NULL, 0);
	}
	if (obj.zone.has_value()) {
		ynl_attr_put_u16(nlh, OVS_CT_ATTR_ZONE, obj.zone.value());
	}
	if (obj.mark.size() > 0) {
		ynl_attr_put(nlh, OVS_CT_ATTR_MARK, obj.mark.data(), obj.mark.size());
	}
	if (obj.labels.size() > 0) {
		ynl_attr_put(nlh, OVS_CT_ATTR_LABELS, obj.labels.data(), obj.labels.size());
	}
	if (obj.helper.size() > 0) {
		ynl_attr_put_str(nlh, OVS_CT_ATTR_HELPER, obj.helper.data());
	}
	if (obj.nat.has_value()) {
		ovs_flow_nat_attrs_put(nlh, OVS_CT_ATTR_NAT, obj.nat.value());
	}
	if (obj.force_commit) {
		ynl_attr_put(nlh, OVS_CT_ATTR_FORCE_COMMIT, NULL, 0);
	}
	if (obj.eventmask.has_value()) {
		ynl_attr_put_u32(nlh, OVS_CT_ATTR_EVENTMASK, obj.eventmask.value());
	}
	if (obj.timeout.size() > 0) {
		ynl_attr_put_str(nlh, OVS_CT_ATTR_TIMEOUT, obj.timeout.data());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_ct_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	ovs_flow_ct_attrs *dst = (ovs_flow_ct_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_CT_ATTR_COMMIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_CT_ATTR_ZONE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->zone = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_CT_ATTR_MARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->mark.assign(data, data + len);
		} else if (type == OVS_CT_ATTR_LABELS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->labels.assign(data, data + len);
		} else if (type == OVS_CT_ATTR_HELPER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->helper.assign(ynl_attr_get_str(attr));
		} else if (type == OVS_CT_ATTR_NAT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_nat_attrs_nest;
			parg.data = &dst->nat.emplace();
			if (ovs_flow_nat_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_CT_ATTR_FORCE_COMMIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_CT_ATTR_EVENTMASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->eventmask = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_CT_ATTR_TIMEOUT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->timeout.assign(ynl_attr_get_str(attr));
		}
	}

	return 0;
}

int ovs_flow_key_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   const ovs_flow_key_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (unsigned int i = 0; i < obj.encap.size(); i++) {
		ovs_flow_key_attrs_put(nlh, OVS_KEY_ATTR_ENCAP, obj.encap[i]);
	}
	if (obj.priority.has_value()) {
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_PRIORITY, obj.priority.value());
	}
	if (obj.in_port.has_value()) {
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_IN_PORT, obj.in_port.value());
	}
	if (obj.ethernet) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_ETHERNET, &*obj.ethernet, sizeof(struct ovs_key_ethernet));
	}
	if (obj.vlan.has_value()) {
		ynl_attr_put_u16(nlh, OVS_KEY_ATTR_VLAN, obj.vlan.value());
	}
	if (obj.ethertype.has_value()) {
		ynl_attr_put_u16(nlh, OVS_KEY_ATTR_ETHERTYPE, obj.ethertype.value());
	}
	if (obj.ipv4) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_IPV4, &*obj.ipv4, sizeof(struct ovs_key_ipv4));
	}
	if (obj.ipv6) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_IPV6, &*obj.ipv6, sizeof(struct ovs_key_ipv6));
	}
	if (obj.tcp) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_TCP, &*obj.tcp, sizeof(struct ovs_key_tcp));
	}
	if (obj.udp) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_UDP, &*obj.udp, sizeof(struct ovs_key_udp));
	}
	if (obj.icmp) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_ICMP, &*obj.icmp, sizeof(struct ovs_key_icmp));
	}
	if (obj.icmpv6) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_ICMPV6, &*obj.icmpv6, sizeof(struct ovs_key_icmp));
	}
	if (obj.arp) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_ARP, &*obj.arp, sizeof(struct ovs_key_arp));
	}
	if (obj.nd) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_ND, &*obj.nd, sizeof(struct ovs_key_nd));
	}
	if (obj.skb_mark.has_value()) {
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_SKB_MARK, obj.skb_mark.value());
	}
	if (obj.tunnel.has_value()) {
		ovs_flow_tunnel_key_attrs_put(nlh, OVS_KEY_ATTR_TUNNEL, obj.tunnel.value());
	}
	if (obj.sctp) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_SCTP, &*obj.sctp, sizeof(struct ovs_key_sctp));
	}
	if (obj.tcp_flags.has_value()) {
		ynl_attr_put_u16(nlh, OVS_KEY_ATTR_TCP_FLAGS, obj.tcp_flags.value());
	}
	if (obj.dp_hash.has_value()) {
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_DP_HASH, obj.dp_hash.value());
	}
	if (obj.recirc_id.has_value()) {
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_RECIRC_ID, obj.recirc_id.value());
	}
	if (obj.mpls) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_MPLS, &*obj.mpls, sizeof(struct ovs_key_mpls));
	}
	if (obj.ct_state.has_value()) {
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_CT_STATE, obj.ct_state.value());
	}
	if (obj.ct_zone.has_value()) {
		ynl_attr_put_u16(nlh, OVS_KEY_ATTR_CT_ZONE, obj.ct_zone.value());
	}
	if (obj.ct_mark.has_value()) {
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_CT_MARK, obj.ct_mark.value());
	}
	if (obj.ct_labels.size() > 0) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_CT_LABELS, obj.ct_labels.data(), obj.ct_labels.size());
	}
	if (obj.ct_orig_tuple_ipv4) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4, &*obj.ct_orig_tuple_ipv4, sizeof(struct ovs_key_ct_tuple_ipv4));
	}
	if (obj.ct_orig_tuple_ipv6.size() > 0) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6, obj.ct_orig_tuple_ipv6.data(), obj.ct_orig_tuple_ipv6.size());
	}
	if (obj.nsh.has_value()) {
		ovs_flow_ovs_nsh_key_attrs_put(nlh, OVS_KEY_ATTR_NSH, obj.nsh.value());
	}
	if (obj.packet_type.has_value()) {
		ynl_attr_put_u32(nlh, OVS_KEY_ATTR_PACKET_TYPE, obj.packet_type.value());
	}
	if (obj.nd_extensions.size() > 0) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_ND_EXTENSIONS, obj.nd_extensions.data(), obj.nd_extensions.size());
	}
	if (obj.tunnel_info.size() > 0) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_TUNNEL_INFO, obj.tunnel_info.data(), obj.tunnel_info.size());
	}
	if (obj.ipv6_exthdrs) {
		ynl_attr_put(nlh, OVS_KEY_ATTR_IPV6_EXTHDRS, &*obj.ipv6_exthdrs, sizeof(struct ovs_key_ipv6_exthdrs));
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_key_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	ovs_flow_key_attrs *dst = (ovs_flow_key_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_KEY_ATTR_ENCAP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			dst->encap.emplace_back();
			parg.data = &dst->encap.back();
			if (ovs_flow_key_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_KEY_ATTR_PRIORITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->priority = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_IN_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->in_port = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_ETHERNET) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_ethernet);
			dst->ethernet.emplace();
			memcpy(&*dst->ethernet, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_VLAN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vlan = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_KEY_ATTR_ETHERTYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ethertype = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_KEY_ATTR_IPV4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_ipv4);
			dst->ipv4.emplace();
			memcpy(&*dst->ipv4, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_IPV6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_ipv6);
			dst->ipv6.emplace();
			memcpy(&*dst->ipv6, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_TCP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_tcp);
			dst->tcp.emplace();
			memcpy(&*dst->tcp, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_UDP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_udp);
			dst->udp.emplace();
			memcpy(&*dst->udp, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_ICMP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_icmp);
			dst->icmp.emplace();
			memcpy(&*dst->icmp, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_ICMPV6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_icmp);
			dst->icmpv6.emplace();
			memcpy(&*dst->icmpv6, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_ARP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_arp);
			dst->arp.emplace();
			memcpy(&*dst->arp, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_ND) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_nd);
			dst->nd.emplace();
			memcpy(&*dst->nd, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_SKB_MARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->skb_mark = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_TUNNEL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_tunnel_key_attrs_nest;
			parg.data = &dst->tunnel.emplace();
			if (ovs_flow_tunnel_key_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_KEY_ATTR_SCTP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_sctp);
			dst->sctp.emplace();
			memcpy(&*dst->sctp, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_TCP_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tcp_flags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_KEY_ATTR_DP_HASH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dp_hash = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_RECIRC_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->recirc_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_MPLS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_mpls);
			dst->mpls.emplace();
			memcpy(&*dst->mpls, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_CT_STATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ct_state = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_CT_ZONE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ct_zone = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_KEY_ATTR_CT_MARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ct_mark = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_CT_LABELS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->ct_labels.assign(data, data + len);
		} else if (type == OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_ct_tuple_ipv4);
			dst->ct_orig_tuple_ipv4.emplace();
			memcpy(&*dst->ct_orig_tuple_ipv4, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->ct_orig_tuple_ipv6.assign(data, data + len);
		} else if (type == OVS_KEY_ATTR_NSH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_ovs_nsh_key_attrs_nest;
			parg.data = &dst->nsh.emplace();
			if (ovs_flow_ovs_nsh_key_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_KEY_ATTR_PACKET_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->packet_type = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_KEY_ATTR_ND_EXTENSIONS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->nd_extensions.assign(data, data + len);
		} else if (type == OVS_KEY_ATTR_TUNNEL_INFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->tunnel_info.assign(data, data + len);
		} else if (type == OVS_KEY_ATTR_IPV6_EXTHDRS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_key_ipv6_exthdrs);
			dst->ipv6_exthdrs.emplace();
			memcpy(&*dst->ipv6_exthdrs, ynl_attr_data(attr), std::min(struct_sz, len));
		}
	}

	return 0;
}

int ovs_flow_sample_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      const ovs_flow_sample_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.probability.has_value()) {
		ynl_attr_put_u32(nlh, OVS_SAMPLE_ATTR_PROBABILITY, obj.probability.value());
	}
	for (unsigned int i = 0; i < obj.actions.size(); i++) {
		ovs_flow_action_attrs_put(nlh, OVS_SAMPLE_ATTR_ACTIONS, obj.actions[i]);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_sample_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	ovs_flow_sample_attrs *dst = (ovs_flow_sample_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_SAMPLE_ATTR_PROBABILITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->probability = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_SAMPLE_ATTR_ACTIONS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			dst->actions.emplace_back();
			parg.data = &dst->actions.back();
			if (ovs_flow_action_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int ovs_flow_check_pkt_len_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     const ovs_flow_check_pkt_len_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.pkt_len.has_value()) {
		ynl_attr_put_u16(nlh, OVS_CHECK_PKT_LEN_ATTR_PKT_LEN, obj.pkt_len.value());
	}
	for (unsigned int i = 0; i < obj.actions_if_greater.size(); i++) {
		ovs_flow_action_attrs_put(nlh, OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER, obj.actions_if_greater[i]);
	}
	for (unsigned int i = 0; i < obj.actions_if_less_equal.size(); i++) {
		ovs_flow_action_attrs_put(nlh, OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL, obj.actions_if_less_equal[i]);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_check_pkt_len_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	ovs_flow_check_pkt_len_attrs *dst = (ovs_flow_check_pkt_len_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_CHECK_PKT_LEN_ATTR_PKT_LEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->pkt_len = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			dst->actions_if_greater.emplace_back();
			parg.data = &dst->actions_if_greater.back();
			if (ovs_flow_action_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			dst->actions_if_less_equal.emplace_back();
			parg.data = &dst->actions_if_less_equal.back();
			if (ovs_flow_action_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int ovs_flow_dec_ttl_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       const ovs_flow_dec_ttl_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (unsigned int i = 0; i < obj.action.size(); i++) {
		ovs_flow_action_attrs_put(nlh, OVS_DEC_TTL_ATTR_ACTION, obj.action[i]);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_dec_ttl_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	ovs_flow_dec_ttl_attrs *dst = (ovs_flow_dec_ttl_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_DEC_TTL_ATTR_ACTION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			dst->action.emplace_back();
			parg.data = &dst->action.back();
			if (ovs_flow_action_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int ovs_flow_action_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      const ovs_flow_action_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.output.has_value()) {
		ynl_attr_put_u32(nlh, OVS_ACTION_ATTR_OUTPUT, obj.output.value());
	}
	if (obj.userspace.has_value()) {
		ovs_flow_userspace_attrs_put(nlh, OVS_ACTION_ATTR_USERSPACE, obj.userspace.value());
	}
	for (unsigned int i = 0; i < obj.set.size(); i++) {
		ovs_flow_key_attrs_put(nlh, OVS_ACTION_ATTR_SET, obj.set[i]);
	}
	if (obj.push_vlan) {
		ynl_attr_put(nlh, OVS_ACTION_ATTR_PUSH_VLAN, &*obj.push_vlan, sizeof(struct ovs_action_push_vlan));
	}
	if (obj.pop_vlan) {
		ynl_attr_put(nlh, OVS_ACTION_ATTR_POP_VLAN, NULL, 0);
	}
	if (obj.sample.has_value()) {
		ovs_flow_sample_attrs_put(nlh, OVS_ACTION_ATTR_SAMPLE, obj.sample.value());
	}
	if (obj.recirc.has_value()) {
		ynl_attr_put_u32(nlh, OVS_ACTION_ATTR_RECIRC, obj.recirc.value());
	}
	if (obj.hash) {
		ynl_attr_put(nlh, OVS_ACTION_ATTR_HASH, &*obj.hash, sizeof(struct ovs_action_hash));
	}
	if (obj.push_mpls) {
		ynl_attr_put(nlh, OVS_ACTION_ATTR_PUSH_MPLS, &*obj.push_mpls, sizeof(struct ovs_action_push_mpls));
	}
	if (obj.pop_mpls.has_value()) {
		ynl_attr_put_u16(nlh, OVS_ACTION_ATTR_POP_MPLS, obj.pop_mpls.value());
	}
	for (unsigned int i = 0; i < obj.set_masked.size(); i++) {
		ovs_flow_key_attrs_put(nlh, OVS_ACTION_ATTR_SET_MASKED, obj.set_masked[i]);
	}
	if (obj.ct.has_value()) {
		ovs_flow_ct_attrs_put(nlh, OVS_ACTION_ATTR_CT, obj.ct.value());
	}
	if (obj.trunc.has_value()) {
		ynl_attr_put_u32(nlh, OVS_ACTION_ATTR_TRUNC, obj.trunc.value());
	}
	if (obj.push_eth.size() > 0) {
		ynl_attr_put(nlh, OVS_ACTION_ATTR_PUSH_ETH, obj.push_eth.data(), obj.push_eth.size());
	}
	if (obj.pop_eth) {
		ynl_attr_put(nlh, OVS_ACTION_ATTR_POP_ETH, NULL, 0);
	}
	if (obj.ct_clear) {
		ynl_attr_put(nlh, OVS_ACTION_ATTR_CT_CLEAR, NULL, 0);
	}
	if (obj.push_nsh.has_value()) {
		ovs_flow_ovs_nsh_key_attrs_put(nlh, OVS_ACTION_ATTR_PUSH_NSH, obj.push_nsh.value());
	}
	if (obj.pop_nsh) {
		ynl_attr_put(nlh, OVS_ACTION_ATTR_POP_NSH, NULL, 0);
	}
	if (obj.meter.has_value()) {
		ynl_attr_put_u32(nlh, OVS_ACTION_ATTR_METER, obj.meter.value());
	}
	for (unsigned int i = 0; i < obj.clone.size(); i++) {
		ovs_flow_action_attrs_put(nlh, OVS_ACTION_ATTR_CLONE, obj.clone[i]);
	}
	if (obj.check_pkt_len.has_value()) {
		ovs_flow_check_pkt_len_attrs_put(nlh, OVS_ACTION_ATTR_CHECK_PKT_LEN, obj.check_pkt_len.value());
	}
	if (obj.add_mpls) {
		ynl_attr_put(nlh, OVS_ACTION_ATTR_ADD_MPLS, &*obj.add_mpls, sizeof(struct ovs_action_add_mpls));
	}
	if (obj.dec_ttl.has_value()) {
		ovs_flow_dec_ttl_attrs_put(nlh, OVS_ACTION_ATTR_DEC_TTL, obj.dec_ttl.value());
	}
	if (obj.psample.has_value()) {
		ovs_flow_psample_attrs_put(nlh, OVS_ACTION_ATTR_PSAMPLE, obj.psample.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovs_flow_action_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	ovs_flow_action_attrs *dst = (ovs_flow_action_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_ACTION_ATTR_OUTPUT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->output = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_ACTION_ATTR_USERSPACE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_userspace_attrs_nest;
			parg.data = &dst->userspace.emplace();
			if (ovs_flow_userspace_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_SET) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			dst->set.emplace_back();
			parg.data = &dst->set.back();
			if (ovs_flow_key_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_PUSH_VLAN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_action_push_vlan);
			dst->push_vlan.emplace();
			memcpy(&*dst->push_vlan, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_ACTION_ATTR_POP_VLAN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_SAMPLE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_sample_attrs_nest;
			parg.data = &dst->sample.emplace();
			if (ovs_flow_sample_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_RECIRC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->recirc = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_ACTION_ATTR_HASH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_action_hash);
			dst->hash.emplace();
			memcpy(&*dst->hash, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_ACTION_ATTR_PUSH_MPLS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_action_push_mpls);
			dst->push_mpls.emplace();
			memcpy(&*dst->push_mpls, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_ACTION_ATTR_POP_MPLS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->pop_mpls = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVS_ACTION_ATTR_SET_MASKED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			dst->set_masked.emplace_back();
			parg.data = &dst->set_masked.back();
			if (ovs_flow_key_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_CT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_ct_attrs_nest;
			parg.data = &dst->ct.emplace();
			if (ovs_flow_ct_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_TRUNC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->trunc = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_ACTION_ATTR_PUSH_ETH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->push_eth.assign(data, data + len);
		} else if (type == OVS_ACTION_ATTR_POP_ETH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_CT_CLEAR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_PUSH_NSH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_ovs_nsh_key_attrs_nest;
			parg.data = &dst->push_nsh.emplace();
			if (ovs_flow_ovs_nsh_key_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_POP_NSH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_METER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->meter = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVS_ACTION_ATTR_CLONE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			dst->clone.emplace_back();
			parg.data = &dst->clone.back();
			if (ovs_flow_action_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_CHECK_PKT_LEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_check_pkt_len_attrs_nest;
			parg.data = &dst->check_pkt_len.emplace();
			if (ovs_flow_check_pkt_len_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_ADD_MPLS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_action_add_mpls);
			dst->add_mpls.emplace();
			memcpy(&*dst->add_mpls, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_ACTION_ATTR_DEC_TTL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_dec_ttl_attrs_nest;
			parg.data = &dst->dec_ttl.emplace();
			if (ovs_flow_dec_ttl_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_ACTION_ATTR_PSAMPLE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_psample_attrs_nest;
			parg.data = &dst->psample.emplace();
			if (ovs_flow_psample_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

/* ============== OVS_FLOW_CMD_GET ============== */
/* OVS_FLOW_CMD_GET - do */
int ovs_flow_get_rsp_parse(const struct nlmsghdr *nlh,
			   struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ovs_flow_get_rsp *dst;
	void *hdr;

	dst = (ovs_flow_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));
	memcpy(&dst->_hdr, hdr, sizeof(struct ovs_header));

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVS_FLOW_ATTR_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			parg.data = &dst->key.emplace();
			if (ovs_flow_key_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_FLOW_ATTR_UFID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->ufid.assign(data, data + len);
		} else if (type == OVS_FLOW_ATTR_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_key_attrs_nest;
			parg.data = &dst->mask.emplace();
			if (ovs_flow_key_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVS_FLOW_ATTR_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ovs_flow_stats);
			dst->stats.emplace();
			memcpy(&*dst->stats, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == OVS_FLOW_ATTR_ACTIONS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovs_flow_action_attrs_nest;
			parg.data = &dst->actions.emplace();
			if (ovs_flow_action_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ovs_flow_get_rsp>
ovs_flow_get(ynl_cpp::ynl_socket& ys, ovs_flow_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ovs_flow_get_rsp> rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVS_FLOW_CMD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ovs_flow_flow_attrs_nest;
	yrs.yarg.rsp_policy = &ovs_flow_flow_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.key.has_value()) {
		ovs_flow_key_attrs_put(nlh, OVS_FLOW_ATTR_KEY, req.key.value());
	}
	if (req.ufid.size() > 0) {
		ynl_attr_put(nlh, OVS_FLOW_ATTR_UFID, req.ufid.data(), req.ufid.size());
	}
	if (req.ufid_flags.has_value()) {
		ynl_attr_put_u32(nlh, OVS_FLOW_ATTR_UFID_FLAGS, req.ufid_flags.value());
	}

	rsp.reset(new ovs_flow_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ovs_flow_get_rsp_parse;
	yrs.rsp_cmd = OVS_FLOW_CMD_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* OVS_FLOW_CMD_GET - dump */
std::unique_ptr<ovs_flow_get_list>
ovs_flow_get_dump(ynl_cpp::ynl_socket& ys, ovs_flow_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<ovs_flow_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ovs_flow_flow_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<ovs_flow_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ovs_flow_get_rsp_parse;
	yds.rsp_cmd = OVS_FLOW_CMD_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, OVS_FLOW_CMD_GET, 1);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &ovs_flow_flow_attrs_nest;

	if (req.key.has_value()) {
		ovs_flow_key_attrs_put(nlh, OVS_FLOW_ATTR_KEY, req.key.value());
	}
	if (req.ufid.size() > 0) {
		ynl_attr_put(nlh, OVS_FLOW_ATTR_UFID, req.ufid.data(), req.ufid.size());
	}
	if (req.ufid_flags.has_value()) {
		ynl_attr_put_u32(nlh, OVS_FLOW_ATTR_UFID_FLAGS, req.ufid_flags.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== OVS_FLOW_CMD_NEW ============== */
/* OVS_FLOW_CMD_NEW - do */
int ovs_flow_new(ynl_cpp::ynl_socket& ys, ovs_flow_new_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVS_FLOW_CMD_NEW, 1);
	((struct ynl_sock*)ys)->req_policy = &ovs_flow_flow_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.key.has_value()) {
		ovs_flow_key_attrs_put(nlh, OVS_FLOW_ATTR_KEY, req.key.value());
	}
	if (req.ufid.size() > 0) {
		ynl_attr_put(nlh, OVS_FLOW_ATTR_UFID, req.ufid.data(), req.ufid.size());
	}
	if (req.mask.has_value()) {
		ovs_flow_key_attrs_put(nlh, OVS_FLOW_ATTR_MASK, req.mask.value());
	}
	if (req.actions.has_value()) {
		ovs_flow_action_attrs_put(nlh, OVS_FLOW_ATTR_ACTIONS, req.actions.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

const struct ynl_family ynl_ovs_flow_family =  {
	.name		= "ovs_flow",
	.hdr_len	= sizeof(struct genlmsghdr) + sizeof(struct ovs_header),
};
const struct ynl_family& get_ynl_ovs_flow_family() {
	return ynl_ovs_flow_family;
};
} //namespace ynl_cpp
