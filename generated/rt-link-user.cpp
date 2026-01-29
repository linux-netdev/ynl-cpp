// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "rt-link-user.hpp"

#include <array>

#include <linux/dpll.h>
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>
#include <linux/rtnetlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, 92 + 1> rt_link_op_strmap = []() {
	std::array<std::string_view, 92 + 1> arr{};
	arr[16] = "getlink";
	arr[92] = "getstats";
	return arr;
} ();

std::string_view rt_link_op_str(int op)
{
	if (op < 0 || op >= (int)(rt_link_op_strmap.size())) {
		return "";
	}
	return rt_link_op_strmap[op];
}

static constexpr std::array<std::string_view, 18 + 1> rt_link_ifinfo_flags_strmap = []() {
	std::array<std::string_view, 18 + 1> arr{};
	arr[0] = "up";
	arr[1] = "broadcast";
	arr[2] = "debug";
	arr[3] = "loopback";
	arr[4] = "point-to-point";
	arr[5] = "no-trailers";
	arr[6] = "running";
	arr[7] = "no-arp";
	arr[8] = "promisc";
	arr[9] = "all-multi";
	arr[10] = "master";
	arr[11] = "slave";
	arr[12] = "multicast";
	arr[13] = "portsel";
	arr[14] = "auto-media";
	arr[15] = "dynamic";
	arr[16] = "lower-up";
	arr[17] = "dormant";
	arr[18] = "echo";
	return arr;
} ();

std::string_view rt_link_ifinfo_flags_str(net_device_flags value)
{
	value = (net_device_flags)(ffs(value) - 1);
	if (value < 0 || value >= (int)(rt_link_ifinfo_flags_strmap.size())) {
		return "";
	}
	return rt_link_ifinfo_flags_strmap[value];
}

static constexpr std::array<std::string_view, 34984 + 1> rt_link_vlan_protocols_strmap = []() {
	std::array<std::string_view, 34984 + 1> arr{};
	arr[33024] = "8021q";
	arr[34984] = "8021ad";
	return arr;
} ();

std::string_view rt_link_vlan_protocols_str(int value)
{
	if (value < 0 || value >= (int)(rt_link_vlan_protocols_strmap.size())) {
		return "";
	}
	return rt_link_vlan_protocols_strmap[value];
}

static constexpr std::array<std::string_view, 32 + 1> rt_link_ipv4_devconf_strmap = []() {
	std::array<std::string_view, 32 + 1> arr{};
	arr[0] = "forwarding";
	arr[1] = "mc-forwarding";
	arr[2] = "proxy-arp";
	arr[3] = "accept-redirects";
	arr[4] = "secure-redirects";
	arr[5] = "send-redirects";
	arr[6] = "shared-media";
	arr[7] = "rp-filter";
	arr[8] = "accept-source-route";
	arr[9] = "bootp-relay";
	arr[10] = "log-martians";
	arr[11] = "tag";
	arr[12] = "arpfilter";
	arr[13] = "medium-id";
	arr[14] = "noxfrm";
	arr[15] = "nopolicy";
	arr[16] = "force-igmp-version";
	arr[17] = "arp-announce";
	arr[18] = "arp-ignore";
	arr[19] = "promote-secondaries";
	arr[20] = "arp-accept";
	arr[21] = "arp-notify";
	arr[22] = "accept-local";
	arr[23] = "src-vmark";
	arr[24] = "proxy-arp-pvlan";
	arr[25] = "route-localnet";
	arr[26] = "igmpv2-unsolicited-report-interval";
	arr[27] = "igmpv3-unsolicited-report-interval";
	arr[28] = "ignore-routes-with-linkdown";
	arr[29] = "drop-unicast-in-l2-multicast";
	arr[30] = "drop-gratuitous-arp";
	arr[31] = "bc-forwarding";
	arr[32] = "arp-evict-nocarrier";
	return arr;
} ();

std::string_view rt_link_ipv4_devconf_str(int value)
{
	if (value < 0 || value >= (int)(rt_link_ipv4_devconf_strmap.size())) {
		return "";
	}
	return rt_link_ipv4_devconf_strmap[value];
}

static constexpr std::array<std::string_view, 57 + 1> rt_link_ipv6_devconf_strmap = []() {
	std::array<std::string_view, 57 + 1> arr{};
	arr[0] = "forwarding";
	arr[1] = "hoplimit";
	arr[2] = "mtu6";
	arr[3] = "accept-ra";
	arr[4] = "accept-redirects";
	arr[5] = "autoconf";
	arr[6] = "dad-transmits";
	arr[7] = "rtr-solicits";
	arr[8] = "rtr-solicit-interval";
	arr[9] = "rtr-solicit-delay";
	arr[10] = "use-tempaddr";
	arr[11] = "temp-valid-lft";
	arr[12] = "temp-prefered-lft";
	arr[13] = "regen-max-retry";
	arr[14] = "max-desync-factor";
	arr[15] = "max-addresses";
	arr[16] = "force-mld-version";
	arr[17] = "accept-ra-defrtr";
	arr[18] = "accept-ra-pinfo";
	arr[19] = "accept-ra-rtr-pref";
	arr[20] = "rtr-probe-interval";
	arr[21] = "accept-ra-rt-info-max-plen";
	arr[22] = "proxy-ndp";
	arr[23] = "optimistic-dad";
	arr[24] = "accept-source-route";
	arr[25] = "mc-forwarding";
	arr[26] = "disable-ipv6";
	arr[27] = "accept-dad";
	arr[28] = "force-tllao";
	arr[29] = "ndisc-notify";
	arr[30] = "mldv1-unsolicited-report-interval";
	arr[31] = "mldv2-unsolicited-report-interval";
	arr[32] = "suppress-frag-ndisc";
	arr[33] = "accept-ra-from-local";
	arr[34] = "use-optimistic";
	arr[35] = "accept-ra-mtu";
	arr[36] = "stable-secret";
	arr[37] = "use-oif-addrs-only";
	arr[38] = "accept-ra-min-hop-limit";
	arr[39] = "ignore-routes-with-linkdown";
	arr[40] = "drop-unicast-in-l2-multicast";
	arr[41] = "drop-unsolicited-na";
	arr[42] = "keep-addr-on-down";
	arr[43] = "rtr-solicit-max-interval";
	arr[44] = "seg6-enabled";
	arr[45] = "seg6-require-hmac";
	arr[46] = "enhanced-dad";
	arr[47] = "addr-gen-mode";
	arr[48] = "disable-policy";
	arr[49] = "accept-ra-rt-info-min-plen";
	arr[50] = "ndisc-tclass";
	arr[51] = "rpl-seg-enabled";
	arr[52] = "ra-defrtr-metric";
	arr[53] = "ioam6-enabled";
	arr[54] = "ioam6-id";
	arr[55] = "ioam6-id-wide";
	arr[56] = "ndisc-evict-nocarrier";
	arr[57] = "accept-untracked-na";
	return arr;
} ();

std::string_view rt_link_ipv6_devconf_str(int value)
{
	if (value < 0 || value >= (int)(rt_link_ipv6_devconf_strmap.size())) {
		return "";
	}
	return rt_link_ipv6_devconf_strmap[value];
}

static constexpr std::array<std::string_view, 6 + 1> rt_link_ifla_icmp6_stats_strmap = []() {
	std::array<std::string_view, 6 + 1> arr{};
	arr[0] = "num";
	arr[1] = "inmsgs";
	arr[2] = "inerrors";
	arr[3] = "outmsgs";
	arr[4] = "outerrors";
	arr[5] = "csumerrors";
	arr[6] = "ratelimithost";
	return arr;
} ();

std::string_view rt_link_ifla_icmp6_stats_str(int value)
{
	if (value < 0 || value >= (int)(rt_link_ifla_icmp6_stats_strmap.size())) {
		return "";
	}
	return rt_link_ifla_icmp6_stats_strmap[value];
}

static constexpr std::array<std::string_view, 36 + 1> rt_link_ifla_inet6_stats_strmap = []() {
	std::array<std::string_view, 36 + 1> arr{};
	arr[0] = "num";
	arr[1] = "inpkts";
	arr[2] = "inoctets";
	arr[3] = "indelivers";
	arr[4] = "outforwdatagrams";
	arr[5] = "outpkts";
	arr[6] = "outoctets";
	arr[7] = "inhdrerrors";
	arr[8] = "intoobigerrors";
	arr[9] = "innoroutes";
	arr[10] = "inaddrerrors";
	arr[11] = "inunknownprotos";
	arr[12] = "intruncatedpkts";
	arr[13] = "indiscards";
	arr[14] = "outdiscards";
	arr[15] = "outnoroutes";
	arr[16] = "reasmtimeout";
	arr[17] = "reasmreqds";
	arr[18] = "reasmoks";
	arr[19] = "reasmfails";
	arr[20] = "fragoks";
	arr[21] = "fragfails";
	arr[22] = "fragcreates";
	arr[23] = "inmcastpkts";
	arr[24] = "outmcastpkts";
	arr[25] = "inbcastpkts";
	arr[26] = "outbcastpkts";
	arr[27] = "inmcastoctets";
	arr[28] = "outmcastoctets";
	arr[29] = "inbcastoctets";
	arr[30] = "outbcastoctets";
	arr[31] = "csumerrors";
	arr[32] = "noectpkts";
	arr[33] = "ect1-pkts";
	arr[34] = "ect0-pkts";
	arr[35] = "cepkts";
	arr[36] = "reasm-overlaps";
	return arr;
} ();

std::string_view rt_link_ifla_inet6_stats_str(int value)
{
	if (value < 0 || value >= (int)(rt_link_ifla_inet6_stats_strmap.size())) {
		return "";
	}
	return rt_link_ifla_inet6_stats_strmap[value];
}

static constexpr std::array<std::string_view, 4 + 1> rt_link_vlan_flags_strmap = []() {
	std::array<std::string_view, 4 + 1> arr{};
	arr[0] = "reorder-hdr";
	arr[1] = "gvrp";
	arr[2] = "loose-binding";
	arr[3] = "mvrp";
	arr[4] = "bridge-binding";
	return arr;
} ();

std::string_view rt_link_vlan_flags_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(rt_link_vlan_flags_strmap.size())) {
		return "";
	}
	return rt_link_vlan_flags_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> rt_link_ifla_vf_link_state_enum_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "auto";
	arr[1] = "enable";
	arr[2] = "disable";
	return arr;
} ();

std::string_view rt_link_ifla_vf_link_state_enum_str(int value)
{
	if (value < 0 || value >= (int)(rt_link_ifla_vf_link_state_enum_strmap.size())) {
		return "";
	}
	return rt_link_ifla_vf_link_state_enum_strmap[value];
}

static constexpr std::array<std::string_view, 7 + 1> rt_link_rtext_filter_strmap = []() {
	std::array<std::string_view, 7 + 1> arr{};
	arr[0] = "vf";
	arr[1] = "brvlan";
	arr[2] = "brvlan-compressed";
	arr[3] = "skip-stats";
	arr[4] = "mrp";
	arr[5] = "cfm-config";
	arr[6] = "cfm-status";
	arr[7] = "mst";
	return arr;
} ();

std::string_view rt_link_rtext_filter_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(rt_link_rtext_filter_strmap.size())) {
		return "";
	}
	return rt_link_rtext_filter_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> rt_link_netkit_policy_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "forward";
	arr[2] = "blackhole";
	return arr;
} ();

std::string_view rt_link_netkit_policy_str(int value)
{
	if (value < 0 || value >= (int)(rt_link_netkit_policy_strmap.size())) {
		return "";
	}
	return rt_link_netkit_policy_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> rt_link_netkit_mode_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "l2";
	arr[1] = "l3";
	return arr;
} ();

std::string_view rt_link_netkit_mode_str(netkit_mode value)
{
	if (value < 0 || value >= (int)(rt_link_netkit_mode_strmap.size())) {
		return "";
	}
	return rt_link_netkit_mode_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> rt_link_netkit_scrub_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "none";
	arr[1] = "default";
	return arr;
} ();

std::string_view rt_link_netkit_scrub_str(int value)
{
	if (value < 0 || value >= (int)(rt_link_netkit_scrub_strmap.size())) {
		return "";
	}
	return rt_link_netkit_scrub_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> rt_link_ovpn_mode_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "p2p";
	arr[1] = "mp";
	return arr;
} ();

std::string_view rt_link_ovpn_mode_str(ovpn_mode value)
{
	if (value < 0 || value >= (int)(rt_link_ovpn_mode_strmap.size())) {
		return "";
	}
	return rt_link_ovpn_mode_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,IFLA_MAX + 1> rt_link_vf_ports_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_MAX + 1> arr{};
	return arr;
} ();

struct ynl_policy_nest rt_link_vf_ports_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_MAX),
	.table = rt_link_vf_ports_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_MAX + 1> rt_link_port_self_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_MAX + 1> arr{};
	return arr;
} ();

struct ynl_policy_nest rt_link_port_self_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_MAX),
	.table = rt_link_port_self_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_XDP_MAX + 1> rt_link_xdp_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_XDP_MAX + 1> arr{};
	arr[IFLA_XDP_FD].name = "fd";
	arr[IFLA_XDP_FD].type = YNL_PT_U32;
	arr[IFLA_XDP_ATTACHED].name = "attached";
	arr[IFLA_XDP_ATTACHED].type = YNL_PT_U8;
	arr[IFLA_XDP_FLAGS].name = "flags";
	arr[IFLA_XDP_FLAGS].type = YNL_PT_U32;
	arr[IFLA_XDP_PROG_ID].name = "prog-id";
	arr[IFLA_XDP_PROG_ID].type = YNL_PT_U32;
	arr[IFLA_XDP_DRV_PROG_ID].name = "drv-prog-id";
	arr[IFLA_XDP_DRV_PROG_ID].type = YNL_PT_U32;
	arr[IFLA_XDP_SKB_PROG_ID].name = "skb-prog-id";
	arr[IFLA_XDP_SKB_PROG_ID].type = YNL_PT_U32;
	arr[IFLA_XDP_HW_PROG_ID].name = "hw-prog-id";
	arr[IFLA_XDP_HW_PROG_ID].type = YNL_PT_U32;
	arr[IFLA_XDP_EXPECTED_FD].name = "expected-fd";
	arr[IFLA_XDP_EXPECTED_FD].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_xdp_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_XDP_MAX),
	.table = rt_link_xdp_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_MAX + 1> rt_link_prop_list_link_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_MAX + 1> arr{};
	arr[IFLA_ALT_IFNAME].name = "alt-ifname";
	arr[IFLA_ALT_IFNAME].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest rt_link_prop_list_link_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_MAX),
	.table = rt_link_prop_list_link_attrs_policy.data(),
};

static std::array<ynl_policy_attr,DPLL_A_MAX + 1> rt_link_link_dpll_pin_attrs_policy = []() {
	std::array<ynl_policy_attr,DPLL_A_MAX + 1> arr{};
	arr[DPLL_A_ID].name = "id";
	arr[DPLL_A_ID].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_link_dpll_pin_attrs_nest = {
	.max_attr = static_cast<unsigned int>(DPLL_A_MAX),
	.table = rt_link_link_dpll_pin_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_INET_MAX + 1> rt_link_ifla_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_INET_MAX + 1> arr{};
	arr[IFLA_INET_CONF].name = "conf";
	arr[IFLA_INET_CONF].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest rt_link_ifla_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_INET_MAX),
	.table = rt_link_ifla_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_INET6_MAX + 1> rt_link_ifla6_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_INET6_MAX + 1> arr{};
	arr[IFLA_INET6_FLAGS].name = "flags";
	arr[IFLA_INET6_FLAGS].type = YNL_PT_U32;
	arr[IFLA_INET6_CONF].name = "conf";
	arr[IFLA_INET6_CONF].type = YNL_PT_BINARY;
	arr[IFLA_INET6_STATS].name = "stats";
	arr[IFLA_INET6_STATS].type = YNL_PT_BINARY;
	arr[IFLA_INET6_MCAST].name = "mcast";
	arr[IFLA_INET6_MCAST].type = YNL_PT_BINARY;
	arr[IFLA_INET6_CACHEINFO].name = "cacheinfo";
	arr[IFLA_INET6_CACHEINFO].type = YNL_PT_BINARY;
	arr[IFLA_INET6_ICMP6STATS].name = "icmp6stats";
	arr[IFLA_INET6_ICMP6STATS].type = YNL_PT_BINARY;
	arr[IFLA_INET6_TOKEN].name = "token";
	arr[IFLA_INET6_TOKEN].type = YNL_PT_BINARY;
	arr[IFLA_INET6_ADDR_GEN_MODE].name = "addr-gen-mode";
	arr[IFLA_INET6_ADDR_GEN_MODE].type = YNL_PT_U8;
	arr[IFLA_INET6_RA_MTU].name = "ra-mtu";
	arr[IFLA_INET6_RA_MTU].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_ifla6_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_INET6_MAX),
	.table = rt_link_ifla6_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_MCTP_MAX + 1> rt_link_mctp_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_MCTP_MAX + 1> arr{};
	arr[IFLA_MCTP_NET].name = "net";
	arr[IFLA_MCTP_NET].type = YNL_PT_U32;
	arr[IFLA_MCTP_PHYS_BINDING].name = "phys-binding";
	arr[IFLA_MCTP_PHYS_BINDING].type = YNL_PT_U8;
	return arr;
} ();

struct ynl_policy_nest rt_link_mctp_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_MCTP_MAX),
	.table = rt_link_mctp_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX + 1> rt_link_hw_s_info_one_policy = []() {
	std::array<ynl_policy_attr,IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX + 1> arr{};
	arr[IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST].name = "request";
	arr[IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST].type = YNL_PT_U8;
	arr[IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED].name = "used";
	arr[IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED].type = YNL_PT_U8;
	return arr;
} ();

struct ynl_policy_nest rt_link_hw_s_info_one_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX),
	.table = rt_link_hw_s_info_one_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_BR_MAX + 1> rt_link_linkinfo_bridge_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_BR_MAX + 1> arr{};
	arr[IFLA_BR_FORWARD_DELAY].name = "forward-delay";
	arr[IFLA_BR_FORWARD_DELAY].type = YNL_PT_U32;
	arr[IFLA_BR_HELLO_TIME].name = "hello-time";
	arr[IFLA_BR_HELLO_TIME].type = YNL_PT_U32;
	arr[IFLA_BR_MAX_AGE].name = "max-age";
	arr[IFLA_BR_MAX_AGE].type = YNL_PT_U32;
	arr[IFLA_BR_AGEING_TIME].name = "ageing-time";
	arr[IFLA_BR_AGEING_TIME].type = YNL_PT_U32;
	arr[IFLA_BR_STP_STATE].name = "stp-state";
	arr[IFLA_BR_STP_STATE].type = YNL_PT_U32;
	arr[IFLA_BR_PRIORITY].name = "priority";
	arr[IFLA_BR_PRIORITY].type = YNL_PT_U16;
	arr[IFLA_BR_VLAN_FILTERING].name = "vlan-filtering";
	arr[IFLA_BR_VLAN_FILTERING].type = YNL_PT_U8;
	arr[IFLA_BR_VLAN_PROTOCOL].name = "vlan-protocol";
	arr[IFLA_BR_VLAN_PROTOCOL].type = YNL_PT_U16;
	arr[IFLA_BR_GROUP_FWD_MASK].name = "group-fwd-mask";
	arr[IFLA_BR_GROUP_FWD_MASK].type = YNL_PT_U16;
	arr[IFLA_BR_ROOT_ID].name = "root-id";
	arr[IFLA_BR_ROOT_ID].type = YNL_PT_BINARY;
	arr[IFLA_BR_BRIDGE_ID].name = "bridge-id";
	arr[IFLA_BR_BRIDGE_ID].type = YNL_PT_BINARY;
	arr[IFLA_BR_ROOT_PORT].name = "root-port";
	arr[IFLA_BR_ROOT_PORT].type = YNL_PT_U16;
	arr[IFLA_BR_ROOT_PATH_COST].name = "root-path-cost";
	arr[IFLA_BR_ROOT_PATH_COST].type = YNL_PT_U32;
	arr[IFLA_BR_TOPOLOGY_CHANGE].name = "topology-change";
	arr[IFLA_BR_TOPOLOGY_CHANGE].type = YNL_PT_U8;
	arr[IFLA_BR_TOPOLOGY_CHANGE_DETECTED].name = "topology-change-detected";
	arr[IFLA_BR_TOPOLOGY_CHANGE_DETECTED].type = YNL_PT_U8;
	arr[IFLA_BR_HELLO_TIMER].name = "hello-timer";
	arr[IFLA_BR_HELLO_TIMER].type = YNL_PT_U64;
	arr[IFLA_BR_TCN_TIMER].name = "tcn-timer";
	arr[IFLA_BR_TCN_TIMER].type = YNL_PT_U64;
	arr[IFLA_BR_TOPOLOGY_CHANGE_TIMER].name = "topology-change-timer";
	arr[IFLA_BR_TOPOLOGY_CHANGE_TIMER].type = YNL_PT_U64;
	arr[IFLA_BR_GC_TIMER].name = "gc-timer";
	arr[IFLA_BR_GC_TIMER].type = YNL_PT_U64;
	arr[IFLA_BR_GROUP_ADDR].name = "group-addr";
	arr[IFLA_BR_GROUP_ADDR].type = YNL_PT_BINARY;
	arr[IFLA_BR_FDB_FLUSH].name = "fdb-flush";
	arr[IFLA_BR_FDB_FLUSH].type = YNL_PT_BINARY;
	arr[IFLA_BR_MCAST_ROUTER].name = "mcast-router";
	arr[IFLA_BR_MCAST_ROUTER].type = YNL_PT_U8;
	arr[IFLA_BR_MCAST_SNOOPING].name = "mcast-snooping";
	arr[IFLA_BR_MCAST_SNOOPING].type = YNL_PT_U8;
	arr[IFLA_BR_MCAST_QUERY_USE_IFADDR].name = "mcast-query-use-ifaddr";
	arr[IFLA_BR_MCAST_QUERY_USE_IFADDR].type = YNL_PT_U8;
	arr[IFLA_BR_MCAST_QUERIER].name = "mcast-querier";
	arr[IFLA_BR_MCAST_QUERIER].type = YNL_PT_U8;
	arr[IFLA_BR_MCAST_HASH_ELASTICITY].name = "mcast-hash-elasticity";
	arr[IFLA_BR_MCAST_HASH_ELASTICITY].type = YNL_PT_U32;
	arr[IFLA_BR_MCAST_HASH_MAX].name = "mcast-hash-max";
	arr[IFLA_BR_MCAST_HASH_MAX].type = YNL_PT_U32;
	arr[IFLA_BR_MCAST_LAST_MEMBER_CNT].name = "mcast-last-member-cnt";
	arr[IFLA_BR_MCAST_LAST_MEMBER_CNT].type = YNL_PT_U32;
	arr[IFLA_BR_MCAST_STARTUP_QUERY_CNT].name = "mcast-startup-query-cnt";
	arr[IFLA_BR_MCAST_STARTUP_QUERY_CNT].type = YNL_PT_U32;
	arr[IFLA_BR_MCAST_LAST_MEMBER_INTVL].name = "mcast-last-member-intvl";
	arr[IFLA_BR_MCAST_LAST_MEMBER_INTVL].type = YNL_PT_U64;
	arr[IFLA_BR_MCAST_MEMBERSHIP_INTVL].name = "mcast-membership-intvl";
	arr[IFLA_BR_MCAST_MEMBERSHIP_INTVL].type = YNL_PT_U64;
	arr[IFLA_BR_MCAST_QUERIER_INTVL].name = "mcast-querier-intvl";
	arr[IFLA_BR_MCAST_QUERIER_INTVL].type = YNL_PT_U64;
	arr[IFLA_BR_MCAST_QUERY_INTVL].name = "mcast-query-intvl";
	arr[IFLA_BR_MCAST_QUERY_INTVL].type = YNL_PT_U64;
	arr[IFLA_BR_MCAST_QUERY_RESPONSE_INTVL].name = "mcast-query-response-intvl";
	arr[IFLA_BR_MCAST_QUERY_RESPONSE_INTVL].type = YNL_PT_U64;
	arr[IFLA_BR_MCAST_STARTUP_QUERY_INTVL].name = "mcast-startup-query-intvl";
	arr[IFLA_BR_MCAST_STARTUP_QUERY_INTVL].type = YNL_PT_U64;
	arr[IFLA_BR_NF_CALL_IPTABLES].name = "nf-call-iptables";
	arr[IFLA_BR_NF_CALL_IPTABLES].type = YNL_PT_U8;
	arr[IFLA_BR_NF_CALL_IP6TABLES].name = "nf-call-ip6tables";
	arr[IFLA_BR_NF_CALL_IP6TABLES].type = YNL_PT_U8;
	arr[IFLA_BR_NF_CALL_ARPTABLES].name = "nf-call-arptables";
	arr[IFLA_BR_NF_CALL_ARPTABLES].type = YNL_PT_U8;
	arr[IFLA_BR_VLAN_DEFAULT_PVID].name = "vlan-default-pvid";
	arr[IFLA_BR_VLAN_DEFAULT_PVID].type = YNL_PT_U16;
	arr[IFLA_BR_PAD].name = "pad";
	arr[IFLA_BR_PAD].type = YNL_PT_IGNORE;
	arr[IFLA_BR_VLAN_STATS_ENABLED].name = "vlan-stats-enabled";
	arr[IFLA_BR_VLAN_STATS_ENABLED].type = YNL_PT_U8;
	arr[IFLA_BR_MCAST_STATS_ENABLED].name = "mcast-stats-enabled";
	arr[IFLA_BR_MCAST_STATS_ENABLED].type = YNL_PT_U8;
	arr[IFLA_BR_MCAST_IGMP_VERSION].name = "mcast-igmp-version";
	arr[IFLA_BR_MCAST_IGMP_VERSION].type = YNL_PT_U8;
	arr[IFLA_BR_MCAST_MLD_VERSION].name = "mcast-mld-version";
	arr[IFLA_BR_MCAST_MLD_VERSION].type = YNL_PT_U8;
	arr[IFLA_BR_VLAN_STATS_PER_PORT].name = "vlan-stats-per-port";
	arr[IFLA_BR_VLAN_STATS_PER_PORT].type = YNL_PT_U8;
	arr[IFLA_BR_MULTI_BOOLOPT].name = "multi-boolopt";
	arr[IFLA_BR_MULTI_BOOLOPT].type = YNL_PT_BINARY;
	arr[IFLA_BR_MCAST_QUERIER_STATE].name = "mcast-querier-state";
	arr[IFLA_BR_MCAST_QUERIER_STATE].type = YNL_PT_BINARY;
	arr[IFLA_BR_FDB_N_LEARNED].name = "fdb-n-learned";
	arr[IFLA_BR_FDB_N_LEARNED].type = YNL_PT_U32;
	arr[IFLA_BR_FDB_MAX_LEARNED].name = "fdb-max-learned";
	arr[IFLA_BR_FDB_MAX_LEARNED].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_bridge_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_BR_MAX),
	.table = rt_link_linkinfo_bridge_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_GRE_MAX + 1> rt_link_linkinfo_gre_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_GRE_MAX + 1> arr{};
	arr[IFLA_GRE_LINK].name = "link";
	arr[IFLA_GRE_LINK].type = YNL_PT_U32;
	arr[IFLA_GRE_IFLAGS].name = "iflags";
	arr[IFLA_GRE_IFLAGS].type = YNL_PT_U16;
	arr[IFLA_GRE_OFLAGS].name = "oflags";
	arr[IFLA_GRE_OFLAGS].type = YNL_PT_U16;
	arr[IFLA_GRE_IKEY].name = "ikey";
	arr[IFLA_GRE_IKEY].type = YNL_PT_U32;
	arr[IFLA_GRE_OKEY].name = "okey";
	arr[IFLA_GRE_OKEY].type = YNL_PT_U32;
	arr[IFLA_GRE_LOCAL].name = "local";
	arr[IFLA_GRE_LOCAL].type = YNL_PT_BINARY;
	arr[IFLA_GRE_REMOTE].name = "remote";
	arr[IFLA_GRE_REMOTE].type = YNL_PT_BINARY;
	arr[IFLA_GRE_TTL].name = "ttl";
	arr[IFLA_GRE_TTL].type = YNL_PT_U8;
	arr[IFLA_GRE_TOS].name = "tos";
	arr[IFLA_GRE_TOS].type = YNL_PT_U8;
	arr[IFLA_GRE_PMTUDISC].name = "pmtudisc";
	arr[IFLA_GRE_PMTUDISC].type = YNL_PT_U8;
	arr[IFLA_GRE_ENCAP_LIMIT].name = "encap-limit";
	arr[IFLA_GRE_ENCAP_LIMIT].type = YNL_PT_U8;
	arr[IFLA_GRE_FLOWINFO].name = "flowinfo";
	arr[IFLA_GRE_FLOWINFO].type = YNL_PT_U32;
	arr[IFLA_GRE_FLAGS].name = "flags";
	arr[IFLA_GRE_FLAGS].type = YNL_PT_U32;
	arr[IFLA_GRE_ENCAP_TYPE].name = "encap-type";
	arr[IFLA_GRE_ENCAP_TYPE].type = YNL_PT_U16;
	arr[IFLA_GRE_ENCAP_FLAGS].name = "encap-flags";
	arr[IFLA_GRE_ENCAP_FLAGS].type = YNL_PT_U16;
	arr[IFLA_GRE_ENCAP_SPORT].name = "encap-sport";
	arr[IFLA_GRE_ENCAP_SPORT].type = YNL_PT_U16;
	arr[IFLA_GRE_ENCAP_DPORT].name = "encap-dport";
	arr[IFLA_GRE_ENCAP_DPORT].type = YNL_PT_U16;
	arr[IFLA_GRE_COLLECT_METADATA].name = "collect-metadata";
	arr[IFLA_GRE_COLLECT_METADATA].type = YNL_PT_FLAG;
	arr[IFLA_GRE_IGNORE_DF].name = "ignore-df";
	arr[IFLA_GRE_IGNORE_DF].type = YNL_PT_U8;
	arr[IFLA_GRE_FWMARK].name = "fwmark";
	arr[IFLA_GRE_FWMARK].type = YNL_PT_U32;
	arr[IFLA_GRE_ERSPAN_INDEX].name = "erspan-index";
	arr[IFLA_GRE_ERSPAN_INDEX].type = YNL_PT_U32;
	arr[IFLA_GRE_ERSPAN_VER].name = "erspan-ver";
	arr[IFLA_GRE_ERSPAN_VER].type = YNL_PT_U8;
	arr[IFLA_GRE_ERSPAN_DIR].name = "erspan-dir";
	arr[IFLA_GRE_ERSPAN_DIR].type = YNL_PT_U8;
	arr[IFLA_GRE_ERSPAN_HWID].name = "erspan-hwid";
	arr[IFLA_GRE_ERSPAN_HWID].type = YNL_PT_U16;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_gre_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_GRE_MAX),
	.table = rt_link_linkinfo_gre_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_GRE_MAX + 1> rt_link_linkinfo_gre6_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_GRE_MAX + 1> arr{};
	arr[IFLA_GRE_LINK].name = "link";
	arr[IFLA_GRE_LINK].type = YNL_PT_U32;
	arr[IFLA_GRE_IFLAGS].name = "iflags";
	arr[IFLA_GRE_IFLAGS].type = YNL_PT_U16;
	arr[IFLA_GRE_OFLAGS].name = "oflags";
	arr[IFLA_GRE_OFLAGS].type = YNL_PT_U16;
	arr[IFLA_GRE_IKEY].name = "ikey";
	arr[IFLA_GRE_IKEY].type = YNL_PT_U32;
	arr[IFLA_GRE_OKEY].name = "okey";
	arr[IFLA_GRE_OKEY].type = YNL_PT_U32;
	arr[IFLA_GRE_LOCAL].name = "local";
	arr[IFLA_GRE_LOCAL].type = YNL_PT_BINARY;
	arr[IFLA_GRE_REMOTE].name = "remote";
	arr[IFLA_GRE_REMOTE].type = YNL_PT_BINARY;
	arr[IFLA_GRE_TTL].name = "ttl";
	arr[IFLA_GRE_TTL].type = YNL_PT_U8;
	arr[IFLA_GRE_ENCAP_LIMIT].name = "encap-limit";
	arr[IFLA_GRE_ENCAP_LIMIT].type = YNL_PT_U8;
	arr[IFLA_GRE_FLOWINFO].name = "flowinfo";
	arr[IFLA_GRE_FLOWINFO].type = YNL_PT_U32;
	arr[IFLA_GRE_FLAGS].name = "flags";
	arr[IFLA_GRE_FLAGS].type = YNL_PT_U32;
	arr[IFLA_GRE_ENCAP_TYPE].name = "encap-type";
	arr[IFLA_GRE_ENCAP_TYPE].type = YNL_PT_U16;
	arr[IFLA_GRE_ENCAP_FLAGS].name = "encap-flags";
	arr[IFLA_GRE_ENCAP_FLAGS].type = YNL_PT_U16;
	arr[IFLA_GRE_ENCAP_SPORT].name = "encap-sport";
	arr[IFLA_GRE_ENCAP_SPORT].type = YNL_PT_U16;
	arr[IFLA_GRE_ENCAP_DPORT].name = "encap-dport";
	arr[IFLA_GRE_ENCAP_DPORT].type = YNL_PT_U16;
	arr[IFLA_GRE_COLLECT_METADATA].name = "collect-metadata";
	arr[IFLA_GRE_COLLECT_METADATA].type = YNL_PT_FLAG;
	arr[IFLA_GRE_FWMARK].name = "fwmark";
	arr[IFLA_GRE_FWMARK].type = YNL_PT_U32;
	arr[IFLA_GRE_ERSPAN_INDEX].name = "erspan-index";
	arr[IFLA_GRE_ERSPAN_INDEX].type = YNL_PT_U32;
	arr[IFLA_GRE_ERSPAN_VER].name = "erspan-ver";
	arr[IFLA_GRE_ERSPAN_VER].type = YNL_PT_U8;
	arr[IFLA_GRE_ERSPAN_DIR].name = "erspan-dir";
	arr[IFLA_GRE_ERSPAN_DIR].type = YNL_PT_U8;
	arr[IFLA_GRE_ERSPAN_HWID].name = "erspan-hwid";
	arr[IFLA_GRE_ERSPAN_HWID].type = YNL_PT_U16;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_gre6_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_GRE_MAX),
	.table = rt_link_linkinfo_gre6_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_GENEVE_MAX + 1> rt_link_linkinfo_geneve_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_GENEVE_MAX + 1> arr{};
	arr[IFLA_GENEVE_ID].name = "id";
	arr[IFLA_GENEVE_ID].type = YNL_PT_U32;
	arr[IFLA_GENEVE_REMOTE].name = "remote";
	arr[IFLA_GENEVE_REMOTE].type = YNL_PT_BINARY;
	arr[IFLA_GENEVE_TTL].name = "ttl";
	arr[IFLA_GENEVE_TTL].type = YNL_PT_U8;
	arr[IFLA_GENEVE_TOS].name = "tos";
	arr[IFLA_GENEVE_TOS].type = YNL_PT_U8;
	arr[IFLA_GENEVE_PORT].name = "port";
	arr[IFLA_GENEVE_PORT].type = YNL_PT_U16;
	arr[IFLA_GENEVE_COLLECT_METADATA].name = "collect-metadata";
	arr[IFLA_GENEVE_COLLECT_METADATA].type = YNL_PT_FLAG;
	arr[IFLA_GENEVE_REMOTE6].name = "remote6";
	arr[IFLA_GENEVE_REMOTE6].type = YNL_PT_BINARY;
	arr[IFLA_GENEVE_UDP_CSUM].name = "udp-csum";
	arr[IFLA_GENEVE_UDP_CSUM].type = YNL_PT_U8;
	arr[IFLA_GENEVE_UDP_ZERO_CSUM6_TX].name = "udp-zero-csum6-tx";
	arr[IFLA_GENEVE_UDP_ZERO_CSUM6_TX].type = YNL_PT_U8;
	arr[IFLA_GENEVE_UDP_ZERO_CSUM6_RX].name = "udp-zero-csum6-rx";
	arr[IFLA_GENEVE_UDP_ZERO_CSUM6_RX].type = YNL_PT_U8;
	arr[IFLA_GENEVE_LABEL].name = "label";
	arr[IFLA_GENEVE_LABEL].type = YNL_PT_U32;
	arr[IFLA_GENEVE_TTL_INHERIT].name = "ttl-inherit";
	arr[IFLA_GENEVE_TTL_INHERIT].type = YNL_PT_U8;
	arr[IFLA_GENEVE_DF].name = "df";
	arr[IFLA_GENEVE_DF].type = YNL_PT_U8;
	arr[IFLA_GENEVE_INNER_PROTO_INHERIT].name = "inner-proto-inherit";
	arr[IFLA_GENEVE_INNER_PROTO_INHERIT].type = YNL_PT_FLAG;
	arr[IFLA_GENEVE_PORT_RANGE].name = "port-range";
	arr[IFLA_GENEVE_PORT_RANGE].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_geneve_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_GENEVE_MAX),
	.table = rt_link_linkinfo_geneve_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_IPTUN_MAX + 1> rt_link_linkinfo_iptun_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_IPTUN_MAX + 1> arr{};
	arr[IFLA_IPTUN_LINK].name = "link";
	arr[IFLA_IPTUN_LINK].type = YNL_PT_U32;
	arr[IFLA_IPTUN_LOCAL].name = "local";
	arr[IFLA_IPTUN_LOCAL].type = YNL_PT_BINARY;
	arr[IFLA_IPTUN_REMOTE].name = "remote";
	arr[IFLA_IPTUN_REMOTE].type = YNL_PT_BINARY;
	arr[IFLA_IPTUN_TTL].name = "ttl";
	arr[IFLA_IPTUN_TTL].type = YNL_PT_U8;
	arr[IFLA_IPTUN_TOS].name = "tos";
	arr[IFLA_IPTUN_TOS].type = YNL_PT_U8;
	arr[IFLA_IPTUN_ENCAP_LIMIT].name = "encap-limit";
	arr[IFLA_IPTUN_ENCAP_LIMIT].type = YNL_PT_U8;
	arr[IFLA_IPTUN_FLOWINFO].name = "flowinfo";
	arr[IFLA_IPTUN_FLOWINFO].type = YNL_PT_U32;
	arr[IFLA_IPTUN_FLAGS].name = "flags";
	arr[IFLA_IPTUN_FLAGS].type = YNL_PT_U16;
	arr[IFLA_IPTUN_PROTO].name = "proto";
	arr[IFLA_IPTUN_PROTO].type = YNL_PT_U8;
	arr[IFLA_IPTUN_PMTUDISC].name = "pmtudisc";
	arr[IFLA_IPTUN_PMTUDISC].type = YNL_PT_U8;
	arr[IFLA_IPTUN_6RD_PREFIX].name = "6rd-prefix";
	arr[IFLA_IPTUN_6RD_PREFIX].type = YNL_PT_BINARY;
	arr[IFLA_IPTUN_6RD_RELAY_PREFIX].name = "6rd-relay-prefix";
	arr[IFLA_IPTUN_6RD_RELAY_PREFIX].type = YNL_PT_BINARY;
	arr[IFLA_IPTUN_6RD_PREFIXLEN].name = "6rd-prefixlen";
	arr[IFLA_IPTUN_6RD_PREFIXLEN].type = YNL_PT_U16;
	arr[IFLA_IPTUN_6RD_RELAY_PREFIXLEN].name = "6rd-relay-prefixlen";
	arr[IFLA_IPTUN_6RD_RELAY_PREFIXLEN].type = YNL_PT_U16;
	arr[IFLA_IPTUN_ENCAP_TYPE].name = "encap-type";
	arr[IFLA_IPTUN_ENCAP_TYPE].type = YNL_PT_U16;
	arr[IFLA_IPTUN_ENCAP_FLAGS].name = "encap-flags";
	arr[IFLA_IPTUN_ENCAP_FLAGS].type = YNL_PT_U16;
	arr[IFLA_IPTUN_ENCAP_SPORT].name = "encap-sport";
	arr[IFLA_IPTUN_ENCAP_SPORT].type = YNL_PT_U16;
	arr[IFLA_IPTUN_ENCAP_DPORT].name = "encap-dport";
	arr[IFLA_IPTUN_ENCAP_DPORT].type = YNL_PT_U16;
	arr[IFLA_IPTUN_COLLECT_METADATA].name = "collect-metadata";
	arr[IFLA_IPTUN_COLLECT_METADATA].type = YNL_PT_FLAG;
	arr[IFLA_IPTUN_FWMARK].name = "fwmark";
	arr[IFLA_IPTUN_FWMARK].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_iptun_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_IPTUN_MAX),
	.table = rt_link_linkinfo_iptun_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_IPTUN_MAX + 1> rt_link_linkinfo_ip6tnl_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_IPTUN_MAX + 1> arr{};
	arr[IFLA_IPTUN_LINK].name = "link";
	arr[IFLA_IPTUN_LINK].type = YNL_PT_U32;
	arr[IFLA_IPTUN_LOCAL].name = "local";
	arr[IFLA_IPTUN_LOCAL].type = YNL_PT_BINARY;
	arr[IFLA_IPTUN_REMOTE].name = "remote";
	arr[IFLA_IPTUN_REMOTE].type = YNL_PT_BINARY;
	arr[IFLA_IPTUN_TTL].name = "ttl";
	arr[IFLA_IPTUN_TTL].type = YNL_PT_U8;
	arr[IFLA_IPTUN_ENCAP_LIMIT].name = "encap-limit";
	arr[IFLA_IPTUN_ENCAP_LIMIT].type = YNL_PT_U8;
	arr[IFLA_IPTUN_FLOWINFO].name = "flowinfo";
	arr[IFLA_IPTUN_FLOWINFO].type = YNL_PT_U32;
	arr[IFLA_IPTUN_FLAGS].name = "flags";
	arr[IFLA_IPTUN_FLAGS].type = YNL_PT_U16;
	arr[IFLA_IPTUN_PROTO].name = "proto";
	arr[IFLA_IPTUN_PROTO].type = YNL_PT_U8;
	arr[IFLA_IPTUN_ENCAP_TYPE].name = "encap-type";
	arr[IFLA_IPTUN_ENCAP_TYPE].type = YNL_PT_U16;
	arr[IFLA_IPTUN_ENCAP_FLAGS].name = "encap-flags";
	arr[IFLA_IPTUN_ENCAP_FLAGS].type = YNL_PT_U16;
	arr[IFLA_IPTUN_ENCAP_SPORT].name = "encap-sport";
	arr[IFLA_IPTUN_ENCAP_SPORT].type = YNL_PT_U16;
	arr[IFLA_IPTUN_ENCAP_DPORT].name = "encap-dport";
	arr[IFLA_IPTUN_ENCAP_DPORT].type = YNL_PT_U16;
	arr[IFLA_IPTUN_COLLECT_METADATA].name = "collect-metadata";
	arr[IFLA_IPTUN_COLLECT_METADATA].type = YNL_PT_FLAG;
	arr[IFLA_IPTUN_FWMARK].name = "fwmark";
	arr[IFLA_IPTUN_FWMARK].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_ip6tnl_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_IPTUN_MAX),
	.table = rt_link_linkinfo_ip6tnl_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_TUN_MAX + 1> rt_link_linkinfo_tun_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_TUN_MAX + 1> arr{};
	arr[IFLA_TUN_OWNER].name = "owner";
	arr[IFLA_TUN_OWNER].type = YNL_PT_U32;
	arr[IFLA_TUN_GROUP].name = "group";
	arr[IFLA_TUN_GROUP].type = YNL_PT_U32;
	arr[IFLA_TUN_TYPE].name = "type";
	arr[IFLA_TUN_TYPE].type = YNL_PT_U8;
	arr[IFLA_TUN_PI].name = "pi";
	arr[IFLA_TUN_PI].type = YNL_PT_U8;
	arr[IFLA_TUN_VNET_HDR].name = "vnet-hdr";
	arr[IFLA_TUN_VNET_HDR].type = YNL_PT_U8;
	arr[IFLA_TUN_PERSIST].name = "persist";
	arr[IFLA_TUN_PERSIST].type = YNL_PT_U8;
	arr[IFLA_TUN_MULTI_QUEUE].name = "multi-queue";
	arr[IFLA_TUN_MULTI_QUEUE].type = YNL_PT_U8;
	arr[IFLA_TUN_NUM_QUEUES].name = "num-queues";
	arr[IFLA_TUN_NUM_QUEUES].type = YNL_PT_U32;
	arr[IFLA_TUN_NUM_DISABLED_QUEUES].name = "num-disabled-queues";
	arr[IFLA_TUN_NUM_DISABLED_QUEUES].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_tun_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_TUN_MAX),
	.table = rt_link_linkinfo_tun_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_VRF_MAX + 1> rt_link_linkinfo_vrf_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_VRF_MAX + 1> arr{};
	arr[IFLA_VRF_TABLE].name = "table";
	arr[IFLA_VRF_TABLE].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_vrf_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_VRF_MAX),
	.table = rt_link_linkinfo_vrf_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_VTI_MAX + 1> rt_link_linkinfo_vti_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_VTI_MAX + 1> arr{};
	arr[IFLA_VTI_LINK].name = "link";
	arr[IFLA_VTI_LINK].type = YNL_PT_U32;
	arr[IFLA_VTI_IKEY].name = "ikey";
	arr[IFLA_VTI_IKEY].type = YNL_PT_U32;
	arr[IFLA_VTI_OKEY].name = "okey";
	arr[IFLA_VTI_OKEY].type = YNL_PT_U32;
	arr[IFLA_VTI_LOCAL].name = "local";
	arr[IFLA_VTI_LOCAL].type = YNL_PT_BINARY;
	arr[IFLA_VTI_REMOTE].name = "remote";
	arr[IFLA_VTI_REMOTE].type = YNL_PT_BINARY;
	arr[IFLA_VTI_FWMARK].name = "fwmark";
	arr[IFLA_VTI_FWMARK].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_vti_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_VTI_MAX),
	.table = rt_link_linkinfo_vti_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_VTI_MAX + 1> rt_link_linkinfo_vti6_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_VTI_MAX + 1> arr{};
	arr[IFLA_VTI_LINK].name = "link";
	arr[IFLA_VTI_LINK].type = YNL_PT_U32;
	arr[IFLA_VTI_IKEY].name = "ikey";
	arr[IFLA_VTI_IKEY].type = YNL_PT_U32;
	arr[IFLA_VTI_OKEY].name = "okey";
	arr[IFLA_VTI_OKEY].type = YNL_PT_U32;
	arr[IFLA_VTI_LOCAL].name = "local";
	arr[IFLA_VTI_LOCAL].type = YNL_PT_BINARY;
	arr[IFLA_VTI_REMOTE].name = "remote";
	arr[IFLA_VTI_REMOTE].type = YNL_PT_BINARY;
	arr[IFLA_VTI_FWMARK].name = "fwmark";
	arr[IFLA_VTI_FWMARK].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_vti6_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_VTI_MAX),
	.table = rt_link_linkinfo_vti6_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_NETKIT_MAX + 1> rt_link_linkinfo_netkit_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_NETKIT_MAX + 1> arr{};
	arr[IFLA_NETKIT_PEER_INFO].name = "peer-info";
	arr[IFLA_NETKIT_PEER_INFO].type = YNL_PT_BINARY;
	arr[IFLA_NETKIT_PRIMARY].name = "primary";
	arr[IFLA_NETKIT_PRIMARY].type = YNL_PT_U8;
	arr[IFLA_NETKIT_POLICY].name = "policy";
	arr[IFLA_NETKIT_POLICY].type = YNL_PT_U32;
	arr[IFLA_NETKIT_PEER_POLICY].name = "peer-policy";
	arr[IFLA_NETKIT_PEER_POLICY].type = YNL_PT_U32;
	arr[IFLA_NETKIT_MODE].name = "mode";
	arr[IFLA_NETKIT_MODE].type = YNL_PT_U32;
	arr[IFLA_NETKIT_SCRUB].name = "scrub";
	arr[IFLA_NETKIT_SCRUB].type = YNL_PT_U32;
	arr[IFLA_NETKIT_PEER_SCRUB].name = "peer-scrub";
	arr[IFLA_NETKIT_PEER_SCRUB].type = YNL_PT_U32;
	arr[IFLA_NETKIT_HEADROOM].name = "headroom";
	arr[IFLA_NETKIT_HEADROOM].type = YNL_PT_U16;
	arr[IFLA_NETKIT_TAILROOM].name = "tailroom";
	arr[IFLA_NETKIT_TAILROOM].type = YNL_PT_U16;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_netkit_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_NETKIT_MAX),
	.table = rt_link_linkinfo_netkit_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_OVPN_MAX + 1> rt_link_linkinfo_ovpn_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_OVPN_MAX + 1> arr{};
	arr[IFLA_OVPN_MODE].name = "mode";
	arr[IFLA_OVPN_MODE].type = YNL_PT_U8;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_ovpn_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_OVPN_MAX),
	.table = rt_link_linkinfo_ovpn_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_BRPORT_MAX + 1> rt_link_linkinfo_brport_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_BRPORT_MAX + 1> arr{};
	arr[IFLA_BRPORT_STATE].name = "state";
	arr[IFLA_BRPORT_STATE].type = YNL_PT_U8;
	arr[IFLA_BRPORT_PRIORITY].name = "priority";
	arr[IFLA_BRPORT_PRIORITY].type = YNL_PT_U16;
	arr[IFLA_BRPORT_COST].name = "cost";
	arr[IFLA_BRPORT_COST].type = YNL_PT_U32;
	arr[IFLA_BRPORT_MODE].name = "mode";
	arr[IFLA_BRPORT_MODE].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_GUARD].name = "guard";
	arr[IFLA_BRPORT_GUARD].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_PROTECT].name = "protect";
	arr[IFLA_BRPORT_PROTECT].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_FAST_LEAVE].name = "fast-leave";
	arr[IFLA_BRPORT_FAST_LEAVE].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_LEARNING].name = "learning";
	arr[IFLA_BRPORT_LEARNING].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_UNICAST_FLOOD].name = "unicast-flood";
	arr[IFLA_BRPORT_UNICAST_FLOOD].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_PROXYARP].name = "proxyarp";
	arr[IFLA_BRPORT_PROXYARP].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_LEARNING_SYNC].name = "learning-sync";
	arr[IFLA_BRPORT_LEARNING_SYNC].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_PROXYARP_WIFI].name = "proxyarp-wifi";
	arr[IFLA_BRPORT_PROXYARP_WIFI].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_ROOT_ID].name = "root-id";
	arr[IFLA_BRPORT_ROOT_ID].type = YNL_PT_BINARY;
	arr[IFLA_BRPORT_BRIDGE_ID].name = "bridge-id";
	arr[IFLA_BRPORT_BRIDGE_ID].type = YNL_PT_BINARY;
	arr[IFLA_BRPORT_DESIGNATED_PORT].name = "designated-port";
	arr[IFLA_BRPORT_DESIGNATED_PORT].type = YNL_PT_U16;
	arr[IFLA_BRPORT_DESIGNATED_COST].name = "designated-cost";
	arr[IFLA_BRPORT_DESIGNATED_COST].type = YNL_PT_U16;
	arr[IFLA_BRPORT_ID].name = "id";
	arr[IFLA_BRPORT_ID].type = YNL_PT_U16;
	arr[IFLA_BRPORT_NO].name = "no";
	arr[IFLA_BRPORT_NO].type = YNL_PT_U16;
	arr[IFLA_BRPORT_TOPOLOGY_CHANGE_ACK].name = "topology-change-ack";
	arr[IFLA_BRPORT_TOPOLOGY_CHANGE_ACK].type = YNL_PT_U8;
	arr[IFLA_BRPORT_CONFIG_PENDING].name = "config-pending";
	arr[IFLA_BRPORT_CONFIG_PENDING].type = YNL_PT_U8;
	arr[IFLA_BRPORT_MESSAGE_AGE_TIMER].name = "message-age-timer";
	arr[IFLA_BRPORT_MESSAGE_AGE_TIMER].type = YNL_PT_U64;
	arr[IFLA_BRPORT_FORWARD_DELAY_TIMER].name = "forward-delay-timer";
	arr[IFLA_BRPORT_FORWARD_DELAY_TIMER].type = YNL_PT_U64;
	arr[IFLA_BRPORT_HOLD_TIMER].name = "hold-timer";
	arr[IFLA_BRPORT_HOLD_TIMER].type = YNL_PT_U64;
	arr[IFLA_BRPORT_FLUSH].name = "flush";
	arr[IFLA_BRPORT_FLUSH].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_MULTICAST_ROUTER].name = "multicast-router";
	arr[IFLA_BRPORT_MULTICAST_ROUTER].type = YNL_PT_U8;
	arr[IFLA_BRPORT_PAD].name = "pad";
	arr[IFLA_BRPORT_PAD].type = YNL_PT_IGNORE;
	arr[IFLA_BRPORT_MCAST_FLOOD].name = "mcast-flood";
	arr[IFLA_BRPORT_MCAST_FLOOD].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_MCAST_TO_UCAST].name = "mcast-to-ucast";
	arr[IFLA_BRPORT_MCAST_TO_UCAST].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_VLAN_TUNNEL].name = "vlan-tunnel";
	arr[IFLA_BRPORT_VLAN_TUNNEL].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_BCAST_FLOOD].name = "bcast-flood";
	arr[IFLA_BRPORT_BCAST_FLOOD].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_GROUP_FWD_MASK].name = "group-fwd-mask";
	arr[IFLA_BRPORT_GROUP_FWD_MASK].type = YNL_PT_U16;
	arr[IFLA_BRPORT_NEIGH_SUPPRESS].name = "neigh-suppress";
	arr[IFLA_BRPORT_NEIGH_SUPPRESS].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_ISOLATED].name = "isolated";
	arr[IFLA_BRPORT_ISOLATED].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_BACKUP_PORT].name = "backup-port";
	arr[IFLA_BRPORT_BACKUP_PORT].type = YNL_PT_U32;
	arr[IFLA_BRPORT_MRP_RING_OPEN].name = "mrp-ring-open";
	arr[IFLA_BRPORT_MRP_RING_OPEN].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_MRP_IN_OPEN].name = "mrp-in-open";
	arr[IFLA_BRPORT_MRP_IN_OPEN].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT].name = "mcast-eht-hosts-limit";
	arr[IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT].type = YNL_PT_U32;
	arr[IFLA_BRPORT_MCAST_EHT_HOSTS_CNT].name = "mcast-eht-hosts-cnt";
	arr[IFLA_BRPORT_MCAST_EHT_HOSTS_CNT].type = YNL_PT_U32;
	arr[IFLA_BRPORT_LOCKED].name = "locked";
	arr[IFLA_BRPORT_LOCKED].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_MAB].name = "mab";
	arr[IFLA_BRPORT_MAB].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_MCAST_N_GROUPS].name = "mcast-n-groups";
	arr[IFLA_BRPORT_MCAST_N_GROUPS].type = YNL_PT_U32;
	arr[IFLA_BRPORT_MCAST_MAX_GROUPS].name = "mcast-max-groups";
	arr[IFLA_BRPORT_MCAST_MAX_GROUPS].type = YNL_PT_U32;
	arr[IFLA_BRPORT_NEIGH_VLAN_SUPPRESS].name = "neigh-vlan-suppress";
	arr[IFLA_BRPORT_NEIGH_VLAN_SUPPRESS].type = YNL_PT_FLAG;
	arr[IFLA_BRPORT_BACKUP_NHID].name = "backup-nhid";
	arr[IFLA_BRPORT_BACKUP_NHID].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_brport_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_BRPORT_MAX),
	.table = rt_link_linkinfo_brport_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_BOND_SLAVE_MAX + 1> rt_link_bond_slave_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_BOND_SLAVE_MAX + 1> arr{};
	arr[IFLA_BOND_SLAVE_STATE].name = "state";
	arr[IFLA_BOND_SLAVE_STATE].type = YNL_PT_U8;
	arr[IFLA_BOND_SLAVE_MII_STATUS].name = "mii-status";
	arr[IFLA_BOND_SLAVE_MII_STATUS].type = YNL_PT_U8;
	arr[IFLA_BOND_SLAVE_LINK_FAILURE_COUNT].name = "link-failure-count";
	arr[IFLA_BOND_SLAVE_LINK_FAILURE_COUNT].type = YNL_PT_U32;
	arr[IFLA_BOND_SLAVE_PERM_HWADDR].name = "perm-hwaddr";
	arr[IFLA_BOND_SLAVE_PERM_HWADDR].type = YNL_PT_BINARY;
	arr[IFLA_BOND_SLAVE_QUEUE_ID].name = "queue-id";
	arr[IFLA_BOND_SLAVE_QUEUE_ID].type = YNL_PT_U16;
	arr[IFLA_BOND_SLAVE_AD_AGGREGATOR_ID].name = "ad-aggregator-id";
	arr[IFLA_BOND_SLAVE_AD_AGGREGATOR_ID].type = YNL_PT_U16;
	arr[IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE].name = "ad-actor-oper-port-state";
	arr[IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE].type = YNL_PT_U8;
	arr[IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE].name = "ad-partner-oper-port-state";
	arr[IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE].type = YNL_PT_U16;
	arr[IFLA_BOND_SLAVE_PRIO].name = "prio";
	arr[IFLA_BOND_SLAVE_PRIO].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest rt_link_bond_slave_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_BOND_SLAVE_MAX),
	.table = rt_link_bond_slave_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_VF_STATS_MAX + 1> rt_link_vf_stats_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_VF_STATS_MAX + 1> arr{};
	arr[IFLA_VF_STATS_RX_PACKETS].name = "rx-packets";
	arr[IFLA_VF_STATS_RX_PACKETS].type = YNL_PT_U64;
	arr[IFLA_VF_STATS_TX_PACKETS].name = "tx-packets";
	arr[IFLA_VF_STATS_TX_PACKETS].type = YNL_PT_U64;
	arr[IFLA_VF_STATS_RX_BYTES].name = "rx-bytes";
	arr[IFLA_VF_STATS_RX_BYTES].type = YNL_PT_U64;
	arr[IFLA_VF_STATS_TX_BYTES].name = "tx-bytes";
	arr[IFLA_VF_STATS_TX_BYTES].type = YNL_PT_U64;
	arr[IFLA_VF_STATS_BROADCAST].name = "broadcast";
	arr[IFLA_VF_STATS_BROADCAST].type = YNL_PT_U64;
	arr[IFLA_VF_STATS_MULTICAST].name = "multicast";
	arr[IFLA_VF_STATS_MULTICAST].type = YNL_PT_U64;
	arr[IFLA_VF_STATS_PAD].name = "pad";
	arr[IFLA_VF_STATS_PAD].type = YNL_PT_IGNORE;
	arr[IFLA_VF_STATS_RX_DROPPED].name = "rx-dropped";
	arr[IFLA_VF_STATS_RX_DROPPED].type = YNL_PT_U64;
	arr[IFLA_VF_STATS_TX_DROPPED].name = "tx-dropped";
	arr[IFLA_VF_STATS_TX_DROPPED].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest rt_link_vf_stats_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_VF_STATS_MAX),
	.table = rt_link_vf_stats_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_VF_VLAN_INFO_MAX + 1> rt_link_vf_vlan_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_VF_VLAN_INFO_MAX + 1> arr{};
	arr[IFLA_VF_VLAN_INFO].name = "info";
	arr[IFLA_VF_VLAN_INFO].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest rt_link_vf_vlan_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_VF_VLAN_INFO_MAX),
	.table = rt_link_vf_vlan_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_BOND_AD_INFO_MAX + 1> rt_link_bond_ad_info_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_BOND_AD_INFO_MAX + 1> arr{};
	arr[IFLA_BOND_AD_INFO_AGGREGATOR].name = "aggregator";
	arr[IFLA_BOND_AD_INFO_AGGREGATOR].type = YNL_PT_U16;
	arr[IFLA_BOND_AD_INFO_NUM_PORTS].name = "num-ports";
	arr[IFLA_BOND_AD_INFO_NUM_PORTS].type = YNL_PT_U16;
	arr[IFLA_BOND_AD_INFO_ACTOR_KEY].name = "actor-key";
	arr[IFLA_BOND_AD_INFO_ACTOR_KEY].type = YNL_PT_U16;
	arr[IFLA_BOND_AD_INFO_PARTNER_KEY].name = "partner-key";
	arr[IFLA_BOND_AD_INFO_PARTNER_KEY].type = YNL_PT_U16;
	arr[IFLA_BOND_AD_INFO_PARTNER_MAC].name = "partner-mac";
	arr[IFLA_BOND_AD_INFO_PARTNER_MAC].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest rt_link_bond_ad_info_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_BOND_AD_INFO_MAX),
	.table = rt_link_bond_ad_info_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_VLAN_QOS_MAX + 1> rt_link_ifla_vlan_qos_policy = []() {
	std::array<ynl_policy_attr,IFLA_VLAN_QOS_MAX + 1> arr{};
	arr[IFLA_VLAN_QOS_MAPPING].name = "mapping";
	arr[IFLA_VLAN_QOS_MAPPING].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest rt_link_ifla_vlan_qos_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_VLAN_QOS_MAX),
	.table = rt_link_ifla_vlan_qos_policy.data(),
};

static std::array<ynl_policy_attr,AF_MAX + 1> rt_link_af_spec_attrs_policy = []() {
	std::array<ynl_policy_attr,AF_MAX + 1> arr{};
	arr[AF_INET].name = "inet";
	arr[AF_INET].type = YNL_PT_NEST;
	arr[AF_INET].nest = &rt_link_ifla_attrs_nest;
	arr[AF_INET6].name = "inet6";
	arr[AF_INET6].type = YNL_PT_NEST;
	arr[AF_INET6].nest = &rt_link_ifla6_attrs_nest;
	arr[AF_MCTP].name = "mctp";
	arr[AF_MCTP].type = YNL_PT_NEST;
	arr[AF_MCTP].nest = &rt_link_mctp_attrs_nest;
	return arr;
} ();

struct ynl_policy_nest rt_link_af_spec_attrs_nest = {
	.max_attr = static_cast<unsigned int>(AF_MAX),
	.table = rt_link_af_spec_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_OFFLOAD_XSTATS_MAX + 1> rt_link_link_offload_xstats_policy = []() {
	std::array<ynl_policy_attr,IFLA_OFFLOAD_XSTATS_MAX + 1> arr{};
	arr[IFLA_OFFLOAD_XSTATS_CPU_HIT].name = "cpu-hit";
	arr[IFLA_OFFLOAD_XSTATS_CPU_HIT].type = YNL_PT_BINARY;
	arr[IFLA_OFFLOAD_XSTATS_HW_S_INFO].name = "hw-s-info";
	arr[IFLA_OFFLOAD_XSTATS_HW_S_INFO].type = YNL_PT_NEST;
	arr[IFLA_OFFLOAD_XSTATS_HW_S_INFO].nest = &rt_link_hw_s_info_one_nest;
	arr[IFLA_OFFLOAD_XSTATS_L3_STATS].name = "l3-stats";
	arr[IFLA_OFFLOAD_XSTATS_L3_STATS].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest rt_link_link_offload_xstats_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_OFFLOAD_XSTATS_MAX),
	.table = rt_link_link_offload_xstats_policy.data(),
};

static std::array<ynl_policy_attr,2> rt_link_linkinfo_member_data_msg_policy = []() {
	std::array<ynl_policy_attr,2> arr{};
	arr[0].type = YNL_PT_SUBMSG;
	arr[0].name = "bridge";
	arr[0].nest = &rt_link_linkinfo_brport_attrs_nest;
	arr[1].type = YNL_PT_SUBMSG;
	arr[1].name = "bond";
	arr[1].nest = &rt_link_bond_slave_attrs_nest;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_member_data_msg_nest = {
	.max_attr = 2,
	.table = rt_link_linkinfo_member_data_msg_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_VF_MAX + 1> rt_link_vfinfo_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_VF_MAX + 1> arr{};
	arr[IFLA_VF_MAC].name = "mac";
	arr[IFLA_VF_MAC].type = YNL_PT_BINARY;
	arr[IFLA_VF_VLAN].name = "vlan";
	arr[IFLA_VF_VLAN].type = YNL_PT_BINARY;
	arr[IFLA_VF_TX_RATE].name = "tx-rate";
	arr[IFLA_VF_TX_RATE].type = YNL_PT_BINARY;
	arr[IFLA_VF_SPOOFCHK].name = "spoofchk";
	arr[IFLA_VF_SPOOFCHK].type = YNL_PT_BINARY;
	arr[IFLA_VF_LINK_STATE].name = "link-state";
	arr[IFLA_VF_LINK_STATE].type = YNL_PT_BINARY;
	arr[IFLA_VF_RATE].name = "rate";
	arr[IFLA_VF_RATE].type = YNL_PT_BINARY;
	arr[IFLA_VF_RSS_QUERY_EN].name = "rss-query-en";
	arr[IFLA_VF_RSS_QUERY_EN].type = YNL_PT_BINARY;
	arr[IFLA_VF_STATS].name = "stats";
	arr[IFLA_VF_STATS].type = YNL_PT_NEST;
	arr[IFLA_VF_STATS].nest = &rt_link_vf_stats_attrs_nest;
	arr[IFLA_VF_TRUST].name = "trust";
	arr[IFLA_VF_TRUST].type = YNL_PT_BINARY;
	arr[IFLA_VF_IB_NODE_GUID].name = "ib-node-guid";
	arr[IFLA_VF_IB_NODE_GUID].type = YNL_PT_BINARY;
	arr[IFLA_VF_IB_PORT_GUID].name = "ib-port-guid";
	arr[IFLA_VF_IB_PORT_GUID].type = YNL_PT_BINARY;
	arr[IFLA_VF_VLAN_LIST].name = "vlan-list";
	arr[IFLA_VF_VLAN_LIST].type = YNL_PT_NEST;
	arr[IFLA_VF_VLAN_LIST].nest = &rt_link_vf_vlan_attrs_nest;
	arr[IFLA_VF_BROADCAST].name = "broadcast";
	arr[IFLA_VF_BROADCAST].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest rt_link_vfinfo_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_VF_MAX),
	.table = rt_link_vfinfo_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_BOND_MAX + 1> rt_link_linkinfo_bond_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_BOND_MAX + 1> arr{};
	arr[IFLA_BOND_MODE].name = "mode";
	arr[IFLA_BOND_MODE].type = YNL_PT_U8;
	arr[IFLA_BOND_ACTIVE_SLAVE].name = "active-slave";
	arr[IFLA_BOND_ACTIVE_SLAVE].type = YNL_PT_U32;
	arr[IFLA_BOND_MIIMON].name = "miimon";
	arr[IFLA_BOND_MIIMON].type = YNL_PT_U32;
	arr[IFLA_BOND_UPDELAY].name = "updelay";
	arr[IFLA_BOND_UPDELAY].type = YNL_PT_U32;
	arr[IFLA_BOND_DOWNDELAY].name = "downdelay";
	arr[IFLA_BOND_DOWNDELAY].type = YNL_PT_U32;
	arr[IFLA_BOND_USE_CARRIER].name = "use-carrier";
	arr[IFLA_BOND_USE_CARRIER].type = YNL_PT_U8;
	arr[IFLA_BOND_ARP_INTERVAL].name = "arp-interval";
	arr[IFLA_BOND_ARP_INTERVAL].type = YNL_PT_U32;
	arr[IFLA_BOND_ARP_IP_TARGET].name = "arp-ip-target";
	arr[IFLA_BOND_ARP_IP_TARGET].type = YNL_PT_U32;
	arr[IFLA_BOND_ARP_VALIDATE].name = "arp-validate";
	arr[IFLA_BOND_ARP_VALIDATE].type = YNL_PT_U32;
	arr[IFLA_BOND_ARP_ALL_TARGETS].name = "arp-all-targets";
	arr[IFLA_BOND_ARP_ALL_TARGETS].type = YNL_PT_U32;
	arr[IFLA_BOND_PRIMARY].name = "primary";
	arr[IFLA_BOND_PRIMARY].type = YNL_PT_U32;
	arr[IFLA_BOND_PRIMARY_RESELECT].name = "primary-reselect";
	arr[IFLA_BOND_PRIMARY_RESELECT].type = YNL_PT_U8;
	arr[IFLA_BOND_FAIL_OVER_MAC].name = "fail-over-mac";
	arr[IFLA_BOND_FAIL_OVER_MAC].type = YNL_PT_U8;
	arr[IFLA_BOND_XMIT_HASH_POLICY].name = "xmit-hash-policy";
	arr[IFLA_BOND_XMIT_HASH_POLICY].type = YNL_PT_U8;
	arr[IFLA_BOND_RESEND_IGMP].name = "resend-igmp";
	arr[IFLA_BOND_RESEND_IGMP].type = YNL_PT_U32;
	arr[IFLA_BOND_NUM_PEER_NOTIF].name = "num-peer-notif";
	arr[IFLA_BOND_NUM_PEER_NOTIF].type = YNL_PT_U8;
	arr[IFLA_BOND_ALL_SLAVES_ACTIVE].name = "all-slaves-active";
	arr[IFLA_BOND_ALL_SLAVES_ACTIVE].type = YNL_PT_U8;
	arr[IFLA_BOND_MIN_LINKS].name = "min-links";
	arr[IFLA_BOND_MIN_LINKS].type = YNL_PT_U32;
	arr[IFLA_BOND_LP_INTERVAL].name = "lp-interval";
	arr[IFLA_BOND_LP_INTERVAL].type = YNL_PT_U32;
	arr[IFLA_BOND_PACKETS_PER_SLAVE].name = "packets-per-slave";
	arr[IFLA_BOND_PACKETS_PER_SLAVE].type = YNL_PT_U32;
	arr[IFLA_BOND_AD_LACP_RATE].name = "ad-lacp-rate";
	arr[IFLA_BOND_AD_LACP_RATE].type = YNL_PT_U8;
	arr[IFLA_BOND_AD_SELECT].name = "ad-select";
	arr[IFLA_BOND_AD_SELECT].type = YNL_PT_U8;
	arr[IFLA_BOND_AD_INFO].name = "ad-info";
	arr[IFLA_BOND_AD_INFO].type = YNL_PT_NEST;
	arr[IFLA_BOND_AD_INFO].nest = &rt_link_bond_ad_info_attrs_nest;
	arr[IFLA_BOND_AD_ACTOR_SYS_PRIO].name = "ad-actor-sys-prio";
	arr[IFLA_BOND_AD_ACTOR_SYS_PRIO].type = YNL_PT_U16;
	arr[IFLA_BOND_AD_USER_PORT_KEY].name = "ad-user-port-key";
	arr[IFLA_BOND_AD_USER_PORT_KEY].type = YNL_PT_U16;
	arr[IFLA_BOND_AD_ACTOR_SYSTEM].name = "ad-actor-system";
	arr[IFLA_BOND_AD_ACTOR_SYSTEM].type = YNL_PT_BINARY;
	arr[IFLA_BOND_TLB_DYNAMIC_LB].name = "tlb-dynamic-lb";
	arr[IFLA_BOND_TLB_DYNAMIC_LB].type = YNL_PT_U8;
	arr[IFLA_BOND_PEER_NOTIF_DELAY].name = "peer-notif-delay";
	arr[IFLA_BOND_PEER_NOTIF_DELAY].type = YNL_PT_U32;
	arr[IFLA_BOND_AD_LACP_ACTIVE].name = "ad-lacp-active";
	arr[IFLA_BOND_AD_LACP_ACTIVE].type = YNL_PT_U8;
	arr[IFLA_BOND_MISSED_MAX].name = "missed-max";
	arr[IFLA_BOND_MISSED_MAX].type = YNL_PT_U8;
	arr[IFLA_BOND_NS_IP6_TARGET].name = "ns-ip6-target";
	arr[IFLA_BOND_NS_IP6_TARGET].type = YNL_PT_BINARY;
	arr[IFLA_BOND_NS_IP6_TARGET].len = 16;
	arr[IFLA_BOND_COUPLED_CONTROL].name = "coupled-control";
	arr[IFLA_BOND_COUPLED_CONTROL].type = YNL_PT_U8;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_bond_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_BOND_MAX),
	.table = rt_link_linkinfo_bond_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_VLAN_MAX + 1> rt_link_linkinfo_vlan_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_VLAN_MAX + 1> arr{};
	arr[IFLA_VLAN_ID].name = "id";
	arr[IFLA_VLAN_ID].type = YNL_PT_U16;
	arr[IFLA_VLAN_FLAGS].name = "flags";
	arr[IFLA_VLAN_FLAGS].type = YNL_PT_BINARY;
	arr[IFLA_VLAN_EGRESS_QOS].name = "egress-qos";
	arr[IFLA_VLAN_EGRESS_QOS].type = YNL_PT_NEST;
	arr[IFLA_VLAN_EGRESS_QOS].nest = &rt_link_ifla_vlan_qos_nest;
	arr[IFLA_VLAN_INGRESS_QOS].name = "ingress-qos";
	arr[IFLA_VLAN_INGRESS_QOS].type = YNL_PT_NEST;
	arr[IFLA_VLAN_INGRESS_QOS].nest = &rt_link_ifla_vlan_qos_nest;
	arr[IFLA_VLAN_PROTOCOL].name = "protocol";
	arr[IFLA_VLAN_PROTOCOL].type = YNL_PT_U16;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_vlan_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_VLAN_MAX),
	.table = rt_link_linkinfo_vlan_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_VF_MAX + 1> rt_link_vfinfo_list_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_VF_MAX + 1> arr{};
	arr[IFLA_VF_INFO].name = "info";
	arr[IFLA_VF_INFO].type = YNL_PT_NEST;
	arr[IFLA_VF_INFO].nest = &rt_link_vfinfo_attrs_nest;
	return arr;
} ();

struct ynl_policy_nest rt_link_vfinfo_list_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_VF_MAX),
	.table = rt_link_vfinfo_list_attrs_policy.data(),
};

static std::array<ynl_policy_attr,17> rt_link_linkinfo_data_msg_policy = []() {
	std::array<ynl_policy_attr,17> arr{};
	arr[0].type = YNL_PT_SUBMSG;
	arr[0].name = "bond";
	arr[0].nest = &rt_link_linkinfo_bond_attrs_nest;
	arr[1].type = YNL_PT_SUBMSG;
	arr[1].name = "bridge";
	arr[1].nest = &rt_link_linkinfo_bridge_attrs_nest;
	arr[2].type = YNL_PT_SUBMSG;
	arr[2].name = "erspan";
	arr[2].nest = &rt_link_linkinfo_gre_attrs_nest;
	arr[3].type = YNL_PT_SUBMSG;
	arr[3].name = "gre";
	arr[3].nest = &rt_link_linkinfo_gre_attrs_nest;
	arr[4].type = YNL_PT_SUBMSG;
	arr[4].name = "gretap";
	arr[4].nest = &rt_link_linkinfo_gre_attrs_nest;
	arr[5].type = YNL_PT_SUBMSG;
	arr[5].name = "ip6gre";
	arr[5].nest = &rt_link_linkinfo_gre6_attrs_nest;
	arr[6].type = YNL_PT_SUBMSG;
	arr[6].name = "geneve";
	arr[6].nest = &rt_link_linkinfo_geneve_attrs_nest;
	arr[7].type = YNL_PT_SUBMSG;
	arr[7].name = "ipip";
	arr[7].nest = &rt_link_linkinfo_iptun_attrs_nest;
	arr[8].type = YNL_PT_SUBMSG;
	arr[8].name = "ip6tnl";
	arr[8].nest = &rt_link_linkinfo_ip6tnl_attrs_nest;
	arr[9].type = YNL_PT_SUBMSG;
	arr[9].name = "sit";
	arr[9].nest = &rt_link_linkinfo_iptun_attrs_nest;
	arr[10].type = YNL_PT_SUBMSG;
	arr[10].name = "tun";
	arr[10].nest = &rt_link_linkinfo_tun_attrs_nest;
	arr[11].type = YNL_PT_SUBMSG;
	arr[11].name = "vlan";
	arr[11].nest = &rt_link_linkinfo_vlan_attrs_nest;
	arr[12].type = YNL_PT_SUBMSG;
	arr[12].name = "vrf";
	arr[12].nest = &rt_link_linkinfo_vrf_attrs_nest;
	arr[13].type = YNL_PT_SUBMSG;
	arr[13].name = "vti";
	arr[13].nest = &rt_link_linkinfo_vti_attrs_nest;
	arr[14].type = YNL_PT_SUBMSG;
	arr[14].name = "vti6";
	arr[14].nest = &rt_link_linkinfo_vti6_attrs_nest;
	arr[15].type = YNL_PT_SUBMSG;
	arr[15].name = "netkit";
	arr[15].nest = &rt_link_linkinfo_netkit_attrs_nest;
	arr[16].type = YNL_PT_SUBMSG;
	arr[16].name = "ovpn";
	arr[16].nest = &rt_link_linkinfo_ovpn_attrs_nest;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_data_msg_nest = {
	.max_attr = 17,
	.table = rt_link_linkinfo_data_msg_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_INFO_MAX + 1> rt_link_linkinfo_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_INFO_MAX + 1> arr{};
	arr[IFLA_INFO_KIND].name = "kind";
	arr[IFLA_INFO_KIND].type  = YNL_PT_NUL_STR;
	arr[IFLA_INFO_DATA].name = "data";
	arr[IFLA_INFO_DATA].type = YNL_PT_NEST;
	arr[IFLA_INFO_DATA].nest = &rt_link_linkinfo_data_msg_nest;
	arr[IFLA_INFO_DATA].is_submsg = 1;
	arr[IFLA_INFO_DATA].selector_type = 1;
	arr[IFLA_INFO_XSTATS].name = "xstats";
	arr[IFLA_INFO_XSTATS].type = YNL_PT_BINARY;
	arr[IFLA_INFO_SLAVE_KIND].name = "slave-kind";
	arr[IFLA_INFO_SLAVE_KIND].type  = YNL_PT_NUL_STR;
	arr[IFLA_INFO_SLAVE_DATA].name = "slave-data";
	arr[IFLA_INFO_SLAVE_DATA].type = YNL_PT_NEST;
	arr[IFLA_INFO_SLAVE_DATA].nest = &rt_link_linkinfo_member_data_msg_nest;
	arr[IFLA_INFO_SLAVE_DATA].is_submsg = 1;
	arr[IFLA_INFO_SLAVE_DATA].selector_type = 4;
	return arr;
} ();

struct ynl_policy_nest rt_link_linkinfo_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_INFO_MAX),
	.table = rt_link_linkinfo_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_MAX + 1> rt_link_link_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_MAX + 1> arr{};
	arr[IFLA_ADDRESS].name = "address";
	arr[IFLA_ADDRESS].type = YNL_PT_BINARY;
	arr[IFLA_BROADCAST].name = "broadcast";
	arr[IFLA_BROADCAST].type = YNL_PT_BINARY;
	arr[IFLA_IFNAME].name = "ifname";
	arr[IFLA_IFNAME].type  = YNL_PT_NUL_STR;
	arr[IFLA_MTU].name = "mtu";
	arr[IFLA_MTU].type = YNL_PT_U32;
	arr[IFLA_LINK].name = "link";
	arr[IFLA_LINK].type = YNL_PT_U32;
	arr[IFLA_QDISC].name = "qdisc";
	arr[IFLA_QDISC].type  = YNL_PT_NUL_STR;
	arr[IFLA_STATS].name = "stats";
	arr[IFLA_STATS].type = YNL_PT_BINARY;
	arr[IFLA_COST].name = "cost";
	arr[IFLA_COST].type  = YNL_PT_NUL_STR;
	arr[IFLA_PRIORITY].name = "priority";
	arr[IFLA_PRIORITY].type  = YNL_PT_NUL_STR;
	arr[IFLA_MASTER].name = "master";
	arr[IFLA_MASTER].type = YNL_PT_U32;
	arr[IFLA_WIRELESS].name = "wireless";
	arr[IFLA_WIRELESS].type  = YNL_PT_NUL_STR;
	arr[IFLA_PROTINFO].name = "protinfo";
	arr[IFLA_PROTINFO].type  = YNL_PT_NUL_STR;
	arr[IFLA_TXQLEN].name = "txqlen";
	arr[IFLA_TXQLEN].type = YNL_PT_U32;
	arr[IFLA_MAP].name = "map";
	arr[IFLA_MAP].type = YNL_PT_BINARY;
	arr[IFLA_WEIGHT].name = "weight";
	arr[IFLA_WEIGHT].type = YNL_PT_U32;
	arr[IFLA_OPERSTATE].name = "operstate";
	arr[IFLA_OPERSTATE].type = YNL_PT_U8;
	arr[IFLA_LINKMODE].name = "linkmode";
	arr[IFLA_LINKMODE].type = YNL_PT_U8;
	arr[IFLA_LINKINFO].name = "linkinfo";
	arr[IFLA_LINKINFO].type = YNL_PT_NEST;
	arr[IFLA_LINKINFO].nest = &rt_link_linkinfo_attrs_nest;
	arr[IFLA_NET_NS_PID].name = "net-ns-pid";
	arr[IFLA_NET_NS_PID].type = YNL_PT_U32;
	arr[IFLA_IFALIAS].name = "ifalias";
	arr[IFLA_IFALIAS].type  = YNL_PT_NUL_STR;
	arr[IFLA_NUM_VF].name = "num-vf";
	arr[IFLA_NUM_VF].type = YNL_PT_U32;
	arr[IFLA_VFINFO_LIST].name = "vfinfo-list";
	arr[IFLA_VFINFO_LIST].type = YNL_PT_NEST;
	arr[IFLA_VFINFO_LIST].nest = &rt_link_vfinfo_list_attrs_nest;
	arr[IFLA_STATS64].name = "stats64";
	arr[IFLA_STATS64].type = YNL_PT_BINARY;
	arr[IFLA_VF_PORTS].name = "vf-ports";
	arr[IFLA_VF_PORTS].type = YNL_PT_NEST;
	arr[IFLA_VF_PORTS].nest = &rt_link_vf_ports_attrs_nest;
	arr[IFLA_PORT_SELF].name = "port-self";
	arr[IFLA_PORT_SELF].type = YNL_PT_NEST;
	arr[IFLA_PORT_SELF].nest = &rt_link_port_self_attrs_nest;
	arr[IFLA_AF_SPEC].name = "af-spec";
	arr[IFLA_AF_SPEC].type = YNL_PT_NEST;
	arr[IFLA_AF_SPEC].nest = &rt_link_af_spec_attrs_nest;
	arr[IFLA_GROUP].name = "group";
	arr[IFLA_GROUP].type = YNL_PT_U32;
	arr[IFLA_NET_NS_FD].name = "net-ns-fd";
	arr[IFLA_NET_NS_FD].type = YNL_PT_U32;
	arr[IFLA_EXT_MASK].name = "ext-mask";
	arr[IFLA_EXT_MASK].type = YNL_PT_U32;
	arr[IFLA_PROMISCUITY].name = "promiscuity";
	arr[IFLA_PROMISCUITY].type = YNL_PT_U32;
	arr[IFLA_NUM_TX_QUEUES].name = "num-tx-queues";
	arr[IFLA_NUM_TX_QUEUES].type = YNL_PT_U32;
	arr[IFLA_NUM_RX_QUEUES].name = "num-rx-queues";
	arr[IFLA_NUM_RX_QUEUES].type = YNL_PT_U32;
	arr[IFLA_CARRIER].name = "carrier";
	arr[IFLA_CARRIER].type = YNL_PT_U8;
	arr[IFLA_PHYS_PORT_ID].name = "phys-port-id";
	arr[IFLA_PHYS_PORT_ID].type = YNL_PT_BINARY;
	arr[IFLA_CARRIER_CHANGES].name = "carrier-changes";
	arr[IFLA_CARRIER_CHANGES].type = YNL_PT_U32;
	arr[IFLA_PHYS_SWITCH_ID].name = "phys-switch-id";
	arr[IFLA_PHYS_SWITCH_ID].type = YNL_PT_BINARY;
	arr[IFLA_LINK_NETNSID].name = "link-netnsid";
	arr[IFLA_LINK_NETNSID].type = YNL_PT_U32;
	arr[IFLA_PHYS_PORT_NAME].name = "phys-port-name";
	arr[IFLA_PHYS_PORT_NAME].type  = YNL_PT_NUL_STR;
	arr[IFLA_PROTO_DOWN].name = "proto-down";
	arr[IFLA_PROTO_DOWN].type = YNL_PT_U8;
	arr[IFLA_GSO_MAX_SEGS].name = "gso-max-segs";
	arr[IFLA_GSO_MAX_SEGS].type = YNL_PT_U32;
	arr[IFLA_GSO_MAX_SIZE].name = "gso-max-size";
	arr[IFLA_GSO_MAX_SIZE].type = YNL_PT_U32;
	arr[IFLA_PAD].name = "pad";
	arr[IFLA_PAD].type = YNL_PT_IGNORE;
	arr[IFLA_XDP].name = "xdp";
	arr[IFLA_XDP].type = YNL_PT_NEST;
	arr[IFLA_XDP].nest = &rt_link_xdp_attrs_nest;
	arr[IFLA_EVENT].name = "event";
	arr[IFLA_EVENT].type = YNL_PT_U32;
	arr[IFLA_NEW_NETNSID].name = "new-netnsid";
	arr[IFLA_NEW_NETNSID].type = YNL_PT_U32;
	arr[IFLA_TARGET_NETNSID].name = "target-netnsid";
	arr[IFLA_TARGET_NETNSID].type = YNL_PT_U32;
	arr[IFLA_CARRIER_UP_COUNT].name = "carrier-up-count";
	arr[IFLA_CARRIER_UP_COUNT].type = YNL_PT_U32;
	arr[IFLA_CARRIER_DOWN_COUNT].name = "carrier-down-count";
	arr[IFLA_CARRIER_DOWN_COUNT].type = YNL_PT_U32;
	arr[IFLA_NEW_IFINDEX].name = "new-ifindex";
	arr[IFLA_NEW_IFINDEX].type = YNL_PT_U32;
	arr[IFLA_MIN_MTU].name = "min-mtu";
	arr[IFLA_MIN_MTU].type = YNL_PT_U32;
	arr[IFLA_MAX_MTU].name = "max-mtu";
	arr[IFLA_MAX_MTU].type = YNL_PT_U32;
	arr[IFLA_PROP_LIST].name = "prop-list";
	arr[IFLA_PROP_LIST].type = YNL_PT_NEST;
	arr[IFLA_PROP_LIST].nest = &rt_link_prop_list_link_attrs_nest;
	arr[IFLA_ALT_IFNAME].name = "alt-ifname";
	arr[IFLA_ALT_IFNAME].type  = YNL_PT_NUL_STR;
	arr[IFLA_PERM_ADDRESS].name = "perm-address";
	arr[IFLA_PERM_ADDRESS].type = YNL_PT_BINARY;
	arr[IFLA_PROTO_DOWN_REASON].name = "proto-down-reason";
	arr[IFLA_PROTO_DOWN_REASON].type  = YNL_PT_NUL_STR;
	arr[IFLA_PARENT_DEV_NAME].name = "parent-dev-name";
	arr[IFLA_PARENT_DEV_NAME].type  = YNL_PT_NUL_STR;
	arr[IFLA_PARENT_DEV_BUS_NAME].name = "parent-dev-bus-name";
	arr[IFLA_PARENT_DEV_BUS_NAME].type  = YNL_PT_NUL_STR;
	arr[IFLA_GRO_MAX_SIZE].name = "gro-max-size";
	arr[IFLA_GRO_MAX_SIZE].type = YNL_PT_U32;
	arr[IFLA_TSO_MAX_SIZE].name = "tso-max-size";
	arr[IFLA_TSO_MAX_SIZE].type = YNL_PT_U32;
	arr[IFLA_TSO_MAX_SEGS].name = "tso-max-segs";
	arr[IFLA_TSO_MAX_SEGS].type = YNL_PT_U32;
	arr[IFLA_ALLMULTI].name = "allmulti";
	arr[IFLA_ALLMULTI].type = YNL_PT_U32;
	arr[IFLA_DEVLINK_PORT].name = "devlink-port";
	arr[IFLA_DEVLINK_PORT].type = YNL_PT_BINARY;
	arr[IFLA_GSO_IPV4_MAX_SIZE].name = "gso-ipv4-max-size";
	arr[IFLA_GSO_IPV4_MAX_SIZE].type = YNL_PT_U32;
	arr[IFLA_GRO_IPV4_MAX_SIZE].name = "gro-ipv4-max-size";
	arr[IFLA_GRO_IPV4_MAX_SIZE].type = YNL_PT_U32;
	arr[IFLA_DPLL_PIN].name = "dpll-pin";
	arr[IFLA_DPLL_PIN].type = YNL_PT_NEST;
	arr[IFLA_DPLL_PIN].nest = &rt_link_link_dpll_pin_attrs_nest;
	arr[IFLA_MAX_PACING_OFFLOAD_HORIZON].name = "max-pacing-offload-horizon";
	arr[IFLA_MAX_PACING_OFFLOAD_HORIZON].type = YNL_PT_UINT;
	arr[IFLA_NETNS_IMMUTABLE].name = "netns-immutable";
	arr[IFLA_NETNS_IMMUTABLE].type = YNL_PT_U8;
	arr[IFLA_HEADROOM].name = "headroom";
	arr[IFLA_HEADROOM].type = YNL_PT_U16;
	arr[IFLA_TAILROOM].name = "tailroom";
	arr[IFLA_TAILROOM].type = YNL_PT_U16;
	return arr;
} ();

struct ynl_policy_nest rt_link_link_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_MAX),
	.table = rt_link_link_attrs_policy.data(),
};

static std::array<ynl_policy_attr,IFLA_STATS_MAX + 1> rt_link_stats_attrs_policy = []() {
	std::array<ynl_policy_attr,IFLA_STATS_MAX + 1> arr{};
	arr[IFLA_STATS_LINK_64].name = "link-64";
	arr[IFLA_STATS_LINK_64].type = YNL_PT_BINARY;
	arr[IFLA_STATS_LINK_XSTATS].name = "link-xstats";
	arr[IFLA_STATS_LINK_XSTATS].type = YNL_PT_BINARY;
	arr[IFLA_STATS_LINK_XSTATS_SLAVE].name = "link-xstats-slave";
	arr[IFLA_STATS_LINK_XSTATS_SLAVE].type = YNL_PT_BINARY;
	arr[IFLA_STATS_LINK_OFFLOAD_XSTATS].name = "link-offload-xstats";
	arr[IFLA_STATS_LINK_OFFLOAD_XSTATS].type = YNL_PT_NEST;
	arr[IFLA_STATS_LINK_OFFLOAD_XSTATS].nest = &rt_link_link_offload_xstats_nest;
	arr[IFLA_STATS_AF_SPEC].name = "af-spec";
	arr[IFLA_STATS_AF_SPEC].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest rt_link_stats_attrs_nest = {
	.max_attr = static_cast<unsigned int>(IFLA_STATS_MAX),
	.table = rt_link_stats_attrs_policy.data(),
};

/* Common nested types */
int rt_link_vf_ports_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       const rt_link_vf_ports_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vf_ports_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	rt_link_vf_ports_attrs *dst = (rt_link_vf_ports_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);
	}

	return 0;
}

int rt_link_port_self_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				const rt_link_port_self_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_port_self_attrs_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	rt_link_port_self_attrs *dst = (rt_link_port_self_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);
	}

	return 0;
}

int rt_link_xdp_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  const rt_link_xdp_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.fd.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_XDP_FD, obj.fd.value());
	}
	if (obj.attached.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_XDP_ATTACHED, obj.attached.value());
	}
	if (obj.flags.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_XDP_FLAGS, obj.flags.value());
	}
	if (obj.prog_id.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_XDP_PROG_ID, obj.prog_id.value());
	}
	if (obj.drv_prog_id.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_XDP_DRV_PROG_ID, obj.drv_prog_id.value());
	}
	if (obj.skb_prog_id.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_XDP_SKB_PROG_ID, obj.skb_prog_id.value());
	}
	if (obj.hw_prog_id.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_XDP_HW_PROG_ID, obj.hw_prog_id.value());
	}
	if (obj.expected_fd.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_XDP_EXPECTED_FD, obj.expected_fd.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_xdp_attrs_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	rt_link_xdp_attrs *dst = (rt_link_xdp_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_XDP_FD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fd = (__s32)ynl_attr_get_s32(attr);
		} else if (type == IFLA_XDP_ATTACHED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->attached = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_XDP_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_PROG_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->prog_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_DRV_PROG_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->drv_prog_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_SKB_PROG_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->skb_prog_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_HW_PROG_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->hw_prog_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP_EXPECTED_FD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->expected_fd = (__s32)ynl_attr_get_s32(attr);
		}
	}

	return 0;
}

int rt_link_prop_list_link_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     const rt_link_prop_list_link_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.alt_ifname.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_ALT_IFNAME, obj.alt_ifname.data());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_prop_list_link_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	rt_link_prop_list_link_attrs *dst = (rt_link_prop_list_link_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_ALT_IFNAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->alt_ifname.assign(ynl_attr_get_str(attr));
		}
	}

	return 0;
}

int rt_link_ifla_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   const rt_link_ifla_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.conf.size() > 0) {
		ynl_attr_put(nlh, IFLA_INET_CONF, obj.conf.data(), obj.conf.size());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_ifla_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	rt_link_ifla_attrs *dst = (rt_link_ifla_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_INET_CONF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->conf.assign(data, data + len);
		}
	}

	return 0;
}

int rt_link_ifla6_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    const rt_link_ifla6_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.flags.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_INET6_FLAGS, obj.flags.value());
	}
	if (obj.conf.size() > 0) {
		ynl_attr_put(nlh, IFLA_INET6_CONF, obj.conf.data(), obj.conf.size());
	}
	if (obj.stats.size() > 0) {
		ynl_attr_put(nlh, IFLA_INET6_STATS, obj.stats.data(), obj.stats.size());
	}
	if (obj.mcast.size() > 0) {
		ynl_attr_put(nlh, IFLA_INET6_MCAST, obj.mcast.data(), obj.mcast.size());
	}
	if (obj.cacheinfo) {
		ynl_attr_put(nlh, IFLA_INET6_CACHEINFO, &*obj.cacheinfo, sizeof(struct ifla_cacheinfo));
	}
	if (obj.icmp6stats.size() > 0) {
		ynl_attr_put(nlh, IFLA_INET6_ICMP6STATS, obj.icmp6stats.data(), obj.icmp6stats.size());
	}
	if (obj.token.size() > 0) {
		ynl_attr_put(nlh, IFLA_INET6_TOKEN, obj.token.data(), obj.token.size());
	}
	if (obj.addr_gen_mode.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_INET6_ADDR_GEN_MODE, obj.addr_gen_mode.value());
	}
	if (obj.ra_mtu.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_INET6_RA_MTU, obj.ra_mtu.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_ifla6_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	rt_link_ifla6_attrs *dst = (rt_link_ifla6_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_INET6_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_INET6_CONF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->conf.assign(data, data + len);
		} else if (type == IFLA_INET6_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->stats.assign(data, data + len);
		} else if (type == IFLA_INET6_MCAST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->mcast.assign(data, data + len);
		} else if (type == IFLA_INET6_CACHEINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_cacheinfo);
			dst->cacheinfo.emplace();
			memcpy(&*dst->cacheinfo, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_INET6_ICMP6STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->icmp6stats.assign(data, data + len);
		} else if (type == IFLA_INET6_TOKEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->token.assign(data, data + len);
		} else if (type == IFLA_INET6_ADDR_GEN_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->addr_gen_mode = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_INET6_RA_MTU) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ra_mtu = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_mctp_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   const rt_link_mctp_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.net.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_MCTP_NET, obj.net.value());
	}
	if (obj.phys_binding.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_MCTP_PHYS_BINDING, obj.phys_binding.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_mctp_attrs_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	rt_link_mctp_attrs *dst = (rt_link_mctp_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_MCTP_NET) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->net = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_MCTP_PHYS_BINDING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->phys_binding = (__u8)ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

int rt_link_hw_s_info_one_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested, __u32 idx)
{
	rt_link_hw_s_info_one *dst = (rt_link_hw_s_info_one *)yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->request = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->used = (__u8)ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_bridge_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      const rt_link_linkinfo_bridge_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.forward_delay.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_FORWARD_DELAY, obj.forward_delay.value());
	}
	if (obj.hello_time.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_HELLO_TIME, obj.hello_time.value());
	}
	if (obj.max_age.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_MAX_AGE, obj.max_age.value());
	}
	if (obj.ageing_time.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_AGEING_TIME, obj.ageing_time.value());
	}
	if (obj.stp_state.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_STP_STATE, obj.stp_state.value());
	}
	if (obj.priority.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BR_PRIORITY, obj.priority.value());
	}
	if (obj.vlan_filtering.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_VLAN_FILTERING, obj.vlan_filtering.value());
	}
	if (obj.vlan_protocol.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BR_VLAN_PROTOCOL, obj.vlan_protocol.value());
	}
	if (obj.group_fwd_mask.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BR_GROUP_FWD_MASK, obj.group_fwd_mask.value());
	}
	if (obj.root_id) {
		ynl_attr_put(nlh, IFLA_BR_ROOT_ID, &*obj.root_id, sizeof(struct ifla_bridge_id));
	}
	if (obj.bridge_id) {
		ynl_attr_put(nlh, IFLA_BR_BRIDGE_ID, &*obj.bridge_id, sizeof(struct ifla_bridge_id));
	}
	if (obj.root_port.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BR_ROOT_PORT, obj.root_port.value());
	}
	if (obj.root_path_cost.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_ROOT_PATH_COST, obj.root_path_cost.value());
	}
	if (obj.topology_change.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_TOPOLOGY_CHANGE, obj.topology_change.value());
	}
	if (obj.topology_change_detected.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_TOPOLOGY_CHANGE_DETECTED, obj.topology_change_detected.value());
	}
	if (obj.hello_timer.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_HELLO_TIMER, obj.hello_timer.value());
	}
	if (obj.tcn_timer.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_TCN_TIMER, obj.tcn_timer.value());
	}
	if (obj.topology_change_timer.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_TOPOLOGY_CHANGE_TIMER, obj.topology_change_timer.value());
	}
	if (obj.gc_timer.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_GC_TIMER, obj.gc_timer.value());
	}
	if (obj.group_addr.size() > 0) {
		ynl_attr_put(nlh, IFLA_BR_GROUP_ADDR, obj.group_addr.data(), obj.group_addr.size());
	}
	if (obj.fdb_flush.size() > 0) {
		ynl_attr_put(nlh, IFLA_BR_FDB_FLUSH, obj.fdb_flush.data(), obj.fdb_flush.size());
	}
	if (obj.mcast_router.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_ROUTER, obj.mcast_router.value());
	}
	if (obj.mcast_snooping.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_SNOOPING, obj.mcast_snooping.value());
	}
	if (obj.mcast_query_use_ifaddr.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_QUERY_USE_IFADDR, obj.mcast_query_use_ifaddr.value());
	}
	if (obj.mcast_querier.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_QUERIER, obj.mcast_querier.value());
	}
	if (obj.mcast_hash_elasticity.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_MCAST_HASH_ELASTICITY, obj.mcast_hash_elasticity.value());
	}
	if (obj.mcast_hash_max.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_MCAST_HASH_MAX, obj.mcast_hash_max.value());
	}
	if (obj.mcast_last_member_cnt.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_MCAST_LAST_MEMBER_CNT, obj.mcast_last_member_cnt.value());
	}
	if (obj.mcast_startup_query_cnt.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_MCAST_STARTUP_QUERY_CNT, obj.mcast_startup_query_cnt.value());
	}
	if (obj.mcast_last_member_intvl.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_LAST_MEMBER_INTVL, obj.mcast_last_member_intvl.value());
	}
	if (obj.mcast_membership_intvl.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_MEMBERSHIP_INTVL, obj.mcast_membership_intvl.value());
	}
	if (obj.mcast_querier_intvl.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_QUERIER_INTVL, obj.mcast_querier_intvl.value());
	}
	if (obj.mcast_query_intvl.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_QUERY_INTVL, obj.mcast_query_intvl.value());
	}
	if (obj.mcast_query_response_intvl.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_QUERY_RESPONSE_INTVL, obj.mcast_query_response_intvl.value());
	}
	if (obj.mcast_startup_query_intvl.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BR_MCAST_STARTUP_QUERY_INTVL, obj.mcast_startup_query_intvl.value());
	}
	if (obj.nf_call_iptables.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_NF_CALL_IPTABLES, obj.nf_call_iptables.value());
	}
	if (obj.nf_call_ip6tables.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_NF_CALL_IP6TABLES, obj.nf_call_ip6tables.value());
	}
	if (obj.nf_call_arptables.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_NF_CALL_ARPTABLES, obj.nf_call_arptables.value());
	}
	if (obj.vlan_default_pvid.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BR_VLAN_DEFAULT_PVID, obj.vlan_default_pvid.value());
	}
	if (obj.vlan_stats_enabled.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_VLAN_STATS_ENABLED, obj.vlan_stats_enabled.value());
	}
	if (obj.mcast_stats_enabled.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_STATS_ENABLED, obj.mcast_stats_enabled.value());
	}
	if (obj.mcast_igmp_version.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_IGMP_VERSION, obj.mcast_igmp_version.value());
	}
	if (obj.mcast_mld_version.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_MCAST_MLD_VERSION, obj.mcast_mld_version.value());
	}
	if (obj.vlan_stats_per_port.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BR_VLAN_STATS_PER_PORT, obj.vlan_stats_per_port.value());
	}
	if (obj.multi_boolopt) {
		ynl_attr_put(nlh, IFLA_BR_MULTI_BOOLOPT, &*obj.multi_boolopt, sizeof(struct br_boolopt_multi));
	}
	if (obj.mcast_querier_state.size() > 0) {
		ynl_attr_put(nlh, IFLA_BR_MCAST_QUERIER_STATE, obj.mcast_querier_state.data(), obj.mcast_querier_state.size());
	}
	if (obj.fdb_n_learned.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_FDB_N_LEARNED, obj.fdb_n_learned.value());
	}
	if (obj.fdb_max_learned.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BR_FDB_MAX_LEARNED, obj.fdb_max_learned.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_bridge_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	rt_link_linkinfo_bridge_attrs *dst = (rt_link_linkinfo_bridge_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BR_FORWARD_DELAY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->forward_delay = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_HELLO_TIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->hello_time = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MAX_AGE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->max_age = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_AGEING_TIME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ageing_time = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_STP_STATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->stp_state = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_PRIORITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->priority = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_VLAN_FILTERING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vlan_filtering = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_VLAN_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vlan_protocol = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_GROUP_FWD_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->group_fwd_mask = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_ROOT_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_bridge_id);
			dst->root_id.emplace();
			memcpy(&*dst->root_id, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_BR_BRIDGE_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_bridge_id);
			dst->bridge_id.emplace();
			memcpy(&*dst->bridge_id, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_BR_ROOT_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->root_port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_ROOT_PATH_COST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->root_path_cost = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_TOPOLOGY_CHANGE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->topology_change = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_TOPOLOGY_CHANGE_DETECTED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->topology_change_detected = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_HELLO_TIMER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->hello_timer = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_TCN_TIMER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tcn_timer = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_TOPOLOGY_CHANGE_TIMER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->topology_change_timer = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_GC_TIMER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gc_timer = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_GROUP_ADDR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->group_addr.assign(data, data + len);
		} else if (type == IFLA_BR_FDB_FLUSH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->fdb_flush.assign(data, data + len);
		} else if (type == IFLA_BR_MCAST_ROUTER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_router = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_SNOOPING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_snooping = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_QUERY_USE_IFADDR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_query_use_ifaddr = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_QUERIER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_querier = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_HASH_ELASTICITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_hash_elasticity = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MCAST_HASH_MAX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_hash_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MCAST_LAST_MEMBER_CNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_last_member_cnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MCAST_STARTUP_QUERY_CNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_startup_query_cnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_MCAST_LAST_MEMBER_INTVL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_last_member_intvl = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_MEMBERSHIP_INTVL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_membership_intvl = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_QUERIER_INTVL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_querier_intvl = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_QUERY_INTVL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_query_intvl = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_QUERY_RESPONSE_INTVL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_query_response_intvl = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_MCAST_STARTUP_QUERY_INTVL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_startup_query_intvl = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BR_NF_CALL_IPTABLES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->nf_call_iptables = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_NF_CALL_IP6TABLES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->nf_call_ip6tables = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_NF_CALL_ARPTABLES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->nf_call_arptables = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_VLAN_DEFAULT_PVID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vlan_default_pvid = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BR_VLAN_STATS_ENABLED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vlan_stats_enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_STATS_ENABLED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_stats_enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_IGMP_VERSION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_igmp_version = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MCAST_MLD_VERSION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_mld_version = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_VLAN_STATS_PER_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vlan_stats_per_port = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BR_MULTI_BOOLOPT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct br_boolopt_multi);
			dst->multi_boolopt.emplace();
			memcpy(&*dst->multi_boolopt, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_BR_MCAST_QUERIER_STATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->mcast_querier_state.assign(data, data + len);
		} else if (type == IFLA_BR_FDB_N_LEARNED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fdb_n_learned = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BR_FDB_MAX_LEARNED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fdb_max_learned = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_gre_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   const rt_link_linkinfo_gre_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.link.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_LINK, obj.link.value());
	}
	if (obj.iflags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_IFLAGS, obj.iflags.value());
	}
	if (obj.oflags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_OFLAGS, obj.oflags.value());
	}
	if (obj.ikey.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_IKEY, obj.ikey.value());
	}
	if (obj.okey.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_OKEY, obj.okey.value());
	}
	if (obj.local.size() > 0) {
		ynl_attr_put(nlh, IFLA_GRE_LOCAL, obj.local.data(), obj.local.size());
	}
	if (obj.remote.size() > 0) {
		ynl_attr_put(nlh, IFLA_GRE_REMOTE, obj.remote.data(), obj.remote.size());
	}
	if (obj.ttl.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_TTL, obj.ttl.value());
	}
	if (obj.tos.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_TOS, obj.tos.value());
	}
	if (obj.pmtudisc.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_PMTUDISC, obj.pmtudisc.value());
	}
	if (obj.encap_limit.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_ENCAP_LIMIT, obj.encap_limit.value());
	}
	if (obj.flowinfo.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_FLOWINFO, obj.flowinfo.value());
	}
	if (obj.flags.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_FLAGS, obj.flags.value());
	}
	if (obj.encap_type.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_TYPE, obj.encap_type.value());
	}
	if (obj.encap_flags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_FLAGS, obj.encap_flags.value());
	}
	if (obj.encap_sport.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_SPORT, obj.encap_sport.value());
	}
	if (obj.encap_dport.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_DPORT, obj.encap_dport.value());
	}
	if (obj.collect_metadata) {
		ynl_attr_put(nlh, IFLA_GRE_COLLECT_METADATA, NULL, 0);
	}
	if (obj.ignore_df.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_IGNORE_DF, obj.ignore_df.value());
	}
	if (obj.fwmark.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_FWMARK, obj.fwmark.value());
	}
	if (obj.erspan_index.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_ERSPAN_INDEX, obj.erspan_index.value());
	}
	if (obj.erspan_ver.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_ERSPAN_VER, obj.erspan_ver.value());
	}
	if (obj.erspan_dir.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_ERSPAN_DIR, obj.erspan_dir.value());
	}
	if (obj.erspan_hwid.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ERSPAN_HWID, obj.erspan_hwid.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_gre_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	rt_link_linkinfo_gre_attrs *dst = (rt_link_linkinfo_gre_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_GRE_LINK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_IFLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->iflags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_OFLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->oflags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_IKEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ikey = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_OKEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->okey = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_LOCAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->local.assign(data, data + len);
		} else if (type == IFLA_GRE_REMOTE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->remote.assign(data, data + len);
		} else if (type == IFLA_GRE_TTL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ttl = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_TOS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tos = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_PMTUDISC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->pmtudisc = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ENCAP_LIMIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_limit = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_FLOWINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flowinfo = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_type = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_flags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_SPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_sport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_DPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_dport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_GRE_IGNORE_DF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ignore_df = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_FWMARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fwmark = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ERSPAN_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->erspan_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ERSPAN_VER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->erspan_ver = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ERSPAN_DIR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->erspan_dir = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ERSPAN_HWID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->erspan_hwid = (__u16)ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_gre6_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    const rt_link_linkinfo_gre6_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.link.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_LINK, obj.link.value());
	}
	if (obj.iflags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_IFLAGS, obj.iflags.value());
	}
	if (obj.oflags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_OFLAGS, obj.oflags.value());
	}
	if (obj.ikey.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_IKEY, obj.ikey.value());
	}
	if (obj.okey.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_OKEY, obj.okey.value());
	}
	if (obj.local.size() > 0) {
		ynl_attr_put(nlh, IFLA_GRE_LOCAL, obj.local.data(), obj.local.size());
	}
	if (obj.remote.size() > 0) {
		ynl_attr_put(nlh, IFLA_GRE_REMOTE, obj.remote.data(), obj.remote.size());
	}
	if (obj.ttl.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_TTL, obj.ttl.value());
	}
	if (obj.encap_limit.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_ENCAP_LIMIT, obj.encap_limit.value());
	}
	if (obj.flowinfo.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_FLOWINFO, obj.flowinfo.value());
	}
	if (obj.flags.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_FLAGS, obj.flags.value());
	}
	if (obj.encap_type.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_TYPE, obj.encap_type.value());
	}
	if (obj.encap_flags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_FLAGS, obj.encap_flags.value());
	}
	if (obj.encap_sport.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_SPORT, obj.encap_sport.value());
	}
	if (obj.encap_dport.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ENCAP_DPORT, obj.encap_dport.value());
	}
	if (obj.collect_metadata) {
		ynl_attr_put(nlh, IFLA_GRE_COLLECT_METADATA, NULL, 0);
	}
	if (obj.fwmark.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_FWMARK, obj.fwmark.value());
	}
	if (obj.erspan_index.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRE_ERSPAN_INDEX, obj.erspan_index.value());
	}
	if (obj.erspan_ver.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_ERSPAN_VER, obj.erspan_ver.value());
	}
	if (obj.erspan_dir.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GRE_ERSPAN_DIR, obj.erspan_dir.value());
	}
	if (obj.erspan_hwid.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GRE_ERSPAN_HWID, obj.erspan_hwid.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_gre6_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	rt_link_linkinfo_gre6_attrs *dst = (rt_link_linkinfo_gre6_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_GRE_LINK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_IFLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->iflags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_OFLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->oflags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_IKEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ikey = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_OKEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->okey = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_LOCAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->local.assign(data, data + len);
		} else if (type == IFLA_GRE_REMOTE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->remote.assign(data, data + len);
		} else if (type == IFLA_GRE_TTL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ttl = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ENCAP_LIMIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_limit = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_FLOWINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flowinfo = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_type = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_flags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_SPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_sport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_ENCAP_DPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_dport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GRE_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_GRE_FWMARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fwmark = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ERSPAN_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->erspan_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRE_ERSPAN_VER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->erspan_ver = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ERSPAN_DIR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->erspan_dir = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GRE_ERSPAN_HWID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->erspan_hwid = (__u16)ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_geneve_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      const rt_link_linkinfo_geneve_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.id.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GENEVE_ID, obj.id.value());
	}
	if (obj.remote.size() > 0) {
		ynl_attr_put(nlh, IFLA_GENEVE_REMOTE, obj.remote.data(), obj.remote.size());
	}
	if (obj.ttl.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GENEVE_TTL, obj.ttl.value());
	}
	if (obj.tos.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GENEVE_TOS, obj.tos.value());
	}
	if (obj.port.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_GENEVE_PORT, obj.port.value());
	}
	if (obj.collect_metadata) {
		ynl_attr_put(nlh, IFLA_GENEVE_COLLECT_METADATA, NULL, 0);
	}
	if (obj.remote6.size() > 0) {
		ynl_attr_put(nlh, IFLA_GENEVE_REMOTE6, obj.remote6.data(), obj.remote6.size());
	}
	if (obj.udp_csum.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GENEVE_UDP_CSUM, obj.udp_csum.value());
	}
	if (obj.udp_zero_csum6_tx.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GENEVE_UDP_ZERO_CSUM6_TX, obj.udp_zero_csum6_tx.value());
	}
	if (obj.udp_zero_csum6_rx.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GENEVE_UDP_ZERO_CSUM6_RX, obj.udp_zero_csum6_rx.value());
	}
	if (obj.label.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GENEVE_LABEL, obj.label.value());
	}
	if (obj.ttl_inherit.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GENEVE_TTL_INHERIT, obj.ttl_inherit.value());
	}
	if (obj.df.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_GENEVE_DF, obj.df.value());
	}
	if (obj.inner_proto_inherit) {
		ynl_attr_put(nlh, IFLA_GENEVE_INNER_PROTO_INHERIT, NULL, 0);
	}
	if (obj.port_range) {
		ynl_attr_put(nlh, IFLA_GENEVE_PORT_RANGE, &*obj.port_range, sizeof(struct ifla_geneve_port_range));
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_geneve_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	rt_link_linkinfo_geneve_attrs *dst = (rt_link_linkinfo_geneve_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_GENEVE_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GENEVE_REMOTE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->remote.assign(data, data + len);
		} else if (type == IFLA_GENEVE_TTL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ttl = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_TOS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tos = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_GENEVE_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_GENEVE_REMOTE6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->remote6.assign(data, data + len);
		} else if (type == IFLA_GENEVE_UDP_CSUM) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->udp_csum = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_UDP_ZERO_CSUM6_TX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->udp_zero_csum6_tx = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_UDP_ZERO_CSUM6_RX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->udp_zero_csum6_rx = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_LABEL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->label = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GENEVE_TTL_INHERIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ttl_inherit = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_DF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->df = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GENEVE_INNER_PROTO_INHERIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_GENEVE_PORT_RANGE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_geneve_port_range);
			dst->port_range.emplace();
			memcpy(&*dst->port_range, ynl_attr_data(attr), std::min(struct_sz, len));
		}
	}

	return 0;
}

int rt_link_linkinfo_iptun_attrs_put(struct nlmsghdr *nlh,
				     unsigned int attr_type,
				     const rt_link_linkinfo_iptun_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.link.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_IPTUN_LINK, obj.link.value());
	}
	if (obj.local.size() > 0) {
		ynl_attr_put(nlh, IFLA_IPTUN_LOCAL, obj.local.data(), obj.local.size());
	}
	if (obj.remote.size() > 0) {
		ynl_attr_put(nlh, IFLA_IPTUN_REMOTE, obj.remote.data(), obj.remote.size());
	}
	if (obj.ttl.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_IPTUN_TTL, obj.ttl.value());
	}
	if (obj.tos.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_IPTUN_TOS, obj.tos.value());
	}
	if (obj.encap_limit.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_IPTUN_ENCAP_LIMIT, obj.encap_limit.value());
	}
	if (obj.flowinfo.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_IPTUN_FLOWINFO, obj.flowinfo.value());
	}
	if (obj.flags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_FLAGS, obj.flags.value());
	}
	if (obj.proto.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_IPTUN_PROTO, obj.proto.value());
	}
	if (obj.pmtudisc.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_IPTUN_PMTUDISC, obj.pmtudisc.value());
	}
	if (obj._6rd_prefix.size() > 0) {
		ynl_attr_put(nlh, IFLA_IPTUN_6RD_PREFIX, obj._6rd_prefix.data(), obj._6rd_prefix.size());
	}
	if (obj._6rd_relay_prefix.size() > 0) {
		ynl_attr_put(nlh, IFLA_IPTUN_6RD_RELAY_PREFIX, obj._6rd_relay_prefix.data(), obj._6rd_relay_prefix.size());
	}
	if (obj._6rd_prefixlen.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_6RD_PREFIXLEN, obj._6rd_prefixlen.value());
	}
	if (obj._6rd_relay_prefixlen.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_6RD_RELAY_PREFIXLEN, obj._6rd_relay_prefixlen.value());
	}
	if (obj.encap_type.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_TYPE, obj.encap_type.value());
	}
	if (obj.encap_flags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_FLAGS, obj.encap_flags.value());
	}
	if (obj.encap_sport.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_SPORT, obj.encap_sport.value());
	}
	if (obj.encap_dport.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_DPORT, obj.encap_dport.value());
	}
	if (obj.collect_metadata) {
		ynl_attr_put(nlh, IFLA_IPTUN_COLLECT_METADATA, NULL, 0);
	}
	if (obj.fwmark.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_IPTUN_FWMARK, obj.fwmark.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_iptun_attrs_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	rt_link_linkinfo_iptun_attrs *dst = (rt_link_linkinfo_iptun_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_IPTUN_LINK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_LOCAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->local.assign(data, data + len);
		} else if (type == IFLA_IPTUN_REMOTE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->remote.assign(data, data + len);
		} else if (type == IFLA_IPTUN_TTL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ttl = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_TOS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tos = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_ENCAP_LIMIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_limit = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_FLOWINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flowinfo = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_PROTO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->proto = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_PMTUDISC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->pmtudisc = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_6RD_PREFIX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->_6rd_prefix.assign(data, data + len);
		} else if (type == IFLA_IPTUN_6RD_RELAY_PREFIX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->_6rd_relay_prefix.assign(data, data + len);
		} else if (type == IFLA_IPTUN_6RD_PREFIXLEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->_6rd_prefixlen = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_6RD_RELAY_PREFIXLEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->_6rd_relay_prefixlen = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_type = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_flags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_SPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_sport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_DPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_dport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_IPTUN_FWMARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fwmark = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_ip6tnl_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      const rt_link_linkinfo_ip6tnl_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.link.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_IPTUN_LINK, obj.link.value());
	}
	if (obj.local.size() > 0) {
		ynl_attr_put(nlh, IFLA_IPTUN_LOCAL, obj.local.data(), obj.local.size());
	}
	if (obj.remote.size() > 0) {
		ynl_attr_put(nlh, IFLA_IPTUN_REMOTE, obj.remote.data(), obj.remote.size());
	}
	if (obj.ttl.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_IPTUN_TTL, obj.ttl.value());
	}
	if (obj.encap_limit.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_IPTUN_ENCAP_LIMIT, obj.encap_limit.value());
	}
	if (obj.flowinfo.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_IPTUN_FLOWINFO, obj.flowinfo.value());
	}
	if (obj.flags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_FLAGS, obj.flags.value());
	}
	if (obj.proto.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_IPTUN_PROTO, obj.proto.value());
	}
	if (obj.encap_type.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_TYPE, obj.encap_type.value());
	}
	if (obj.encap_flags.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_FLAGS, obj.encap_flags.value());
	}
	if (obj.encap_sport.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_SPORT, obj.encap_sport.value());
	}
	if (obj.encap_dport.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_IPTUN_ENCAP_DPORT, obj.encap_dport.value());
	}
	if (obj.collect_metadata) {
		ynl_attr_put(nlh, IFLA_IPTUN_COLLECT_METADATA, NULL, 0);
	}
	if (obj.fwmark.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_IPTUN_FWMARK, obj.fwmark.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_ip6tnl_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	rt_link_linkinfo_ip6tnl_attrs *dst = (rt_link_linkinfo_ip6tnl_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_IPTUN_LINK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_LOCAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->local.assign(data, data + len);
		} else if (type == IFLA_IPTUN_REMOTE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->remote.assign(data, data + len);
		} else if (type == IFLA_IPTUN_TTL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ttl = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_ENCAP_LIMIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_limit = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_FLOWINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flowinfo = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_IPTUN_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_PROTO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->proto = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_IPTUN_ENCAP_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_type = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_flags = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_SPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_sport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_ENCAP_DPORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->encap_dport = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_IPTUN_COLLECT_METADATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_IPTUN_FWMARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fwmark = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_tun_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   const rt_link_linkinfo_tun_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.owner.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_TUN_OWNER, obj.owner.value());
	}
	if (obj.group.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_TUN_GROUP, obj.group.value());
	}
	if (obj.type.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_TUN_TYPE, obj.type.value());
	}
	if (obj.pi.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_TUN_PI, obj.pi.value());
	}
	if (obj.vnet_hdr.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_TUN_VNET_HDR, obj.vnet_hdr.value());
	}
	if (obj.persist.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_TUN_PERSIST, obj.persist.value());
	}
	if (obj.multi_queue.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_TUN_MULTI_QUEUE, obj.multi_queue.value());
	}
	if (obj.num_queues.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_TUN_NUM_QUEUES, obj.num_queues.value());
	}
	if (obj.num_disabled_queues.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_TUN_NUM_DISABLED_QUEUES, obj.num_disabled_queues.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_tun_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	rt_link_linkinfo_tun_attrs *dst = (rt_link_linkinfo_tun_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_TUN_OWNER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->owner = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_TUN_GROUP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->group = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_TUN_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->type = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_PI) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->pi = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_VNET_HDR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vnet_hdr = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_PERSIST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->persist = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_MULTI_QUEUE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->multi_queue = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_TUN_NUM_QUEUES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->num_queues = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_TUN_NUM_DISABLED_QUEUES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->num_disabled_queues = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_vrf_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   const rt_link_linkinfo_vrf_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.table.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_VRF_TABLE, obj.table.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_vrf_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	rt_link_linkinfo_vrf_attrs *dst = (rt_link_linkinfo_vrf_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VRF_TABLE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->table = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_vti_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   const rt_link_linkinfo_vti_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.link.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_VTI_LINK, obj.link.value());
	}
	if (obj.ikey.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_VTI_IKEY, obj.ikey.value());
	}
	if (obj.okey.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_VTI_OKEY, obj.okey.value());
	}
	if (obj.local.size() > 0) {
		ynl_attr_put(nlh, IFLA_VTI_LOCAL, obj.local.data(), obj.local.size());
	}
	if (obj.remote.size() > 0) {
		ynl_attr_put(nlh, IFLA_VTI_REMOTE, obj.remote.data(), obj.remote.size());
	}
	if (obj.fwmark.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_VTI_FWMARK, obj.fwmark.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_vti_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	rt_link_linkinfo_vti_attrs *dst = (rt_link_linkinfo_vti_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VTI_LINK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_IKEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ikey = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_OKEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->okey = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_LOCAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->local.assign(data, data + len);
		} else if (type == IFLA_VTI_REMOTE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->remote.assign(data, data + len);
		} else if (type == IFLA_VTI_FWMARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fwmark = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_vti6_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    const rt_link_linkinfo_vti6_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.link.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_VTI_LINK, obj.link.value());
	}
	if (obj.ikey.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_VTI_IKEY, obj.ikey.value());
	}
	if (obj.okey.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_VTI_OKEY, obj.okey.value());
	}
	if (obj.local.size() > 0) {
		ynl_attr_put(nlh, IFLA_VTI_LOCAL, obj.local.data(), obj.local.size());
	}
	if (obj.remote.size() > 0) {
		ynl_attr_put(nlh, IFLA_VTI_REMOTE, obj.remote.data(), obj.remote.size());
	}
	if (obj.fwmark.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_VTI_FWMARK, obj.fwmark.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_vti6_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	rt_link_linkinfo_vti6_attrs *dst = (rt_link_linkinfo_vti6_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VTI_LINK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_IKEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ikey = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_OKEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->okey = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_VTI_LOCAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->local.assign(data, data + len);
		} else if (type == IFLA_VTI_REMOTE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->remote.assign(data, data + len);
		} else if (type == IFLA_VTI_FWMARK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fwmark = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_netkit_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      const rt_link_linkinfo_netkit_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.peer_info.size() > 0) {
		ynl_attr_put(nlh, IFLA_NETKIT_PEER_INFO, obj.peer_info.data(), obj.peer_info.size());
	}
	if (obj.primary.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_NETKIT_PRIMARY, obj.primary.value());
	}
	if (obj.policy.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NETKIT_POLICY, obj.policy.value());
	}
	if (obj.peer_policy.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NETKIT_PEER_POLICY, obj.peer_policy.value());
	}
	if (obj.mode.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NETKIT_MODE, obj.mode.value());
	}
	if (obj.scrub.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NETKIT_SCRUB, obj.scrub.value());
	}
	if (obj.peer_scrub.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NETKIT_PEER_SCRUB, obj.peer_scrub.value());
	}
	if (obj.headroom.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_NETKIT_HEADROOM, obj.headroom.value());
	}
	if (obj.tailroom.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_NETKIT_TAILROOM, obj.tailroom.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_netkit_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	rt_link_linkinfo_netkit_attrs *dst = (rt_link_linkinfo_netkit_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_NETKIT_PEER_INFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->peer_info.assign(data, data + len);
		} else if (type == IFLA_NETKIT_PRIMARY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->primary = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_NETKIT_POLICY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->policy = (int)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_PEER_POLICY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->peer_policy = (int)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mode = (enum netkit_mode)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_SCRUB) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->scrub = (int)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_PEER_SCRUB) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->peer_scrub = (int)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NETKIT_HEADROOM) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->headroom = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_NETKIT_TAILROOM) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tailroom = (__u16)ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_ovpn_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    const rt_link_linkinfo_ovpn_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.mode.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_OVPN_MODE, obj.mode.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_ovpn_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	rt_link_linkinfo_ovpn_attrs *dst = (rt_link_linkinfo_ovpn_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_OVPN_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mode = (enum ovpn_mode)ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

int rt_link_linkinfo_brport_attrs_put(struct nlmsghdr *nlh,
				      unsigned int attr_type,
				      const rt_link_linkinfo_brport_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.state.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BRPORT_STATE, obj.state.value());
	}
	if (obj.priority.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BRPORT_PRIORITY, obj.priority.value());
	}
	if (obj.cost.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BRPORT_COST, obj.cost.value());
	}
	if (obj.mode) {
		ynl_attr_put(nlh, IFLA_BRPORT_MODE, NULL, 0);
	}
	if (obj.guard) {
		ynl_attr_put(nlh, IFLA_BRPORT_GUARD, NULL, 0);
	}
	if (obj.protect) {
		ynl_attr_put(nlh, IFLA_BRPORT_PROTECT, NULL, 0);
	}
	if (obj.fast_leave) {
		ynl_attr_put(nlh, IFLA_BRPORT_FAST_LEAVE, NULL, 0);
	}
	if (obj.learning) {
		ynl_attr_put(nlh, IFLA_BRPORT_LEARNING, NULL, 0);
	}
	if (obj.unicast_flood) {
		ynl_attr_put(nlh, IFLA_BRPORT_UNICAST_FLOOD, NULL, 0);
	}
	if (obj.proxyarp) {
		ynl_attr_put(nlh, IFLA_BRPORT_PROXYARP, NULL, 0);
	}
	if (obj.learning_sync) {
		ynl_attr_put(nlh, IFLA_BRPORT_LEARNING_SYNC, NULL, 0);
	}
	if (obj.proxyarp_wifi) {
		ynl_attr_put(nlh, IFLA_BRPORT_PROXYARP_WIFI, NULL, 0);
	}
	if (obj.root_id) {
		ynl_attr_put(nlh, IFLA_BRPORT_ROOT_ID, &*obj.root_id, sizeof(struct ifla_bridge_id));
	}
	if (obj.bridge_id) {
		ynl_attr_put(nlh, IFLA_BRPORT_BRIDGE_ID, &*obj.bridge_id, sizeof(struct ifla_bridge_id));
	}
	if (obj.designated_port.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BRPORT_DESIGNATED_PORT, obj.designated_port.value());
	}
	if (obj.designated_cost.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BRPORT_DESIGNATED_COST, obj.designated_cost.value());
	}
	if (obj.id.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BRPORT_ID, obj.id.value());
	}
	if (obj.no.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BRPORT_NO, obj.no.value());
	}
	if (obj.topology_change_ack.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BRPORT_TOPOLOGY_CHANGE_ACK, obj.topology_change_ack.value());
	}
	if (obj.config_pending.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BRPORT_CONFIG_PENDING, obj.config_pending.value());
	}
	if (obj.message_age_timer.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BRPORT_MESSAGE_AGE_TIMER, obj.message_age_timer.value());
	}
	if (obj.forward_delay_timer.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BRPORT_FORWARD_DELAY_TIMER, obj.forward_delay_timer.value());
	}
	if (obj.hold_timer.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_BRPORT_HOLD_TIMER, obj.hold_timer.value());
	}
	if (obj.flush) {
		ynl_attr_put(nlh, IFLA_BRPORT_FLUSH, NULL, 0);
	}
	if (obj.multicast_router.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BRPORT_MULTICAST_ROUTER, obj.multicast_router.value());
	}
	if (obj.mcast_flood) {
		ynl_attr_put(nlh, IFLA_BRPORT_MCAST_FLOOD, NULL, 0);
	}
	if (obj.mcast_to_ucast) {
		ynl_attr_put(nlh, IFLA_BRPORT_MCAST_TO_UCAST, NULL, 0);
	}
	if (obj.vlan_tunnel) {
		ynl_attr_put(nlh, IFLA_BRPORT_VLAN_TUNNEL, NULL, 0);
	}
	if (obj.bcast_flood) {
		ynl_attr_put(nlh, IFLA_BRPORT_BCAST_FLOOD, NULL, 0);
	}
	if (obj.group_fwd_mask.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BRPORT_GROUP_FWD_MASK, obj.group_fwd_mask.value());
	}
	if (obj.neigh_suppress) {
		ynl_attr_put(nlh, IFLA_BRPORT_NEIGH_SUPPRESS, NULL, 0);
	}
	if (obj.isolated) {
		ynl_attr_put(nlh, IFLA_BRPORT_ISOLATED, NULL, 0);
	}
	if (obj.backup_port.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BRPORT_BACKUP_PORT, obj.backup_port.value());
	}
	if (obj.mrp_ring_open) {
		ynl_attr_put(nlh, IFLA_BRPORT_MRP_RING_OPEN, NULL, 0);
	}
	if (obj.mrp_in_open) {
		ynl_attr_put(nlh, IFLA_BRPORT_MRP_IN_OPEN, NULL, 0);
	}
	if (obj.mcast_eht_hosts_limit.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT, obj.mcast_eht_hosts_limit.value());
	}
	if (obj.mcast_eht_hosts_cnt.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BRPORT_MCAST_EHT_HOSTS_CNT, obj.mcast_eht_hosts_cnt.value());
	}
	if (obj.locked) {
		ynl_attr_put(nlh, IFLA_BRPORT_LOCKED, NULL, 0);
	}
	if (obj.mab) {
		ynl_attr_put(nlh, IFLA_BRPORT_MAB, NULL, 0);
	}
	if (obj.mcast_n_groups.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BRPORT_MCAST_N_GROUPS, obj.mcast_n_groups.value());
	}
	if (obj.mcast_max_groups.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BRPORT_MCAST_MAX_GROUPS, obj.mcast_max_groups.value());
	}
	if (obj.neigh_vlan_suppress) {
		ynl_attr_put(nlh, IFLA_BRPORT_NEIGH_VLAN_SUPPRESS, NULL, 0);
	}
	if (obj.backup_nhid.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BRPORT_BACKUP_NHID, obj.backup_nhid.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_brport_attrs_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	rt_link_linkinfo_brport_attrs *dst = (rt_link_linkinfo_brport_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BRPORT_STATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->state = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BRPORT_PRIORITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->priority = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_COST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cost = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_GUARD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_PROTECT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_FAST_LEAVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_LEARNING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_UNICAST_FLOOD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_PROXYARP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_LEARNING_SYNC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_PROXYARP_WIFI) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_ROOT_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_bridge_id);
			dst->root_id.emplace();
			memcpy(&*dst->root_id, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_BRPORT_BRIDGE_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_bridge_id);
			dst->bridge_id.emplace();
			memcpy(&*dst->bridge_id, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_BRPORT_DESIGNATED_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->designated_port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_DESIGNATED_COST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->designated_cost = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_NO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->no = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_TOPOLOGY_CHANGE_ACK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->topology_change_ack = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BRPORT_CONFIG_PENDING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->config_pending = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BRPORT_MESSAGE_AGE_TIMER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->message_age_timer = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BRPORT_FORWARD_DELAY_TIMER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->forward_delay_timer = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BRPORT_HOLD_TIMER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->hold_timer = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_BRPORT_FLUSH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_MULTICAST_ROUTER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->multicast_router = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BRPORT_MCAST_FLOOD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_MCAST_TO_UCAST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_VLAN_TUNNEL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_BCAST_FLOOD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_GROUP_FWD_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->group_fwd_mask = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BRPORT_NEIGH_SUPPRESS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_ISOLATED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_BACKUP_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->backup_port = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_MRP_RING_OPEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_MRP_IN_OPEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_eht_hosts_limit = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_MCAST_EHT_HOSTS_CNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_eht_hosts_cnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_LOCKED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_MAB) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_MCAST_N_GROUPS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_n_groups = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_MCAST_MAX_GROUPS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mcast_max_groups = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BRPORT_NEIGH_VLAN_SUPPRESS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BRPORT_BACKUP_NHID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->backup_nhid = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_bond_slave_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 const rt_link_bond_slave_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.state.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_SLAVE_STATE, obj.state.value());
	}
	if (obj.mii_status.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_SLAVE_MII_STATUS, obj.mii_status.value());
	}
	if (obj.link_failure_count.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_SLAVE_LINK_FAILURE_COUNT, obj.link_failure_count.value());
	}
	if (obj.perm_hwaddr.size() > 0) {
		ynl_attr_put(nlh, IFLA_BOND_SLAVE_PERM_HWADDR, obj.perm_hwaddr.data(), obj.perm_hwaddr.size());
	}
	if (obj.queue_id.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BOND_SLAVE_QUEUE_ID, obj.queue_id.value());
	}
	if (obj.ad_aggregator_id.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BOND_SLAVE_AD_AGGREGATOR_ID, obj.ad_aggregator_id.value());
	}
	if (obj.ad_actor_oper_port_state.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE, obj.ad_actor_oper_port_state.value());
	}
	if (obj.ad_partner_oper_port_state.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE, obj.ad_partner_oper_port_state.value());
	}
	if (obj.prio.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_SLAVE_PRIO, obj.prio.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_bond_slave_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	rt_link_bond_slave_attrs *dst = (rt_link_bond_slave_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BOND_SLAVE_STATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->state = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_SLAVE_MII_STATUS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mii_status = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_SLAVE_LINK_FAILURE_COUNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link_failure_count = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_SLAVE_PERM_HWADDR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->perm_hwaddr.assign(data, data + len);
		} else if (type == IFLA_BOND_SLAVE_QUEUE_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->queue_id = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_SLAVE_AD_AGGREGATOR_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ad_aggregator_id = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ad_actor_oper_port_state = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ad_partner_oper_port_state = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_SLAVE_PRIO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->prio = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int rt_link_vf_stats_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       const rt_link_vf_stats_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.rx_packets.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_RX_PACKETS, obj.rx_packets.value());
	}
	if (obj.tx_packets.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_TX_PACKETS, obj.tx_packets.value());
	}
	if (obj.rx_bytes.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_RX_BYTES, obj.rx_bytes.value());
	}
	if (obj.tx_bytes.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_TX_BYTES, obj.tx_bytes.value());
	}
	if (obj.broadcast.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_BROADCAST, obj.broadcast.value());
	}
	if (obj.multicast.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_MULTICAST, obj.multicast.value());
	}
	if (obj.rx_dropped.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_RX_DROPPED, obj.rx_dropped.value());
	}
	if (obj.tx_dropped.has_value()) {
		ynl_attr_put_u64(nlh, IFLA_VF_STATS_TX_DROPPED, obj.tx_dropped.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vf_stats_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	rt_link_vf_stats_attrs *dst = (rt_link_vf_stats_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VF_STATS_RX_PACKETS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rx_packets = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_TX_PACKETS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tx_packets = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_RX_BYTES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rx_bytes = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_TX_BYTES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tx_bytes = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_BROADCAST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->broadcast = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_MULTICAST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->multicast = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_RX_DROPPED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rx_dropped = (__u64)ynl_attr_get_u64(attr);
		} else if (type == IFLA_VF_STATS_TX_DROPPED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tx_dropped = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int rt_link_vf_vlan_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      const rt_link_vf_vlan_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (unsigned int i = 0; i < obj.info.size(); i++) {
		ynl_attr_put(nlh, IFLA_VF_VLAN_INFO, &obj.info[i], sizeof(struct ifla_vf_vlan_info));
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vf_vlan_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	rt_link_vf_vlan_attrs *dst = (rt_link_vf_vlan_attrs *)yarg->data;
	const struct nlattr *attr;
	unsigned int n_info = 0;
	int i;

	if (dst->info.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (vf-vlan-attrs.info)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VF_VLAN_INFO) {
			n_info++;
		}
	}

	if (n_info) {
		dst->info.resize(n_info);
		i = 0;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == IFLA_VF_VLAN_INFO) {
				size_t len = ynl_attr_data_len(attr);

				if (len > sizeof(dst->info[0])) {
					len = sizeof(dst->info[0]);
				}
				memcpy(&dst->info[i], ynl_attr_data(attr), len);
				i++;
			}
		}
	}

	return 0;
}

int rt_link_bond_ad_info_attrs_put(struct nlmsghdr *nlh,
				   unsigned int attr_type,
				   const rt_link_bond_ad_info_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.aggregator.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_INFO_AGGREGATOR, obj.aggregator.value());
	}
	if (obj.num_ports.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_INFO_NUM_PORTS, obj.num_ports.value());
	}
	if (obj.actor_key.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_INFO_ACTOR_KEY, obj.actor_key.value());
	}
	if (obj.partner_key.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_INFO_PARTNER_KEY, obj.partner_key.value());
	}
	if (obj.partner_mac.size() > 0) {
		ynl_attr_put(nlh, IFLA_BOND_AD_INFO_PARTNER_MAC, obj.partner_mac.data(), obj.partner_mac.size());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_bond_ad_info_attrs_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	rt_link_bond_ad_info_attrs *dst = (rt_link_bond_ad_info_attrs *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BOND_AD_INFO_AGGREGATOR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->aggregator = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_INFO_NUM_PORTS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->num_ports = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_INFO_ACTOR_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->actor_key = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_INFO_PARTNER_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->partner_key = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_INFO_PARTNER_MAC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->partner_mac.assign(data, data + len);
		}
	}

	return 0;
}

int rt_link_ifla_vlan_qos_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      const rt_link_ifla_vlan_qos&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (unsigned int i = 0; i < obj.mapping.size(); i++) {
		ynl_attr_put(nlh, IFLA_VLAN_QOS_MAPPING, &obj.mapping[i], sizeof(struct ifla_vlan_qos_mapping));
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_ifla_vlan_qos_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	rt_link_ifla_vlan_qos *dst = (rt_link_ifla_vlan_qos *)yarg->data;
	unsigned int n_mapping = 0;
	const struct nlattr *attr;
	int i;

	if (dst->mapping.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (ifla-vlan-qos.mapping)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VLAN_QOS_MAPPING) {
			n_mapping++;
		}
	}

	if (n_mapping) {
		dst->mapping.resize(n_mapping);
		i = 0;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == IFLA_VLAN_QOS_MAPPING) {
				size_t len = ynl_attr_data_len(attr);

				if (len > sizeof(dst->mapping[0])) {
					len = sizeof(dst->mapping[0]);
				}
				memcpy(&dst->mapping[i], ynl_attr_data(attr), len);
				i++;
			}
		}
	}

	return 0;
}

int rt_link_af_spec_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			      const rt_link_af_spec_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.inet.has_value()) {
		rt_link_ifla_attrs_put(nlh, AF_INET, obj.inet.value());
	}
	if (obj.inet6.has_value()) {
		rt_link_ifla6_attrs_put(nlh, AF_INET6, obj.inet6.value());
	}
	if (obj.mctp.has_value()) {
		rt_link_mctp_attrs_put(nlh, AF_MCTP, obj.mctp.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_af_spec_attrs_parse(struct ynl_parse_arg *yarg,
				const struct nlattr *nested)
{
	rt_link_af_spec_attrs *dst = (rt_link_af_spec_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == AF_INET) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_ifla_attrs_nest;
			parg.data = &dst->inet.emplace();
			if (rt_link_ifla_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == AF_INET6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_ifla6_attrs_nest;
			parg.data = &dst->inet6.emplace();
			if (rt_link_ifla6_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == AF_MCTP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_mctp_attrs_nest;
			parg.data = &dst->mctp.emplace();
			if (rt_link_mctp_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int rt_link_link_offload_xstats_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	rt_link_link_offload_xstats *dst = (rt_link_link_offload_xstats *)yarg->data;
	const struct nlattr *attr_hw_s_info;
	unsigned int n_hw_s_info = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->hw_s_info.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (link-offload-xstats.hw-s-info)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_OFFLOAD_XSTATS_CPU_HIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->cpu_hit.assign(data, data + len);
		} else if (type == IFLA_OFFLOAD_XSTATS_HW_S_INFO) {
			const struct nlattr *attr2;

			attr_hw_s_info = attr;
		} else if (type == IFLA_OFFLOAD_XSTATS_L3_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->l3_stats.assign(data, data + len);
		}
	}

	if (n_hw_s_info) {
		dst->hw_s_info.resize(n_hw_s_info);
		i = 0;
		parg.rsp_policy = &rt_link_hw_s_info_one_nest;
		ynl_attr_for_each_nested(attr, attr_hw_s_info) {
			parg.data = &dst->hw_s_info[i];
			if (rt_link_hw_s_info_one_parse(&parg, attr, ynl_attr_type(attr))) {
				return YNL_PARSE_CB_ERROR;
			}
			i++;
		}
	}

	return 0;
}

int rt_link_linkinfo_member_data_msg_put(struct nlmsghdr *nlh,
					 unsigned int attr_type,
					 const rt_link_linkinfo_member_data_msg&  obj)
{
	if (obj.bridge.has_value()) {
		rt_link_linkinfo_brport_attrs_put(nlh, IFLA_INFO_SLAVE_DATA, obj.bridge.value());
	}
	if (obj.bond.has_value()) {
		rt_link_bond_slave_attrs_put(nlh, IFLA_INFO_SLAVE_DATA, obj.bond.value());
	}

	return 0;
}

int rt_link_linkinfo_member_data_msg_parse(struct ynl_parse_arg *yarg,
					   const std::string& sel,
					   const struct nlattr *nested)
{
	rt_link_linkinfo_member_data_msg *dst = static_cast<rt_link_linkinfo_member_data_msg *>(yarg->data);
	const struct nlattr *attr = nested;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	if (sel == "bridge") {
		parg.rsp_policy = &rt_link_linkinfo_brport_attrs_nest;
		parg.data = &dst->bridge.emplace();
		if (rt_link_linkinfo_brport_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "bond") {
		parg.rsp_policy = &rt_link_bond_slave_attrs_nest;
		parg.data = &dst->bond.emplace();
		if (rt_link_bond_slave_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	}
	return 0;
}

int rt_link_vfinfo_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			     const rt_link_vfinfo_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.mac) {
		ynl_attr_put(nlh, IFLA_VF_MAC, &*obj.mac, sizeof(struct ifla_vf_mac));
	}
	if (obj.vlan) {
		ynl_attr_put(nlh, IFLA_VF_VLAN, &*obj.vlan, sizeof(struct ifla_vf_vlan));
	}
	if (obj.tx_rate) {
		ynl_attr_put(nlh, IFLA_VF_TX_RATE, &*obj.tx_rate, sizeof(struct ifla_vf_tx_rate));
	}
	if (obj.spoofchk) {
		ynl_attr_put(nlh, IFLA_VF_SPOOFCHK, &*obj.spoofchk, sizeof(struct ifla_vf_spoofchk));
	}
	if (obj.link_state) {
		ynl_attr_put(nlh, IFLA_VF_LINK_STATE, &*obj.link_state, sizeof(struct ifla_vf_link_state));
	}
	if (obj.rate) {
		ynl_attr_put(nlh, IFLA_VF_RATE, &*obj.rate, sizeof(struct ifla_vf_rate));
	}
	if (obj.rss_query_en) {
		ynl_attr_put(nlh, IFLA_VF_RSS_QUERY_EN, &*obj.rss_query_en, sizeof(struct ifla_vf_rss_query_en));
	}
	if (obj.stats.has_value()) {
		rt_link_vf_stats_attrs_put(nlh, IFLA_VF_STATS, obj.stats.value());
	}
	if (obj.trust) {
		ynl_attr_put(nlh, IFLA_VF_TRUST, &*obj.trust, sizeof(struct ifla_vf_trust));
	}
	if (obj.ib_node_guid) {
		ynl_attr_put(nlh, IFLA_VF_IB_NODE_GUID, &*obj.ib_node_guid, sizeof(struct ifla_vf_guid));
	}
	if (obj.ib_port_guid) {
		ynl_attr_put(nlh, IFLA_VF_IB_PORT_GUID, &*obj.ib_port_guid, sizeof(struct ifla_vf_guid));
	}
	if (obj.vlan_list.has_value()) {
		rt_link_vf_vlan_attrs_put(nlh, IFLA_VF_VLAN_LIST, obj.vlan_list.value());
	}
	if (obj.broadcast.size() > 0) {
		ynl_attr_put(nlh, IFLA_VF_BROADCAST, obj.broadcast.data(), obj.broadcast.size());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vfinfo_attrs_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested)
{
	rt_link_vfinfo_attrs *dst = (rt_link_vfinfo_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VF_MAC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_mac);
			dst->mac.emplace();
			memcpy(&*dst->mac, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_VLAN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_vlan);
			dst->vlan.emplace();
			memcpy(&*dst->vlan, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_TX_RATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_tx_rate);
			dst->tx_rate.emplace();
			memcpy(&*dst->tx_rate, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_SPOOFCHK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_spoofchk);
			dst->spoofchk.emplace();
			memcpy(&*dst->spoofchk, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_LINK_STATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_link_state);
			dst->link_state.emplace();
			memcpy(&*dst->link_state, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_RATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_rate);
			dst->rate.emplace();
			memcpy(&*dst->rate, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_RSS_QUERY_EN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_rss_query_en);
			dst->rss_query_en.emplace();
			memcpy(&*dst->rss_query_en, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_vf_stats_attrs_nest;
			parg.data = &dst->stats.emplace();
			if (rt_link_vf_stats_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_VF_TRUST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_trust);
			dst->trust.emplace();
			memcpy(&*dst->trust, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_IB_NODE_GUID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_guid);
			dst->ib_node_guid.emplace();
			memcpy(&*dst->ib_node_guid, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_IB_PORT_GUID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vf_guid);
			dst->ib_port_guid.emplace();
			memcpy(&*dst->ib_port_guid, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_VLAN_LIST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_vf_vlan_attrs_nest;
			parg.data = &dst->vlan_list.emplace();
			if (rt_link_vf_vlan_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_VF_BROADCAST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->broadcast.assign(data, data + len);
		}
	}

	return 0;
}

int rt_link_linkinfo_bond_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    const rt_link_linkinfo_bond_attrs&  obj)
{
	struct nlattr *array;
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.mode.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_MODE, obj.mode.value());
	}
	if (obj.active_slave.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_ACTIVE_SLAVE, obj.active_slave.value());
	}
	if (obj.miimon.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_MIIMON, obj.miimon.value());
	}
	if (obj.updelay.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_UPDELAY, obj.updelay.value());
	}
	if (obj.downdelay.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_DOWNDELAY, obj.downdelay.value());
	}
	if (obj.use_carrier.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_USE_CARRIER, obj.use_carrier.value());
	}
	if (obj.arp_interval.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_ARP_INTERVAL, obj.arp_interval.value());
	}
	array = ynl_attr_nest_start(nlh, IFLA_BOND_ARP_IP_TARGET);
	for (unsigned int i = 0; i < obj.arp_ip_target.size(); i++) {
		ynl_attr_put_u32(nlh, i, obj.arp_ip_target[i]);
	}
	ynl_attr_nest_end(nlh, array);
	if (obj.arp_validate.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_ARP_VALIDATE, obj.arp_validate.value());
	}
	if (obj.arp_all_targets.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_ARP_ALL_TARGETS, obj.arp_all_targets.value());
	}
	if (obj.primary.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_PRIMARY, obj.primary.value());
	}
	if (obj.primary_reselect.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_PRIMARY_RESELECT, obj.primary_reselect.value());
	}
	if (obj.fail_over_mac.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_FAIL_OVER_MAC, obj.fail_over_mac.value());
	}
	if (obj.xmit_hash_policy.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_XMIT_HASH_POLICY, obj.xmit_hash_policy.value());
	}
	if (obj.resend_igmp.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_RESEND_IGMP, obj.resend_igmp.value());
	}
	if (obj.num_peer_notif.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_NUM_PEER_NOTIF, obj.num_peer_notif.value());
	}
	if (obj.all_slaves_active.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_ALL_SLAVES_ACTIVE, obj.all_slaves_active.value());
	}
	if (obj.min_links.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_MIN_LINKS, obj.min_links.value());
	}
	if (obj.lp_interval.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_LP_INTERVAL, obj.lp_interval.value());
	}
	if (obj.packets_per_slave.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_PACKETS_PER_SLAVE, obj.packets_per_slave.value());
	}
	if (obj.ad_lacp_rate.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_AD_LACP_RATE, obj.ad_lacp_rate.value());
	}
	if (obj.ad_select.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_AD_SELECT, obj.ad_select.value());
	}
	if (obj.ad_info.has_value()) {
		rt_link_bond_ad_info_attrs_put(nlh, IFLA_BOND_AD_INFO, obj.ad_info.value());
	}
	if (obj.ad_actor_sys_prio.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_ACTOR_SYS_PRIO, obj.ad_actor_sys_prio.value());
	}
	if (obj.ad_user_port_key.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_BOND_AD_USER_PORT_KEY, obj.ad_user_port_key.value());
	}
	if (obj.ad_actor_system.size() > 0) {
		ynl_attr_put(nlh, IFLA_BOND_AD_ACTOR_SYSTEM, obj.ad_actor_system.data(), obj.ad_actor_system.size());
	}
	if (obj.tlb_dynamic_lb.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_TLB_DYNAMIC_LB, obj.tlb_dynamic_lb.value());
	}
	if (obj.peer_notif_delay.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_BOND_PEER_NOTIF_DELAY, obj.peer_notif_delay.value());
	}
	if (obj.ad_lacp_active.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_AD_LACP_ACTIVE, obj.ad_lacp_active.value());
	}
	if (obj.missed_max.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_MISSED_MAX, obj.missed_max.value());
	}
	array = ynl_attr_nest_start(nlh, IFLA_BOND_NS_IP6_TARGET);
	for (unsigned int i = 0; i < obj.ns_ip6_target.size(); i++) {
		ynl_attr_put(nlh, i, &obj.ns_ip6_target[i], 16);
	}
	ynl_attr_nest_end(nlh, array);
	if (obj.coupled_control.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_BOND_COUPLED_CONTROL, obj.coupled_control.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_bond_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	rt_link_linkinfo_bond_attrs *dst = (rt_link_linkinfo_bond_attrs *)yarg->data;
	const struct nlattr *attr_arp_ip_target;
	const struct nlattr *attr_ns_ip6_target;
	unsigned int n_arp_ip_target = 0;
	unsigned int n_ns_ip6_target = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->arp_ip_target.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (linkinfo-bond-attrs.arp-ip-target)");
	}
	if (dst->ns_ip6_target.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (linkinfo-bond-attrs.ns-ip6-target)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_BOND_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mode = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_ACTIVE_SLAVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->active_slave = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_MIIMON) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->miimon = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_UPDELAY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->updelay = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_DOWNDELAY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->downdelay = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_USE_CARRIER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->use_carrier = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_ARP_INTERVAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->arp_interval = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_ARP_IP_TARGET) {
			const struct nlattr *attr2;

			attr_arp_ip_target = attr;
		} else if (type == IFLA_BOND_ARP_VALIDATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->arp_validate = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_ARP_ALL_TARGETS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->arp_all_targets = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_PRIMARY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->primary = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_PRIMARY_RESELECT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->primary_reselect = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_FAIL_OVER_MAC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fail_over_mac = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_XMIT_HASH_POLICY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->xmit_hash_policy = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_RESEND_IGMP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resend_igmp = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_NUM_PEER_NOTIF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->num_peer_notif = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_ALL_SLAVES_ACTIVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->all_slaves_active = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_MIN_LINKS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->min_links = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_LP_INTERVAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->lp_interval = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_PACKETS_PER_SLAVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->packets_per_slave = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_AD_LACP_RATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ad_lacp_rate = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_AD_SELECT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ad_select = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_AD_INFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_bond_ad_info_attrs_nest;
			parg.data = &dst->ad_info.emplace();
			if (rt_link_bond_ad_info_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_BOND_AD_ACTOR_SYS_PRIO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ad_actor_sys_prio = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_USER_PORT_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ad_user_port_key = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_BOND_AD_ACTOR_SYSTEM) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->ad_actor_system.assign(data, data + len);
		} else if (type == IFLA_BOND_TLB_DYNAMIC_LB) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tlb_dynamic_lb = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_PEER_NOTIF_DELAY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->peer_notif_delay = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_BOND_AD_LACP_ACTIVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ad_lacp_active = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_MISSED_MAX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->missed_max = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_BOND_NS_IP6_TARGET) {
			const struct nlattr *attr2;

			attr_ns_ip6_target = attr;
		} else if (type == IFLA_BOND_COUPLED_CONTROL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->coupled_control = (__u8)ynl_attr_get_u8(attr);
		}
	}

	if (n_arp_ip_target) {
		dst->arp_ip_target.resize(n_arp_ip_target);
		i = 0;
		ynl_attr_for_each_nested(attr, attr_arp_ip_target) {
			dst->arp_ip_target[i] = ynl_attr_get_u32(attr);
			i++;
		}
	}
	if (n_ns_ip6_target) {
		dst->ns_ip6_target.resize(n_ns_ip6_target);
		i = 0;
		ynl_attr_for_each_nested(attr, attr_ns_ip6_target) {
			memcpy(dst->ns_ip6_target[i].data(), ynl_attr_data(attr), 16);
			i++;
		}
	}

	return 0;
}

int rt_link_linkinfo_vlan_attrs_put(struct nlmsghdr *nlh,
				    unsigned int attr_type,
				    const rt_link_linkinfo_vlan_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.id.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_VLAN_ID, obj.id.value());
	}
	if (obj.flags) {
		ynl_attr_put(nlh, IFLA_VLAN_FLAGS, &*obj.flags, sizeof(struct ifla_vlan_flags));
	}
	if (obj.egress_qos.has_value()) {
		rt_link_ifla_vlan_qos_put(nlh, IFLA_VLAN_EGRESS_QOS, obj.egress_qos.value());
	}
	if (obj.ingress_qos.has_value()) {
		rt_link_ifla_vlan_qos_put(nlh, IFLA_VLAN_INGRESS_QOS, obj.ingress_qos.value());
	}
	if (obj.protocol.has_value()) {
		ynl_attr_put_u16(nlh, IFLA_VLAN_PROTOCOL, obj.protocol.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_vlan_attrs_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	rt_link_linkinfo_vlan_attrs *dst = (rt_link_linkinfo_vlan_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VLAN_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u16)ynl_attr_get_u16(attr);
		} else if (type == IFLA_VLAN_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct ifla_vlan_flags);
			dst->flags.emplace();
			memcpy(&*dst->flags, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VLAN_EGRESS_QOS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_ifla_vlan_qos_nest;
			parg.data = &dst->egress_qos.emplace();
			if (rt_link_ifla_vlan_qos_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_VLAN_INGRESS_QOS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_ifla_vlan_qos_nest;
			parg.data = &dst->ingress_qos.emplace();
			if (rt_link_ifla_vlan_qos_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_VLAN_PROTOCOL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->protocol = (int)ynl_attr_get_u16(attr);
		}
	}

	return 0;
}

int rt_link_vfinfo_list_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  const rt_link_vfinfo_list_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (unsigned int i = 0; i < obj.info.size(); i++) {
		rt_link_vfinfo_attrs_put(nlh, IFLA_VF_INFO, obj.info[i]);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_vfinfo_list_attrs_parse(struct ynl_parse_arg *yarg,
				    const struct nlattr *nested)
{
	rt_link_vfinfo_list_attrs *dst = (rt_link_vfinfo_list_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_info = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->info.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (vfinfo-list-attrs.info)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_VF_INFO) {
			n_info++;
		}
	}

	if (n_info) {
		dst->info.resize(n_info);
		i = 0;
		parg.rsp_policy = &rt_link_vfinfo_attrs_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == IFLA_VF_INFO) {
				parg.data = &dst->info[i];
				if (rt_link_vfinfo_attrs_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int rt_link_linkinfo_data_msg_put(struct nlmsghdr *nlh, unsigned int attr_type,
				  const rt_link_linkinfo_data_msg&  obj)
{
	if (obj.bond.has_value()) {
		rt_link_linkinfo_bond_attrs_put(nlh, IFLA_INFO_DATA, obj.bond.value());
	}
	if (obj.bridge.has_value()) {
		rt_link_linkinfo_bridge_attrs_put(nlh, IFLA_INFO_DATA, obj.bridge.value());
	}
	if (obj.erspan.has_value()) {
		rt_link_linkinfo_gre_attrs_put(nlh, IFLA_INFO_DATA, obj.erspan.value());
	}
	if (obj.gre.has_value()) {
		rt_link_linkinfo_gre_attrs_put(nlh, IFLA_INFO_DATA, obj.gre.value());
	}
	if (obj.gretap.has_value()) {
		rt_link_linkinfo_gre_attrs_put(nlh, IFLA_INFO_DATA, obj.gretap.value());
	}
	if (obj.ip6gre.has_value()) {
		rt_link_linkinfo_gre6_attrs_put(nlh, IFLA_INFO_DATA, obj.ip6gre.value());
	}
	if (obj.geneve.has_value()) {
		rt_link_linkinfo_geneve_attrs_put(nlh, IFLA_INFO_DATA, obj.geneve.value());
	}
	if (obj.ipip.has_value()) {
		rt_link_linkinfo_iptun_attrs_put(nlh, IFLA_INFO_DATA, obj.ipip.value());
	}
	if (obj.ip6tnl.has_value()) {
		rt_link_linkinfo_ip6tnl_attrs_put(nlh, IFLA_INFO_DATA, obj.ip6tnl.value());
	}
	if (obj.sit.has_value()) {
		rt_link_linkinfo_iptun_attrs_put(nlh, IFLA_INFO_DATA, obj.sit.value());
	}
	if (obj.tun.has_value()) {
		rt_link_linkinfo_tun_attrs_put(nlh, IFLA_INFO_DATA, obj.tun.value());
	}
	if (obj.vlan.has_value()) {
		rt_link_linkinfo_vlan_attrs_put(nlh, IFLA_INFO_DATA, obj.vlan.value());
	}
	if (obj.vrf.has_value()) {
		rt_link_linkinfo_vrf_attrs_put(nlh, IFLA_INFO_DATA, obj.vrf.value());
	}
	if (obj.vti.has_value()) {
		rt_link_linkinfo_vti_attrs_put(nlh, IFLA_INFO_DATA, obj.vti.value());
	}
	if (obj.vti6.has_value()) {
		rt_link_linkinfo_vti6_attrs_put(nlh, IFLA_INFO_DATA, obj.vti6.value());
	}
	if (obj.netkit.has_value()) {
		rt_link_linkinfo_netkit_attrs_put(nlh, IFLA_INFO_DATA, obj.netkit.value());
	}
	if (obj.ovpn.has_value()) {
		rt_link_linkinfo_ovpn_attrs_put(nlh, IFLA_INFO_DATA, obj.ovpn.value());
	}

	return 0;
}

int rt_link_linkinfo_data_msg_parse(struct ynl_parse_arg *yarg,
				    const std::string& sel,
				    const struct nlattr *nested)
{
	rt_link_linkinfo_data_msg *dst = static_cast<rt_link_linkinfo_data_msg *>(yarg->data);
	const struct nlattr *attr = nested;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	if (sel == "bond") {
		parg.rsp_policy = &rt_link_linkinfo_bond_attrs_nest;
		parg.data = &dst->bond.emplace();
		if (rt_link_linkinfo_bond_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "bridge") {
		parg.rsp_policy = &rt_link_linkinfo_bridge_attrs_nest;
		parg.data = &dst->bridge.emplace();
		if (rt_link_linkinfo_bridge_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "erspan") {
		parg.rsp_policy = &rt_link_linkinfo_gre_attrs_nest;
		parg.data = &dst->erspan.emplace();
		if (rt_link_linkinfo_gre_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "gre") {
		parg.rsp_policy = &rt_link_linkinfo_gre_attrs_nest;
		parg.data = &dst->gre.emplace();
		if (rt_link_linkinfo_gre_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "gretap") {
		parg.rsp_policy = &rt_link_linkinfo_gre_attrs_nest;
		parg.data = &dst->gretap.emplace();
		if (rt_link_linkinfo_gre_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "ip6gre") {
		parg.rsp_policy = &rt_link_linkinfo_gre6_attrs_nest;
		parg.data = &dst->ip6gre.emplace();
		if (rt_link_linkinfo_gre6_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "geneve") {
		parg.rsp_policy = &rt_link_linkinfo_geneve_attrs_nest;
		parg.data = &dst->geneve.emplace();
		if (rt_link_linkinfo_geneve_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "ipip") {
		parg.rsp_policy = &rt_link_linkinfo_iptun_attrs_nest;
		parg.data = &dst->ipip.emplace();
		if (rt_link_linkinfo_iptun_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "ip6tnl") {
		parg.rsp_policy = &rt_link_linkinfo_ip6tnl_attrs_nest;
		parg.data = &dst->ip6tnl.emplace();
		if (rt_link_linkinfo_ip6tnl_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "sit") {
		parg.rsp_policy = &rt_link_linkinfo_iptun_attrs_nest;
		parg.data = &dst->sit.emplace();
		if (rt_link_linkinfo_iptun_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "tun") {
		parg.rsp_policy = &rt_link_linkinfo_tun_attrs_nest;
		parg.data = &dst->tun.emplace();
		if (rt_link_linkinfo_tun_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "vlan") {
		parg.rsp_policy = &rt_link_linkinfo_vlan_attrs_nest;
		parg.data = &dst->vlan.emplace();
		if (rt_link_linkinfo_vlan_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "vrf") {
		parg.rsp_policy = &rt_link_linkinfo_vrf_attrs_nest;
		parg.data = &dst->vrf.emplace();
		if (rt_link_linkinfo_vrf_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "vti") {
		parg.rsp_policy = &rt_link_linkinfo_vti_attrs_nest;
		parg.data = &dst->vti.emplace();
		if (rt_link_linkinfo_vti_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "vti6") {
		parg.rsp_policy = &rt_link_linkinfo_vti6_attrs_nest;
		parg.data = &dst->vti6.emplace();
		if (rt_link_linkinfo_vti6_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "netkit") {
		parg.rsp_policy = &rt_link_linkinfo_netkit_attrs_nest;
		parg.data = &dst->netkit.emplace();
		if (rt_link_linkinfo_netkit_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	} else if (sel == "ovpn") {
		parg.rsp_policy = &rt_link_linkinfo_ovpn_attrs_nest;
		parg.data = &dst->ovpn.emplace();
		if (rt_link_linkinfo_ovpn_attrs_parse(&parg, attr)) {
			return YNL_PARSE_CB_ERROR;
		}
	}
	return 0;
}

int rt_link_linkinfo_attrs_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       const rt_link_linkinfo_attrs&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.kind.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_INFO_KIND, obj.kind.data());
	}
	if (obj.data.has_value()) {
		rt_link_linkinfo_data_msg_put(nlh, IFLA_INFO_DATA, obj.data.value());
	}
	if (obj.xstats.size() > 0) {
		ynl_attr_put(nlh, IFLA_INFO_XSTATS, obj.xstats.data(), obj.xstats.size());
	}
	if (obj.slave_kind.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_INFO_SLAVE_KIND, obj.slave_kind.data());
	}
	if (obj.slave_data.has_value()) {
		rt_link_linkinfo_member_data_msg_put(nlh, IFLA_INFO_SLAVE_DATA, obj.slave_data.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int rt_link_linkinfo_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	rt_link_linkinfo_attrs *dst = (rt_link_linkinfo_attrs *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_INFO_KIND) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->kind.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_INFO_DATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_linkinfo_data_msg_nest;
			parg.data = &dst->data;
			if (dst->kind.empty()) {
				return ynl_submsg_failed(yarg, "data", "kind");
			}
			if (rt_link_linkinfo_data_msg_parse(&parg, dst->kind, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_INFO_XSTATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->xstats.assign(data, data + len);
		} else if (type == IFLA_INFO_SLAVE_KIND) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->slave_kind.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_INFO_SLAVE_DATA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_linkinfo_member_data_msg_nest;
			parg.data = &dst->slave_data;
			if (dst->slave_kind.empty()) {
				return ynl_submsg_failed(yarg, "slave-data", "slave-kind");
			}
			if (rt_link_linkinfo_member_data_msg_parse(&parg, dst->slave_kind, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

/* ============== RTM_NEWLINK ============== */
/* RTM_NEWLINK - do */
int rt_link_newlink(ynl_cpp::ynl_socket& ys, rt_link_newlink_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_NEWLINK, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_link_link_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.ifname.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_IFNAME, req.ifname.data());
	}
	if (req.net_ns_pid.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NET_NS_PID, req.net_ns_pid.value());
	}
	if (req.net_ns_fd.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NET_NS_FD, req.net_ns_fd.value());
	}
	if (req.target_netnsid.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_TARGET_NETNSID, req.target_netnsid.value());
	}
	if (req.link_netnsid.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_LINK_NETNSID, req.link_netnsid.value());
	}
	if (req.linkinfo.has_value()) {
		rt_link_linkinfo_attrs_put(nlh, IFLA_LINKINFO, req.linkinfo.value());
	}
	if (req.group.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GROUP, req.group.value());
	}
	if (req.num_tx_queues.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NUM_TX_QUEUES, req.num_tx_queues.value());
	}
	if (req.num_rx_queues.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NUM_RX_QUEUES, req.num_rx_queues.value());
	}
	if (req.address.size() > 0) {
		ynl_attr_put(nlh, IFLA_ADDRESS, req.address.data(), req.address.size());
	}
	if (req.broadcast.size() > 0) {
		ynl_attr_put(nlh, IFLA_BROADCAST, req.broadcast.data(), req.broadcast.size());
	}
	if (req.mtu.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_MTU, req.mtu.value());
	}
	if (req.txqlen.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_TXQLEN, req.txqlen.value());
	}
	if (req.operstate.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_OPERSTATE, req.operstate.value());
	}
	if (req.linkmode.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_LINKMODE, req.linkmode.value());
	}
	if (req.gso_max_size.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GSO_MAX_SIZE, req.gso_max_size.value());
	}
	if (req.gso_max_segs.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GSO_MAX_SEGS, req.gso_max_segs.value());
	}
	if (req.gro_max_size.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRO_MAX_SIZE, req.gro_max_size.value());
	}
	if (req.gso_ipv4_max_size.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GSO_IPV4_MAX_SIZE, req.gso_ipv4_max_size.value());
	}
	if (req.gro_ipv4_max_size.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRO_IPV4_MAX_SIZE, req.gro_ipv4_max_size.value());
	}
	if (req.af_spec.has_value()) {
		rt_link_af_spec_attrs_put(nlh, IFLA_AF_SPEC, req.af_spec.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_DELLINK ============== */
/* RTM_DELLINK - do */
int rt_link_dellink(ynl_cpp::ynl_socket& ys, rt_link_dellink_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_DELLINK, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_link_link_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.ifname.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_IFNAME, req.ifname.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_GETLINK ============== */
/* RTM_GETLINK - do */
int rt_link_getlink_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	rt_link_getlink_rsp *dst;
	void *hdr;

	dst = (rt_link_getlink_rsp*)yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct ifinfomsg));

	ynl_attr_for_each(attr, nlh, sizeof(struct ifinfomsg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_ADDRESS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->address.assign(data, data + len);
		} else if (type == IFLA_BROADCAST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->broadcast.assign(data, data + len);
		} else if (type == IFLA_IFNAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifname.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_MTU) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mtu = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_LINK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_QDISC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->qdisc.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct rtnl_link_stats);
			dst->stats.emplace();
			memcpy(&*dst->stats, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_COST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cost.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_PRIORITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->priority.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_MASTER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->master = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_WIRELESS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->wireless.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_PROTINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->protinfo.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_TXQLEN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->txqlen = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_MAP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct rtnl_link_ifmap);
			dst->map.emplace();
			memcpy(&*dst->map, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_WEIGHT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->weight = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_OPERSTATE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->operstate = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_LINKMODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->linkmode = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_LINKINFO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_linkinfo_attrs_nest;
			parg.data = &dst->linkinfo.emplace();
			if (rt_link_linkinfo_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_NET_NS_PID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->net_ns_pid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_IFALIAS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifalias.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_NUM_VF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->num_vf = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_VFINFO_LIST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_vfinfo_list_attrs_nest;
			parg.data = &dst->vfinfo_list.emplace();
			if (rt_link_vfinfo_list_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_STATS64) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct rtnl_link_stats64);
			dst->stats64.emplace();
			memcpy(&*dst->stats64, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_VF_PORTS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_vf_ports_attrs_nest;
			parg.data = &dst->vf_ports.emplace();
			if (rt_link_vf_ports_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_PORT_SELF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_port_self_attrs_nest;
			parg.data = &dst->port_self.emplace();
			if (rt_link_port_self_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_AF_SPEC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_af_spec_attrs_nest;
			parg.data = &dst->af_spec.emplace();
			if (rt_link_af_spec_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_GROUP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->group = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NET_NS_FD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->net_ns_fd = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_EXT_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ext_mask = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_PROMISCUITY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->promiscuity = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NUM_TX_QUEUES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->num_tx_queues = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NUM_RX_QUEUES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->num_rx_queues = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_CARRIER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->carrier = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_PHYS_PORT_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->phys_port_id.assign(data, data + len);
		} else if (type == IFLA_CARRIER_CHANGES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->carrier_changes = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_PHYS_SWITCH_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->phys_switch_id.assign(data, data + len);
		} else if (type == IFLA_LINK_NETNSID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link_netnsid = (__s32)ynl_attr_get_s32(attr);
		} else if (type == IFLA_PHYS_PORT_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->phys_port_name.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_PROTO_DOWN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->proto_down = (__u8)ynl_attr_get_u8(attr);
		} else if (type == IFLA_GSO_MAX_SEGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gso_max_segs = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GSO_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gso_max_size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_XDP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_xdp_attrs_nest;
			parg.data = &dst->xdp.emplace();
			if (rt_link_xdp_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_EVENT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->event = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NEW_NETNSID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->new_netnsid = (__s32)ynl_attr_get_s32(attr);
		} else if (type == IFLA_TARGET_NETNSID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->target_netnsid = (__s32)ynl_attr_get_s32(attr);
		} else if (type == IFLA_CARRIER_UP_COUNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->carrier_up_count = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_CARRIER_DOWN_COUNT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->carrier_down_count = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_NEW_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->new_ifindex = (__s32)ynl_attr_get_s32(attr);
		} else if (type == IFLA_MIN_MTU) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->min_mtu = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_MAX_MTU) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->max_mtu = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_PROP_LIST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_prop_list_link_attrs_nest;
			parg.data = &dst->prop_list.emplace();
			if (rt_link_prop_list_link_attrs_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_PERM_ADDRESS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->perm_address.assign(data, data + len);
		} else if (type == IFLA_PROTO_DOWN_REASON) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->proto_down_reason.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_PARENT_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->parent_dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_PARENT_DEV_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->parent_dev_bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == IFLA_GRO_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gro_max_size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_TSO_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tso_max_size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_TSO_MAX_SEGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->tso_max_segs = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_ALLMULTI) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->allmulti = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_DEVLINK_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->devlink_port.assign(data, data + len);
		} else if (type == IFLA_GSO_IPV4_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gso_ipv4_max_size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == IFLA_GRO_IPV4_MAX_SIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->gro_ipv4_max_size = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<rt_link_getlink_rsp>
rt_link_getlink(ynl_cpp::ynl_socket& ys, rt_link_getlink_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<rt_link_getlink_rsp> rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETLINK, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_link_link_attrs_nest;
	yrs.yarg.rsp_policy = &rt_link_link_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.ifname.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_IFNAME, req.ifname.data());
	}
	if (req.alt_ifname.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_ALT_IFNAME, req.alt_ifname.data());
	}
	if (req.ext_mask.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_EXT_MASK, req.ext_mask.value());
	}
	if (req.target_netnsid.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_TARGET_NETNSID, req.target_netnsid.value());
	}

	rsp.reset(new rt_link_getlink_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = rt_link_getlink_rsp_parse;
	yrs.rsp_cmd = 16;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* RTM_GETLINK - dump */
std::unique_ptr<rt_link_getlink_list>
rt_link_getlink_dump(ynl_cpp::ynl_socket& ys, rt_link_getlink_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<rt_link_getlink_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_link_link_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<rt_link_getlink_list*>(arg)->objs.emplace_back());};
	yds.cb = rt_link_getlink_rsp_parse;
	yds.rsp_cmd = 16;

	nlh = ynl_msg_start_dump(ys, RTM_GETLINK);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &rt_link_link_attrs_nest;

	if (req.target_netnsid.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_TARGET_NETNSID, req.target_netnsid.value());
	}
	if (req.ext_mask.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_EXT_MASK, req.ext_mask.value());
	}
	if (req.master.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_MASTER, req.master.value());
	}
	if (req.linkinfo.has_value()) {
		rt_link_linkinfo_attrs_put(nlh, IFLA_LINKINFO, req.linkinfo.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* RTM_GETLINK - notify */
static void rt_link_getlink_ntf_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<rt_link_getlink_ntf*>(ntf);
	typed_ntf->obj.~rt_link_getlink_rsp();
	free(ntf);
}

/* ============== RTM_SETLINK ============== */
/* RTM_SETLINK - do */
int rt_link_setlink(ynl_cpp::ynl_socket& ys, rt_link_setlink_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_SETLINK, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_link_link_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	if (req.address.size() > 0) {
		ynl_attr_put(nlh, IFLA_ADDRESS, req.address.data(), req.address.size());
	}
	if (req.broadcast.size() > 0) {
		ynl_attr_put(nlh, IFLA_BROADCAST, req.broadcast.data(), req.broadcast.size());
	}
	if (req.ifname.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_IFNAME, req.ifname.data());
	}
	if (req.mtu.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_MTU, req.mtu.value());
	}
	if (req.link.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_LINK, req.link.value());
	}
	if (req.qdisc.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_QDISC, req.qdisc.data());
	}
	if (req.stats) {
		ynl_attr_put(nlh, IFLA_STATS, &*req.stats, sizeof(struct rtnl_link_stats));
	}
	if (req.cost.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_COST, req.cost.data());
	}
	if (req.priority.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_PRIORITY, req.priority.data());
	}
	if (req.master.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_MASTER, req.master.value());
	}
	if (req.wireless.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_WIRELESS, req.wireless.data());
	}
	if (req.protinfo.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_PROTINFO, req.protinfo.data());
	}
	if (req.txqlen.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_TXQLEN, req.txqlen.value());
	}
	if (req.map) {
		ynl_attr_put(nlh, IFLA_MAP, &*req.map, sizeof(struct rtnl_link_ifmap));
	}
	if (req.weight.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_WEIGHT, req.weight.value());
	}
	if (req.operstate.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_OPERSTATE, req.operstate.value());
	}
	if (req.linkmode.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_LINKMODE, req.linkmode.value());
	}
	if (req.linkinfo.has_value()) {
		rt_link_linkinfo_attrs_put(nlh, IFLA_LINKINFO, req.linkinfo.value());
	}
	if (req.net_ns_pid.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NET_NS_PID, req.net_ns_pid.value());
	}
	if (req.ifalias.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_IFALIAS, req.ifalias.data());
	}
	if (req.num_vf.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NUM_VF, req.num_vf.value());
	}
	if (req.vfinfo_list.has_value()) {
		rt_link_vfinfo_list_attrs_put(nlh, IFLA_VFINFO_LIST, req.vfinfo_list.value());
	}
	if (req.stats64) {
		ynl_attr_put(nlh, IFLA_STATS64, &*req.stats64, sizeof(struct rtnl_link_stats64));
	}
	if (req.vf_ports.has_value()) {
		rt_link_vf_ports_attrs_put(nlh, IFLA_VF_PORTS, req.vf_ports.value());
	}
	if (req.port_self.has_value()) {
		rt_link_port_self_attrs_put(nlh, IFLA_PORT_SELF, req.port_self.value());
	}
	if (req.af_spec.has_value()) {
		rt_link_af_spec_attrs_put(nlh, IFLA_AF_SPEC, req.af_spec.value());
	}
	if (req.group.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GROUP, req.group.value());
	}
	if (req.net_ns_fd.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NET_NS_FD, req.net_ns_fd.value());
	}
	if (req.ext_mask.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_EXT_MASK, req.ext_mask.value());
	}
	if (req.promiscuity.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_PROMISCUITY, req.promiscuity.value());
	}
	if (req.num_tx_queues.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NUM_TX_QUEUES, req.num_tx_queues.value());
	}
	if (req.num_rx_queues.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_NUM_RX_QUEUES, req.num_rx_queues.value());
	}
	if (req.carrier.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_CARRIER, req.carrier.value());
	}
	if (req.phys_port_id.size() > 0) {
		ynl_attr_put(nlh, IFLA_PHYS_PORT_ID, req.phys_port_id.data(), req.phys_port_id.size());
	}
	if (req.carrier_changes.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_CARRIER_CHANGES, req.carrier_changes.value());
	}
	if (req.phys_switch_id.size() > 0) {
		ynl_attr_put(nlh, IFLA_PHYS_SWITCH_ID, req.phys_switch_id.data(), req.phys_switch_id.size());
	}
	if (req.link_netnsid.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_LINK_NETNSID, req.link_netnsid.value());
	}
	if (req.phys_port_name.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_PHYS_PORT_NAME, req.phys_port_name.data());
	}
	if (req.proto_down.has_value()) {
		ynl_attr_put_u8(nlh, IFLA_PROTO_DOWN, req.proto_down.value());
	}
	if (req.gso_max_segs.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GSO_MAX_SEGS, req.gso_max_segs.value());
	}
	if (req.gso_max_size.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GSO_MAX_SIZE, req.gso_max_size.value());
	}
	if (req.xdp.has_value()) {
		rt_link_xdp_attrs_put(nlh, IFLA_XDP, req.xdp.value());
	}
	if (req.event.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_EVENT, req.event.value());
	}
	if (req.new_netnsid.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_NEW_NETNSID, req.new_netnsid.value());
	}
	if (req.target_netnsid.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_TARGET_NETNSID, req.target_netnsid.value());
	}
	if (req.carrier_up_count.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_CARRIER_UP_COUNT, req.carrier_up_count.value());
	}
	if (req.carrier_down_count.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_CARRIER_DOWN_COUNT, req.carrier_down_count.value());
	}
	if (req.new_ifindex.has_value()) {
		ynl_attr_put_s32(nlh, IFLA_NEW_IFINDEX, req.new_ifindex.value());
	}
	if (req.min_mtu.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_MIN_MTU, req.min_mtu.value());
	}
	if (req.max_mtu.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_MAX_MTU, req.max_mtu.value());
	}
	if (req.prop_list.has_value()) {
		rt_link_prop_list_link_attrs_put(nlh, IFLA_PROP_LIST, req.prop_list.value());
	}
	if (req.perm_address.size() > 0) {
		ynl_attr_put(nlh, IFLA_PERM_ADDRESS, req.perm_address.data(), req.perm_address.size());
	}
	if (req.proto_down_reason.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_PROTO_DOWN_REASON, req.proto_down_reason.data());
	}
	if (req.parent_dev_name.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_PARENT_DEV_NAME, req.parent_dev_name.data());
	}
	if (req.parent_dev_bus_name.size() > 0) {
		ynl_attr_put_str(nlh, IFLA_PARENT_DEV_BUS_NAME, req.parent_dev_bus_name.data());
	}
	if (req.gro_max_size.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRO_MAX_SIZE, req.gro_max_size.value());
	}
	if (req.tso_max_size.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_TSO_MAX_SIZE, req.tso_max_size.value());
	}
	if (req.tso_max_segs.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_TSO_MAX_SEGS, req.tso_max_segs.value());
	}
	if (req.allmulti.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_ALLMULTI, req.allmulti.value());
	}
	if (req.devlink_port.size() > 0) {
		ynl_attr_put(nlh, IFLA_DEVLINK_PORT, req.devlink_port.data(), req.devlink_port.size());
	}
	if (req.gso_ipv4_max_size.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GSO_IPV4_MAX_SIZE, req.gso_ipv4_max_size.value());
	}
	if (req.gro_ipv4_max_size.has_value()) {
		ynl_attr_put_u32(nlh, IFLA_GRO_IPV4_MAX_SIZE, req.gro_ipv4_max_size.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== RTM_GETSTATS ============== */
/* RTM_GETSTATS - do */
int rt_link_getstats_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	rt_link_getstats_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	void *hdr;

	dst = (rt_link_getstats_rsp*)yarg->data;
	parg.ys = yarg->ys;

	hdr = ynl_nlmsg_data(nlh);
	memcpy(&dst->_hdr, hdr, sizeof(struct if_stats_msg));

	ynl_attr_for_each(attr, nlh, sizeof(struct if_stats_msg)) {
		unsigned int type = ynl_attr_type(attr);

		if (type == IFLA_STATS_LINK_64) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			unsigned int struct_sz = sizeof(struct rtnl_link_stats64);
			dst->link_64.emplace();
			memcpy(&*dst->link_64, ynl_attr_data(attr), std::min(struct_sz, len));
		} else if (type == IFLA_STATS_LINK_XSTATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->link_xstats.assign(data, data + len);
		} else if (type == IFLA_STATS_LINK_XSTATS_SLAVE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->link_xstats_slave.assign(data, data + len);
		} else if (type == IFLA_STATS_LINK_OFFLOAD_XSTATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &rt_link_link_offload_xstats_nest;
			parg.data = &dst->link_offload_xstats.emplace();
			if (rt_link_link_offload_xstats_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == IFLA_STATS_AF_SPEC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->af_spec.assign(data, data + len);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<rt_link_getstats_rsp>
rt_link_getstats(ynl_cpp::ynl_socket& ys, rt_link_getstats_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<rt_link_getstats_rsp> rsp;
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	nlh = ynl_msg_start_req(ys, RTM_GETSTATS, req._nlmsg_flags);
	((struct ynl_sock*)ys)->req_policy = &rt_link_stats_attrs_nest;
	yrs.yarg.rsp_policy = &rt_link_stats_attrs_nest;

	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	rsp.reset(new rt_link_getstats_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = rt_link_getstats_rsp_parse;
	yrs.rsp_cmd = 92;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* RTM_GETSTATS - dump */
std::unique_ptr<rt_link_getstats_list>
rt_link_getstats_dump(ynl_cpp::ynl_socket& ys, rt_link_getstats_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	size_t hdr_len;
	void *hdr;
	int err;

	auto ret = std::make_unique<rt_link_getstats_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &rt_link_stats_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<rt_link_getstats_list*>(arg)->objs.emplace_back());};
	yds.cb = rt_link_getstats_rsp_parse;
	yds.rsp_cmd = 92;

	nlh = ynl_msg_start_dump(ys, RTM_GETSTATS);
	hdr_len = sizeof(req._hdr);
	hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);
	memcpy(hdr, &req._hdr, hdr_len);

	((struct ynl_sock*)ys)->req_policy = &rt_link_stats_attrs_nest;

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

static constexpr std::array<ynl_ntf_info, RTM_NEWLINK + 1> rt_link_ntf_info = []() {
	std::array<ynl_ntf_info, RTM_NEWLINK + 1> arr{};
	arr[RTM_NEWLINK].policy		= &rt_link_link_attrs_nest;
	arr[RTM_NEWLINK].cb		= rt_link_getlink_rsp_parse;
	arr[RTM_NEWLINK].alloc_sz	= sizeof(rt_link_getlink_ntf);
	arr[RTM_NEWLINK].free		= rt_link_getlink_ntf_free;
	return arr;
} ();

const struct ynl_family ynl_rt_link_family =  {
	.name		= "rt_link",
	.is_classic	= true,
	.classic_id	= 0,
	.ntf_info	= rt_link_ntf_info.data(),
	.ntf_info_size	= rt_link_ntf_info.size(),
};
const struct ynl_family& get_ynl_rt_link_family() {
	return ynl_rt_link_family;
};
} //namespace ynl_cpp
