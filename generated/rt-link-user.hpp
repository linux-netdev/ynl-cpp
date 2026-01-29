/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_RT_LINK_GEN_H
#define _LINUX_RT_LINK_GEN_H

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

#include <linux/dpll.h>
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>
#include <linux/rtnetlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_rt_link_family();

/* Enums */
std::string_view rt_link_op_str(int op);
std::string_view rt_link_ifinfo_flags_str(net_device_flags value);
std::string_view rt_link_vlan_protocols_str(int value);
std::string_view rt_link_ipv4_devconf_str(int value);
std::string_view rt_link_ipv6_devconf_str(int value);
std::string_view rt_link_ifla_icmp6_stats_str(int value);
std::string_view rt_link_ifla_inet6_stats_str(int value);
std::string_view rt_link_vlan_flags_str(int value);
std::string_view rt_link_ifla_vf_link_state_enum_str(int value);
std::string_view rt_link_rtext_filter_str(int value);
std::string_view rt_link_netkit_policy_str(int value);
std::string_view rt_link_netkit_mode_str(netkit_mode value);
std::string_view rt_link_netkit_scrub_str(int value);
std::string_view rt_link_ovpn_mode_str(ovpn_mode value);

/* Common nested types */
struct rt_link_vf_ports_attrs {
};

struct rt_link_port_self_attrs {
};

struct rt_link_xdp_attrs {
	std::optional<__s32> fd;
	std::optional<__u8> attached;
	std::optional<__u32> flags;
	std::optional<__u32> prog_id;
	std::optional<__u32> drv_prog_id;
	std::optional<__u32> skb_prog_id;
	std::optional<__u32> hw_prog_id;
	std::optional<__s32> expected_fd;
};

struct rt_link_prop_list_link_attrs {
	std::string alt_ifname;
};

struct rt_link_link_dpll_pin_attrs {
	std::optional<__u32> id;
};

struct rt_link_ifla_attrs {
	std::vector<__u8> conf;
};

struct rt_link_ifla6_attrs {
	std::optional<__u32> flags;
	std::vector<__u8> conf;
	std::vector<__u8> stats;
	std::vector<__u8> mcast;
	std::optional<struct ifla_cacheinfo> cacheinfo;
	std::vector<__u8> icmp6stats;
	std::vector<__u8> token;
	std::optional<__u8> addr_gen_mode;
	std::optional<__u32> ra_mtu;
};

struct rt_link_mctp_attrs {
	std::optional<__u32> net;
	std::optional<__u8> phys_binding;
};

struct rt_link_hw_s_info_one {
	std::optional<__u32> idx;
	std::optional<__u8> request;
	std::optional<__u8> used;
};

struct rt_link_linkinfo_bridge_attrs {
	std::optional<__u32> forward_delay;
	std::optional<__u32> hello_time;
	std::optional<__u32> max_age;
	std::optional<__u32> ageing_time;
	std::optional<__u32> stp_state;
	std::optional<__u16> priority;
	std::optional<__u8> vlan_filtering;
	std::optional<__u16> vlan_protocol;
	std::optional<__u16> group_fwd_mask;
	std::optional<struct ifla_bridge_id> root_id;
	std::optional<struct ifla_bridge_id> bridge_id;
	std::optional<__u16> root_port;
	std::optional<__u32> root_path_cost;
	std::optional<__u8> topology_change;
	std::optional<__u8> topology_change_detected;
	std::optional<__u64> hello_timer;
	std::optional<__u64> tcn_timer;
	std::optional<__u64> topology_change_timer;
	std::optional<__u64> gc_timer;
	std::vector<__u8> group_addr;
	std::vector<__u8> fdb_flush;
	std::optional<__u8> mcast_router;
	std::optional<__u8> mcast_snooping;
	std::optional<__u8> mcast_query_use_ifaddr;
	std::optional<__u8> mcast_querier;
	std::optional<__u32> mcast_hash_elasticity;
	std::optional<__u32> mcast_hash_max;
	std::optional<__u32> mcast_last_member_cnt;
	std::optional<__u32> mcast_startup_query_cnt;
	std::optional<__u64> mcast_last_member_intvl;
	std::optional<__u64> mcast_membership_intvl;
	std::optional<__u64> mcast_querier_intvl;
	std::optional<__u64> mcast_query_intvl;
	std::optional<__u64> mcast_query_response_intvl;
	std::optional<__u64> mcast_startup_query_intvl;
	std::optional<__u8> nf_call_iptables;
	std::optional<__u8> nf_call_ip6tables;
	std::optional<__u8> nf_call_arptables;
	std::optional<__u16> vlan_default_pvid;
	std::optional<__u8> vlan_stats_enabled;
	std::optional<__u8> mcast_stats_enabled;
	std::optional<__u8> mcast_igmp_version;
	std::optional<__u8> mcast_mld_version;
	std::optional<__u8> vlan_stats_per_port;
	std::optional<struct br_boolopt_multi> multi_boolopt;
	std::vector<__u8> mcast_querier_state;
	std::optional<__u32> fdb_n_learned;
	std::optional<__u32> fdb_max_learned;
};

struct rt_link_linkinfo_gre_attrs {
	std::optional<__u32> link;
	std::optional<__u16> iflags /* big-endian */;
	std::optional<__u16> oflags /* big-endian */;
	std::optional<__u32> ikey /* big-endian */;
	std::optional<__u32> okey /* big-endian */;
	std::vector<__u8> local;
	std::vector<__u8> remote;
	std::optional<__u8> ttl;
	std::optional<__u8> tos;
	std::optional<__u8> pmtudisc;
	std::optional<__u8> encap_limit;
	std::optional<__u32> flowinfo /* big-endian */;
	std::optional<__u32> flags;
	std::optional<__u16> encap_type;
	std::optional<__u16> encap_flags;
	std::optional<__u16> encap_sport /* big-endian */;
	std::optional<__u16> encap_dport /* big-endian */;
	bool collect_metadata{};
	std::optional<__u8> ignore_df;
	std::optional<__u32> fwmark;
	std::optional<__u32> erspan_index;
	std::optional<__u8> erspan_ver;
	std::optional<__u8> erspan_dir;
	std::optional<__u16> erspan_hwid;
};

struct rt_link_linkinfo_gre6_attrs {
	std::optional<__u32> link;
	std::optional<__u16> iflags /* big-endian */;
	std::optional<__u16> oflags /* big-endian */;
	std::optional<__u32> ikey /* big-endian */;
	std::optional<__u32> okey /* big-endian */;
	std::vector<__u8> local;
	std::vector<__u8> remote;
	std::optional<__u8> ttl;
	std::optional<__u8> encap_limit;
	std::optional<__u32> flowinfo /* big-endian */;
	std::optional<__u32> flags;
	std::optional<__u16> encap_type;
	std::optional<__u16> encap_flags;
	std::optional<__u16> encap_sport /* big-endian */;
	std::optional<__u16> encap_dport /* big-endian */;
	bool collect_metadata{};
	std::optional<__u32> fwmark;
	std::optional<__u32> erspan_index;
	std::optional<__u8> erspan_ver;
	std::optional<__u8> erspan_dir;
	std::optional<__u16> erspan_hwid;
};

struct rt_link_linkinfo_geneve_attrs {
	std::optional<__u32> id;
	std::vector<__u8> remote;
	std::optional<__u8> ttl;
	std::optional<__u8> tos;
	std::optional<__u16> port /* big-endian */;
	bool collect_metadata{};
	std::vector<__u8> remote6;
	std::optional<__u8> udp_csum;
	std::optional<__u8> udp_zero_csum6_tx;
	std::optional<__u8> udp_zero_csum6_rx;
	std::optional<__u32> label /* big-endian */;
	std::optional<__u8> ttl_inherit;
	std::optional<__u8> df;
	bool inner_proto_inherit{};
	std::optional<struct ifla_geneve_port_range> port_range;
};

struct rt_link_linkinfo_iptun_attrs {
	std::optional<__u32> link;
	std::vector<__u8> local;
	std::vector<__u8> remote;
	std::optional<__u8> ttl;
	std::optional<__u8> tos;
	std::optional<__u8> encap_limit;
	std::optional<__u32> flowinfo /* big-endian */;
	std::optional<__u16> flags /* big-endian */;
	std::optional<__u8> proto;
	std::optional<__u8> pmtudisc;
	std::vector<__u8> _6rd_prefix;
	std::vector<__u8> _6rd_relay_prefix;
	std::optional<__u16> _6rd_prefixlen;
	std::optional<__u16> _6rd_relay_prefixlen;
	std::optional<__u16> encap_type;
	std::optional<__u16> encap_flags;
	std::optional<__u16> encap_sport /* big-endian */;
	std::optional<__u16> encap_dport /* big-endian */;
	bool collect_metadata{};
	std::optional<__u32> fwmark;
};

struct rt_link_linkinfo_ip6tnl_attrs {
	std::optional<__u32> link;
	std::vector<__u8> local;
	std::vector<__u8> remote;
	std::optional<__u8> ttl;
	std::optional<__u8> encap_limit;
	std::optional<__u32> flowinfo /* big-endian */;
	std::optional<__u16> flags /* big-endian */;
	std::optional<__u8> proto;
	std::optional<__u16> encap_type;
	std::optional<__u16> encap_flags;
	std::optional<__u16> encap_sport /* big-endian */;
	std::optional<__u16> encap_dport /* big-endian */;
	bool collect_metadata{};
	std::optional<__u32> fwmark;
};

struct rt_link_linkinfo_tun_attrs {
	std::optional<__u32> owner;
	std::optional<__u32> group;
	std::optional<__u8> type;
	std::optional<__u8> pi;
	std::optional<__u8> vnet_hdr;
	std::optional<__u8> persist;
	std::optional<__u8> multi_queue;
	std::optional<__u32> num_queues;
	std::optional<__u32> num_disabled_queues;
};

struct rt_link_linkinfo_vrf_attrs {
	std::optional<__u32> table;
};

struct rt_link_linkinfo_vti_attrs {
	std::optional<__u32> link;
	std::optional<__u32> ikey /* big-endian */;
	std::optional<__u32> okey /* big-endian */;
	std::vector<__u8> local;
	std::vector<__u8> remote;
	std::optional<__u32> fwmark;
};

struct rt_link_linkinfo_vti6_attrs {
	std::optional<__u32> link;
	std::optional<__u32> ikey /* big-endian */;
	std::optional<__u32> okey /* big-endian */;
	std::vector<__u8> local;
	std::vector<__u8> remote;
	std::optional<__u32> fwmark;
};

struct rt_link_linkinfo_netkit_attrs {
	std::vector<__u8> peer_info;
	std::optional<__u8> primary;
	std::optional<int> policy;
	std::optional<int> peer_policy;
	std::optional<enum netkit_mode> mode;
	std::optional<int> scrub;
	std::optional<int> peer_scrub;
	std::optional<__u16> headroom;
	std::optional<__u16> tailroom;
};

struct rt_link_linkinfo_ovpn_attrs {
	std::optional<enum ovpn_mode> mode;
};

struct rt_link_linkinfo_brport_attrs {
	std::optional<__u8> state;
	std::optional<__u16> priority;
	std::optional<__u32> cost;
	bool mode{};
	bool guard{};
	bool protect{};
	bool fast_leave{};
	bool learning{};
	bool unicast_flood{};
	bool proxyarp{};
	bool learning_sync{};
	bool proxyarp_wifi{};
	std::optional<struct ifla_bridge_id> root_id;
	std::optional<struct ifla_bridge_id> bridge_id;
	std::optional<__u16> designated_port;
	std::optional<__u16> designated_cost;
	std::optional<__u16> id;
	std::optional<__u16> no;
	std::optional<__u8> topology_change_ack;
	std::optional<__u8> config_pending;
	std::optional<__u64> message_age_timer;
	std::optional<__u64> forward_delay_timer;
	std::optional<__u64> hold_timer;
	bool flush{};
	std::optional<__u8> multicast_router;
	bool mcast_flood{};
	bool mcast_to_ucast{};
	bool vlan_tunnel{};
	bool bcast_flood{};
	std::optional<__u16> group_fwd_mask;
	bool neigh_suppress{};
	bool isolated{};
	std::optional<__u32> backup_port;
	bool mrp_ring_open{};
	bool mrp_in_open{};
	std::optional<__u32> mcast_eht_hosts_limit;
	std::optional<__u32> mcast_eht_hosts_cnt;
	bool locked{};
	bool mab{};
	std::optional<__u32> mcast_n_groups;
	std::optional<__u32> mcast_max_groups;
	bool neigh_vlan_suppress{};
	std::optional<__u32> backup_nhid;
};

struct rt_link_bond_slave_attrs {
	std::optional<__u8> state;
	std::optional<__u8> mii_status;
	std::optional<__u32> link_failure_count;
	std::vector<__u8> perm_hwaddr;
	std::optional<__u16> queue_id;
	std::optional<__u16> ad_aggregator_id;
	std::optional<__u8> ad_actor_oper_port_state;
	std::optional<__u16> ad_partner_oper_port_state;
	std::optional<__u32> prio;
};

struct rt_link_vf_stats_attrs {
	std::optional<__u64> rx_packets;
	std::optional<__u64> tx_packets;
	std::optional<__u64> rx_bytes;
	std::optional<__u64> tx_bytes;
	std::optional<__u64> broadcast;
	std::optional<__u64> multicast;
	std::optional<__u64> rx_dropped;
	std::optional<__u64> tx_dropped;
};

struct rt_link_vf_vlan_attrs {
	std::vector<struct ifla_vf_vlan_info> info;
};

struct rt_link_bond_ad_info_attrs {
	std::optional<__u16> aggregator;
	std::optional<__u16> num_ports;
	std::optional<__u16> actor_key;
	std::optional<__u16> partner_key;
	std::vector<__u8> partner_mac;
};

struct rt_link_ifla_vlan_qos {
	std::vector<struct ifla_vlan_qos_mapping> mapping;
};

struct rt_link_af_spec_attrs {
	std::optional<rt_link_ifla_attrs> inet;
	std::optional<rt_link_ifla6_attrs> inet6;
	std::optional<rt_link_mctp_attrs> mctp;
};

struct rt_link_link_offload_xstats {
	std::vector<__u8> cpu_hit;
	std::vector<rt_link_hw_s_info_one> hw_s_info;
	std::vector<__u8> l3_stats;
};

struct rt_link_linkinfo_member_data_msg {
	std::optional<rt_link_linkinfo_brport_attrs> bridge;
	std::optional<rt_link_bond_slave_attrs> bond;
};

struct rt_link_vfinfo_attrs {
	std::optional<struct ifla_vf_mac> mac;
	std::optional<struct ifla_vf_vlan> vlan;
	std::optional<struct ifla_vf_tx_rate> tx_rate;
	std::optional<struct ifla_vf_spoofchk> spoofchk;
	std::optional<struct ifla_vf_link_state> link_state;
	std::optional<struct ifla_vf_rate> rate;
	std::optional<struct ifla_vf_rss_query_en> rss_query_en;
	std::optional<rt_link_vf_stats_attrs> stats;
	std::optional<struct ifla_vf_trust> trust;
	std::optional<struct ifla_vf_guid> ib_node_guid;
	std::optional<struct ifla_vf_guid> ib_port_guid;
	std::optional<rt_link_vf_vlan_attrs> vlan_list;
	std::vector<__u8> broadcast;
};

struct rt_link_linkinfo_bond_attrs {
	std::optional<__u8> mode;
	std::optional<__u32> active_slave;
	std::optional<__u32> miimon;
	std::optional<__u32> updelay;
	std::optional<__u32> downdelay;
	std::optional<__u8> use_carrier;
	std::optional<__u32> arp_interval;
	std::vector<__u32> arp_ip_target;
	std::optional<__u32> arp_validate;
	std::optional<__u32> arp_all_targets;
	std::optional<__u32> primary;
	std::optional<__u8> primary_reselect;
	std::optional<__u8> fail_over_mac;
	std::optional<__u8> xmit_hash_policy;
	std::optional<__u32> resend_igmp;
	std::optional<__u8> num_peer_notif;
	std::optional<__u8> all_slaves_active;
	std::optional<__u32> min_links;
	std::optional<__u32> lp_interval;
	std::optional<__u32> packets_per_slave;
	std::optional<__u8> ad_lacp_rate;
	std::optional<__u8> ad_select;
	std::optional<rt_link_bond_ad_info_attrs> ad_info;
	std::optional<__u16> ad_actor_sys_prio;
	std::optional<__u16> ad_user_port_key;
	std::vector<__u8> ad_actor_system;
	std::optional<__u8> tlb_dynamic_lb;
	std::optional<__u32> peer_notif_delay;
	std::optional<__u8> ad_lacp_active;
	std::optional<__u8> missed_max;
	std::vector<std::array<__u8, 16>> ns_ip6_target;
	std::optional<__u8> coupled_control;
};

struct rt_link_linkinfo_vlan_attrs {
	std::optional<__u16> id;
	std::optional<struct ifla_vlan_flags> flags;
	std::optional<rt_link_ifla_vlan_qos> egress_qos;
	std::optional<rt_link_ifla_vlan_qos> ingress_qos;
	std::optional<int> protocol /* big-endian */;
};

struct rt_link_vfinfo_list_attrs {
	std::vector<rt_link_vfinfo_attrs> info;
};

struct rt_link_linkinfo_data_msg {
	std::optional<rt_link_linkinfo_bond_attrs> bond;
	std::optional<rt_link_linkinfo_bridge_attrs> bridge;
	std::optional<rt_link_linkinfo_gre_attrs> erspan;
	std::optional<rt_link_linkinfo_gre_attrs> gre;
	std::optional<rt_link_linkinfo_gre_attrs> gretap;
	std::optional<rt_link_linkinfo_gre6_attrs> ip6gre;
	std::optional<rt_link_linkinfo_geneve_attrs> geneve;
	std::optional<rt_link_linkinfo_iptun_attrs> ipip;
	std::optional<rt_link_linkinfo_ip6tnl_attrs> ip6tnl;
	std::optional<rt_link_linkinfo_iptun_attrs> sit;
	std::optional<rt_link_linkinfo_tun_attrs> tun;
	std::optional<rt_link_linkinfo_vlan_attrs> vlan;
	std::optional<rt_link_linkinfo_vrf_attrs> vrf;
	std::optional<rt_link_linkinfo_vti_attrs> vti;
	std::optional<rt_link_linkinfo_vti6_attrs> vti6;
	std::optional<rt_link_linkinfo_netkit_attrs> netkit;
	std::optional<rt_link_linkinfo_ovpn_attrs> ovpn;
};

struct rt_link_linkinfo_attrs {
	std::string kind;
	std::optional<rt_link_linkinfo_data_msg> data;
	std::vector<__u8> xstats;
	std::string slave_kind;
	std::optional<rt_link_linkinfo_member_data_msg> slave_data;
};

/* ============== RTM_NEWLINK ============== */
/* RTM_NEWLINK - do */
struct rt_link_newlink_req {
	__u16 _nlmsg_flags;

	struct ifinfomsg _hdr;

	std::string ifname;
	std::optional<__u32> net_ns_pid;
	std::optional<__u32> net_ns_fd;
	std::optional<__s32> target_netnsid;
	std::optional<__s32> link_netnsid;
	std::optional<rt_link_linkinfo_attrs> linkinfo;
	std::optional<__u32> group;
	std::optional<__u32> num_tx_queues;
	std::optional<__u32> num_rx_queues;
	std::vector<__u8> address;
	std::vector<__u8> broadcast;
	std::optional<__u32> mtu;
	std::optional<__u32> txqlen;
	std::optional<__u8> operstate;
	std::optional<__u8> linkmode;
	std::optional<__u32> gso_max_size;
	std::optional<__u32> gso_max_segs;
	std::optional<__u32> gro_max_size;
	std::optional<__u32> gso_ipv4_max_size;
	std::optional<__u32> gro_ipv4_max_size;
	std::optional<rt_link_af_spec_attrs> af_spec;
};

/*
 * Create a new link.
 */
int rt_link_newlink(ynl_cpp::ynl_socket& ys, rt_link_newlink_req& req);

/* ============== RTM_DELLINK ============== */
/* RTM_DELLINK - do */
struct rt_link_dellink_req {
	__u16 _nlmsg_flags;

	struct ifinfomsg _hdr;

	std::string ifname;
};

/*
 * Delete an existing link.
 */
int rt_link_dellink(ynl_cpp::ynl_socket& ys, rt_link_dellink_req& req);

/* ============== RTM_GETLINK ============== */
/* RTM_GETLINK - do */
struct rt_link_getlink_req {
	__u16 _nlmsg_flags;

	struct ifinfomsg _hdr;

	std::string ifname;
	std::string alt_ifname;
	std::optional<__u32> ext_mask;
	std::optional<__s32> target_netnsid;
};

struct rt_link_getlink_rsp {
	struct ifinfomsg _hdr;

	std::vector<__u8> address;
	std::vector<__u8> broadcast;
	std::string ifname;
	std::optional<__u32> mtu;
	std::optional<__u32> link;
	std::string qdisc;
	std::optional<struct rtnl_link_stats> stats;
	std::string cost;
	std::string priority;
	std::optional<__u32> master;
	std::string wireless;
	std::string protinfo;
	std::optional<__u32> txqlen;
	std::optional<struct rtnl_link_ifmap> map;
	std::optional<__u32> weight;
	std::optional<__u8> operstate;
	std::optional<__u8> linkmode;
	std::optional<rt_link_linkinfo_attrs> linkinfo;
	std::optional<__u32> net_ns_pid;
	std::string ifalias;
	std::optional<__u32> num_vf;
	std::optional<rt_link_vfinfo_list_attrs> vfinfo_list;
	std::optional<struct rtnl_link_stats64> stats64;
	std::optional<rt_link_vf_ports_attrs> vf_ports;
	std::optional<rt_link_port_self_attrs> port_self;
	std::optional<rt_link_af_spec_attrs> af_spec;
	std::optional<__u32> group;
	std::optional<__u32> net_ns_fd;
	std::optional<__u32> ext_mask;
	std::optional<__u32> promiscuity;
	std::optional<__u32> num_tx_queues;
	std::optional<__u32> num_rx_queues;
	std::optional<__u8> carrier;
	std::vector<__u8> phys_port_id;
	std::optional<__u32> carrier_changes;
	std::vector<__u8> phys_switch_id;
	std::optional<__s32> link_netnsid;
	std::string phys_port_name;
	std::optional<__u8> proto_down;
	std::optional<__u32> gso_max_segs;
	std::optional<__u32> gso_max_size;
	std::optional<rt_link_xdp_attrs> xdp;
	std::optional<__u32> event;
	std::optional<__s32> new_netnsid;
	std::optional<__s32> target_netnsid;
	std::optional<__u32> carrier_up_count;
	std::optional<__u32> carrier_down_count;
	std::optional<__s32> new_ifindex;
	std::optional<__u32> min_mtu;
	std::optional<__u32> max_mtu;
	std::optional<rt_link_prop_list_link_attrs> prop_list;
	std::vector<__u8> perm_address;
	std::string proto_down_reason;
	std::string parent_dev_name;
	std::string parent_dev_bus_name;
	std::optional<__u32> gro_max_size;
	std::optional<__u32> tso_max_size;
	std::optional<__u32> tso_max_segs;
	std::optional<__u32> allmulti;
	std::vector<__u8> devlink_port;
	std::optional<__u32> gso_ipv4_max_size;
	std::optional<__u32> gro_ipv4_max_size;
};

/*
 * Get / dump information about a link.
 */
std::unique_ptr<rt_link_getlink_rsp>
rt_link_getlink(ynl_cpp::ynl_socket& ys, rt_link_getlink_req& req);

/* RTM_GETLINK - dump */
struct rt_link_getlink_req_dump {
	struct ifinfomsg _hdr;

	std::optional<__s32> target_netnsid;
	std::optional<__u32> ext_mask;
	std::optional<__u32> master;
	std::optional<rt_link_linkinfo_attrs> linkinfo;
};

struct rt_link_getlink_list {
	std::list<rt_link_getlink_rsp> objs;
};

std::unique_ptr<rt_link_getlink_list>
rt_link_getlink_dump(ynl_cpp::ynl_socket& ys, rt_link_getlink_req_dump& req);

/* RTM_GETLINK - notify */
struct rt_link_getlink_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	rt_link_getlink_rsp obj __attribute__((aligned(8)));
};

/* ============== RTM_SETLINK ============== */
/* RTM_SETLINK - do */
struct rt_link_setlink_req {
	__u16 _nlmsg_flags;

	struct ifinfomsg _hdr;

	std::vector<__u8> address;
	std::vector<__u8> broadcast;
	std::string ifname;
	std::optional<__u32> mtu;
	std::optional<__u32> link;
	std::string qdisc;
	std::optional<struct rtnl_link_stats> stats;
	std::string cost;
	std::string priority;
	std::optional<__u32> master;
	std::string wireless;
	std::string protinfo;
	std::optional<__u32> txqlen;
	std::optional<struct rtnl_link_ifmap> map;
	std::optional<__u32> weight;
	std::optional<__u8> operstate;
	std::optional<__u8> linkmode;
	std::optional<rt_link_linkinfo_attrs> linkinfo;
	std::optional<__u32> net_ns_pid;
	std::string ifalias;
	std::optional<__u32> num_vf;
	std::optional<rt_link_vfinfo_list_attrs> vfinfo_list;
	std::optional<struct rtnl_link_stats64> stats64;
	std::optional<rt_link_vf_ports_attrs> vf_ports;
	std::optional<rt_link_port_self_attrs> port_self;
	std::optional<rt_link_af_spec_attrs> af_spec;
	std::optional<__u32> group;
	std::optional<__u32> net_ns_fd;
	std::optional<__u32> ext_mask;
	std::optional<__u32> promiscuity;
	std::optional<__u32> num_tx_queues;
	std::optional<__u32> num_rx_queues;
	std::optional<__u8> carrier;
	std::vector<__u8> phys_port_id;
	std::optional<__u32> carrier_changes;
	std::vector<__u8> phys_switch_id;
	std::optional<__s32> link_netnsid;
	std::string phys_port_name;
	std::optional<__u8> proto_down;
	std::optional<__u32> gso_max_segs;
	std::optional<__u32> gso_max_size;
	std::optional<rt_link_xdp_attrs> xdp;
	std::optional<__u32> event;
	std::optional<__s32> new_netnsid;
	std::optional<__s32> target_netnsid;
	std::optional<__u32> carrier_up_count;
	std::optional<__u32> carrier_down_count;
	std::optional<__s32> new_ifindex;
	std::optional<__u32> min_mtu;
	std::optional<__u32> max_mtu;
	std::optional<rt_link_prop_list_link_attrs> prop_list;
	std::vector<__u8> perm_address;
	std::string proto_down_reason;
	std::string parent_dev_name;
	std::string parent_dev_bus_name;
	std::optional<__u32> gro_max_size;
	std::optional<__u32> tso_max_size;
	std::optional<__u32> tso_max_segs;
	std::optional<__u32> allmulti;
	std::vector<__u8> devlink_port;
	std::optional<__u32> gso_ipv4_max_size;
	std::optional<__u32> gro_ipv4_max_size;
};

/*
 * Set information about a link.
 */
int rt_link_setlink(ynl_cpp::ynl_socket& ys, rt_link_setlink_req& req);

/* ============== RTM_GETSTATS ============== */
/* RTM_GETSTATS - do */
struct rt_link_getstats_req {
	__u16 _nlmsg_flags;

	struct if_stats_msg _hdr;
};

struct rt_link_getstats_rsp {
	struct if_stats_msg _hdr;

	std::optional<struct rtnl_link_stats64> link_64;
	std::vector<__u8> link_xstats;
	std::vector<__u8> link_xstats_slave;
	std::optional<rt_link_link_offload_xstats> link_offload_xstats;
	std::vector<__u8> af_spec;
};

/*
 * Get / dump link stats.
 */
std::unique_ptr<rt_link_getstats_rsp>
rt_link_getstats(ynl_cpp::ynl_socket& ys, rt_link_getstats_req& req);

/* RTM_GETSTATS - dump */
struct rt_link_getstats_req_dump {
	struct if_stats_msg _hdr;
};

struct rt_link_getstats_list {
	std::list<rt_link_getstats_rsp> objs;
};

std::unique_ptr<rt_link_getstats_list>
rt_link_getstats_dump(ynl_cpp::ynl_socket& ys, rt_link_getstats_req_dump& req);

} //namespace ynl_cpp
#endif /* _LINUX_RT_LINK_GEN_H */
