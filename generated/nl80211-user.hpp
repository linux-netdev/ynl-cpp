/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_NL80211_GEN_H
#define _LINUX_NL80211_GEN_H

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

#include <linux/nl80211.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_nl80211_family();

/* Enums */
std::string_view nl80211_op_str(int op);
std::string_view nl80211_commands_str(nl80211_commands value);
std::string_view nl80211_feature_flags_str(nl80211_feature_flags value);
std::string_view nl80211_channel_type_str(nl80211_channel_type value);
std::string_view
nl80211_protocol_features_str(nl80211_protocol_features value);

/* Common nested types */
struct nl80211_supported_iftypes {
	bool adhoc{};
	bool station{};
	bool ap{};
	bool ap_vlan{};
	bool wds{};
	bool monitor{};
	bool mesh_point{};
	bool p2p_client{};
	bool p2p_go{};
	bool p2p_device{};
	bool ocb{};
	bool nan{};
};

struct nl80211_wowlan_triggers_attrs {
	bool any{};
	bool disconnect{};
	bool magic_pkt{};
	bool pkt_pattern{};
	bool gtk_rekey_supported{};
	bool gtk_rekey_failure{};
	bool eap_ident_request{};
	bool _4way_handshake{};
	bool rfkill_release{};
	bool wakeup_pkt_80211{};
	bool wakeup_pkt_80211_len{};
	bool wakeup_pkt_8023{};
	bool wakeup_pkt_8023_len{};
	bool tcp_connection{};
	bool wakeup_tcp_match{};
	bool wakeup_tcp_connlost{};
	bool wakeup_tcp_nomoretokens{};
	bool net_detect{};
	bool net_detect_results{};
	bool unprotected_deauth_disassoc{};
};

struct nl80211_txq_stats_attrs {
	std::optional<__u32> backlog_bytes;
	std::optional<__u32> backlog_packets;
	std::optional<__u32> flows;
	std::optional<__u32> drops;
	std::optional<__u32> ecn_marks;
	std::optional<__u32> overlimit;
	std::optional<__u32> overmemory;
	std::optional<__u32> collisions;
	std::optional<__u32> tx_bytes;
	std::optional<__u32> tx_packets;
	std::optional<__u32> max_flows;
};

struct nl80211_frame_type_attrs {
	std::optional<__u16> frame_type;
};

struct nl80211_iface_limit_attributes {
	std::optional<__u32> idx;
	std::optional<__u32> max;
	std::optional<nl80211_supported_iftypes> types;
};

struct nl80211_sar_specs {
	std::optional<__u32> idx;
	std::optional<__s32> power;
	std::optional<__u32> range_index;
	std::optional<__u32> start_freq;
	std::optional<__u32> end_freq;
};

struct nl80211_bitrate_attrs {
	std::optional<__u32> idx;
	std::optional<__u32> rate;
	bool _2ghz_shortpreamble{};
};

struct nl80211_iftype_data_attrs {
	std::optional<__u32> idx;
	std::vector<__u8> iftypes;
	std::vector<__u8> he_cap_mac;
	std::vector<__u8> he_cap_phy;
	std::vector<__u8> he_cap_mcs_set;
	std::vector<__u8> he_cap_ppe;
	std::vector<__u8> he_6ghz_capa;
	std::vector<__u8> vendor_elems;
	std::vector<__u8> eht_cap_mac;
	std::vector<__u8> eht_cap_phy;
	std::vector<__u8> eht_cap_mcs_set;
	std::vector<__u8> eht_cap_ppe;
};

struct nl80211_wmm_attrs {
	std::optional<__u32> idx;
	std::optional<__u16> cw_min;
	std::optional<__u16> cw_max;
	std::optional<__u8> aifsn;
	std::optional<__u16> txop;
};

struct nl80211_iftype_attrs {
	std::optional<nl80211_frame_type_attrs> unspecified;
	std::optional<nl80211_frame_type_attrs> adhoc;
	std::optional<nl80211_frame_type_attrs> station;
	std::optional<nl80211_frame_type_attrs> ap;
	std::optional<nl80211_frame_type_attrs> ap_vlan;
	std::optional<nl80211_frame_type_attrs> wds;
	std::optional<nl80211_frame_type_attrs> monitor;
	std::optional<nl80211_frame_type_attrs> mesh_point;
	std::optional<nl80211_frame_type_attrs> p2p_client;
	std::optional<nl80211_frame_type_attrs> p2p_go;
	std::optional<nl80211_frame_type_attrs> p2p_device;
	std::optional<nl80211_frame_type_attrs> ocb;
	std::optional<nl80211_frame_type_attrs> nan;
};

struct nl80211_if_combination_attributes {
	std::optional<__u32> idx;
	std::vector<nl80211_iface_limit_attributes> limits;
	std::optional<__u32> maxnum;
	bool sta_ap_bi_match{};
	std::optional<__u32> num_channels;
	std::optional<__u32> radar_detect_widths;
	std::optional<__u32> radar_detect_regions;
	std::optional<__u32> bi_min_gcd;
};

struct nl80211_sar_attributes {
	std::optional<__u32> type;
	std::vector<nl80211_sar_specs> specs;
};

struct nl80211_frequency_attrs {
	std::optional<__u32> idx;
	std::optional<__u32> freq;
	bool disabled{};
	bool no_ir{};
	bool no_ibss{};
	bool radar{};
	std::optional<__u32> max_tx_power;
	std::optional<__u32> dfs_state;
	std::vector<__u8> dfs_time;
	std::vector<__u8> no_ht40_minus;
	std::vector<__u8> no_ht40_plus;
	std::vector<__u8> no_80mhz;
	std::vector<__u8> no_160mhz;
	std::vector<__u8> dfs_cac_time;
	std::vector<__u8> indoor_only;
	std::vector<__u8> ir_concurrent;
	std::vector<__u8> no_20mhz;
	std::vector<__u8> no_10mhz;
	std::vector<nl80211_wmm_attrs> wmm;
	std::vector<__u8> no_he;
	std::optional<__u32> offset;
	std::vector<__u8> _1mhz;
	std::vector<__u8> _2mhz;
	std::vector<__u8> _4mhz;
	std::vector<__u8> _8mhz;
	std::vector<__u8> _16mhz;
	std::vector<__u8> no_320mhz;
	std::vector<__u8> no_eht;
	std::vector<__u8> psd;
	std::vector<__u8> dfs_concurrent;
	std::vector<__u8> no_6ghz_vlp_client;
	std::vector<__u8> no_6ghz_afc_client;
	std::vector<__u8> can_monitor;
	std::vector<__u8> allow_6ghz_vlp_ap;
};

struct nl80211_band_attrs {
	std::vector<nl80211_frequency_attrs> freqs;
	std::vector<nl80211_bitrate_attrs> rates;
	std::vector<__u8> ht_mcs_set;
	std::optional<__u16> ht_capa;
	std::optional<__u8> ht_ampdu_factor;
	std::optional<__u8> ht_ampdu_density;
	std::vector<__u8> vht_mcs_set;
	std::optional<__u32> vht_capa;
	std::vector<nl80211_iftype_data_attrs> iftype_data;
	std::vector<__u8> edmg_channels;
	std::vector<__u8> edmg_bw_config;
	std::vector<__u8> s1g_mcs_nss_set;
	std::vector<__u8> s1g_capa;
};

struct nl80211_wiphy_bands {
	std::optional<nl80211_band_attrs> _2ghz;
	std::optional<nl80211_band_attrs> _5ghz;
	std::optional<nl80211_band_attrs> _60ghz;
	std::optional<nl80211_band_attrs> _6ghz;
	std::optional<nl80211_band_attrs> s1ghz;
	std::optional<nl80211_band_attrs> lc;
};

/* ============== NL80211_CMD_GET_WIPHY ============== */
/* NL80211_CMD_GET_WIPHY - do */
struct nl80211_get_wiphy_req {
	std::optional<__u32> wiphy;
	std::optional<__u64> wdev;
	std::optional<__u32> ifindex;
};

struct nl80211_get_wiphy_rsp {
	std::optional<__u32> bands;
	std::vector<__u8> cipher_suites;
	bool control_port_ethertype{};
	std::vector<__u8> ext_capa;
	std::vector<__u8> ext_capa_mask;
	std::vector<__u8> ext_features;
	std::optional<__u32> feature_flags;
	std::optional<__u32> generation;
	std::vector<__u8> ht_capability_mask;
	std::vector<nl80211_if_combination_attributes> interface_combinations;
	std::vector<__u8> mac;
	std::optional<__u8> max_csa_counters;
	std::optional<__u8> max_match_sets;
	std::vector<__u8> max_num_akm_suites;
	std::optional<__u8> max_num_pmkids;
	std::optional<__u8> max_num_scan_ssids;
	std::optional<__u32> max_num_sched_scan_plans;
	std::optional<__u8> max_num_sched_scan_ssids;
	std::optional<__u32> max_remain_on_channel_duration;
	std::optional<__u16> max_scan_ie_len;
	std::optional<__u32> max_scan_plan_interval;
	std::optional<__u32> max_scan_plan_iterations;
	std::optional<__u16> max_sched_scan_ie_len;
	bool offchannel_tx_ok{};
	std::optional<nl80211_iftype_attrs> rx_frame_types;
	std::optional<nl80211_sar_attributes> sar_spec;
	std::optional<__u32> sched_scan_max_reqs;
	std::optional<nl80211_supported_iftypes> software_iftypes;
	bool support_ap_uapsd{};
	std::vector<__u32> supported_commands;
	std::optional<nl80211_supported_iftypes> supported_iftypes;
	bool tdls_external_setup{};
	bool tdls_support{};
	std::optional<nl80211_iftype_attrs> tx_frame_types;
	std::optional<__u32> txq_limit;
	std::optional<__u32> txq_memory_limit;
	std::optional<__u32> txq_quantum;
	std::optional<nl80211_txq_stats_attrs> txq_stats;
	std::vector<__u8> vht_capability_mask;
	std::optional<__u32> wiphy;
	std::optional<__u32> wiphy_antenna_avail_rx;
	std::optional<__u32> wiphy_antenna_avail_tx;
	std::optional<__u32> wiphy_antenna_rx;
	std::optional<__u32> wiphy_antenna_tx;
	std::optional<nl80211_wiphy_bands> wiphy_bands;
	std::optional<__u8> wiphy_coverage_class;
	std::optional<__u32> wiphy_frag_threshold;
	std::string wiphy_name;
	std::optional<__u8> wiphy_retry_long;
	std::optional<__u8> wiphy_retry_short;
	std::optional<__u32> wiphy_rts_threshold;
	std::optional<nl80211_wowlan_triggers_attrs> wowlan_triggers_supported;
};

/*
 * Get information about a wiphy or dump a list of all wiphys. Requests to
dump get-wiphy should unconditionally include the split-wiphy-dump flag
in the request.

 */
std::unique_ptr<nl80211_get_wiphy_rsp>
nl80211_get_wiphy(ynl_cpp::ynl_socket& ys, nl80211_get_wiphy_req& req);

/* NL80211_CMD_GET_WIPHY - dump */
struct nl80211_get_wiphy_req_dump {
	std::optional<__u32> wiphy;
	std::optional<__u64> wdev;
	std::optional<__u32> ifindex;
	bool split_wiphy_dump{};
};

struct nl80211_get_wiphy_rsp_dump {
	std::optional<__u32> bands;
	std::vector<__u8> cipher_suites;
	bool control_port_ethertype{};
	std::vector<__u8> ext_capa;
	std::vector<__u8> ext_capa_mask;
	std::vector<__u8> ext_features;
	std::optional<__u32> feature_flags;
	std::optional<__u32> generation;
	std::vector<__u8> ht_capability_mask;
	std::vector<nl80211_if_combination_attributes> interface_combinations;
	std::vector<__u8> mac;
	std::optional<__u8> max_csa_counters;
	std::optional<__u8> max_match_sets;
	std::vector<__u8> max_num_akm_suites;
	std::optional<__u8> max_num_pmkids;
	std::optional<__u8> max_num_scan_ssids;
	std::optional<__u32> max_num_sched_scan_plans;
	std::optional<__u8> max_num_sched_scan_ssids;
	std::optional<__u32> max_remain_on_channel_duration;
	std::optional<__u16> max_scan_ie_len;
	std::optional<__u32> max_scan_plan_interval;
	std::optional<__u32> max_scan_plan_iterations;
	std::optional<__u16> max_sched_scan_ie_len;
	bool offchannel_tx_ok{};
	std::optional<nl80211_iftype_attrs> rx_frame_types;
	std::optional<nl80211_sar_attributes> sar_spec;
	std::optional<__u32> sched_scan_max_reqs;
	std::optional<nl80211_supported_iftypes> software_iftypes;
	bool support_ap_uapsd{};
	std::vector<__u32> supported_commands;
	std::optional<nl80211_supported_iftypes> supported_iftypes;
	bool tdls_external_setup{};
	bool tdls_support{};
	std::optional<nl80211_iftype_attrs> tx_frame_types;
	std::optional<__u32> txq_limit;
	std::optional<__u32> txq_memory_limit;
	std::optional<__u32> txq_quantum;
	std::optional<nl80211_txq_stats_attrs> txq_stats;
	std::vector<__u8> vht_capability_mask;
	std::optional<__u32> wiphy;
	std::optional<__u32> wiphy_antenna_avail_rx;
	std::optional<__u32> wiphy_antenna_avail_tx;
	std::optional<__u32> wiphy_antenna_rx;
	std::optional<__u32> wiphy_antenna_tx;
	std::optional<nl80211_wiphy_bands> wiphy_bands;
	std::optional<__u8> wiphy_coverage_class;
	std::optional<__u32> wiphy_frag_threshold;
	std::string wiphy_name;
	std::optional<__u8> wiphy_retry_long;
	std::optional<__u8> wiphy_retry_short;
	std::optional<__u32> wiphy_rts_threshold;
	std::optional<nl80211_wowlan_triggers_attrs> wowlan_triggers_supported;
};

struct nl80211_get_wiphy_rsp_list {
	std::list<nl80211_get_wiphy_rsp_dump> objs;
};

std::unique_ptr<nl80211_get_wiphy_rsp_list>
nl80211_get_wiphy_dump(ynl_cpp::ynl_socket& ys,
		       nl80211_get_wiphy_req_dump& req);

/* ============== NL80211_CMD_GET_INTERFACE ============== */
/* NL80211_CMD_GET_INTERFACE - do */
struct nl80211_get_interface_req {
	std::string ifname;
};

struct nl80211_get_interface_rsp {
	std::string ifname;
	std::optional<__u32> iftype;
	std::optional<__u32> ifindex;
	std::optional<__u32> wiphy;
	std::optional<__u64> wdev;
	std::vector<__u8> mac;
	std::optional<__u32> generation;
	std::optional<nl80211_txq_stats_attrs> txq_stats;
	std::optional<__u8> _4addr;
};

/*
 * Get information about an interface or dump a list of all interfaces
 */
std::unique_ptr<nl80211_get_interface_rsp>
nl80211_get_interface(ynl_cpp::ynl_socket& ys, nl80211_get_interface_req& req);

/* NL80211_CMD_GET_INTERFACE - dump */
struct nl80211_get_interface_req_dump {
	std::string ifname;
};

struct nl80211_get_interface_rsp_dump {
	std::string ifname;
	std::optional<__u32> iftype;
	std::optional<__u32> ifindex;
	std::optional<__u32> wiphy;
	std::optional<__u64> wdev;
	std::vector<__u8> mac;
	std::optional<__u32> generation;
	std::optional<nl80211_txq_stats_attrs> txq_stats;
	std::optional<__u8> _4addr;
};

struct nl80211_get_interface_rsp_list {
	std::list<nl80211_get_interface_rsp_dump> objs;
};

std::unique_ptr<nl80211_get_interface_rsp_list>
nl80211_get_interface_dump(ynl_cpp::ynl_socket& ys,
			   nl80211_get_interface_req_dump& req);

/* ============== NL80211_CMD_GET_PROTOCOL_FEATURES ============== */
/* NL80211_CMD_GET_PROTOCOL_FEATURES - do */
struct nl80211_get_protocol_features_req {
	std::optional<__u32> protocol_features;
};

struct nl80211_get_protocol_features_rsp {
	std::optional<__u32> protocol_features;
};

/*
 * Get information about supported protocol features
 */
std::unique_ptr<nl80211_get_protocol_features_rsp>
nl80211_get_protocol_features(ynl_cpp::ynl_socket& ys,
			      nl80211_get_protocol_features_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_NL80211_GEN_H */
