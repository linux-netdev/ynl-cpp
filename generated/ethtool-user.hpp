/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_ETHTOOL_GEN_H
#define _LINUX_ETHTOOL_GEN_H

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

#include <linux/ethtool.h>
#include <linux/ethtool_netlink_generated.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_ethtool_family();

/* Enums */
std::string_view ethtool_op_str(int op);
std::string_view ethtool_udp_tunnel_type_str(int value);
std::string_view ethtool_stringset_str(ethtool_stringset value);
std::string_view ethtool_header_flags_str(ethtool_header_flags value);
std::string_view
ethtool_module_fw_flash_status_str(ethtool_module_fw_flash_status value);
std::string_view
ethtool_c33_pse_ext_state_str(ethtool_c33_pse_ext_state value);
std::string_view ethtool_phy_upstream_type_str(phy_upstream value);
std::string_view ethtool_tcp_data_split_str(ethtool_tcp_data_split value);
std::string_view ethtool_hwtstamp_source_str(hwtstamp_source value);
std::string_view ethtool_pse_event_str(ethtool_pse_event value);
std::string_view ethtool_input_xfrm_str(int value);
std::string_view ethtool_rxfh_fields_str(int value);

/* Common nested types */
struct ethtool_header {
	std::optional<__u32> dev_index;
	std::string dev_name;
	std::optional<__u32> flags;
	std::optional<__u32> phy_index;
};

struct ethtool_pause_stat {
	std::optional<__u64> tx_frames;
	std::optional<__u64> rx_frames;
};

struct ethtool_ts_stat {
	std::optional<__u64> tx_pkts;
	std::optional<__u64> tx_lost;
	std::optional<__u64> tx_err;
	std::optional<__u64> tx_onestep_pkts_unconfirmed;
};

struct ethtool_ts_hwtstamp_provider {
	std::optional<__u32> index;
	std::optional<__u32> qualifier;
};

struct ethtool_cable_test_tdr_cfg {
	std::optional<__u32> first;
	std::optional<__u32> last;
	std::optional<__u32> step;
	std::optional<__u8> pair;
};

struct ethtool_c33_pse_pw_limit {
	std::optional<__u32> min;
	std::optional<__u32> max;
};

struct ethtool_flow {
	std::optional<__u64> ether;
	std::optional<__u64> ip4;
	std::optional<__u64> ip6;
	std::optional<__u64> tcp4;
	std::optional<__u64> tcp6;
	std::optional<__u64> udp4;
	std::optional<__u64> udp6;
	std::optional<__u64> sctp4;
	std::optional<__u64> sctp6;
	std::optional<__u64> ah4;
	std::optional<__u64> ah6;
	std::optional<__u64> esp4;
	std::optional<__u64> esp6;
	std::optional<__u64> ah_esp4;
	std::optional<__u64> ah_esp6;
	std::optional<__u64> gtpu4;
	std::optional<__u64> gtpu6;
	std::optional<__u64> gtpc4;
	std::optional<__u64> gtpc6;
	std::optional<__u64> gtpc_teid4;
	std::optional<__u64> gtpc_teid6;
	std::optional<__u64> gtpu_eh4;
	std::optional<__u64> gtpu_eh6;
	std::optional<__u64> gtpu_ul4;
	std::optional<__u64> gtpu_ul6;
	std::optional<__u64> gtpu_dl4;
	std::optional<__u64> gtpu_dl6;
};

struct ethtool_mm_stat {
	std::optional<__u64> reassembly_errors;
	std::optional<__u64> smd_errors;
	std::optional<__u64> reassembly_ok;
	std::optional<__u64> rx_frag_count;
	std::optional<__u64> tx_frag_count;
	std::optional<__u64> hold_count;
};

struct ethtool_mse_capabilities {
	std::optional<__u64> max_average_mse;
	std::optional<__u64> max_peak_mse;
	std::optional<__u64> refresh_rate_ps;
	std::optional<__u64> num_symbols;
};

struct ethtool_mse_snapshot {
	std::optional<__u64> average_mse;
	std::optional<__u64> peak_mse;
	std::optional<__u64> worst_peak_mse;
};

struct ethtool_irq_moderation {
	std::optional<__u32> usec;
	std::optional<__u32> pkts;
	std::optional<__u32> comps;
};

struct ethtool_cable_result {
	std::optional<__u8> pair;
	std::optional<__u8> code;
	std::optional<__u32> src;
};

struct ethtool_cable_fault_length {
	std::optional<__u8> pair;
	std::optional<__u32> cm;
	std::optional<__u32> src;
};

struct ethtool_fec_hist {
	std::optional<__u32> bin_low;
	std::optional<__u32> bin_high;
	std::optional<__u64> bin_val;
	std::vector<__u8> bin_val_per_lane;
};

struct ethtool_stats_grp_hist {
	std::optional<__u32> hist_bkt_low;
	std::optional<__u32> hist_bkt_hi;
	std::optional<__u64> hist_val;
};

struct ethtool_bitset_bit {
	std::optional<__u32> index;
	std::string name;
	bool value{};
};

struct ethtool_tunnel_udp_entry {
	std::optional<__u16> port /* big-endian */;
	std::optional<int> type;
};

struct ethtool_string {
	std::optional<__u32> index;
	std::string value;
};

struct ethtool_profile {
	std::vector<ethtool_irq_moderation> irq_moderation;
};

struct ethtool_cable_nest {
	std::optional<ethtool_cable_result> result;
	std::optional<ethtool_cable_fault_length> fault_length;
};

struct ethtool_fec_stat {
	std::vector<__u8> corrected;
	std::vector<__u8> uncorr;
	std::vector<__u8> corr_bits;
	std::vector<ethtool_fec_hist> hist;
};

struct ethtool_stats_grp {
	std::optional<__u32> id;
	std::optional<__u32> ss_id;
	std::optional<__u64> stat;
	std::optional<ethtool_stats_grp_hist> hist_rx;
	std::optional<ethtool_stats_grp_hist> hist_tx;
	std::optional<__u32> hist_bkt_low;
	std::optional<__u32> hist_bkt_hi;
	std::optional<__u64> hist_val;
};

struct ethtool_bitset_bits {
	std::vector<ethtool_bitset_bit> bit;
};

struct ethtool_strings {
	std::vector<ethtool_string> string;
};

struct ethtool_bitset {
	bool nomask{};
	std::optional<__u32> size;
	std::optional<ethtool_bitset_bits> bits;
	std::vector<__u8> value;
	std::vector<__u8> mask;
};

struct ethtool_stringset_t {
	std::optional<__u32> id;
	std::optional<__u32> count;
	std::vector<ethtool_strings> strings;
};

struct ethtool_tunnel_udp_table {
	std::optional<__u32> size;
	std::optional<ethtool_bitset> types;
	std::vector<ethtool_tunnel_udp_entry> entry;
};

struct ethtool_stringsets {
	std::vector<ethtool_stringset_t> stringset;
};

struct ethtool_tunnel_udp {
	std::optional<ethtool_tunnel_udp_table> table;
};

/* ============== ETHTOOL_MSG_STRSET_GET ============== */
/* ETHTOOL_MSG_STRSET_GET - do */
struct ethtool_strset_get_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_stringsets> stringsets;
	bool counts_only{};
};

struct ethtool_strset_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_stringsets> stringsets;
};

/*
 * Get string set from the kernel.
 */
std::unique_ptr<ethtool_strset_get_rsp>
ethtool_strset_get(ynl_cpp::ynl_socket& ys, ethtool_strset_get_req& req);

/* ETHTOOL_MSG_STRSET_GET - dump */
struct ethtool_strset_get_req_dump {
	std::optional<ethtool_header> header;
	std::optional<ethtool_stringsets> stringsets;
	bool counts_only{};
};

struct ethtool_strset_get_list {
	std::list<ethtool_strset_get_rsp> objs;
};

std::unique_ptr<ethtool_strset_get_list>
ethtool_strset_get_dump(ynl_cpp::ynl_socket& ys,
			ethtool_strset_get_req_dump& req);

/* ============== ETHTOOL_MSG_LINKINFO_GET ============== */
/* ETHTOOL_MSG_LINKINFO_GET - do */
struct ethtool_linkinfo_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_linkinfo_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u8> port;
	std::optional<__u8> phyaddr;
	std::optional<__u8> tp_mdix;
	std::optional<__u8> tp_mdix_ctrl;
	std::optional<__u8> transceiver;
};

/*
 * Get link info.
 */
std::unique_ptr<ethtool_linkinfo_get_rsp>
ethtool_linkinfo_get(ynl_cpp::ynl_socket& ys, ethtool_linkinfo_get_req& req);

/* ETHTOOL_MSG_LINKINFO_GET - dump */
struct ethtool_linkinfo_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_linkinfo_get_list {
	std::list<ethtool_linkinfo_get_rsp> objs;
};

std::unique_ptr<ethtool_linkinfo_get_list>
ethtool_linkinfo_get_dump(ynl_cpp::ynl_socket& ys,
			  ethtool_linkinfo_get_req_dump& req);

/* ETHTOOL_MSG_LINKINFO_GET - notify */
struct ethtool_linkinfo_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_linkinfo_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_LINKINFO_SET ============== */
/* ETHTOOL_MSG_LINKINFO_SET - do */
struct ethtool_linkinfo_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u8> port;
	std::optional<__u8> phyaddr;
	std::optional<__u8> tp_mdix;
	std::optional<__u8> tp_mdix_ctrl;
	std::optional<__u8> transceiver;
};

/*
 * Set link info.
 */
int ethtool_linkinfo_set(ynl_cpp::ynl_socket& ys,
			 ethtool_linkinfo_set_req& req);

/* ============== ETHTOOL_MSG_LINKMODES_GET ============== */
/* ETHTOOL_MSG_LINKMODES_GET - do */
struct ethtool_linkmodes_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_linkmodes_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u8> autoneg;
	std::optional<ethtool_bitset> ours;
	std::optional<ethtool_bitset> peer;
	std::optional<__u32> speed;
	std::optional<__u8> duplex;
	std::optional<__u8> master_slave_cfg;
	std::optional<__u8> master_slave_state;
	std::optional<__u32> lanes;
	std::optional<__u8> rate_matching;
};

/*
 * Get link modes.
 */
std::unique_ptr<ethtool_linkmodes_get_rsp>
ethtool_linkmodes_get(ynl_cpp::ynl_socket& ys, ethtool_linkmodes_get_req& req);

/* ETHTOOL_MSG_LINKMODES_GET - dump */
struct ethtool_linkmodes_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_linkmodes_get_list {
	std::list<ethtool_linkmodes_get_rsp> objs;
};

std::unique_ptr<ethtool_linkmodes_get_list>
ethtool_linkmodes_get_dump(ynl_cpp::ynl_socket& ys,
			   ethtool_linkmodes_get_req_dump& req);

/* ETHTOOL_MSG_LINKMODES_GET - notify */
struct ethtool_linkmodes_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_linkmodes_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_LINKMODES_SET ============== */
/* ETHTOOL_MSG_LINKMODES_SET - do */
struct ethtool_linkmodes_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u8> autoneg;
	std::optional<ethtool_bitset> ours;
	std::optional<ethtool_bitset> peer;
	std::optional<__u32> speed;
	std::optional<__u8> duplex;
	std::optional<__u8> master_slave_cfg;
	std::optional<__u8> master_slave_state;
	std::optional<__u32> lanes;
	std::optional<__u8> rate_matching;
};

/*
 * Set link modes.
 */
int ethtool_linkmodes_set(ynl_cpp::ynl_socket& ys,
			  ethtool_linkmodes_set_req& req);

/* ============== ETHTOOL_MSG_LINKSTATE_GET ============== */
/* ETHTOOL_MSG_LINKSTATE_GET - do */
struct ethtool_linkstate_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_linkstate_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u8> link;
	std::optional<__u32> sqi;
	std::optional<__u32> sqi_max;
	std::optional<__u8> ext_state;
	std::optional<__u8> ext_substate;
	std::optional<__u32> ext_down_cnt;
};

/*
 * Get link state.
 */
std::unique_ptr<ethtool_linkstate_get_rsp>
ethtool_linkstate_get(ynl_cpp::ynl_socket& ys, ethtool_linkstate_get_req& req);

/* ETHTOOL_MSG_LINKSTATE_GET - dump */
struct ethtool_linkstate_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_linkstate_get_list {
	std::list<ethtool_linkstate_get_rsp> objs;
};

std::unique_ptr<ethtool_linkstate_get_list>
ethtool_linkstate_get_dump(ynl_cpp::ynl_socket& ys,
			   ethtool_linkstate_get_req_dump& req);

/* ============== ETHTOOL_MSG_DEBUG_GET ============== */
/* ETHTOOL_MSG_DEBUG_GET - do */
struct ethtool_debug_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_debug_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> msgmask;
};

/*
 * Get debug message mask.
 */
std::unique_ptr<ethtool_debug_get_rsp>
ethtool_debug_get(ynl_cpp::ynl_socket& ys, ethtool_debug_get_req& req);

/* ETHTOOL_MSG_DEBUG_GET - dump */
struct ethtool_debug_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_debug_get_list {
	std::list<ethtool_debug_get_rsp> objs;
};

std::unique_ptr<ethtool_debug_get_list>
ethtool_debug_get_dump(ynl_cpp::ynl_socket& ys,
		       ethtool_debug_get_req_dump& req);

/* ETHTOOL_MSG_DEBUG_GET - notify */
struct ethtool_debug_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_debug_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_DEBUG_SET ============== */
/* ETHTOOL_MSG_DEBUG_SET - do */
struct ethtool_debug_set_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> msgmask;
};

/*
 * Set debug message mask.
 */
int ethtool_debug_set(ynl_cpp::ynl_socket& ys, ethtool_debug_set_req& req);

/* ============== ETHTOOL_MSG_WOL_GET ============== */
/* ETHTOOL_MSG_WOL_GET - do */
struct ethtool_wol_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_wol_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> modes;
	std::vector<__u8> sopass;
};

/*
 * Get WOL params.
 */
std::unique_ptr<ethtool_wol_get_rsp>
ethtool_wol_get(ynl_cpp::ynl_socket& ys, ethtool_wol_get_req& req);

/* ETHTOOL_MSG_WOL_GET - dump */
struct ethtool_wol_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_wol_get_list {
	std::list<ethtool_wol_get_rsp> objs;
};

std::unique_ptr<ethtool_wol_get_list>
ethtool_wol_get_dump(ynl_cpp::ynl_socket& ys, ethtool_wol_get_req_dump& req);

/* ETHTOOL_MSG_WOL_GET - notify */
struct ethtool_wol_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_wol_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_WOL_SET ============== */
/* ETHTOOL_MSG_WOL_SET - do */
struct ethtool_wol_set_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> modes;
	std::vector<__u8> sopass;
};

/*
 * Set WOL params.
 */
int ethtool_wol_set(ynl_cpp::ynl_socket& ys, ethtool_wol_set_req& req);

/* ============== ETHTOOL_MSG_FEATURES_GET ============== */
/* ETHTOOL_MSG_FEATURES_GET - do */
struct ethtool_features_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_features_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> hw;
	std::optional<ethtool_bitset> wanted;
	std::optional<ethtool_bitset> active;
	std::optional<ethtool_bitset> nochange;
};

/*
 * Get features.
 */
std::unique_ptr<ethtool_features_get_rsp>
ethtool_features_get(ynl_cpp::ynl_socket& ys, ethtool_features_get_req& req);

/* ETHTOOL_MSG_FEATURES_GET - dump */
struct ethtool_features_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_features_get_list {
	std::list<ethtool_features_get_rsp> objs;
};

std::unique_ptr<ethtool_features_get_list>
ethtool_features_get_dump(ynl_cpp::ynl_socket& ys,
			  ethtool_features_get_req_dump& req);

/* ETHTOOL_MSG_FEATURES_GET - notify */
struct ethtool_features_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_features_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_FEATURES_SET ============== */
/* ETHTOOL_MSG_FEATURES_SET - do */
struct ethtool_features_set_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> hw;
	std::optional<ethtool_bitset> wanted;
	std::optional<ethtool_bitset> active;
	std::optional<ethtool_bitset> nochange;
};

struct ethtool_features_set_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> hw;
	std::optional<ethtool_bitset> wanted;
	std::optional<ethtool_bitset> active;
	std::optional<ethtool_bitset> nochange;
};

/*
 * Set features.
 */
std::unique_ptr<ethtool_features_set_rsp>
ethtool_features_set(ynl_cpp::ynl_socket& ys, ethtool_features_set_req& req);

/* ============== ETHTOOL_MSG_PRIVFLAGS_GET ============== */
/* ETHTOOL_MSG_PRIVFLAGS_GET - do */
struct ethtool_privflags_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_privflags_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> flags;
};

/*
 * Get device private flags.
 */
std::unique_ptr<ethtool_privflags_get_rsp>
ethtool_privflags_get(ynl_cpp::ynl_socket& ys, ethtool_privflags_get_req& req);

/* ETHTOOL_MSG_PRIVFLAGS_GET - dump */
struct ethtool_privflags_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_privflags_get_list {
	std::list<ethtool_privflags_get_rsp> objs;
};

std::unique_ptr<ethtool_privflags_get_list>
ethtool_privflags_get_dump(ynl_cpp::ynl_socket& ys,
			   ethtool_privflags_get_req_dump& req);

/* ETHTOOL_MSG_PRIVFLAGS_GET - notify */
struct ethtool_privflags_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_privflags_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_PRIVFLAGS_SET ============== */
/* ETHTOOL_MSG_PRIVFLAGS_SET - do */
struct ethtool_privflags_set_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> flags;
};

/*
 * Set device private flags.
 */
int ethtool_privflags_set(ynl_cpp::ynl_socket& ys,
			  ethtool_privflags_set_req& req);

/* ============== ETHTOOL_MSG_RINGS_GET ============== */
/* ETHTOOL_MSG_RINGS_GET - do */
struct ethtool_rings_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_rings_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u32> rx_max;
	std::optional<__u32> rx_mini_max;
	std::optional<__u32> rx_jumbo_max;
	std::optional<__u32> tx_max;
	std::optional<__u32> rx;
	std::optional<__u32> rx_mini;
	std::optional<__u32> rx_jumbo;
	std::optional<__u32> tx;
	std::optional<__u32> rx_buf_len;
	std::optional<enum ethtool_tcp_data_split> tcp_data_split;
	std::optional<__u32> cqe_size;
	std::optional<__u8> tx_push;
	std::optional<__u8> rx_push;
	std::optional<__u32> tx_push_buf_len;
	std::optional<__u32> tx_push_buf_len_max;
	std::optional<__u32> hds_thresh;
	std::optional<__u32> hds_thresh_max;
};

/*
 * Get ring params.
 */
std::unique_ptr<ethtool_rings_get_rsp>
ethtool_rings_get(ynl_cpp::ynl_socket& ys, ethtool_rings_get_req& req);

/* ETHTOOL_MSG_RINGS_GET - dump */
struct ethtool_rings_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_rings_get_list {
	std::list<ethtool_rings_get_rsp> objs;
};

std::unique_ptr<ethtool_rings_get_list>
ethtool_rings_get_dump(ynl_cpp::ynl_socket& ys,
		       ethtool_rings_get_req_dump& req);

/* ETHTOOL_MSG_RINGS_GET - notify */
struct ethtool_rings_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_rings_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_RINGS_SET ============== */
/* ETHTOOL_MSG_RINGS_SET - do */
struct ethtool_rings_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u32> rx_max;
	std::optional<__u32> rx_mini_max;
	std::optional<__u32> rx_jumbo_max;
	std::optional<__u32> tx_max;
	std::optional<__u32> rx;
	std::optional<__u32> rx_mini;
	std::optional<__u32> rx_jumbo;
	std::optional<__u32> tx;
	std::optional<__u32> rx_buf_len;
	std::optional<enum ethtool_tcp_data_split> tcp_data_split;
	std::optional<__u32> cqe_size;
	std::optional<__u8> tx_push;
	std::optional<__u8> rx_push;
	std::optional<__u32> tx_push_buf_len;
	std::optional<__u32> tx_push_buf_len_max;
	std::optional<__u32> hds_thresh;
	std::optional<__u32> hds_thresh_max;
};

/*
 * Set ring params.
 */
int ethtool_rings_set(ynl_cpp::ynl_socket& ys, ethtool_rings_set_req& req);

/* ============== ETHTOOL_MSG_CHANNELS_GET ============== */
/* ETHTOOL_MSG_CHANNELS_GET - do */
struct ethtool_channels_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_channels_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u32> rx_max;
	std::optional<__u32> tx_max;
	std::optional<__u32> other_max;
	std::optional<__u32> combined_max;
	std::optional<__u32> rx_count;
	std::optional<__u32> tx_count;
	std::optional<__u32> other_count;
	std::optional<__u32> combined_count;
};

/*
 * Get channel params.
 */
std::unique_ptr<ethtool_channels_get_rsp>
ethtool_channels_get(ynl_cpp::ynl_socket& ys, ethtool_channels_get_req& req);

/* ETHTOOL_MSG_CHANNELS_GET - dump */
struct ethtool_channels_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_channels_get_list {
	std::list<ethtool_channels_get_rsp> objs;
};

std::unique_ptr<ethtool_channels_get_list>
ethtool_channels_get_dump(ynl_cpp::ynl_socket& ys,
			  ethtool_channels_get_req_dump& req);

/* ETHTOOL_MSG_CHANNELS_GET - notify */
struct ethtool_channels_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_channels_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_CHANNELS_SET ============== */
/* ETHTOOL_MSG_CHANNELS_SET - do */
struct ethtool_channels_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u32> rx_max;
	std::optional<__u32> tx_max;
	std::optional<__u32> other_max;
	std::optional<__u32> combined_max;
	std::optional<__u32> rx_count;
	std::optional<__u32> tx_count;
	std::optional<__u32> other_count;
	std::optional<__u32> combined_count;
};

/*
 * Set channel params.
 */
int ethtool_channels_set(ynl_cpp::ynl_socket& ys,
			 ethtool_channels_set_req& req);

/* ============== ETHTOOL_MSG_COALESCE_GET ============== */
/* ETHTOOL_MSG_COALESCE_GET - do */
struct ethtool_coalesce_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_coalesce_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u32> rx_usecs;
	std::optional<__u32> rx_max_frames;
	std::optional<__u32> rx_usecs_irq;
	std::optional<__u32> rx_max_frames_irq;
	std::optional<__u32> tx_usecs;
	std::optional<__u32> tx_max_frames;
	std::optional<__u32> tx_usecs_irq;
	std::optional<__u32> tx_max_frames_irq;
	std::optional<__u32> stats_block_usecs;
	std::optional<__u8> use_adaptive_rx;
	std::optional<__u8> use_adaptive_tx;
	std::optional<__u32> pkt_rate_low;
	std::optional<__u32> rx_usecs_low;
	std::optional<__u32> rx_max_frames_low;
	std::optional<__u32> tx_usecs_low;
	std::optional<__u32> tx_max_frames_low;
	std::optional<__u32> pkt_rate_high;
	std::optional<__u32> rx_usecs_high;
	std::optional<__u32> rx_max_frames_high;
	std::optional<__u32> tx_usecs_high;
	std::optional<__u32> tx_max_frames_high;
	std::optional<__u32> rate_sample_interval;
	std::optional<__u8> use_cqe_mode_tx;
	std::optional<__u8> use_cqe_mode_rx;
	std::optional<__u32> tx_aggr_max_bytes;
	std::optional<__u32> tx_aggr_max_frames;
	std::optional<__u32> tx_aggr_time_usecs;
	std::optional<ethtool_profile> rx_profile;
	std::optional<ethtool_profile> tx_profile;
};

/*
 * Get coalesce params.
 */
std::unique_ptr<ethtool_coalesce_get_rsp>
ethtool_coalesce_get(ynl_cpp::ynl_socket& ys, ethtool_coalesce_get_req& req);

/* ETHTOOL_MSG_COALESCE_GET - dump */
struct ethtool_coalesce_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_coalesce_get_list {
	std::list<ethtool_coalesce_get_rsp> objs;
};

std::unique_ptr<ethtool_coalesce_get_list>
ethtool_coalesce_get_dump(ynl_cpp::ynl_socket& ys,
			  ethtool_coalesce_get_req_dump& req);

/* ETHTOOL_MSG_COALESCE_GET - notify */
struct ethtool_coalesce_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_coalesce_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_COALESCE_SET ============== */
/* ETHTOOL_MSG_COALESCE_SET - do */
struct ethtool_coalesce_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u32> rx_usecs;
	std::optional<__u32> rx_max_frames;
	std::optional<__u32> rx_usecs_irq;
	std::optional<__u32> rx_max_frames_irq;
	std::optional<__u32> tx_usecs;
	std::optional<__u32> tx_max_frames;
	std::optional<__u32> tx_usecs_irq;
	std::optional<__u32> tx_max_frames_irq;
	std::optional<__u32> stats_block_usecs;
	std::optional<__u8> use_adaptive_rx;
	std::optional<__u8> use_adaptive_tx;
	std::optional<__u32> pkt_rate_low;
	std::optional<__u32> rx_usecs_low;
	std::optional<__u32> rx_max_frames_low;
	std::optional<__u32> tx_usecs_low;
	std::optional<__u32> tx_max_frames_low;
	std::optional<__u32> pkt_rate_high;
	std::optional<__u32> rx_usecs_high;
	std::optional<__u32> rx_max_frames_high;
	std::optional<__u32> tx_usecs_high;
	std::optional<__u32> tx_max_frames_high;
	std::optional<__u32> rate_sample_interval;
	std::optional<__u8> use_cqe_mode_tx;
	std::optional<__u8> use_cqe_mode_rx;
	std::optional<__u32> tx_aggr_max_bytes;
	std::optional<__u32> tx_aggr_max_frames;
	std::optional<__u32> tx_aggr_time_usecs;
	std::optional<ethtool_profile> rx_profile;
	std::optional<ethtool_profile> tx_profile;
};

/*
 * Set coalesce params.
 */
int ethtool_coalesce_set(ynl_cpp::ynl_socket& ys,
			 ethtool_coalesce_set_req& req);

/* ============== ETHTOOL_MSG_PAUSE_GET ============== */
/* ETHTOOL_MSG_PAUSE_GET - do */
struct ethtool_pause_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_pause_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u8> autoneg;
	std::optional<__u8> rx;
	std::optional<__u8> tx;
	std::optional<ethtool_pause_stat> stats;
	std::optional<__u32> stats_src;
};

/*
 * Get pause params.
 */
std::unique_ptr<ethtool_pause_get_rsp>
ethtool_pause_get(ynl_cpp::ynl_socket& ys, ethtool_pause_get_req& req);

/* ETHTOOL_MSG_PAUSE_GET - dump */
struct ethtool_pause_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_pause_get_list {
	std::list<ethtool_pause_get_rsp> objs;
};

std::unique_ptr<ethtool_pause_get_list>
ethtool_pause_get_dump(ynl_cpp::ynl_socket& ys,
		       ethtool_pause_get_req_dump& req);

/* ETHTOOL_MSG_PAUSE_GET - notify */
struct ethtool_pause_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_pause_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_PAUSE_SET ============== */
/* ETHTOOL_MSG_PAUSE_SET - do */
struct ethtool_pause_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u8> autoneg;
	std::optional<__u8> rx;
	std::optional<__u8> tx;
	std::optional<ethtool_pause_stat> stats;
	std::optional<__u32> stats_src;
};

/*
 * Set pause params.
 */
int ethtool_pause_set(ynl_cpp::ynl_socket& ys, ethtool_pause_set_req& req);

/* ============== ETHTOOL_MSG_EEE_GET ============== */
/* ETHTOOL_MSG_EEE_GET - do */
struct ethtool_eee_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_eee_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> modes_ours;
	std::optional<ethtool_bitset> modes_peer;
	std::optional<__u8> active;
	std::optional<__u8> enabled;
	std::optional<__u8> tx_lpi_enabled;
	std::optional<__u32> tx_lpi_timer;
};

/*
 * Get eee params.
 */
std::unique_ptr<ethtool_eee_get_rsp>
ethtool_eee_get(ynl_cpp::ynl_socket& ys, ethtool_eee_get_req& req);

/* ETHTOOL_MSG_EEE_GET - dump */
struct ethtool_eee_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_eee_get_list {
	std::list<ethtool_eee_get_rsp> objs;
};

std::unique_ptr<ethtool_eee_get_list>
ethtool_eee_get_dump(ynl_cpp::ynl_socket& ys, ethtool_eee_get_req_dump& req);

/* ETHTOOL_MSG_EEE_GET - notify */
struct ethtool_eee_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_eee_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_EEE_SET ============== */
/* ETHTOOL_MSG_EEE_SET - do */
struct ethtool_eee_set_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> modes_ours;
	std::optional<ethtool_bitset> modes_peer;
	std::optional<__u8> active;
	std::optional<__u8> enabled;
	std::optional<__u8> tx_lpi_enabled;
	std::optional<__u32> tx_lpi_timer;
};

/*
 * Set eee params.
 */
int ethtool_eee_set(ynl_cpp::ynl_socket& ys, ethtool_eee_set_req& req);

/* ============== ETHTOOL_MSG_TSINFO_GET ============== */
/* ETHTOOL_MSG_TSINFO_GET - do */
struct ethtool_tsinfo_get_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_ts_hwtstamp_provider> hwtstamp_provider;
};

struct ethtool_tsinfo_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> timestamping;
	std::optional<ethtool_bitset> tx_types;
	std::optional<ethtool_bitset> rx_filters;
	std::optional<__u32> phc_index;
	std::optional<ethtool_ts_stat> stats;
	std::optional<ethtool_ts_hwtstamp_provider> hwtstamp_provider;
	std::optional<enum hwtstamp_source> hwtstamp_source;
	std::optional<__u32> hwtstamp_phyindex;
};

/*
 * Get tsinfo params.
 */
std::unique_ptr<ethtool_tsinfo_get_rsp>
ethtool_tsinfo_get(ynl_cpp::ynl_socket& ys, ethtool_tsinfo_get_req& req);

/* ETHTOOL_MSG_TSINFO_GET - dump */
struct ethtool_tsinfo_get_req_dump {
	std::optional<ethtool_header> header;
	std::optional<ethtool_ts_hwtstamp_provider> hwtstamp_provider;
};

struct ethtool_tsinfo_get_list {
	std::list<ethtool_tsinfo_get_rsp> objs;
};

std::unique_ptr<ethtool_tsinfo_get_list>
ethtool_tsinfo_get_dump(ynl_cpp::ynl_socket& ys,
			ethtool_tsinfo_get_req_dump& req);

/* ============== ETHTOOL_MSG_CABLE_TEST_ACT ============== */
/* ETHTOOL_MSG_CABLE_TEST_ACT - do */
struct ethtool_cable_test_act_req {
	std::optional<ethtool_header> header;
};

/*
 * Cable test.
 */
int ethtool_cable_test_act(ynl_cpp::ynl_socket& ys,
			   ethtool_cable_test_act_req& req);

/* ============== ETHTOOL_MSG_CABLE_TEST_TDR_ACT ============== */
/* ETHTOOL_MSG_CABLE_TEST_TDR_ACT - do */
struct ethtool_cable_test_tdr_act_req {
	std::optional<ethtool_header> header;
};

/*
 * Cable test TDR.
 */
int ethtool_cable_test_tdr_act(ynl_cpp::ynl_socket& ys,
			       ethtool_cable_test_tdr_act_req& req);

/* ============== ETHTOOL_MSG_TUNNEL_INFO_GET ============== */
/* ETHTOOL_MSG_TUNNEL_INFO_GET - do */
struct ethtool_tunnel_info_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_tunnel_info_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_tunnel_udp> udp_ports;
};

/*
 * Get tsinfo params.
 */
std::unique_ptr<ethtool_tunnel_info_get_rsp>
ethtool_tunnel_info_get(ynl_cpp::ynl_socket& ys,
			ethtool_tunnel_info_get_req& req);

/* ETHTOOL_MSG_TUNNEL_INFO_GET - dump */
struct ethtool_tunnel_info_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_tunnel_info_get_list {
	std::list<ethtool_tunnel_info_get_rsp> objs;
};

std::unique_ptr<ethtool_tunnel_info_get_list>
ethtool_tunnel_info_get_dump(ynl_cpp::ynl_socket& ys,
			     ethtool_tunnel_info_get_req_dump& req);

/* ============== ETHTOOL_MSG_FEC_GET ============== */
/* ETHTOOL_MSG_FEC_GET - do */
struct ethtool_fec_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_fec_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> modes;
	std::optional<__u8> auto_;
	std::optional<__u32> active;
	std::optional<ethtool_fec_stat> stats;
};

/*
 * Get FEC params.
 */
std::unique_ptr<ethtool_fec_get_rsp>
ethtool_fec_get(ynl_cpp::ynl_socket& ys, ethtool_fec_get_req& req);

/* ETHTOOL_MSG_FEC_GET - dump */
struct ethtool_fec_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_fec_get_list {
	std::list<ethtool_fec_get_rsp> objs;
};

std::unique_ptr<ethtool_fec_get_list>
ethtool_fec_get_dump(ynl_cpp::ynl_socket& ys, ethtool_fec_get_req_dump& req);

/* ETHTOOL_MSG_FEC_GET - notify */
struct ethtool_fec_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_fec_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_FEC_SET ============== */
/* ETHTOOL_MSG_FEC_SET - do */
struct ethtool_fec_set_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> modes;
	std::optional<__u8> auto_;
	std::optional<__u32> active;
	std::optional<ethtool_fec_stat> stats;
};

/*
 * Set FEC params.
 */
int ethtool_fec_set(ynl_cpp::ynl_socket& ys, ethtool_fec_set_req& req);

/* ============== ETHTOOL_MSG_MODULE_EEPROM_GET ============== */
/* ETHTOOL_MSG_MODULE_EEPROM_GET - do */
struct ethtool_module_eeprom_get_req {
	std::optional<ethtool_header> header;
	std::optional<__u32> offset;
	std::optional<__u32> length;
	std::optional<__u8> page;
	std::optional<__u8> bank;
	std::optional<__u8> i2c_address;
};

struct ethtool_module_eeprom_get_rsp {
	std::optional<ethtool_header> header;
	std::vector<__u8> data;
};

/*
 * Get module EEPROM params.
 */
std::unique_ptr<ethtool_module_eeprom_get_rsp>
ethtool_module_eeprom_get(ynl_cpp::ynl_socket& ys,
			  ethtool_module_eeprom_get_req& req);

/* ETHTOOL_MSG_MODULE_EEPROM_GET - dump */
struct ethtool_module_eeprom_get_req_dump {
	std::optional<ethtool_header> header;
	std::optional<__u32> offset;
	std::optional<__u32> length;
	std::optional<__u8> page;
	std::optional<__u8> bank;
	std::optional<__u8> i2c_address;
};

struct ethtool_module_eeprom_get_list {
	std::list<ethtool_module_eeprom_get_rsp> objs;
};

std::unique_ptr<ethtool_module_eeprom_get_list>
ethtool_module_eeprom_get_dump(ynl_cpp::ynl_socket& ys,
			       ethtool_module_eeprom_get_req_dump& req);

/* ============== ETHTOOL_MSG_STATS_GET ============== */
/* ETHTOOL_MSG_STATS_GET - do */
struct ethtool_stats_get_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> groups;
};

struct ethtool_stats_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> groups;
	std::optional<ethtool_stats_grp> grp;
	std::optional<__u32> src;
};

/*
 * Get statistics.
 */
std::unique_ptr<ethtool_stats_get_rsp>
ethtool_stats_get(ynl_cpp::ynl_socket& ys, ethtool_stats_get_req& req);

/* ETHTOOL_MSG_STATS_GET - dump */
struct ethtool_stats_get_req_dump {
	std::optional<ethtool_header> header;
	std::optional<ethtool_bitset> groups;
};

struct ethtool_stats_get_list {
	std::list<ethtool_stats_get_rsp> objs;
};

std::unique_ptr<ethtool_stats_get_list>
ethtool_stats_get_dump(ynl_cpp::ynl_socket& ys,
		       ethtool_stats_get_req_dump& req);

/* ============== ETHTOOL_MSG_PHC_VCLOCKS_GET ============== */
/* ETHTOOL_MSG_PHC_VCLOCKS_GET - do */
struct ethtool_phc_vclocks_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_phc_vclocks_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u32> num;
};

/*
 * Get PHC VCLOCKs.
 */
std::unique_ptr<ethtool_phc_vclocks_get_rsp>
ethtool_phc_vclocks_get(ynl_cpp::ynl_socket& ys,
			ethtool_phc_vclocks_get_req& req);

/* ETHTOOL_MSG_PHC_VCLOCKS_GET - dump */
struct ethtool_phc_vclocks_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_phc_vclocks_get_list {
	std::list<ethtool_phc_vclocks_get_rsp> objs;
};

std::unique_ptr<ethtool_phc_vclocks_get_list>
ethtool_phc_vclocks_get_dump(ynl_cpp::ynl_socket& ys,
			     ethtool_phc_vclocks_get_req_dump& req);

/* ============== ETHTOOL_MSG_MODULE_GET ============== */
/* ETHTOOL_MSG_MODULE_GET - do */
struct ethtool_module_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_module_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u8> power_mode_policy;
	std::optional<__u8> power_mode;
};

/*
 * Get module params.
 */
std::unique_ptr<ethtool_module_get_rsp>
ethtool_module_get(ynl_cpp::ynl_socket& ys, ethtool_module_get_req& req);

/* ETHTOOL_MSG_MODULE_GET - dump */
struct ethtool_module_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_module_get_list {
	std::list<ethtool_module_get_rsp> objs;
};

std::unique_ptr<ethtool_module_get_list>
ethtool_module_get_dump(ynl_cpp::ynl_socket& ys,
			ethtool_module_get_req_dump& req);

/* ETHTOOL_MSG_MODULE_GET - notify */
struct ethtool_module_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_module_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_MODULE_SET ============== */
/* ETHTOOL_MSG_MODULE_SET - do */
struct ethtool_module_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u8> power_mode_policy;
	std::optional<__u8> power_mode;
};

/*
 * Set module params.
 */
int ethtool_module_set(ynl_cpp::ynl_socket& ys, ethtool_module_set_req& req);

/* ============== ETHTOOL_MSG_PSE_GET ============== */
/* ETHTOOL_MSG_PSE_GET - do */
struct ethtool_pse_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_pse_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u32> podl_pse_admin_state;
	std::optional<__u32> podl_pse_admin_control;
	std::optional<__u32> podl_pse_pw_d_status;
	std::optional<__u32> c33_pse_admin_state;
	std::optional<__u32> c33_pse_admin_control;
	std::optional<__u32> c33_pse_pw_d_status;
	std::optional<__u32> c33_pse_pw_class;
	std::optional<__u32> c33_pse_actual_pw;
	std::optional<enum ethtool_c33_pse_ext_state> c33_pse_ext_state;
	std::optional<__u32> c33_pse_ext_substate;
	std::optional<__u32> c33_pse_avail_pw_limit;
	std::vector<ethtool_c33_pse_pw_limit> c33_pse_pw_limit_ranges;
	std::optional<__u32> pse_pw_d_id;
	std::optional<__u32> pse_prio_max;
	std::optional<__u32> pse_prio;
};

/*
 * Get Power Sourcing Equipment params.
 */
std::unique_ptr<ethtool_pse_get_rsp>
ethtool_pse_get(ynl_cpp::ynl_socket& ys, ethtool_pse_get_req& req);

/* ETHTOOL_MSG_PSE_GET - dump */
struct ethtool_pse_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_pse_get_list {
	std::list<ethtool_pse_get_rsp> objs;
};

std::unique_ptr<ethtool_pse_get_list>
ethtool_pse_get_dump(ynl_cpp::ynl_socket& ys, ethtool_pse_get_req_dump& req);

/* ============== ETHTOOL_MSG_PSE_SET ============== */
/* ETHTOOL_MSG_PSE_SET - do */
struct ethtool_pse_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u32> podl_pse_admin_control;
	std::optional<__u32> c33_pse_admin_control;
	std::optional<__u32> c33_pse_avail_pw_limit;
	std::optional<__u32> pse_prio;
};

/*
 * Set Power Sourcing Equipment params.
 */
int ethtool_pse_set(ynl_cpp::ynl_socket& ys, ethtool_pse_set_req& req);

/* ============== ETHTOOL_MSG_RSS_GET ============== */
/* ETHTOOL_MSG_RSS_GET - do */
struct ethtool_rss_get_req {
	std::optional<ethtool_header> header;
	std::optional<__u32> context;
};

struct ethtool_rss_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u32> context;
	std::optional<__u32> hfunc;
	std::vector<__u8> indir;
	std::vector<__u8> hkey;
	std::optional<__u32> input_xfrm;
	std::optional<ethtool_flow> flow_hash;
};

/*
 * Get RSS params.
 */
std::unique_ptr<ethtool_rss_get_rsp>
ethtool_rss_get(ynl_cpp::ynl_socket& ys, ethtool_rss_get_req& req);

/* ETHTOOL_MSG_RSS_GET - dump */
struct ethtool_rss_get_req_dump {
	std::optional<ethtool_header> header;
	std::optional<__u32> start_context;
};

struct ethtool_rss_get_list {
	std::list<ethtool_rss_get_rsp> objs;
};

std::unique_ptr<ethtool_rss_get_list>
ethtool_rss_get_dump(ynl_cpp::ynl_socket& ys, ethtool_rss_get_req_dump& req);

/* ETHTOOL_MSG_RSS_GET - notify */
struct ethtool_rss_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_rss_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_PLCA_GET_CFG ============== */
/* ETHTOOL_MSG_PLCA_GET_CFG - do */
struct ethtool_plca_get_cfg_req {
	std::optional<ethtool_header> header;
};

struct ethtool_plca_get_cfg_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u16> version;
	std::optional<__u8> enabled;
	std::optional<__u8> status;
	std::optional<__u32> node_cnt;
	std::optional<__u32> node_id;
	std::optional<__u32> to_tmr;
	std::optional<__u32> burst_cnt;
	std::optional<__u32> burst_tmr;
};

/*
 * Get PLCA params.
 */
std::unique_ptr<ethtool_plca_get_cfg_rsp>
ethtool_plca_get_cfg(ynl_cpp::ynl_socket& ys, ethtool_plca_get_cfg_req& req);

/* ETHTOOL_MSG_PLCA_GET_CFG - dump */
struct ethtool_plca_get_cfg_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_plca_get_cfg_list {
	std::list<ethtool_plca_get_cfg_rsp> objs;
};

std::unique_ptr<ethtool_plca_get_cfg_list>
ethtool_plca_get_cfg_dump(ynl_cpp::ynl_socket& ys,
			  ethtool_plca_get_cfg_req_dump& req);

/* ETHTOOL_MSG_PLCA_GET_CFG - notify */
struct ethtool_plca_get_cfg_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_plca_get_cfg_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_PLCA_SET_CFG ============== */
/* ETHTOOL_MSG_PLCA_SET_CFG - do */
struct ethtool_plca_set_cfg_req {
	std::optional<ethtool_header> header;
	std::optional<__u16> version;
	std::optional<__u8> enabled;
	std::optional<__u8> status;
	std::optional<__u32> node_cnt;
	std::optional<__u32> node_id;
	std::optional<__u32> to_tmr;
	std::optional<__u32> burst_cnt;
	std::optional<__u32> burst_tmr;
};

/*
 * Set PLCA params.
 */
int ethtool_plca_set_cfg(ynl_cpp::ynl_socket& ys,
			 ethtool_plca_set_cfg_req& req);

/* ============== ETHTOOL_MSG_PLCA_GET_STATUS ============== */
/* ETHTOOL_MSG_PLCA_GET_STATUS - do */
struct ethtool_plca_get_status_req {
	std::optional<ethtool_header> header;
};

struct ethtool_plca_get_status_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u16> version;
	std::optional<__u8> enabled;
	std::optional<__u8> status;
	std::optional<__u32> node_cnt;
	std::optional<__u32> node_id;
	std::optional<__u32> to_tmr;
	std::optional<__u32> burst_cnt;
	std::optional<__u32> burst_tmr;
};

/*
 * Get PLCA status params.
 */
std::unique_ptr<ethtool_plca_get_status_rsp>
ethtool_plca_get_status(ynl_cpp::ynl_socket& ys,
			ethtool_plca_get_status_req& req);

/* ETHTOOL_MSG_PLCA_GET_STATUS - dump */
struct ethtool_plca_get_status_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_plca_get_status_list {
	std::list<ethtool_plca_get_status_rsp> objs;
};

std::unique_ptr<ethtool_plca_get_status_list>
ethtool_plca_get_status_dump(ynl_cpp::ynl_socket& ys,
			     ethtool_plca_get_status_req_dump& req);

/* ============== ETHTOOL_MSG_MM_GET ============== */
/* ETHTOOL_MSG_MM_GET - do */
struct ethtool_mm_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_mm_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u8> pmac_enabled;
	std::optional<__u8> tx_enabled;
	std::optional<__u8> tx_active;
	std::optional<__u32> tx_min_frag_size;
	std::optional<__u32> rx_min_frag_size;
	std::optional<__u8> verify_enabled;
	std::optional<__u32> verify_time;
	std::optional<__u32> max_verify_time;
	std::optional<ethtool_mm_stat> stats;
};

/*
 * Get MAC Merge configuration and state
 */
std::unique_ptr<ethtool_mm_get_rsp>
ethtool_mm_get(ynl_cpp::ynl_socket& ys, ethtool_mm_get_req& req);

/* ETHTOOL_MSG_MM_GET - dump */
struct ethtool_mm_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_mm_get_list {
	std::list<ethtool_mm_get_rsp> objs;
};

std::unique_ptr<ethtool_mm_get_list>
ethtool_mm_get_dump(ynl_cpp::ynl_socket& ys, ethtool_mm_get_req_dump& req);

/* ETHTOOL_MSG_MM_GET - notify */
struct ethtool_mm_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_mm_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_MM_SET ============== */
/* ETHTOOL_MSG_MM_SET - do */
struct ethtool_mm_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u8> verify_enabled;
	std::optional<__u32> verify_time;
	std::optional<__u8> tx_enabled;
	std::optional<__u8> pmac_enabled;
	std::optional<__u32> tx_min_frag_size;
};

/*
 * Set MAC Merge configuration
 */
int ethtool_mm_set(ynl_cpp::ynl_socket& ys, ethtool_mm_set_req& req);

/* ============== ETHTOOL_MSG_MODULE_FW_FLASH_ACT ============== */
/* ETHTOOL_MSG_MODULE_FW_FLASH_ACT - do */
struct ethtool_module_fw_flash_act_req {
	std::optional<ethtool_header> header;
	std::string file_name;
	std::optional<__u32> password;
};

/*
 * Flash transceiver module firmware.
 */
int ethtool_module_fw_flash_act(ynl_cpp::ynl_socket& ys,
				ethtool_module_fw_flash_act_req& req);

/* ============== ETHTOOL_MSG_PHY_GET ============== */
/* ETHTOOL_MSG_PHY_GET - do */
struct ethtool_phy_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_phy_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u32> index;
	std::string drvname;
	std::string name;
	std::optional<enum phy_upstream> upstream_type;
	std::optional<__u32> upstream_index;
	std::string upstream_sfp_name;
	std::string downstream_sfp_name;
};

/*
 * Get PHY devices attached to an interface
 */
std::unique_ptr<ethtool_phy_get_rsp>
ethtool_phy_get(ynl_cpp::ynl_socket& ys, ethtool_phy_get_req& req);

/* ETHTOOL_MSG_PHY_GET - dump */
struct ethtool_phy_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_phy_get_list {
	std::list<ethtool_phy_get_rsp> objs;
};

std::unique_ptr<ethtool_phy_get_list>
ethtool_phy_get_dump(ynl_cpp::ynl_socket& ys, ethtool_phy_get_req_dump& req);

/* ETHTOOL_MSG_PHY_GET - notify */
struct ethtool_phy_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_phy_get_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_TSCONFIG_GET ============== */
/* ETHTOOL_MSG_TSCONFIG_GET - do */
struct ethtool_tsconfig_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_tsconfig_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_ts_hwtstamp_provider> hwtstamp_provider;
	std::optional<ethtool_bitset> tx_types;
	std::optional<ethtool_bitset> rx_filters;
	std::optional<ethtool_bitset> hwtstamp_flags;
};

/*
 * Get hwtstamp config.
 */
std::unique_ptr<ethtool_tsconfig_get_rsp>
ethtool_tsconfig_get(ynl_cpp::ynl_socket& ys, ethtool_tsconfig_get_req& req);

/* ETHTOOL_MSG_TSCONFIG_GET - dump */
struct ethtool_tsconfig_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_tsconfig_get_list {
	std::list<ethtool_tsconfig_get_rsp> objs;
};

std::unique_ptr<ethtool_tsconfig_get_list>
ethtool_tsconfig_get_dump(ynl_cpp::ynl_socket& ys,
			  ethtool_tsconfig_get_req_dump& req);

/* ============== ETHTOOL_MSG_TSCONFIG_SET ============== */
/* ETHTOOL_MSG_TSCONFIG_SET - do */
struct ethtool_tsconfig_set_req {
	std::optional<ethtool_header> header;
	std::optional<ethtool_ts_hwtstamp_provider> hwtstamp_provider;
	std::optional<ethtool_bitset> tx_types;
	std::optional<ethtool_bitset> rx_filters;
	std::optional<ethtool_bitset> hwtstamp_flags;
};

struct ethtool_tsconfig_set_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_ts_hwtstamp_provider> hwtstamp_provider;
	std::optional<ethtool_bitset> tx_types;
	std::optional<ethtool_bitset> rx_filters;
	std::optional<ethtool_bitset> hwtstamp_flags;
};

/*
 * Set hwtstamp config.
 */
std::unique_ptr<ethtool_tsconfig_set_rsp>
ethtool_tsconfig_set(ynl_cpp::ynl_socket& ys, ethtool_tsconfig_set_req& req);

/* ============== ETHTOOL_MSG_RSS_SET ============== */
/* ETHTOOL_MSG_RSS_SET - do */
struct ethtool_rss_set_req {
	std::optional<ethtool_header> header;
	std::optional<__u32> context;
	std::optional<__u32> hfunc;
	std::vector<__u8> indir;
	std::vector<__u8> hkey;
	std::optional<__u32> input_xfrm;
	std::optional<ethtool_flow> flow_hash;
};

/*
 * Set RSS params.
 */
int ethtool_rss_set(ynl_cpp::ynl_socket& ys, ethtool_rss_set_req& req);

/* ============== ETHTOOL_MSG_RSS_CREATE_ACT ============== */
/* ETHTOOL_MSG_RSS_CREATE_ACT - do */
struct ethtool_rss_create_act_req {
	std::optional<ethtool_header> header;
	std::optional<__u32> context;
	std::optional<__u32> hfunc;
	std::vector<__u8> indir;
	std::vector<__u8> hkey;
	std::optional<__u32> input_xfrm;
};

struct ethtool_rss_create_act_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u32> context;
	std::optional<__u32> hfunc;
	std::vector<__u8> indir;
	std::vector<__u8> hkey;
	std::optional<__u32> input_xfrm;
};

/*
 * Create an RSS context.
 */
std::unique_ptr<ethtool_rss_create_act_rsp>
ethtool_rss_create_act(ynl_cpp::ynl_socket& ys,
		       ethtool_rss_create_act_req& req);

/* ETHTOOL_MSG_RSS_CREATE_ACT - notify */
struct ethtool_rss_create_act_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_rss_create_act_rsp obj __attribute__((aligned(8)));
};

/* ============== ETHTOOL_MSG_RSS_DELETE_ACT ============== */
/* ETHTOOL_MSG_RSS_DELETE_ACT - do */
struct ethtool_rss_delete_act_req {
	std::optional<ethtool_header> header;
	std::optional<__u32> context;
};

/*
 * Delete an RSS context.
 */
int ethtool_rss_delete_act(ynl_cpp::ynl_socket& ys,
			   ethtool_rss_delete_act_req& req);

/* ============== ETHTOOL_MSG_MSE_GET ============== */
/* ETHTOOL_MSG_MSE_GET - do */
struct ethtool_mse_get_req {
	std::optional<ethtool_header> header;
};

struct ethtool_mse_get_rsp {
	std::optional<ethtool_header> header;
	std::optional<ethtool_mse_capabilities> capabilities;
	std::optional<ethtool_mse_snapshot> channel_a;
	std::optional<ethtool_mse_snapshot> channel_b;
	std::optional<ethtool_mse_snapshot> channel_c;
	std::optional<ethtool_mse_snapshot> channel_d;
	std::optional<ethtool_mse_snapshot> worst_channel;
	std::optional<ethtool_mse_snapshot> link;
};

/*
 * Get PHY MSE measurement data and capabilities.
 */
std::unique_ptr<ethtool_mse_get_rsp>
ethtool_mse_get(ynl_cpp::ynl_socket& ys, ethtool_mse_get_req& req);

/* ETHTOOL_MSG_MSE_GET - dump */
struct ethtool_mse_get_req_dump {
	std::optional<ethtool_header> header;
};

struct ethtool_mse_get_list {
	std::list<ethtool_mse_get_rsp> objs;
};

std::unique_ptr<ethtool_mse_get_list>
ethtool_mse_get_dump(ynl_cpp::ynl_socket& ys, ethtool_mse_get_req_dump& req);

/* ETHTOOL_MSG_CABLE_TEST_NTF - event */
struct ethtool_cable_test_ntf_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u8> status;
};

struct ethtool_cable_test_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_cable_test_ntf_rsp obj __attribute__((aligned(8)));
};

/* ETHTOOL_MSG_CABLE_TEST_TDR_NTF - event */
struct ethtool_cable_test_tdr_ntf_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u8> status;
	std::optional<ethtool_cable_nest> nest;
};

struct ethtool_cable_test_tdr_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_cable_test_tdr_ntf_rsp obj __attribute__((aligned(8)));
};

/* ETHTOOL_MSG_MODULE_FW_FLASH_NTF - event */
struct ethtool_module_fw_flash_ntf_rsp {
	std::optional<ethtool_header> header;
	std::optional<enum ethtool_module_fw_flash_status> status;
	std::string status_msg;
	std::optional<__u64> done;
	std::optional<__u64> total;
};

struct ethtool_module_fw_flash_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_module_fw_flash_ntf_rsp obj __attribute__((aligned(8)));
};

/* ETHTOOL_MSG_PSE_NTF - event */
struct ethtool_pse_ntf_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u64> events;
};

struct ethtool_pse_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_pse_ntf_rsp obj __attribute__((aligned(8)));
};

/* ETHTOOL_MSG_RSS_DELETE_NTF - event */
struct ethtool_rss_delete_ntf_rsp {
	std::optional<ethtool_header> header;
	std::optional<__u32> context;
};

struct ethtool_rss_delete_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ethtool_rss_delete_ntf_rsp obj __attribute__((aligned(8)));
};

} //namespace ynl_cpp
#endif /* _LINUX_ETHTOOL_GEN_H */
