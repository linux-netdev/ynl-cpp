/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_DEVLINK_GEN_H
#define _LINUX_DEVLINK_GEN_H

#include <linux/types.h>
#include <linux/netlink.h>
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

#include <linux/devlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_devlink_family();

/* Enums */
std::string_view devlink_op_str(int op);
std::string_view devlink_sb_pool_type_str(devlink_sb_pool_type value);
std::string_view devlink_port_type_str(devlink_port_type value);
std::string_view devlink_port_flavour_str(devlink_port_flavour value);
std::string_view devlink_port_fn_state_str(devlink_port_fn_state value);
std::string_view devlink_port_fn_opstate_str(devlink_port_fn_opstate value);
std::string_view devlink_port_fn_attr_cap_str(devlink_port_fn_attr_cap value);
std::string_view devlink_rate_type_str(devlink_rate_type value);
std::string_view
devlink_sb_threshold_type_str(devlink_sb_threshold_type value);
std::string_view devlink_eswitch_mode_str(devlink_eswitch_mode value);
std::string_view
devlink_eswitch_inline_mode_str(devlink_eswitch_inline_mode value);
std::string_view
devlink_eswitch_encap_mode_str(devlink_eswitch_encap_mode value);
std::string_view devlink_dpipe_header_id_str(devlink_dpipe_header_id value);
std::string_view devlink_dpipe_match_type_str(devlink_dpipe_match_type value);
std::string_view
devlink_dpipe_action_type_str(devlink_dpipe_action_type value);
std::string_view
devlink_dpipe_field_mapping_type_str(devlink_dpipe_field_mapping_type value);
std::string_view devlink_resource_unit_str(devlink_resource_unit value);
std::string_view devlink_reload_action_str(devlink_reload_action value);
std::string_view devlink_param_cmode_str(devlink_param_cmode value);
std::string_view devlink_flash_overwrite_str(devlink_flash_overwrite value);
std::string_view devlink_trap_action_str(devlink_trap_action value);
std::string_view devlink_trap_type_str(devlink_trap_type value);
std::string_view devlink_var_attr_type_str(devlink_var_attr_type value);

/* Common nested types */
struct devlink_dl_dpipe_match {
	std::optional<enum devlink_dpipe_match_type> dpipe_match_type;
	std::optional<enum devlink_dpipe_header_id> dpipe_header_id;
	std::optional<__u8> dpipe_header_global;
	std::optional<__u32> dpipe_header_index;
	std::optional<__u32> dpipe_field_id;
};

struct devlink_dl_dpipe_match_value {
	std::vector<devlink_dl_dpipe_match> dpipe_match;
	std::vector<__u8> dpipe_value;
	std::vector<__u8> dpipe_value_mask;
	std::optional<__u32> dpipe_value_mapping;
};

struct devlink_dl_dpipe_action {
	std::optional<enum devlink_dpipe_action_type> dpipe_action_type;
	std::optional<enum devlink_dpipe_header_id> dpipe_header_id;
	std::optional<__u8> dpipe_header_global;
	std::optional<__u32> dpipe_header_index;
	std::optional<__u32> dpipe_field_id;
};

struct devlink_dl_dpipe_action_value {
	std::vector<devlink_dl_dpipe_action> dpipe_action;
	std::vector<__u8> dpipe_value;
	std::vector<__u8> dpipe_value_mask;
	std::optional<__u32> dpipe_value_mapping;
};

struct devlink_dl_dpipe_field {
	std::string dpipe_field_name;
	std::optional<__u32> dpipe_field_id;
	std::optional<__u32> dpipe_field_bitwidth;
	std::optional<enum devlink_dpipe_field_mapping_type> dpipe_field_mapping_type;
};

struct devlink_dl_resource {
	std::string resource_name;
	std::optional<__u64> resource_id;
	std::optional<__u64> resource_size;
	std::optional<__u64> resource_size_new;
	std::optional<__u8> resource_size_valid;
	std::optional<__u64> resource_size_min;
	std::optional<__u64> resource_size_max;
	std::optional<__u64> resource_size_gran;
	std::optional<enum devlink_resource_unit> resource_unit;
	std::optional<__u64> resource_occ;
};

struct devlink_dl_param {
	std::string param_name;
	bool param_generic{};
	std::optional<enum devlink_var_attr_type> param_type;
};

struct devlink_dl_region_snapshot {
	std::optional<__u32> region_snapshot_id;
};

struct devlink_dl_region_chunk {
	std::vector<__u8> region_chunk_data;
	std::optional<__u64> region_chunk_addr;
};

struct devlink_dl_info_version {
	std::string info_version_name;
	std::string info_version_value;
};

struct devlink_dl_fmsg {
	bool fmsg_obj_nest_start{};
	bool fmsg_pair_nest_start{};
	bool fmsg_arr_nest_start{};
	bool fmsg_nest_end{};
	std::string fmsg_obj_name;
};

struct devlink_dl_health_reporter {
	std::string health_reporter_name;
	std::optional<__u8> health_reporter_state;
	std::optional<__u64> health_reporter_err_count;
	std::optional<__u64> health_reporter_recover_count;
	std::optional<__u64> health_reporter_graceful_period;
	std::optional<__u8> health_reporter_auto_recover;
	std::optional<__u64> health_reporter_dump_ts;
	std::optional<__u64> health_reporter_dump_ts_ns;
	std::optional<__u8> health_reporter_auto_dump;
	std::optional<__u64> health_reporter_burst_period;
};

struct devlink_dl_attr_stats {
	std::optional<__u64> stats_rx_packets;
	std::optional<__u64> stats_rx_bytes;
	std::optional<__u64> stats_rx_dropped;
};

struct devlink_dl_trap_metadata {
	bool trap_metadata_type_in_port{};
	bool trap_metadata_type_fa_cookie{};
};

struct devlink_dl_port_function {
	std::vector<__u8> hw_addr;
	std::optional<enum devlink_port_fn_state> state;
	std::optional<enum devlink_port_fn_opstate> opstate;
	std::optional<struct nla_bitfield32> caps;
};

struct devlink_dl_reload_stats_entry {
	std::optional<__u8> reload_stats_limit;
	std::optional<__u32> reload_stats_value;
};

struct devlink_dl_reload_act_stats {
	std::vector<devlink_dl_reload_stats_entry> reload_stats_entry;
};

struct devlink_dl_linecard_supported_types {
	std::string linecard_type;
};

struct devlink_dl_selftest_id {
	bool flash{};
};

struct devlink_dl_rate_tc_bws {
	std::optional<__u8> index;
	std::optional<__u32> bw;
};

struct devlink_dl_dpipe_table_matches {
	std::vector<devlink_dl_dpipe_match> dpipe_match;
};

struct devlink_dl_dpipe_table_actions {
	std::vector<devlink_dl_dpipe_action> dpipe_action;
};

struct devlink_dl_dpipe_entry_match_values {
	std::vector<devlink_dl_dpipe_match_value> dpipe_match_value;
};

struct devlink_dl_dpipe_entry_action_values {
	std::vector<devlink_dl_dpipe_action_value> dpipe_action_value;
};

struct devlink_dl_dpipe_header_fields {
	std::vector<devlink_dl_dpipe_field> dpipe_field;
};

struct devlink_dl_resource_list {
	std::vector<devlink_dl_resource> resource;
};

struct devlink_dl_region_snapshots {
	std::optional<devlink_dl_region_snapshot> region_snapshot;
};

struct devlink_dl_region_chunks {
	std::optional<devlink_dl_region_chunk> region_chunk;
};

struct devlink_dl_reload_act_info {
	std::optional<enum devlink_reload_action> reload_action;
	std::vector<devlink_dl_reload_act_stats> reload_action_stats;
};

struct devlink_dl_dpipe_table {
	std::string dpipe_table_name;
	std::optional<__u64> dpipe_table_size;
	std::optional<devlink_dl_dpipe_table_matches> dpipe_table_matches;
	std::optional<devlink_dl_dpipe_table_actions> dpipe_table_actions;
	std::optional<__u8> dpipe_table_counters_enabled;
	std::optional<__u64> dpipe_table_resource_id;
	std::optional<__u64> dpipe_table_resource_units;
};

struct devlink_dl_dpipe_entry {
	std::optional<__u64> dpipe_entry_index;
	std::optional<devlink_dl_dpipe_entry_match_values> dpipe_entry_match_values;
	std::optional<devlink_dl_dpipe_entry_action_values> dpipe_entry_action_values;
	std::optional<__u64> dpipe_entry_counter;
};

struct devlink_dl_dpipe_header {
	std::string dpipe_header_name;
	std::optional<enum devlink_dpipe_header_id> dpipe_header_id;
	std::optional<__u8> dpipe_header_global;
	std::optional<devlink_dl_dpipe_header_fields> dpipe_header_fields;
};

struct devlink_dl_reload_stats {
	std::vector<devlink_dl_reload_act_info> reload_action_info;
};

struct devlink_dl_dpipe_tables {
	std::vector<devlink_dl_dpipe_table> dpipe_table;
};

struct devlink_dl_dpipe_entries {
	std::vector<devlink_dl_dpipe_entry> dpipe_entry;
};

struct devlink_dl_dpipe_headers {
	std::vector<devlink_dl_dpipe_header> dpipe_header;
};

struct devlink_dl_dev_stats {
	std::optional<devlink_dl_reload_stats> reload_stats;
	std::optional<devlink_dl_reload_stats> remote_reload_stats;
};

/* ============== DEVLINK_CMD_GET ============== */
/* DEVLINK_CMD_GET - do */
struct devlink_get_req {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u8> reload_failed;
	std::optional<devlink_dl_dev_stats> dev_stats;
};

/*
 * Get devlink instances.
 */
std::unique_ptr<devlink_get_rsp>
devlink_get(ynl_cpp::ynl_socket& ys, devlink_get_req& req);

/* DEVLINK_CMD_GET - dump */
struct devlink_get_list {
	std::list<devlink_get_rsp> objs;
};

std::unique_ptr<devlink_get_list> devlink_get_dump(ynl_cpp::ynl_socket& ys);

/* ============== DEVLINK_CMD_PORT_GET ============== */
/* DEVLINK_CMD_PORT_GET - do */
struct devlink_port_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

struct devlink_port_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

/*
 * Get devlink port instances.
 */
std::unique_ptr<devlink_port_get_rsp>
devlink_port_get(ynl_cpp::ynl_socket& ys, devlink_port_get_req& req);

/* DEVLINK_CMD_PORT_GET - dump */
struct devlink_port_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_port_get_rsp_dump {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

struct devlink_port_get_rsp_list {
	std::list<devlink_port_get_rsp_dump> objs;
};

std::unique_ptr<devlink_port_get_rsp_list>
devlink_port_get_dump(ynl_cpp::ynl_socket& ys, devlink_port_get_req_dump& req);

/* ============== DEVLINK_CMD_PORT_SET ============== */
/* DEVLINK_CMD_PORT_SET - do */
struct devlink_port_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::optional<enum devlink_port_type> port_type;
	std::optional<devlink_dl_port_function> port_function;
};

/*
 * Set devlink port instances.
 */
int devlink_port_set(ynl_cpp::ynl_socket& ys, devlink_port_set_req& req);

/* ============== DEVLINK_CMD_PORT_NEW ============== */
/* DEVLINK_CMD_PORT_NEW - do */
struct devlink_port_new_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::optional<enum devlink_port_flavour> port_flavour;
	std::optional<__u16> port_pci_pf_number;
	std::optional<__u32> port_pci_sf_number;
	std::optional<__u32> port_controller_number;
};

struct devlink_port_new_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

/*
 * Create devlink port instances.
 */
std::unique_ptr<devlink_port_new_rsp>
devlink_port_new(ynl_cpp::ynl_socket& ys, devlink_port_new_req& req);

/* ============== DEVLINK_CMD_PORT_DEL ============== */
/* DEVLINK_CMD_PORT_DEL - do */
struct devlink_port_del_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

/*
 * Delete devlink port instances.
 */
int devlink_port_del(ynl_cpp::ynl_socket& ys, devlink_port_del_req& req);

/* ============== DEVLINK_CMD_PORT_SPLIT ============== */
/* DEVLINK_CMD_PORT_SPLIT - do */
struct devlink_port_split_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::optional<__u32> port_split_count;
};

/*
 * Split devlink port instances.
 */
int devlink_port_split(ynl_cpp::ynl_socket& ys, devlink_port_split_req& req);

/* ============== DEVLINK_CMD_PORT_UNSPLIT ============== */
/* DEVLINK_CMD_PORT_UNSPLIT - do */
struct devlink_port_unsplit_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

/*
 * Unplit devlink port instances.
 */
int devlink_port_unsplit(ynl_cpp::ynl_socket& ys,
			 devlink_port_unsplit_req& req);

/* ============== DEVLINK_CMD_SB_GET ============== */
/* DEVLINK_CMD_SB_GET - do */
struct devlink_sb_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> sb_index;
};

struct devlink_sb_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> sb_index;
};

/*
 * Get shared buffer instances.
 */
std::unique_ptr<devlink_sb_get_rsp>
devlink_sb_get(ynl_cpp::ynl_socket& ys, devlink_sb_get_req& req);

/* DEVLINK_CMD_SB_GET - dump */
struct devlink_sb_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_sb_get_list {
	std::list<devlink_sb_get_rsp> objs;
};

std::unique_ptr<devlink_sb_get_list>
devlink_sb_get_dump(ynl_cpp::ynl_socket& ys, devlink_sb_get_req_dump& req);

/* ============== DEVLINK_CMD_SB_POOL_GET ============== */
/* DEVLINK_CMD_SB_POOL_GET - do */
struct devlink_sb_pool_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> sb_index;
	std::optional<__u16> sb_pool_index;
};

struct devlink_sb_pool_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> sb_index;
	std::optional<__u16> sb_pool_index;
};

/*
 * Get shared buffer pool instances.
 */
std::unique_ptr<devlink_sb_pool_get_rsp>
devlink_sb_pool_get(ynl_cpp::ynl_socket& ys, devlink_sb_pool_get_req& req);

/* DEVLINK_CMD_SB_POOL_GET - dump */
struct devlink_sb_pool_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_sb_pool_get_list {
	std::list<devlink_sb_pool_get_rsp> objs;
};

std::unique_ptr<devlink_sb_pool_get_list>
devlink_sb_pool_get_dump(ynl_cpp::ynl_socket& ys,
			 devlink_sb_pool_get_req_dump& req);

/* ============== DEVLINK_CMD_SB_POOL_SET ============== */
/* DEVLINK_CMD_SB_POOL_SET - do */
struct devlink_sb_pool_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> sb_index;
	std::optional<__u16> sb_pool_index;
	std::optional<enum devlink_sb_threshold_type> sb_pool_threshold_type;
	std::optional<__u32> sb_pool_size;
};

/*
 * Set shared buffer pool instances.
 */
int devlink_sb_pool_set(ynl_cpp::ynl_socket& ys, devlink_sb_pool_set_req& req);

/* ============== DEVLINK_CMD_SB_PORT_POOL_GET ============== */
/* DEVLINK_CMD_SB_PORT_POOL_GET - do */
struct devlink_sb_port_pool_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::optional<__u32> sb_index;
	std::optional<__u16> sb_pool_index;
};

struct devlink_sb_port_pool_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::optional<__u32> sb_index;
	std::optional<__u16> sb_pool_index;
};

/*
 * Get shared buffer port-pool combinations and threshold.
 */
std::unique_ptr<devlink_sb_port_pool_get_rsp>
devlink_sb_port_pool_get(ynl_cpp::ynl_socket& ys,
			 devlink_sb_port_pool_get_req& req);

/* DEVLINK_CMD_SB_PORT_POOL_GET - dump */
struct devlink_sb_port_pool_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_sb_port_pool_get_list {
	std::list<devlink_sb_port_pool_get_rsp> objs;
};

std::unique_ptr<devlink_sb_port_pool_get_list>
devlink_sb_port_pool_get_dump(ynl_cpp::ynl_socket& ys,
			      devlink_sb_port_pool_get_req_dump& req);

/* ============== DEVLINK_CMD_SB_PORT_POOL_SET ============== */
/* DEVLINK_CMD_SB_PORT_POOL_SET - do */
struct devlink_sb_port_pool_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::optional<__u32> sb_index;
	std::optional<__u16> sb_pool_index;
	std::optional<__u32> sb_threshold;
};

/*
 * Set shared buffer port-pool combinations and threshold.
 */
int devlink_sb_port_pool_set(ynl_cpp::ynl_socket& ys,
			     devlink_sb_port_pool_set_req& req);

/* ============== DEVLINK_CMD_SB_TC_POOL_BIND_GET ============== */
/* DEVLINK_CMD_SB_TC_POOL_BIND_GET - do */
struct devlink_sb_tc_pool_bind_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::optional<__u32> sb_index;
	std::optional<enum devlink_sb_pool_type> sb_pool_type;
	std::optional<__u16> sb_tc_index;
};

struct devlink_sb_tc_pool_bind_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::optional<__u32> sb_index;
	std::optional<enum devlink_sb_pool_type> sb_pool_type;
	std::optional<__u16> sb_tc_index;
};

/*
 * Get shared buffer port-TC to pool bindings and threshold.
 */
std::unique_ptr<devlink_sb_tc_pool_bind_get_rsp>
devlink_sb_tc_pool_bind_get(ynl_cpp::ynl_socket& ys,
			    devlink_sb_tc_pool_bind_get_req& req);

/* DEVLINK_CMD_SB_TC_POOL_BIND_GET - dump */
struct devlink_sb_tc_pool_bind_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_sb_tc_pool_bind_get_list {
	std::list<devlink_sb_tc_pool_bind_get_rsp> objs;
};

std::unique_ptr<devlink_sb_tc_pool_bind_get_list>
devlink_sb_tc_pool_bind_get_dump(ynl_cpp::ynl_socket& ys,
				 devlink_sb_tc_pool_bind_get_req_dump& req);

/* ============== DEVLINK_CMD_SB_TC_POOL_BIND_SET ============== */
/* DEVLINK_CMD_SB_TC_POOL_BIND_SET - do */
struct devlink_sb_tc_pool_bind_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::optional<__u32> sb_index;
	std::optional<__u16> sb_pool_index;
	std::optional<enum devlink_sb_pool_type> sb_pool_type;
	std::optional<__u16> sb_tc_index;
	std::optional<__u32> sb_threshold;
};

/*
 * Set shared buffer port-TC to pool bindings and threshold.
 */
int devlink_sb_tc_pool_bind_set(ynl_cpp::ynl_socket& ys,
				devlink_sb_tc_pool_bind_set_req& req);

/* ============== DEVLINK_CMD_SB_OCC_SNAPSHOT ============== */
/* DEVLINK_CMD_SB_OCC_SNAPSHOT - do */
struct devlink_sb_occ_snapshot_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> sb_index;
};

/*
 * Take occupancy snapshot of shared buffer.
 */
int devlink_sb_occ_snapshot(ynl_cpp::ynl_socket& ys,
			    devlink_sb_occ_snapshot_req& req);

/* ============== DEVLINK_CMD_SB_OCC_MAX_CLEAR ============== */
/* DEVLINK_CMD_SB_OCC_MAX_CLEAR - do */
struct devlink_sb_occ_max_clear_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> sb_index;
};

/*
 * Clear occupancy watermarks of shared buffer.
 */
int devlink_sb_occ_max_clear(ynl_cpp::ynl_socket& ys,
			     devlink_sb_occ_max_clear_req& req);

/* ============== DEVLINK_CMD_ESWITCH_GET ============== */
/* DEVLINK_CMD_ESWITCH_GET - do */
struct devlink_eswitch_get_req {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_eswitch_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<enum devlink_eswitch_mode> eswitch_mode;
	std::optional<enum devlink_eswitch_inline_mode> eswitch_inline_mode;
	std::optional<enum devlink_eswitch_encap_mode> eswitch_encap_mode;
};

/*
 * Get eswitch attributes.
 */
std::unique_ptr<devlink_eswitch_get_rsp>
devlink_eswitch_get(ynl_cpp::ynl_socket& ys, devlink_eswitch_get_req& req);

/* ============== DEVLINK_CMD_ESWITCH_SET ============== */
/* DEVLINK_CMD_ESWITCH_SET - do */
struct devlink_eswitch_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<enum devlink_eswitch_mode> eswitch_mode;
	std::optional<enum devlink_eswitch_inline_mode> eswitch_inline_mode;
	std::optional<enum devlink_eswitch_encap_mode> eswitch_encap_mode;
};

/*
 * Set eswitch attributes.
 */
int devlink_eswitch_set(ynl_cpp::ynl_socket& ys, devlink_eswitch_set_req& req);

/* ============== DEVLINK_CMD_DPIPE_TABLE_GET ============== */
/* DEVLINK_CMD_DPIPE_TABLE_GET - do */
struct devlink_dpipe_table_get_req {
	std::string bus_name;
	std::string dev_name;
	std::string dpipe_table_name;
};

struct devlink_dpipe_table_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<devlink_dl_dpipe_tables> dpipe_tables;
};

/*
 * Get dpipe table attributes.
 */
std::unique_ptr<devlink_dpipe_table_get_rsp>
devlink_dpipe_table_get(ynl_cpp::ynl_socket& ys,
			devlink_dpipe_table_get_req& req);

/* ============== DEVLINK_CMD_DPIPE_ENTRIES_GET ============== */
/* DEVLINK_CMD_DPIPE_ENTRIES_GET - do */
struct devlink_dpipe_entries_get_req {
	std::string bus_name;
	std::string dev_name;
	std::string dpipe_table_name;
};

struct devlink_dpipe_entries_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<devlink_dl_dpipe_entries> dpipe_entries;
};

/*
 * Get dpipe entries attributes.
 */
std::unique_ptr<devlink_dpipe_entries_get_rsp>
devlink_dpipe_entries_get(ynl_cpp::ynl_socket& ys,
			  devlink_dpipe_entries_get_req& req);

/* ============== DEVLINK_CMD_DPIPE_HEADERS_GET ============== */
/* DEVLINK_CMD_DPIPE_HEADERS_GET - do */
struct devlink_dpipe_headers_get_req {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_dpipe_headers_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<devlink_dl_dpipe_headers> dpipe_headers;
};

/*
 * Get dpipe headers attributes.
 */
std::unique_ptr<devlink_dpipe_headers_get_rsp>
devlink_dpipe_headers_get(ynl_cpp::ynl_socket& ys,
			  devlink_dpipe_headers_get_req& req);

/* ============== DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET ============== */
/* DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET - do */
struct devlink_dpipe_table_counters_set_req {
	std::string bus_name;
	std::string dev_name;
	std::string dpipe_table_name;
	std::optional<__u8> dpipe_table_counters_enabled;
};

/*
 * Set dpipe counter attributes.
 */
int devlink_dpipe_table_counters_set(ynl_cpp::ynl_socket& ys,
				     devlink_dpipe_table_counters_set_req& req);

/* ============== DEVLINK_CMD_RESOURCE_SET ============== */
/* DEVLINK_CMD_RESOURCE_SET - do */
struct devlink_resource_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u64> resource_id;
	std::optional<__u64> resource_size;
};

/*
 * Set resource attributes.
 */
int devlink_resource_set(ynl_cpp::ynl_socket& ys,
			 devlink_resource_set_req& req);

/* ============== DEVLINK_CMD_RESOURCE_DUMP ============== */
/* DEVLINK_CMD_RESOURCE_DUMP - do */
struct devlink_resource_dump_req {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_resource_dump_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<devlink_dl_resource_list> resource_list;
};

/*
 * Get resource attributes.
 */
std::unique_ptr<devlink_resource_dump_rsp>
devlink_resource_dump(ynl_cpp::ynl_socket& ys, devlink_resource_dump_req& req);

/* ============== DEVLINK_CMD_RELOAD ============== */
/* DEVLINK_CMD_RELOAD - do */
struct devlink_reload_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<enum devlink_reload_action> reload_action;
	std::optional<struct nla_bitfield32> reload_limits;
	std::optional<__u32> netns_pid;
	std::optional<__u32> netns_fd;
	std::optional<__u32> netns_id;
};

struct devlink_reload_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<struct nla_bitfield32> reload_actions_performed;
};

/*
 * Reload devlink.
 */
std::unique_ptr<devlink_reload_rsp>
devlink_reload(ynl_cpp::ynl_socket& ys, devlink_reload_req& req);

/* ============== DEVLINK_CMD_PARAM_GET ============== */
/* DEVLINK_CMD_PARAM_GET - do */
struct devlink_param_get_req {
	std::string bus_name;
	std::string dev_name;
	std::string param_name;
};

struct devlink_param_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::string param_name;
};

/*
 * Get param instances.
 */
std::unique_ptr<devlink_param_get_rsp>
devlink_param_get(ynl_cpp::ynl_socket& ys, devlink_param_get_req& req);

/* DEVLINK_CMD_PARAM_GET - dump */
struct devlink_param_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_param_get_list {
	std::list<devlink_param_get_rsp> objs;
};

std::unique_ptr<devlink_param_get_list>
devlink_param_get_dump(ynl_cpp::ynl_socket& ys,
		       devlink_param_get_req_dump& req);

/* ============== DEVLINK_CMD_PARAM_SET ============== */
/* DEVLINK_CMD_PARAM_SET - do */
struct devlink_param_set_req {
	std::string bus_name;
	std::string dev_name;
	std::string param_name;
	std::optional<enum devlink_var_attr_type> param_type;
	std::optional<enum devlink_param_cmode> param_value_cmode;
};

/*
 * Set param instances.
 */
int devlink_param_set(ynl_cpp::ynl_socket& ys, devlink_param_set_req& req);

/* ============== DEVLINK_CMD_REGION_GET ============== */
/* DEVLINK_CMD_REGION_GET - do */
struct devlink_region_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string region_name;
};

struct devlink_region_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string region_name;
};

/*
 * Get region instances.
 */
std::unique_ptr<devlink_region_get_rsp>
devlink_region_get(ynl_cpp::ynl_socket& ys, devlink_region_get_req& req);

/* DEVLINK_CMD_REGION_GET - dump */
struct devlink_region_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_region_get_list {
	std::list<devlink_region_get_rsp> objs;
};

std::unique_ptr<devlink_region_get_list>
devlink_region_get_dump(ynl_cpp::ynl_socket& ys,
			devlink_region_get_req_dump& req);

/* ============== DEVLINK_CMD_REGION_NEW ============== */
/* DEVLINK_CMD_REGION_NEW - do */
struct devlink_region_new_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string region_name;
	std::optional<__u32> region_snapshot_id;
};

struct devlink_region_new_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string region_name;
	std::optional<__u32> region_snapshot_id;
};

/*
 * Create region snapshot.
 */
std::unique_ptr<devlink_region_new_rsp>
devlink_region_new(ynl_cpp::ynl_socket& ys, devlink_region_new_req& req);

/* ============== DEVLINK_CMD_REGION_DEL ============== */
/* DEVLINK_CMD_REGION_DEL - do */
struct devlink_region_del_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string region_name;
	std::optional<__u32> region_snapshot_id;
};

/*
 * Delete region snapshot.
 */
int devlink_region_del(ynl_cpp::ynl_socket& ys, devlink_region_del_req& req);

/* ============== DEVLINK_CMD_REGION_READ ============== */
/* DEVLINK_CMD_REGION_READ - dump */
struct devlink_region_read_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string region_name;
	std::optional<__u32> region_snapshot_id;
	bool region_direct{};
	std::optional<__u64> region_chunk_addr;
	std::optional<__u64> region_chunk_len;
};

struct devlink_region_read_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string region_name;
};

struct devlink_region_read_list {
	std::list<devlink_region_read_rsp> objs;
};

std::unique_ptr<devlink_region_read_list>
devlink_region_read_dump(ynl_cpp::ynl_socket& ys, devlink_region_read_req& req);

/* ============== DEVLINK_CMD_PORT_PARAM_GET ============== */
/* DEVLINK_CMD_PORT_PARAM_GET - do */
struct devlink_port_param_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

struct devlink_port_param_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

/*
 * Get port param instances.
 */
std::unique_ptr<devlink_port_param_get_rsp>
devlink_port_param_get(ynl_cpp::ynl_socket& ys,
		       devlink_port_param_get_req& req);

/* DEVLINK_CMD_PORT_PARAM_GET - dump */
struct devlink_port_param_get_list {
	std::list<devlink_port_param_get_rsp> objs;
};

std::unique_ptr<devlink_port_param_get_list>
devlink_port_param_get_dump(ynl_cpp::ynl_socket& ys);

/* ============== DEVLINK_CMD_PORT_PARAM_SET ============== */
/* DEVLINK_CMD_PORT_PARAM_SET - do */
struct devlink_port_param_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

/*
 * Set port param instances.
 */
int devlink_port_param_set(ynl_cpp::ynl_socket& ys,
			   devlink_port_param_set_req& req);

/* ============== DEVLINK_CMD_INFO_GET ============== */
/* DEVLINK_CMD_INFO_GET - do */
struct devlink_info_get_req {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_info_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::string info_driver_name;
	std::string info_serial_number;
	std::vector<devlink_dl_info_version> info_version_fixed;
	std::vector<devlink_dl_info_version> info_version_running;
	std::vector<devlink_dl_info_version> info_version_stored;
	std::string info_board_serial_number;
};

/*
 * Get device information, like driver name, hardware and firmware versions
etc.

 */
std::unique_ptr<devlink_info_get_rsp>
devlink_info_get(ynl_cpp::ynl_socket& ys, devlink_info_get_req& req);

/* DEVLINK_CMD_INFO_GET - dump */
struct devlink_info_get_list {
	std::list<devlink_info_get_rsp> objs;
};

std::unique_ptr<devlink_info_get_list>
devlink_info_get_dump(ynl_cpp::ynl_socket& ys);

/* ============== DEVLINK_CMD_HEALTH_REPORTER_GET ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_GET - do */
struct devlink_health_reporter_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string health_reporter_name;
};

struct devlink_health_reporter_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string health_reporter_name;
};

/*
 * Get health reporter instances.
 */
std::unique_ptr<devlink_health_reporter_get_rsp>
devlink_health_reporter_get(ynl_cpp::ynl_socket& ys,
			    devlink_health_reporter_get_req& req);

/* DEVLINK_CMD_HEALTH_REPORTER_GET - dump */
struct devlink_health_reporter_get_req_dump {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

struct devlink_health_reporter_get_list {
	std::list<devlink_health_reporter_get_rsp> objs;
};

std::unique_ptr<devlink_health_reporter_get_list>
devlink_health_reporter_get_dump(ynl_cpp::ynl_socket& ys,
				 devlink_health_reporter_get_req_dump& req);

/* ============== DEVLINK_CMD_HEALTH_REPORTER_SET ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_SET - do */
struct devlink_health_reporter_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string health_reporter_name;
	std::optional<__u64> health_reporter_graceful_period;
	std::optional<__u8> health_reporter_auto_recover;
	std::optional<__u8> health_reporter_auto_dump;
	std::optional<__u64> health_reporter_burst_period;
};

/*
 * Set health reporter instances.
 */
int devlink_health_reporter_set(ynl_cpp::ynl_socket& ys,
				devlink_health_reporter_set_req& req);

/* ============== DEVLINK_CMD_HEALTH_REPORTER_RECOVER ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_RECOVER - do */
struct devlink_health_reporter_recover_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string health_reporter_name;
};

/*
 * Recover health reporter instances.
 */
int devlink_health_reporter_recover(ynl_cpp::ynl_socket& ys,
				    devlink_health_reporter_recover_req& req);

/* ============== DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE - do */
struct devlink_health_reporter_diagnose_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string health_reporter_name;
};

/*
 * Diagnose health reporter instances.
 */
int devlink_health_reporter_diagnose(ynl_cpp::ynl_socket& ys,
				     devlink_health_reporter_diagnose_req& req);

/* ============== DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET - dump */
struct devlink_health_reporter_dump_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string health_reporter_name;
};

struct devlink_health_reporter_dump_get_rsp {
	std::optional<devlink_dl_fmsg> fmsg;
};

struct devlink_health_reporter_dump_get_list {
	std::list<devlink_health_reporter_dump_get_rsp> objs;
};

std::unique_ptr<devlink_health_reporter_dump_get_list>
devlink_health_reporter_dump_get_dump(ynl_cpp::ynl_socket& ys,
				      devlink_health_reporter_dump_get_req& req);

/* ============== DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR - do */
struct devlink_health_reporter_dump_clear_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string health_reporter_name;
};

/*
 * Clear dump of health reporter instances.
 */
int devlink_health_reporter_dump_clear(ynl_cpp::ynl_socket& ys,
				       devlink_health_reporter_dump_clear_req& req);

/* ============== DEVLINK_CMD_FLASH_UPDATE ============== */
/* DEVLINK_CMD_FLASH_UPDATE - do */
struct devlink_flash_update_req {
	std::string bus_name;
	std::string dev_name;
	std::string flash_update_file_name;
	std::string flash_update_component;
	std::optional<struct nla_bitfield32> flash_update_overwrite_mask;
};

/*
 * Flash update devlink instances.
 */
int devlink_flash_update(ynl_cpp::ynl_socket& ys,
			 devlink_flash_update_req& req);

/* ============== DEVLINK_CMD_TRAP_GET ============== */
/* DEVLINK_CMD_TRAP_GET - do */
struct devlink_trap_get_req {
	std::string bus_name;
	std::string dev_name;
	std::string trap_name;
};

struct devlink_trap_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::string trap_name;
};

/*
 * Get trap instances.
 */
std::unique_ptr<devlink_trap_get_rsp>
devlink_trap_get(ynl_cpp::ynl_socket& ys, devlink_trap_get_req& req);

/* DEVLINK_CMD_TRAP_GET - dump */
struct devlink_trap_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_trap_get_list {
	std::list<devlink_trap_get_rsp> objs;
};

std::unique_ptr<devlink_trap_get_list>
devlink_trap_get_dump(ynl_cpp::ynl_socket& ys, devlink_trap_get_req_dump& req);

/* ============== DEVLINK_CMD_TRAP_SET ============== */
/* DEVLINK_CMD_TRAP_SET - do */
struct devlink_trap_set_req {
	std::string bus_name;
	std::string dev_name;
	std::string trap_name;
	std::optional<enum devlink_trap_action> trap_action;
};

/*
 * Set trap instances.
 */
int devlink_trap_set(ynl_cpp::ynl_socket& ys, devlink_trap_set_req& req);

/* ============== DEVLINK_CMD_TRAP_GROUP_GET ============== */
/* DEVLINK_CMD_TRAP_GROUP_GET - do */
struct devlink_trap_group_get_req {
	std::string bus_name;
	std::string dev_name;
	std::string trap_group_name;
};

struct devlink_trap_group_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::string trap_group_name;
};

/*
 * Get trap group instances.
 */
std::unique_ptr<devlink_trap_group_get_rsp>
devlink_trap_group_get(ynl_cpp::ynl_socket& ys,
		       devlink_trap_group_get_req& req);

/* DEVLINK_CMD_TRAP_GROUP_GET - dump */
struct devlink_trap_group_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_trap_group_get_list {
	std::list<devlink_trap_group_get_rsp> objs;
};

std::unique_ptr<devlink_trap_group_get_list>
devlink_trap_group_get_dump(ynl_cpp::ynl_socket& ys,
			    devlink_trap_group_get_req_dump& req);

/* ============== DEVLINK_CMD_TRAP_GROUP_SET ============== */
/* DEVLINK_CMD_TRAP_GROUP_SET - do */
struct devlink_trap_group_set_req {
	std::string bus_name;
	std::string dev_name;
	std::string trap_group_name;
	std::optional<enum devlink_trap_action> trap_action;
	std::optional<__u32> trap_policer_id;
};

/*
 * Set trap group instances.
 */
int devlink_trap_group_set(ynl_cpp::ynl_socket& ys,
			   devlink_trap_group_set_req& req);

/* ============== DEVLINK_CMD_TRAP_POLICER_GET ============== */
/* DEVLINK_CMD_TRAP_POLICER_GET - do */
struct devlink_trap_policer_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> trap_policer_id;
};

struct devlink_trap_policer_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> trap_policer_id;
};

/*
 * Get trap policer instances.
 */
std::unique_ptr<devlink_trap_policer_get_rsp>
devlink_trap_policer_get(ynl_cpp::ynl_socket& ys,
			 devlink_trap_policer_get_req& req);

/* DEVLINK_CMD_TRAP_POLICER_GET - dump */
struct devlink_trap_policer_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_trap_policer_get_list {
	std::list<devlink_trap_policer_get_rsp> objs;
};

std::unique_ptr<devlink_trap_policer_get_list>
devlink_trap_policer_get_dump(ynl_cpp::ynl_socket& ys,
			      devlink_trap_policer_get_req_dump& req);

/* ============== DEVLINK_CMD_TRAP_POLICER_SET ============== */
/* DEVLINK_CMD_TRAP_POLICER_SET - do */
struct devlink_trap_policer_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> trap_policer_id;
	std::optional<__u64> trap_policer_rate;
	std::optional<__u64> trap_policer_burst;
};

/*
 * Get trap policer instances.
 */
int devlink_trap_policer_set(ynl_cpp::ynl_socket& ys,
			     devlink_trap_policer_set_req& req);

/* ============== DEVLINK_CMD_HEALTH_REPORTER_TEST ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_TEST - do */
struct devlink_health_reporter_test_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string health_reporter_name;
};

/*
 * Test health reporter instances.
 */
int devlink_health_reporter_test(ynl_cpp::ynl_socket& ys,
				 devlink_health_reporter_test_req& req);

/* ============== DEVLINK_CMD_RATE_GET ============== */
/* DEVLINK_CMD_RATE_GET - do */
struct devlink_rate_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string rate_node_name;
};

struct devlink_rate_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
	std::string rate_node_name;
};

/*
 * Get rate instances.
 */
std::unique_ptr<devlink_rate_get_rsp>
devlink_rate_get(ynl_cpp::ynl_socket& ys, devlink_rate_get_req& req);

/* DEVLINK_CMD_RATE_GET - dump */
struct devlink_rate_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_rate_get_list {
	std::list<devlink_rate_get_rsp> objs;
};

std::unique_ptr<devlink_rate_get_list>
devlink_rate_get_dump(ynl_cpp::ynl_socket& ys, devlink_rate_get_req_dump& req);

/* ============== DEVLINK_CMD_RATE_SET ============== */
/* DEVLINK_CMD_RATE_SET - do */
struct devlink_rate_set_req {
	std::string bus_name;
	std::string dev_name;
	std::string rate_node_name;
	std::optional<__u64> rate_tx_share;
	std::optional<__u64> rate_tx_max;
	std::optional<__u32> rate_tx_priority;
	std::optional<__u32> rate_tx_weight;
	std::string rate_parent_node_name;
	std::vector<devlink_dl_rate_tc_bws> rate_tc_bws;
};

/*
 * Set rate instances.
 */
int devlink_rate_set(ynl_cpp::ynl_socket& ys, devlink_rate_set_req& req);

/* ============== DEVLINK_CMD_RATE_NEW ============== */
/* DEVLINK_CMD_RATE_NEW - do */
struct devlink_rate_new_req {
	std::string bus_name;
	std::string dev_name;
	std::string rate_node_name;
	std::optional<__u64> rate_tx_share;
	std::optional<__u64> rate_tx_max;
	std::optional<__u32> rate_tx_priority;
	std::optional<__u32> rate_tx_weight;
	std::string rate_parent_node_name;
	std::vector<devlink_dl_rate_tc_bws> rate_tc_bws;
};

/*
 * Create rate instances.
 */
int devlink_rate_new(ynl_cpp::ynl_socket& ys, devlink_rate_new_req& req);

/* ============== DEVLINK_CMD_RATE_DEL ============== */
/* DEVLINK_CMD_RATE_DEL - do */
struct devlink_rate_del_req {
	std::string bus_name;
	std::string dev_name;
	std::string rate_node_name;
};

/*
 * Delete rate instances.
 */
int devlink_rate_del(ynl_cpp::ynl_socket& ys, devlink_rate_del_req& req);

/* ============== DEVLINK_CMD_LINECARD_GET ============== */
/* DEVLINK_CMD_LINECARD_GET - do */
struct devlink_linecard_get_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> linecard_index;
};

struct devlink_linecard_get_rsp {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> linecard_index;
};

/*
 * Get line card instances.
 */
std::unique_ptr<devlink_linecard_get_rsp>
devlink_linecard_get(ynl_cpp::ynl_socket& ys, devlink_linecard_get_req& req);

/* DEVLINK_CMD_LINECARD_GET - dump */
struct devlink_linecard_get_req_dump {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_linecard_get_list {
	std::list<devlink_linecard_get_rsp> objs;
};

std::unique_ptr<devlink_linecard_get_list>
devlink_linecard_get_dump(ynl_cpp::ynl_socket& ys,
			  devlink_linecard_get_req_dump& req);

/* ============== DEVLINK_CMD_LINECARD_SET ============== */
/* DEVLINK_CMD_LINECARD_SET - do */
struct devlink_linecard_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> linecard_index;
	std::string linecard_type;
};

/*
 * Set line card instances.
 */
int devlink_linecard_set(ynl_cpp::ynl_socket& ys,
			 devlink_linecard_set_req& req);

/* ============== DEVLINK_CMD_SELFTESTS_GET ============== */
/* DEVLINK_CMD_SELFTESTS_GET - do */
struct devlink_selftests_get_req {
	std::string bus_name;
	std::string dev_name;
};

struct devlink_selftests_get_rsp {
	std::string bus_name;
	std::string dev_name;
};

/*
 * Get device selftest instances.
 */
std::unique_ptr<devlink_selftests_get_rsp>
devlink_selftests_get(ynl_cpp::ynl_socket& ys, devlink_selftests_get_req& req);

/* DEVLINK_CMD_SELFTESTS_GET - dump */
struct devlink_selftests_get_list {
	std::list<devlink_selftests_get_rsp> objs;
};

std::unique_ptr<devlink_selftests_get_list>
devlink_selftests_get_dump(ynl_cpp::ynl_socket& ys);

/* ============== DEVLINK_CMD_SELFTESTS_RUN ============== */
/* DEVLINK_CMD_SELFTESTS_RUN - do */
struct devlink_selftests_run_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<devlink_dl_selftest_id> selftests;
};

/*
 * Run device selftest instances.
 */
int devlink_selftests_run(ynl_cpp::ynl_socket& ys,
			  devlink_selftests_run_req& req);

/* ============== DEVLINK_CMD_NOTIFY_FILTER_SET ============== */
/* DEVLINK_CMD_NOTIFY_FILTER_SET - do */
struct devlink_notify_filter_set_req {
	std::string bus_name;
	std::string dev_name;
	std::optional<__u32> port_index;
};

/*
 * Set notification messages socket filter.
 */
int devlink_notify_filter_set(ynl_cpp::ynl_socket& ys,
			      devlink_notify_filter_set_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_DEVLINK_GEN_H */
