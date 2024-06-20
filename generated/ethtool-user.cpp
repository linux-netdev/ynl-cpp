// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "ethtool-user.hpp"

#include <array>

#include <linux/ethtool.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, 43 + 1> ethtool_op_strmap = []() {
	std::array<std::string_view, 43 + 1> arr{};
	arr[ETHTOOL_MSG_STRSET_GET] = "strset-get";
	arr[ETHTOOL_MSG_LINKINFO_GET] = "linkinfo-get";
	arr[3] = "linkinfo-ntf";
	arr[ETHTOOL_MSG_LINKMODES_GET] = "linkmodes-get";
	arr[5] = "linkmodes-ntf";
	arr[ETHTOOL_MSG_LINKSTATE_GET] = "linkstate-get";
	arr[ETHTOOL_MSG_DEBUG_GET] = "debug-get";
	arr[8] = "debug-ntf";
	arr[ETHTOOL_MSG_WOL_GET] = "wol-get";
	arr[10] = "wol-ntf";
	arr[ETHTOOL_MSG_FEATURES_GET] = "features-get";
	arr[ETHTOOL_MSG_FEATURES_SET] = "features-set";
	arr[13] = "features-ntf";
	arr[14] = "privflags-get";
	arr[15] = "privflags-ntf";
	arr[16] = "rings-get";
	arr[17] = "rings-ntf";
	arr[18] = "channels-get";
	arr[19] = "channels-ntf";
	arr[20] = "coalesce-get";
	arr[21] = "coalesce-ntf";
	arr[22] = "pause-get";
	arr[23] = "pause-ntf";
	arr[24] = "eee-get";
	arr[25] = "eee-ntf";
	arr[26] = "tsinfo-get";
	arr[27] = "cable-test-ntf";
	arr[28] = "cable-test-tdr-ntf";
	arr[29] = "tunnel-info-get";
	arr[30] = "fec-get";
	arr[31] = "fec-ntf";
	arr[32] = "module-eeprom-get";
	arr[33] = "stats-get";
	arr[34] = "phc-vclocks-get";
	arr[35] = "module-get";
	arr[36] = "module-ntf";
	arr[37] = "pse-get";
	arr[ETHTOOL_MSG_RSS_GET] = "rss-get";
	arr[ETHTOOL_MSG_PLCA_GET_CFG] = "plca-get-cfg";
	arr[40] = "plca-get-status";
	arr[41] = "plca-ntf";
	arr[ETHTOOL_MSG_MM_GET] = "mm-get";
	arr[43] = "mm-ntf";
	return arr;
} ();

std::string_view ethtool_op_str(int op)
{
	if (op < 0 || op >= (int)(ethtool_op_strmap.size()))
		return "";
	return ethtool_op_strmap[op];
}

static constexpr std::array<std::string_view, 2 + 1> ethtool_udp_tunnel_type_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "vxlan";
	arr[1] = "geneve";
	arr[2] = "vxlan-gpe";
	return arr;
} ();

std::string_view ethtool_udp_tunnel_type_str(int value)
{
	if (value < 0 || value >= (int)(ethtool_udp_tunnel_type_strmap.size()))
		return "";
	return ethtool_udp_tunnel_type_strmap[value];
}

static constexpr std::array<std::string_view, 0 + 1> ethtool_stringset_strmap = []() {
	std::array<std::string_view, 0 + 1> arr{};
	return arr;
} ();

std::string_view ethtool_stringset_str(ethtool_stringset value)
{
	if (value < 0 || value >= (int)(ethtool_stringset_strmap.size()))
		return "";
	return ethtool_stringset_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> ethtool_header_flags_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "compact-bitsets";
	arr[1] = "omit-reply";
	arr[2] = "stats";
	return arr;
} ();

std::string_view ethtool_header_flags_str(ethtool_header_flags value)
{
	value = (ethtool_header_flags)(ffs(value) - 1);
	if (value < 0 || value >= (int)(ethtool_header_flags_strmap.size()))
		return "";
	return ethtool_header_flags_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,ETHTOOL_A_HEADER_MAX + 1> ethtool_header_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_HEADER_MAX + 1> arr{};
	arr[ETHTOOL_A_HEADER_DEV_INDEX] = { .name = "dev-index", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_HEADER_DEV_NAME] = { .name = "dev-name", .type = YNL_PT_NUL_STR, };
	arr[ETHTOOL_A_HEADER_FLAGS] = { .name = "flags", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_header_nest = {
	.max_attr = ETHTOOL_A_HEADER_MAX,
	.table = ethtool_header_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_PAUSE_STAT_MAX + 1> ethtool_pause_stat_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_PAUSE_STAT_MAX + 1> arr{};
	arr[ETHTOOL_A_PAUSE_STAT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, };
	arr[ETHTOOL_A_PAUSE_STAT_TX_FRAMES] = { .name = "tx-frames", .type = YNL_PT_U64, };
	arr[ETHTOOL_A_PAUSE_STAT_RX_FRAMES] = { .name = "rx-frames", .type = YNL_PT_U64, };
	return arr;
} ();

struct ynl_policy_nest ethtool_pause_stat_nest = {
	.max_attr = ETHTOOL_A_PAUSE_STAT_MAX,
	.table = ethtool_pause_stat_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_TS_STAT_MAX + 1> ethtool_ts_stat_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_TS_STAT_MAX + 1> arr{};
	arr[ETHTOOL_A_TS_STAT_TX_PKTS] = { .name = "tx-pkts", .type = YNL_PT_UINT, };
	arr[ETHTOOL_A_TS_STAT_TX_LOST] = { .name = "tx-lost", .type = YNL_PT_UINT, };
	arr[ETHTOOL_A_TS_STAT_TX_ERR] = { .name = "tx-err", .type = YNL_PT_UINT, };
	return arr;
} ();

struct ynl_policy_nest ethtool_ts_stat_nest = {
	.max_attr = ETHTOOL_A_TS_STAT_MAX,
	.table = ethtool_ts_stat_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_TDR_CFG_MAX + 1> ethtool_cable_test_tdr_cfg_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_TDR_CFG_MAX + 1> arr{};
	arr[ETHTOOL_A_CABLE_TEST_TDR_CFG_FIRST] = { .name = "first", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CABLE_TEST_TDR_CFG_LAST] = { .name = "last", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CABLE_TEST_TDR_CFG_STEP] = { .name = "step", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CABLE_TEST_TDR_CFG_PAIR] = { .name = "pair", .type = YNL_PT_U8, };
	return arr;
} ();

struct ynl_policy_nest ethtool_cable_test_tdr_cfg_nest = {
	.max_attr = ETHTOOL_A_CABLE_TEST_TDR_CFG_MAX,
	.table = ethtool_cable_test_tdr_cfg_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_FEC_STAT_MAX + 1> ethtool_fec_stat_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_FEC_STAT_MAX + 1> arr{};
	arr[ETHTOOL_A_FEC_STAT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, };
	arr[ETHTOOL_A_FEC_STAT_CORRECTED] = { .name = "corrected", .type = YNL_PT_BINARY,};
	arr[ETHTOOL_A_FEC_STAT_UNCORR] = { .name = "uncorr", .type = YNL_PT_BINARY,};
	arr[ETHTOOL_A_FEC_STAT_CORR_BITS] = { .name = "corr-bits", .type = YNL_PT_BINARY,};
	return arr;
} ();

struct ynl_policy_nest ethtool_fec_stat_nest = {
	.max_attr = ETHTOOL_A_FEC_STAT_MAX,
	.table = ethtool_fec_stat_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_MM_STAT_MAX + 1> ethtool_mm_stat_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_MM_STAT_MAX + 1> arr{};
	arr[ETHTOOL_A_MM_STAT_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, };
	arr[ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS] = { .name = "reassembly-errors", .type = YNL_PT_U64, };
	arr[ETHTOOL_A_MM_STAT_SMD_ERRORS] = { .name = "smd-errors", .type = YNL_PT_U64, };
	arr[ETHTOOL_A_MM_STAT_REASSEMBLY_OK] = { .name = "reassembly-ok", .type = YNL_PT_U64, };
	arr[ETHTOOL_A_MM_STAT_RX_FRAG_COUNT] = { .name = "rx-frag-count", .type = YNL_PT_U64, };
	arr[ETHTOOL_A_MM_STAT_TX_FRAG_COUNT] = { .name = "tx-frag-count", .type = YNL_PT_U64, };
	arr[ETHTOOL_A_MM_STAT_HOLD_COUNT] = { .name = "hold-count", .type = YNL_PT_U64, };
	return arr;
} ();

struct ynl_policy_nest ethtool_mm_stat_nest = {
	.max_attr = ETHTOOL_A_MM_STAT_MAX,
	.table = ethtool_mm_stat_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_CABLE_RESULT_MAX + 1> ethtool_cable_result_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_CABLE_RESULT_MAX + 1> arr{};
	arr[ETHTOOL_A_CABLE_RESULT_PAIR] = { .name = "pair", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_CABLE_RESULT_CODE] = { .name = "code", .type = YNL_PT_U8, };
	return arr;
} ();

struct ynl_policy_nest ethtool_cable_result_nest = {
	.max_attr = ETHTOOL_A_CABLE_RESULT_MAX,
	.table = ethtool_cable_result_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_CABLE_FAULT_LENGTH_MAX + 1> ethtool_cable_fault_length_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_CABLE_FAULT_LENGTH_MAX + 1> arr{};
	arr[ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR] = { .name = "pair", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_CABLE_FAULT_LENGTH_CM] = { .name = "cm", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_cable_fault_length_nest = {
	.max_attr = ETHTOOL_A_CABLE_FAULT_LENGTH_MAX,
	.table = ethtool_cable_fault_length_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_STATS_GRP_MAX + 1> ethtool_stats_grp_hist_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_STATS_GRP_MAX + 1> arr{};
	arr[ETHTOOL_A_STATS_GRP_HIST_BKT_LOW] = { .name = "hist-bkt-low", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_STATS_GRP_HIST_BKT_HI] = { .name = "hist-bkt-hi", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_STATS_GRP_HIST_VAL] = { .name = "hist-val", .type = YNL_PT_U64, };
	return arr;
} ();

struct ynl_policy_nest ethtool_stats_grp_hist_nest = {
	.max_attr = ETHTOOL_A_STATS_GRP_MAX,
	.table = ethtool_stats_grp_hist_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_BITSET_BIT_MAX + 1> ethtool_bitset_bit_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_BITSET_BIT_MAX + 1> arr{};
	arr[ETHTOOL_A_BITSET_BIT_INDEX] = { .name = "index", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_BITSET_BIT_NAME] = { .name = "name", .type = YNL_PT_NUL_STR, };
	arr[ETHTOOL_A_BITSET_BIT_VALUE] = { .name = "value", .type = YNL_PT_FLAG, };
	return arr;
} ();

struct ynl_policy_nest ethtool_bitset_bit_nest = {
	.max_attr = ETHTOOL_A_BITSET_BIT_MAX,
	.table = ethtool_bitset_bit_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_TUNNEL_UDP_ENTRY_MAX + 1> ethtool_tunnel_udp_entry_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_TUNNEL_UDP_ENTRY_MAX + 1> arr{};
	arr[ETHTOOL_A_TUNNEL_UDP_ENTRY_PORT] = { .name = "port", .type = YNL_PT_U16, };
	arr[ETHTOOL_A_TUNNEL_UDP_ENTRY_TYPE] = { .name = "type", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_tunnel_udp_entry_nest = {
	.max_attr = ETHTOOL_A_TUNNEL_UDP_ENTRY_MAX,
	.table = ethtool_tunnel_udp_entry_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_STRING_MAX + 1> ethtool_string_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_STRING_MAX + 1> arr{};
	arr[ETHTOOL_A_STRING_INDEX] = { .name = "index", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_STRING_VALUE] = { .name = "value", .type = YNL_PT_NUL_STR, };
	return arr;
} ();

struct ynl_policy_nest ethtool_string_nest = {
	.max_attr = ETHTOOL_A_STRING_MAX,
	.table = ethtool_string_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_CABLE_NEST_MAX + 1> ethtool_cable_nest_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_CABLE_NEST_MAX + 1> arr{};
	arr[ETHTOOL_A_CABLE_NEST_RESULT] = { .name = "result", .type = YNL_PT_NEST, .nest = &ethtool_cable_result_nest, };
	arr[ETHTOOL_A_CABLE_NEST_FAULT_LENGTH] = { .name = "fault-length", .type = YNL_PT_NEST, .nest = &ethtool_cable_fault_length_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_cable_nest_nest = {
	.max_attr = ETHTOOL_A_CABLE_NEST_MAX,
	.table = ethtool_cable_nest_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_STATS_GRP_MAX + 1> ethtool_stats_grp_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_STATS_GRP_MAX + 1> arr{};
	arr[ETHTOOL_A_STATS_GRP_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, };
	arr[ETHTOOL_A_STATS_GRP_ID] = { .name = "id", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_STATS_GRP_SS_ID] = { .name = "ss-id", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_STATS_GRP_STAT] = { .name = "stat", .type = YNL_PT_U64, };
	arr[ETHTOOL_A_STATS_GRP_HIST_RX] = { .name = "hist-rx", .type = YNL_PT_NEST, .nest = &ethtool_stats_grp_hist_nest, };
	arr[ETHTOOL_A_STATS_GRP_HIST_TX] = { .name = "hist-tx", .type = YNL_PT_NEST, .nest = &ethtool_stats_grp_hist_nest, };
	arr[ETHTOOL_A_STATS_GRP_HIST_BKT_LOW] = { .name = "hist-bkt-low", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_STATS_GRP_HIST_BKT_HI] = { .name = "hist-bkt-hi", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_STATS_GRP_HIST_VAL] = { .name = "hist-val", .type = YNL_PT_U64, };
	return arr;
} ();

struct ynl_policy_nest ethtool_stats_grp_nest = {
	.max_attr = ETHTOOL_A_STATS_GRP_MAX,
	.table = ethtool_stats_grp_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_BITSET_BITS_MAX + 1> ethtool_bitset_bits_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_BITSET_BITS_MAX + 1> arr{};
	arr[ETHTOOL_A_BITSET_BITS_BIT] = { .name = "bit", .type = YNL_PT_NEST, .nest = &ethtool_bitset_bit_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_bitset_bits_nest = {
	.max_attr = ETHTOOL_A_BITSET_BITS_MAX,
	.table = ethtool_bitset_bits_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_STRINGS_MAX + 1> ethtool_strings_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_STRINGS_MAX + 1> arr{};
	arr[ETHTOOL_A_STRINGS_STRING] = { .name = "string", .type = YNL_PT_NEST, .nest = &ethtool_string_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_strings_nest = {
	.max_attr = ETHTOOL_A_STRINGS_MAX,
	.table = ethtool_strings_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_BITSET_MAX + 1> ethtool_bitset_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_BITSET_MAX + 1> arr{};
	arr[ETHTOOL_A_BITSET_NOMASK] = { .name = "nomask", .type = YNL_PT_FLAG, };
	arr[ETHTOOL_A_BITSET_SIZE] = { .name = "size", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_BITSET_BITS] = { .name = "bits", .type = YNL_PT_NEST, .nest = &ethtool_bitset_bits_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_bitset_nest = {
	.max_attr = ETHTOOL_A_BITSET_MAX,
	.table = ethtool_bitset_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_STRINGSET_MAX + 1> ethtool_stringset_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_STRINGSET_MAX + 1> arr{};
	arr[ETHTOOL_A_STRINGSET_ID] = { .name = "id", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_STRINGSET_COUNT] = { .name = "count", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_STRINGSET_STRINGS] = { .name = "strings", .type = YNL_PT_NEST, .nest = &ethtool_strings_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_stringset_nest = {
	.max_attr = ETHTOOL_A_STRINGSET_MAX,
	.table = ethtool_stringset_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_TUNNEL_UDP_TABLE_MAX + 1> ethtool_tunnel_udp_table_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_TUNNEL_UDP_TABLE_MAX + 1> arr{};
	arr[ETHTOOL_A_TUNNEL_UDP_TABLE_SIZE] = { .name = "size", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_TUNNEL_UDP_TABLE_TYPES] = { .name = "types", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY] = { .name = "entry", .type = YNL_PT_NEST, .nest = &ethtool_tunnel_udp_entry_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_tunnel_udp_table_nest = {
	.max_attr = ETHTOOL_A_TUNNEL_UDP_TABLE_MAX,
	.table = ethtool_tunnel_udp_table_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_STRINGSETS_MAX + 1> ethtool_stringsets_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_STRINGSETS_MAX + 1> arr{};
	arr[ETHTOOL_A_STRINGSETS_STRINGSET] = { .name = "stringset", .type = YNL_PT_NEST, .nest = &ethtool_stringset_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_stringsets_nest = {
	.max_attr = ETHTOOL_A_STRINGSETS_MAX,
	.table = ethtool_stringsets_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_TUNNEL_UDP_MAX + 1> ethtool_tunnel_udp_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_TUNNEL_UDP_MAX + 1> arr{};
	arr[ETHTOOL_A_TUNNEL_UDP_TABLE] = { .name = "table", .type = YNL_PT_NEST, .nest = &ethtool_tunnel_udp_table_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_tunnel_udp_nest = {
	.max_attr = ETHTOOL_A_TUNNEL_UDP_MAX,
	.table = ethtool_tunnel_udp_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_STRSET_MAX + 1> ethtool_strset_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_STRSET_MAX + 1> arr{};
	arr[ETHTOOL_A_STRSET_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_STRSET_STRINGSETS] = { .name = "stringsets", .type = YNL_PT_NEST, .nest = &ethtool_stringsets_nest, };
	arr[ETHTOOL_A_STRSET_COUNTS_ONLY] = { .name = "counts-only", .type = YNL_PT_FLAG, };
	return arr;
} ();

struct ynl_policy_nest ethtool_strset_nest = {
	.max_attr = ETHTOOL_A_STRSET_MAX,
	.table = ethtool_strset_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_LINKINFO_MAX + 1> ethtool_linkinfo_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_LINKINFO_MAX + 1> arr{};
	arr[ETHTOOL_A_LINKINFO_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_LINKINFO_PORT] = { .name = "port", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKINFO_PHYADDR] = { .name = "phyaddr", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKINFO_TP_MDIX] = { .name = "tp-mdix", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKINFO_TP_MDIX_CTRL] = { .name = "tp-mdix-ctrl", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKINFO_TRANSCEIVER] = { .name = "transceiver", .type = YNL_PT_U8, };
	return arr;
} ();

struct ynl_policy_nest ethtool_linkinfo_nest = {
	.max_attr = ETHTOOL_A_LINKINFO_MAX,
	.table = ethtool_linkinfo_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_LINKMODES_MAX + 1> ethtool_linkmodes_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_LINKMODES_MAX + 1> arr{};
	arr[ETHTOOL_A_LINKMODES_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_LINKMODES_AUTONEG] = { .name = "autoneg", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKMODES_OURS] = { .name = "ours", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_LINKMODES_PEER] = { .name = "peer", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_LINKMODES_SPEED] = { .name = "speed", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_LINKMODES_DUPLEX] = { .name = "duplex", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG] = { .name = "master-slave-cfg", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE] = { .name = "master-slave-state", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKMODES_LANES] = { .name = "lanes", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_LINKMODES_RATE_MATCHING] = { .name = "rate-matching", .type = YNL_PT_U8, };
	return arr;
} ();

struct ynl_policy_nest ethtool_linkmodes_nest = {
	.max_attr = ETHTOOL_A_LINKMODES_MAX,
	.table = ethtool_linkmodes_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_LINKSTATE_MAX + 1> ethtool_linkstate_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_LINKSTATE_MAX + 1> arr{};
	arr[ETHTOOL_A_LINKSTATE_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_LINKSTATE_LINK] = { .name = "link", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKSTATE_SQI] = { .name = "sqi", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_LINKSTATE_SQI_MAX] = { .name = "sqi-max", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_LINKSTATE_EXT_STATE] = { .name = "ext-state", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKSTATE_EXT_SUBSTATE] = { .name = "ext-substate", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT] = { .name = "ext-down-cnt", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_linkstate_nest = {
	.max_attr = ETHTOOL_A_LINKSTATE_MAX,
	.table = ethtool_linkstate_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_DEBUG_MAX + 1> ethtool_debug_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_DEBUG_MAX + 1> arr{};
	arr[ETHTOOL_A_DEBUG_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_DEBUG_MSGMASK] = { .name = "msgmask", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_debug_nest = {
	.max_attr = ETHTOOL_A_DEBUG_MAX,
	.table = ethtool_debug_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_WOL_MAX + 1> ethtool_wol_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_WOL_MAX + 1> arr{};
	arr[ETHTOOL_A_WOL_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_WOL_MODES] = { .name = "modes", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_WOL_SOPASS] = { .name = "sopass", .type = YNL_PT_BINARY,};
	return arr;
} ();

struct ynl_policy_nest ethtool_wol_nest = {
	.max_attr = ETHTOOL_A_WOL_MAX,
	.table = ethtool_wol_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_FEATURES_MAX + 1> ethtool_features_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_FEATURES_MAX + 1> arr{};
	arr[ETHTOOL_A_FEATURES_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_FEATURES_HW] = { .name = "hw", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_FEATURES_WANTED] = { .name = "wanted", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_FEATURES_ACTIVE] = { .name = "active", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_FEATURES_NOCHANGE] = { .name = "nochange", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_features_nest = {
	.max_attr = ETHTOOL_A_FEATURES_MAX,
	.table = ethtool_features_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_PRIVFLAGS_MAX + 1> ethtool_privflags_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_PRIVFLAGS_MAX + 1> arr{};
	arr[ETHTOOL_A_PRIVFLAGS_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_PRIVFLAGS_FLAGS] = { .name = "flags", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_privflags_nest = {
	.max_attr = ETHTOOL_A_PRIVFLAGS_MAX,
	.table = ethtool_privflags_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_RINGS_MAX + 1> ethtool_rings_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_RINGS_MAX + 1> arr{};
	arr[ETHTOOL_A_RINGS_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_RINGS_RX_MAX] = { .name = "rx-max", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_RX_MINI_MAX] = { .name = "rx-mini-max", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_RX_JUMBO_MAX] = { .name = "rx-jumbo-max", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_TX_MAX] = { .name = "tx-max", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_RX] = { .name = "rx", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_RX_MINI] = { .name = "rx-mini", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_RX_JUMBO] = { .name = "rx-jumbo", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_TX] = { .name = "tx", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_RX_BUF_LEN] = { .name = "rx-buf-len", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_TCP_DATA_SPLIT] = { .name = "tcp-data-split", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_RINGS_CQE_SIZE] = { .name = "cqe-size", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_TX_PUSH] = { .name = "tx-push", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_RINGS_RX_PUSH] = { .name = "rx-push", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN] = { .name = "tx-push-buf-len", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX] = { .name = "tx-push-buf-len-max", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_rings_nest = {
	.max_attr = ETHTOOL_A_RINGS_MAX,
	.table = ethtool_rings_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_CHANNELS_MAX + 1> ethtool_channels_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_CHANNELS_MAX + 1> arr{};
	arr[ETHTOOL_A_CHANNELS_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_CHANNELS_RX_MAX] = { .name = "rx-max", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CHANNELS_TX_MAX] = { .name = "tx-max", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CHANNELS_OTHER_MAX] = { .name = "other-max", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CHANNELS_COMBINED_MAX] = { .name = "combined-max", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CHANNELS_RX_COUNT] = { .name = "rx-count", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CHANNELS_TX_COUNT] = { .name = "tx-count", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CHANNELS_OTHER_COUNT] = { .name = "other-count", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_CHANNELS_COMBINED_COUNT] = { .name = "combined-count", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_channels_nest = {
	.max_attr = ETHTOOL_A_CHANNELS_MAX,
	.table = ethtool_channels_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_COALESCE_MAX + 1> ethtool_coalesce_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_COALESCE_MAX + 1> arr{};
	arr[ETHTOOL_A_COALESCE_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_COALESCE_RX_USECS] = { .name = "rx-usecs", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_RX_MAX_FRAMES] = { .name = "rx-max-frames", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_RX_USECS_IRQ] = { .name = "rx-usecs-irq", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ] = { .name = "rx-max-frames-irq", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_USECS] = { .name = "tx-usecs", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_MAX_FRAMES] = { .name = "tx-max-frames", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_USECS_IRQ] = { .name = "tx-usecs-irq", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ] = { .name = "tx-max-frames-irq", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_STATS_BLOCK_USECS] = { .name = "stats-block-usecs", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX] = { .name = "use-adaptive-rx", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX] = { .name = "use-adaptive-tx", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_COALESCE_PKT_RATE_LOW] = { .name = "pkt-rate-low", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_RX_USECS_LOW] = { .name = "rx-usecs-low", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW] = { .name = "rx-max-frames-low", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_USECS_LOW] = { .name = "tx-usecs-low", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW] = { .name = "tx-max-frames-low", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_PKT_RATE_HIGH] = { .name = "pkt-rate-high", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_RX_USECS_HIGH] = { .name = "rx-usecs-high", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH] = { .name = "rx-max-frames-high", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_USECS_HIGH] = { .name = "tx-usecs-high", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH] = { .name = "tx-max-frames-high", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL] = { .name = "rate-sample-interval", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_USE_CQE_MODE_TX] = { .name = "use-cqe-mode-tx", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_COALESCE_USE_CQE_MODE_RX] = { .name = "use-cqe-mode-rx", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES] = { .name = "tx-aggr-max-bytes", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES] = { .name = "tx-aggr-max-frames", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS] = { .name = "tx-aggr-time-usecs", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_coalesce_nest = {
	.max_attr = ETHTOOL_A_COALESCE_MAX,
	.table = ethtool_coalesce_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_PAUSE_MAX + 1> ethtool_pause_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_PAUSE_MAX + 1> arr{};
	arr[ETHTOOL_A_PAUSE_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_PAUSE_AUTONEG] = { .name = "autoneg", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_PAUSE_RX] = { .name = "rx", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_PAUSE_TX] = { .name = "tx", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_PAUSE_STATS] = { .name = "stats", .type = YNL_PT_NEST, .nest = &ethtool_pause_stat_nest, };
	arr[ETHTOOL_A_PAUSE_STATS_SRC] = { .name = "stats-src", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_pause_nest = {
	.max_attr = ETHTOOL_A_PAUSE_MAX,
	.table = ethtool_pause_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_EEE_MAX + 1> ethtool_eee_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_EEE_MAX + 1> arr{};
	arr[ETHTOOL_A_EEE_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_EEE_MODES_OURS] = { .name = "modes-ours", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_EEE_MODES_PEER] = { .name = "modes-peer", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_EEE_ACTIVE] = { .name = "active", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_EEE_ENABLED] = { .name = "enabled", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_EEE_TX_LPI_ENABLED] = { .name = "tx-lpi-enabled", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_EEE_TX_LPI_TIMER] = { .name = "tx-lpi-timer", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_eee_nest = {
	.max_attr = ETHTOOL_A_EEE_MAX,
	.table = ethtool_eee_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_TSINFO_MAX + 1> ethtool_tsinfo_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_TSINFO_MAX + 1> arr{};
	arr[ETHTOOL_A_TSINFO_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_TSINFO_TIMESTAMPING] = { .name = "timestamping", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_TSINFO_TX_TYPES] = { .name = "tx-types", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_TSINFO_RX_FILTERS] = { .name = "rx-filters", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_TSINFO_PHC_INDEX] = { .name = "phc-index", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_TSINFO_STATS] = { .name = "stats", .type = YNL_PT_NEST, .nest = &ethtool_ts_stat_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_tsinfo_nest = {
	.max_attr = ETHTOOL_A_TSINFO_MAX,
	.table = ethtool_tsinfo_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_MAX + 1> ethtool_cable_test_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_MAX + 1> arr{};
	arr[ETHTOOL_A_CABLE_TEST_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_cable_test_nest = {
	.max_attr = ETHTOOL_A_CABLE_TEST_MAX,
	.table = ethtool_cable_test_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_NTF_MAX + 1> ethtool_cable_test_ntf_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_NTF_MAX + 1> arr{};
	arr[ETHTOOL_A_CABLE_TEST_NTF_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_CABLE_TEST_NTF_STATUS] = { .name = "status", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_CABLE_TEST_NTF_NEST] = { .name = "nest", .type = YNL_PT_NEST, .nest = &ethtool_cable_nest_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_cable_test_ntf_nest = {
	.max_attr = ETHTOOL_A_CABLE_TEST_NTF_MAX,
	.table = ethtool_cable_test_ntf_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_TDR_MAX + 1> ethtool_cable_test_tdr_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_TDR_MAX + 1> arr{};
	arr[ETHTOOL_A_CABLE_TEST_TDR_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_CABLE_TEST_TDR_CFG] = { .name = "cfg", .type = YNL_PT_NEST, .nest = &ethtool_cable_test_tdr_cfg_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_cable_test_tdr_nest = {
	.max_attr = ETHTOOL_A_CABLE_TEST_TDR_MAX,
	.table = ethtool_cable_test_tdr_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX + 1> ethtool_cable_test_tdr_ntf_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX + 1> arr{};
	arr[ETHTOOL_A_CABLE_TEST_TDR_NTF_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_CABLE_TEST_TDR_NTF_STATUS] = { .name = "status", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST] = { .name = "nest", .type = YNL_PT_NEST, .nest = &ethtool_cable_nest_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_cable_test_tdr_ntf_nest = {
	.max_attr = ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX,
	.table = ethtool_cable_test_tdr_ntf_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_TUNNEL_INFO_MAX + 1> ethtool_tunnel_info_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_TUNNEL_INFO_MAX + 1> arr{};
	arr[ETHTOOL_A_TUNNEL_INFO_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_TUNNEL_INFO_UDP_PORTS] = { .name = "udp-ports", .type = YNL_PT_NEST, .nest = &ethtool_tunnel_udp_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_tunnel_info_nest = {
	.max_attr = ETHTOOL_A_TUNNEL_INFO_MAX,
	.table = ethtool_tunnel_info_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_FEC_MAX + 1> ethtool_fec_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_FEC_MAX + 1> arr{};
	arr[ETHTOOL_A_FEC_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_FEC_MODES] = { .name = "modes", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_FEC_AUTO] = { .name = "auto", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_FEC_ACTIVE] = { .name = "active", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_FEC_STATS] = { .name = "stats", .type = YNL_PT_NEST, .nest = &ethtool_fec_stat_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_fec_nest = {
	.max_attr = ETHTOOL_A_FEC_MAX,
	.table = ethtool_fec_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_MODULE_EEPROM_MAX + 1> ethtool_module_eeprom_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_MODULE_EEPROM_MAX + 1> arr{};
	arr[ETHTOOL_A_MODULE_EEPROM_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_MODULE_EEPROM_OFFSET] = { .name = "offset", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_MODULE_EEPROM_LENGTH] = { .name = "length", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_MODULE_EEPROM_PAGE] = { .name = "page", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_MODULE_EEPROM_BANK] = { .name = "bank", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS] = { .name = "i2c-address", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_MODULE_EEPROM_DATA] = { .name = "data", .type = YNL_PT_BINARY,};
	return arr;
} ();

struct ynl_policy_nest ethtool_module_eeprom_nest = {
	.max_attr = ETHTOOL_A_MODULE_EEPROM_MAX,
	.table = ethtool_module_eeprom_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_STATS_MAX + 1> ethtool_stats_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_STATS_MAX + 1> arr{};
	arr[ETHTOOL_A_STATS_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, };
	arr[ETHTOOL_A_STATS_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_STATS_GROUPS] = { .name = "groups", .type = YNL_PT_NEST, .nest = &ethtool_bitset_nest, };
	arr[ETHTOOL_A_STATS_GRP] = { .name = "grp", .type = YNL_PT_NEST, .nest = &ethtool_stats_grp_nest, };
	arr[ETHTOOL_A_STATS_SRC] = { .name = "src", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_stats_nest = {
	.max_attr = ETHTOOL_A_STATS_MAX,
	.table = ethtool_stats_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_PHC_VCLOCKS_MAX + 1> ethtool_phc_vclocks_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_PHC_VCLOCKS_MAX + 1> arr{};
	arr[ETHTOOL_A_PHC_VCLOCKS_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_PHC_VCLOCKS_NUM] = { .name = "num", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_PHC_VCLOCKS_INDEX] = { .name = "index", .type = YNL_PT_BINARY,};
	return arr;
} ();

struct ynl_policy_nest ethtool_phc_vclocks_nest = {
	.max_attr = ETHTOOL_A_PHC_VCLOCKS_MAX,
	.table = ethtool_phc_vclocks_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_MODULE_MAX + 1> ethtool_module_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_MODULE_MAX + 1> arr{};
	arr[ETHTOOL_A_MODULE_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_MODULE_POWER_MODE_POLICY] = { .name = "power-mode-policy", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_MODULE_POWER_MODE] = { .name = "power-mode", .type = YNL_PT_U8, };
	return arr;
} ();

struct ynl_policy_nest ethtool_module_nest = {
	.max_attr = ETHTOOL_A_MODULE_MAX,
	.table = ethtool_module_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_PSE_MAX + 1> ethtool_pse_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_PSE_MAX + 1> arr{};
	arr[ETHTOOL_A_PSE_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_PODL_PSE_ADMIN_STATE] = { .name = "podl-pse-admin-state", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_PODL_PSE_ADMIN_CONTROL] = { .name = "podl-pse-admin-control", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_PODL_PSE_PW_D_STATUS] = { .name = "podl-pse-pw-d-status", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_C33_PSE_ADMIN_STATE] = { .name = "c33-pse-admin-state", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_C33_PSE_ADMIN_CONTROL] = { .name = "c33-pse-admin-control", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_C33_PSE_PW_D_STATUS] = { .name = "c33-pse-pw-d-status", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_pse_nest = {
	.max_attr = ETHTOOL_A_PSE_MAX,
	.table = ethtool_pse_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_RSS_MAX + 1> ethtool_rss_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_RSS_MAX + 1> arr{};
	arr[ETHTOOL_A_RSS_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_RSS_CONTEXT] = { .name = "context", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RSS_HFUNC] = { .name = "hfunc", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_RSS_INDIR] = { .name = "indir", .type = YNL_PT_BINARY,};
	arr[ETHTOOL_A_RSS_HKEY] = { .name = "hkey", .type = YNL_PT_BINARY,};
	arr[ETHTOOL_A_RSS_INPUT_XFRM] = { .name = "input_xfrm", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_rss_nest = {
	.max_attr = ETHTOOL_A_RSS_MAX,
	.table = ethtool_rss_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_PLCA_MAX + 1> ethtool_plca_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_PLCA_MAX + 1> arr{};
	arr[ETHTOOL_A_PLCA_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_PLCA_VERSION] = { .name = "version", .type = YNL_PT_U16, };
	arr[ETHTOOL_A_PLCA_ENABLED] = { .name = "enabled", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_PLCA_STATUS] = { .name = "status", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_PLCA_NODE_CNT] = { .name = "node-cnt", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_PLCA_NODE_ID] = { .name = "node-id", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_PLCA_TO_TMR] = { .name = "to-tmr", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_PLCA_BURST_CNT] = { .name = "burst-cnt", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_PLCA_BURST_TMR] = { .name = "burst-tmr", .type = YNL_PT_U32, };
	return arr;
} ();

struct ynl_policy_nest ethtool_plca_nest = {
	.max_attr = ETHTOOL_A_PLCA_MAX,
	.table = ethtool_plca_policy.data(),
};

static std::array<ynl_policy_attr,ETHTOOL_A_MM_MAX + 1> ethtool_mm_policy = []() {
	std::array<ynl_policy_attr,ETHTOOL_A_MM_MAX + 1> arr{};
	arr[ETHTOOL_A_MM_HEADER] = { .name = "header", .type = YNL_PT_NEST, .nest = &ethtool_header_nest, };
	arr[ETHTOOL_A_MM_PMAC_ENABLED] = { .name = "pmac-enabled", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_MM_TX_ENABLED] = { .name = "tx-enabled", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_MM_TX_ACTIVE] = { .name = "tx-active", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_MM_TX_MIN_FRAG_SIZE] = { .name = "tx-min-frag-size", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_MM_RX_MIN_FRAG_SIZE] = { .name = "rx-min-frag-size", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_MM_VERIFY_ENABLED] = { .name = "verify-enabled", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_MM_VERIFY_STATUS] = { .name = "verify-status", .type = YNL_PT_U8, };
	arr[ETHTOOL_A_MM_VERIFY_TIME] = { .name = "verify-time", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_MM_MAX_VERIFY_TIME] = { .name = "max-verify-time", .type = YNL_PT_U32, };
	arr[ETHTOOL_A_MM_STATS] = { .name = "stats", .type = YNL_PT_NEST, .nest = &ethtool_mm_stat_nest, };
	return arr;
} ();

struct ynl_policy_nest ethtool_mm_nest = {
	.max_attr = ETHTOOL_A_MM_MAX,
	.table = ethtool_mm_policy.data(),
};

/* Common nested types */
int ethtool_header_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       const ethtool_header&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.dev_index.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_HEADER_DEV_INDEX, obj.dev_index.value());
	if (obj.dev_name.size() > 0)
		ynl_attr_put_str(nlh, ETHTOOL_A_HEADER_DEV_NAME, obj.dev_name.data());
	if (obj.flags.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_HEADER_FLAGS, obj.flags.value());
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_header_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	ethtool_header *dst = (ethtool_header *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_HEADER_DEV_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->dev_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_HEADER_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->dev_name.assign(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
		} else if (type == ETHTOOL_A_HEADER_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int ethtool_pause_stat_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   const ethtool_pause_stat&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.tx_frames.has_value())
		ynl_attr_put_u64(nlh, ETHTOOL_A_PAUSE_STAT_TX_FRAMES, obj.tx_frames.value());
	if (obj.rx_frames.has_value())
		ynl_attr_put_u64(nlh, ETHTOOL_A_PAUSE_STAT_RX_FRAMES, obj.rx_frames.value());
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_pause_stat_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	ethtool_pause_stat *dst = (ethtool_pause_stat *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_PAUSE_STAT_TX_FRAMES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_frames = (__u64)ynl_attr_get_u64(attr);
		} else if (type == ETHTOOL_A_PAUSE_STAT_RX_FRAMES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_frames = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int ethtool_ts_stat_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	ethtool_ts_stat *dst = (ethtool_ts_stat *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_TS_STAT_TX_PKTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_pkts = (__u64)ynl_attr_get_uint(attr);
		} else if (type == ETHTOOL_A_TS_STAT_TX_LOST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_lost = (__u64)ynl_attr_get_uint(attr);
		} else if (type == ETHTOOL_A_TS_STAT_TX_ERR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_err = (__u64)ynl_attr_get_uint(attr);
		}
	}

	return 0;
}

int ethtool_fec_stat_put(struct nlmsghdr *nlh, unsigned int attr_type,
			 const ethtool_fec_stat&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.corrected.size() > 0)
		ynl_attr_put(nlh, ETHTOOL_A_FEC_STAT_CORRECTED, obj.corrected.data(), obj.corrected.size());
	if (obj.uncorr.size() > 0)
		ynl_attr_put(nlh, ETHTOOL_A_FEC_STAT_UNCORR, obj.uncorr.data(), obj.uncorr.size());
	if (obj.corr_bits.size() > 0)
		ynl_attr_put(nlh, ETHTOOL_A_FEC_STAT_CORR_BITS, obj.corr_bits.data(), obj.corr_bits.size());
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_fec_stat_parse(struct ynl_parse_arg *yarg,
			   const struct nlattr *nested)
{
	ethtool_fec_stat *dst = (ethtool_fec_stat *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_FEC_STAT_CORRECTED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->corrected.assign(data, data + len);
		} else if (type == ETHTOOL_A_FEC_STAT_UNCORR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->uncorr.assign(data, data + len);
		} else if (type == ETHTOOL_A_FEC_STAT_CORR_BITS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->corr_bits.assign(data, data + len);
		}
	}

	return 0;
}

int ethtool_mm_stat_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	ethtool_mm_stat *dst = (ethtool_mm_stat *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->reassembly_errors = (__u64)ynl_attr_get_u64(attr);
		} else if (type == ETHTOOL_A_MM_STAT_SMD_ERRORS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->smd_errors = (__u64)ynl_attr_get_u64(attr);
		} else if (type == ETHTOOL_A_MM_STAT_REASSEMBLY_OK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->reassembly_ok = (__u64)ynl_attr_get_u64(attr);
		} else if (type == ETHTOOL_A_MM_STAT_RX_FRAG_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_frag_count = (__u64)ynl_attr_get_u64(attr);
		} else if (type == ETHTOOL_A_MM_STAT_TX_FRAG_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_frag_count = (__u64)ynl_attr_get_u64(attr);
		} else if (type == ETHTOOL_A_MM_STAT_HOLD_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->hold_count = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int ethtool_cable_result_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested)
{
	ethtool_cable_result *dst = (ethtool_cable_result *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_CABLE_RESULT_PAIR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->pair = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_CABLE_RESULT_CODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->code = (__u8)ynl_attr_get_u8(attr);
		}
	}

	return 0;
}

int ethtool_cable_fault_length_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	ethtool_cable_fault_length *dst = (ethtool_cable_fault_length *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->pair = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_CABLE_FAULT_LENGTH_CM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->cm = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int ethtool_stats_grp_hist_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	ethtool_stats_grp_hist *dst = (ethtool_stats_grp_hist *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_STATS_GRP_HIST_BKT_LOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->hist_bkt_low = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_STATS_GRP_HIST_BKT_HI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->hist_bkt_hi = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_STATS_GRP_HIST_VAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->hist_val = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int ethtool_bitset_bit_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   const ethtool_bitset_bit&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.index.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_BITSET_BIT_INDEX, obj.index.value());
	if (obj.name.size() > 0)
		ynl_attr_put_str(nlh, ETHTOOL_A_BITSET_BIT_NAME, obj.name.data());
	if (obj.value)
		ynl_attr_put(nlh, ETHTOOL_A_BITSET_BIT_VALUE, NULL, 0);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_bitset_bit_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	ethtool_bitset_bit *dst = (ethtool_bitset_bit *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_BITSET_BIT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_BITSET_BIT_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->name.assign(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
		} else if (type == ETHTOOL_A_BITSET_BIT_VALUE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

int ethtool_tunnel_udp_entry_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	ethtool_tunnel_udp_entry *dst = (ethtool_tunnel_udp_entry *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_TUNNEL_UDP_ENTRY_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == ETHTOOL_A_TUNNEL_UDP_ENTRY_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->type = (int)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int ethtool_string_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       const ethtool_string&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.index.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_STRING_INDEX, obj.index.value());
	if (obj.value.size() > 0)
		ynl_attr_put_str(nlh, ETHTOOL_A_STRING_VALUE, obj.value.data());
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_string_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	ethtool_string *dst = (ethtool_string *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_STRING_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_STRING_VALUE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->value.assign(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
		}
	}

	return 0;
}

int ethtool_cable_nest_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	ethtool_cable_nest *dst = (ethtool_cable_nest *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_CABLE_NEST_RESULT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_cable_result_nest;
			parg.data = &dst->result;
			if (ethtool_cable_result_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_CABLE_NEST_FAULT_LENGTH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_cable_fault_length_nest;
			parg.data = &dst->fault_length;
			if (ethtool_cable_fault_length_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

int ethtool_stats_grp_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	ethtool_stats_grp *dst = (ethtool_stats_grp *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_STATS_GRP_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_STATS_GRP_SS_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->ss_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_STATS_GRP_STAT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->stat = (__u64)ynl_attr_get_u64(attr);
		} else if (type == ETHTOOL_A_STATS_GRP_HIST_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_stats_grp_hist_nest;
			parg.data = &dst->hist_rx;
			if (ethtool_stats_grp_hist_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_STATS_GRP_HIST_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_stats_grp_hist_nest;
			parg.data = &dst->hist_tx;
			if (ethtool_stats_grp_hist_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_STATS_GRP_HIST_BKT_LOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->hist_bkt_low = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_STATS_GRP_HIST_BKT_HI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->hist_bkt_hi = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_STATS_GRP_HIST_VAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->hist_val = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int ethtool_bitset_bits_put(struct nlmsghdr *nlh, unsigned int attr_type,
			    const ethtool_bitset_bits&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (unsigned int i = 0; i < obj.bit.size(); i++)
		ethtool_bitset_bit_put(nlh, ETHTOOL_A_BITSET_BITS_BIT, obj.bit[i]);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_bitset_bits_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	ethtool_bitset_bits *dst = (ethtool_bitset_bits *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_bit = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->bit.size() > 0)
		return ynl_error_parse(yarg, "attribute already present (bitset-bits.bit)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_BITSET_BITS_BIT) {
			n_bit++;
		}
	}

	if (n_bit) {
		dst->bit.resize(n_bit);
		i = 0;
		parg.rsp_policy = &ethtool_bitset_bit_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == ETHTOOL_A_BITSET_BITS_BIT) {
				parg.data = &dst->bit[i];
				if (ethtool_bitset_bit_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

int ethtool_strings_put(struct nlmsghdr *nlh, unsigned int attr_type,
			const ethtool_strings&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (unsigned int i = 0; i < obj.string.size(); i++)
		ethtool_string_put(nlh, ETHTOOL_A_STRINGS_STRING, obj.string[i]);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_strings_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	ethtool_strings *dst = (ethtool_strings *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_string = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->string.size() > 0)
		return ynl_error_parse(yarg, "attribute already present (strings.string)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_STRINGS_STRING) {
			n_string++;
		}
	}

	if (n_string) {
		dst->string.resize(n_string);
		i = 0;
		parg.rsp_policy = &ethtool_string_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == ETHTOOL_A_STRINGS_STRING) {
				parg.data = &dst->string[i];
				if (ethtool_string_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

int ethtool_bitset_put(struct nlmsghdr *nlh, unsigned int attr_type,
		       const ethtool_bitset&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.nomask)
		ynl_attr_put(nlh, ETHTOOL_A_BITSET_NOMASK, NULL, 0);
	if (obj.size.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_BITSET_SIZE, obj.size.value());
	if (obj.bits.has_value())
		ethtool_bitset_bits_put(nlh, ETHTOOL_A_BITSET_BITS, obj.bits.value());
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_bitset_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	ethtool_bitset *dst = (ethtool_bitset *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_BITSET_NOMASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_BITSET_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_BITSET_BITS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_bits_nest;
			parg.data = &dst->bits;
			if (ethtool_bitset_bits_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

int ethtool_stringset_put(struct nlmsghdr *nlh, unsigned int attr_type,
			  const ethtool_stringset_t&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.id.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_STRINGSET_ID, obj.id.value());
	if (obj.count.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_STRINGSET_COUNT, obj.count.value());
	for (unsigned int i = 0; i < obj.strings.size(); i++)
		ethtool_strings_put(nlh, ETHTOOL_A_STRINGSET_STRINGS, obj.strings[i]);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_stringset_parse(struct ynl_parse_arg *yarg,
			    const struct nlattr *nested)
{
	ethtool_stringset_t *dst = (ethtool_stringset_t *)yarg->data;
	unsigned int n_strings = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->strings.size() > 0)
		return ynl_error_parse(yarg, "attribute already present (stringset.strings)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_STRINGSET_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_STRINGSET_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->count = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_STRINGSET_STRINGS) {
			n_strings++;
		}
	}

	if (n_strings) {
		dst->strings.resize(n_strings);
		i = 0;
		parg.rsp_policy = &ethtool_strings_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == ETHTOOL_A_STRINGSET_STRINGS) {
				parg.data = &dst->strings[i];
				if (ethtool_strings_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

int ethtool_tunnel_udp_table_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	ethtool_tunnel_udp_table *dst = (ethtool_tunnel_udp_table *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_entry = 0;
	int i;

	parg.ys = yarg->ys;

	if (dst->entry.size() > 0)
		return ynl_error_parse(yarg, "attribute already present (tunnel-udp-table.entry)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_TUNNEL_UDP_TABLE_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_TUNNEL_UDP_TABLE_TYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->types;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY) {
			n_entry++;
		}
	}

	if (n_entry) {
		dst->entry.resize(n_entry);
		i = 0;
		parg.rsp_policy = &ethtool_tunnel_udp_entry_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY) {
				parg.data = &dst->entry[i];
				if (ethtool_tunnel_udp_entry_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

int ethtool_stringsets_put(struct nlmsghdr *nlh, unsigned int attr_type,
			   const ethtool_stringsets&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	for (unsigned int i = 0; i < obj.stringset.size(); i++)
		ethtool_stringset_put(nlh, ETHTOOL_A_STRINGSETS_STRINGSET, obj.stringset[i]);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ethtool_stringsets_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	ethtool_stringsets *dst = (ethtool_stringsets *)yarg->data;
	unsigned int n_stringset = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->stringset.size() > 0)
		return ynl_error_parse(yarg, "attribute already present (stringsets.stringset)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_STRINGSETS_STRINGSET) {
			n_stringset++;
		}
	}

	if (n_stringset) {
		dst->stringset.resize(n_stringset);
		i = 0;
		parg.rsp_policy = &ethtool_stringset_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == ETHTOOL_A_STRINGSETS_STRINGSET) {
				parg.data = &dst->stringset[i];
				if (ethtool_stringset_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

int ethtool_tunnel_udp_parse(struct ynl_parse_arg *yarg,
			     const struct nlattr *nested)
{
	ethtool_tunnel_udp *dst = (ethtool_tunnel_udp *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_TUNNEL_UDP_TABLE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_tunnel_udp_table_nest;
			parg.data = &dst->table;
			if (ethtool_tunnel_udp_table_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

/* ============== ETHTOOL_MSG_STRSET_GET ============== */
/* ETHTOOL_MSG_STRSET_GET - do */
int ethtool_strset_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	ethtool_strset_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_strset_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_STRSET_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_STRSET_STRINGSETS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_stringsets_nest;
			parg.data = &dst->stringsets;
			if (ethtool_stringsets_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_strset_get_rsp>
ethtool_strset_get(ynl_cpp::ynl_socket&  ys, ethtool_strset_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_strset_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_STRSET_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_strset_nest;
	yrs.yarg.rsp_policy = &ethtool_strset_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_STRSET_HEADER, req.header.value());
	if (req.stringsets.has_value())
		ethtool_stringsets_put(nlh, ETHTOOL_A_STRSET_STRINGSETS, req.stringsets.value());
	if (req.counts_only)
		ynl_attr_put(nlh, ETHTOOL_A_STRSET_COUNTS_ONLY, NULL, 0);

	rsp.reset(new ethtool_strset_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_strset_get_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_STRSET_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_STRSET_GET - dump */
std::unique_ptr<ethtool_strset_get_list>
ethtool_strset_get_dump(ynl_cpp::ynl_socket&  ys,
			ethtool_strset_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_strset_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_strset_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_strset_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_strset_get_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_STRSET_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_STRSET_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_strset_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_STRSET_HEADER, req.header.value());
	if (req.stringsets.has_value())
		ethtool_stringsets_put(nlh, ETHTOOL_A_STRSET_STRINGSETS, req.stringsets.value());
	if (req.counts_only)
		ynl_attr_put(nlh, ETHTOOL_A_STRSET_COUNTS_ONLY, NULL, 0);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_LINKINFO_GET ============== */
/* ETHTOOL_MSG_LINKINFO_GET - do */
int ethtool_linkinfo_get_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	ethtool_linkinfo_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_linkinfo_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_LINKINFO_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_LINKINFO_PORT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->port = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKINFO_PHYADDR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->phyaddr = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKINFO_TP_MDIX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tp_mdix = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKINFO_TP_MDIX_CTRL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tp_mdix_ctrl = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKINFO_TRANSCEIVER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->transceiver = (__u8)ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_linkinfo_get_rsp>
ethtool_linkinfo_get(ynl_cpp::ynl_socket&  ys, ethtool_linkinfo_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_linkinfo_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_LINKINFO_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_linkinfo_nest;
	yrs.yarg.rsp_policy = &ethtool_linkinfo_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_LINKINFO_HEADER, req.header.value());

	rsp.reset(new ethtool_linkinfo_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_linkinfo_get_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_LINKINFO_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_LINKINFO_GET - dump */
std::unique_ptr<ethtool_linkinfo_get_list>
ethtool_linkinfo_get_dump(ynl_cpp::ynl_socket&  ys,
			  ethtool_linkinfo_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_linkinfo_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_linkinfo_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_linkinfo_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_linkinfo_get_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_LINKINFO_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_LINKINFO_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_linkinfo_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_LINKINFO_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_LINKINFO_GET - notify */
/* ============== ETHTOOL_MSG_LINKINFO_SET ============== */
/* ETHTOOL_MSG_LINKINFO_SET - do */
int ethtool_linkinfo_set(ynl_cpp::ynl_socket&  ys,
			 ethtool_linkinfo_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_LINKINFO_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_linkinfo_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_LINKINFO_HEADER, req.header.value());
	if (req.port.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKINFO_PORT, req.port.value());
	if (req.phyaddr.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKINFO_PHYADDR, req.phyaddr.value());
	if (req.tp_mdix.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKINFO_TP_MDIX, req.tp_mdix.value());
	if (req.tp_mdix_ctrl.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKINFO_TP_MDIX_CTRL, req.tp_mdix_ctrl.value());
	if (req.transceiver.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKINFO_TRANSCEIVER, req.transceiver.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_LINKMODES_GET ============== */
/* ETHTOOL_MSG_LINKMODES_GET - do */
int ethtool_linkmodes_get_rsp_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	ethtool_linkmodes_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_linkmodes_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_LINKMODES_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_LINKMODES_AUTONEG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->autoneg = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKMODES_OURS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->ours;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_LINKMODES_PEER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->peer;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_LINKMODES_SPEED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->speed = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_LINKMODES_DUPLEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->duplex = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->master_slave_cfg = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->master_slave_state = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKMODES_LANES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->lanes = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_LINKMODES_RATE_MATCHING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rate_matching = (__u8)ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_linkmodes_get_rsp>
ethtool_linkmodes_get(ynl_cpp::ynl_socket&  ys, ethtool_linkmodes_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_linkmodes_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_LINKMODES_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_linkmodes_nest;
	yrs.yarg.rsp_policy = &ethtool_linkmodes_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_LINKMODES_HEADER, req.header.value());

	rsp.reset(new ethtool_linkmodes_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_linkmodes_get_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_LINKMODES_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_LINKMODES_GET - dump */
std::unique_ptr<ethtool_linkmodes_get_list>
ethtool_linkmodes_get_dump(ynl_cpp::ynl_socket&  ys,
			   ethtool_linkmodes_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_linkmodes_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_linkmodes_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_linkmodes_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_linkmodes_get_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_LINKMODES_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_LINKMODES_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_linkmodes_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_LINKMODES_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_LINKMODES_GET - notify */
/* ============== ETHTOOL_MSG_LINKMODES_SET ============== */
/* ETHTOOL_MSG_LINKMODES_SET - do */
int ethtool_linkmodes_set(ynl_cpp::ynl_socket&  ys,
			  ethtool_linkmodes_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_LINKMODES_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_linkmodes_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_LINKMODES_HEADER, req.header.value());
	if (req.autoneg.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKMODES_AUTONEG, req.autoneg.value());
	if (req.ours.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_LINKMODES_OURS, req.ours.value());
	if (req.peer.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_LINKMODES_PEER, req.peer.value());
	if (req.speed.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_LINKMODES_SPEED, req.speed.value());
	if (req.duplex.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKMODES_DUPLEX, req.duplex.value());
	if (req.master_slave_cfg.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG, req.master_slave_cfg.value());
	if (req.master_slave_state.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE, req.master_slave_state.value());
	if (req.lanes.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_LINKMODES_LANES, req.lanes.value());
	if (req.rate_matching.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_LINKMODES_RATE_MATCHING, req.rate_matching.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_LINKSTATE_GET ============== */
/* ETHTOOL_MSG_LINKSTATE_GET - do */
int ethtool_linkstate_get_rsp_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	ethtool_linkstate_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_linkstate_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_LINKSTATE_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_LINKSTATE_LINK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->link = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKSTATE_SQI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->sqi = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_LINKSTATE_SQI_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->sqi_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_LINKSTATE_EXT_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->ext_state = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKSTATE_EXT_SUBSTATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->ext_substate = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->ext_down_cnt = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_linkstate_get_rsp>
ethtool_linkstate_get(ynl_cpp::ynl_socket&  ys, ethtool_linkstate_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_linkstate_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_LINKSTATE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_linkstate_nest;
	yrs.yarg.rsp_policy = &ethtool_linkstate_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_LINKSTATE_HEADER, req.header.value());

	rsp.reset(new ethtool_linkstate_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_linkstate_get_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_LINKSTATE_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_LINKSTATE_GET - dump */
std::unique_ptr<ethtool_linkstate_get_list>
ethtool_linkstate_get_dump(ynl_cpp::ynl_socket&  ys,
			   ethtool_linkstate_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_linkstate_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_linkstate_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_linkstate_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_linkstate_get_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_LINKSTATE_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_LINKSTATE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_linkstate_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_LINKSTATE_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_DEBUG_GET ============== */
/* ETHTOOL_MSG_DEBUG_GET - do */
int ethtool_debug_get_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	ethtool_debug_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_debug_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_DEBUG_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_DEBUG_MSGMASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->msgmask;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_debug_get_rsp>
ethtool_debug_get(ynl_cpp::ynl_socket&  ys, ethtool_debug_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_debug_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_DEBUG_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_debug_nest;
	yrs.yarg.rsp_policy = &ethtool_debug_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_DEBUG_HEADER, req.header.value());

	rsp.reset(new ethtool_debug_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_debug_get_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_DEBUG_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_DEBUG_GET - dump */
std::unique_ptr<ethtool_debug_get_list>
ethtool_debug_get_dump(ynl_cpp::ynl_socket&  ys,
		       ethtool_debug_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_debug_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_debug_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_debug_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_debug_get_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_DEBUG_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_DEBUG_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_debug_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_DEBUG_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_DEBUG_GET - notify */
/* ============== ETHTOOL_MSG_DEBUG_SET ============== */
/* ETHTOOL_MSG_DEBUG_SET - do */
int ethtool_debug_set(ynl_cpp::ynl_socket&  ys, ethtool_debug_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_DEBUG_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_debug_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_DEBUG_HEADER, req.header.value());
	if (req.msgmask.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_DEBUG_MSGMASK, req.msgmask.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_WOL_GET ============== */
/* ETHTOOL_MSG_WOL_GET - do */
int ethtool_wol_get_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ethtool_wol_get_rsp *dst;

	dst = (ethtool_wol_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_WOL_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_WOL_MODES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->modes;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_WOL_SOPASS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->sopass.assign(data, data + len);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_wol_get_rsp>
ethtool_wol_get(ynl_cpp::ynl_socket&  ys, ethtool_wol_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_wol_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_WOL_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_wol_nest;
	yrs.yarg.rsp_policy = &ethtool_wol_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_WOL_HEADER, req.header.value());

	rsp.reset(new ethtool_wol_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_wol_get_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_WOL_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_WOL_GET - dump */
std::unique_ptr<ethtool_wol_get_list>
ethtool_wol_get_dump(ynl_cpp::ynl_socket&  ys, ethtool_wol_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_wol_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_wol_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_wol_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_wol_get_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_WOL_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_WOL_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_wol_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_WOL_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_WOL_GET - notify */
/* ============== ETHTOOL_MSG_WOL_SET ============== */
/* ETHTOOL_MSG_WOL_SET - do */
int ethtool_wol_set(ynl_cpp::ynl_socket&  ys, ethtool_wol_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_WOL_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_wol_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_WOL_HEADER, req.header.value());
	if (req.modes.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_WOL_MODES, req.modes.value());
	if (req.sopass.size() > 0)
		ynl_attr_put(nlh, ETHTOOL_A_WOL_SOPASS, req.sopass.data(), req.sopass.size());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_FEATURES_GET ============== */
/* ETHTOOL_MSG_FEATURES_GET - do */
int ethtool_features_get_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	ethtool_features_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_features_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_FEATURES_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEATURES_HW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->hw;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEATURES_WANTED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->wanted;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEATURES_ACTIVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->active;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEATURES_NOCHANGE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->nochange;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_features_get_rsp>
ethtool_features_get(ynl_cpp::ynl_socket&  ys, ethtool_features_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_features_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_FEATURES_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_features_nest;
	yrs.yarg.rsp_policy = &ethtool_features_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_FEATURES_HEADER, req.header.value());

	rsp.reset(new ethtool_features_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_features_get_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_FEATURES_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_FEATURES_GET - dump */
std::unique_ptr<ethtool_features_get_list>
ethtool_features_get_dump(ynl_cpp::ynl_socket&  ys,
			  ethtool_features_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_features_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_features_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_features_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_features_get_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_FEATURES_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_FEATURES_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_features_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_FEATURES_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_FEATURES_GET - notify */
/* ============== ETHTOOL_MSG_FEATURES_SET ============== */
/* ETHTOOL_MSG_FEATURES_SET - do */
int ethtool_features_set_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	ethtool_features_set_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_features_set_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_FEATURES_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEATURES_HW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->hw;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEATURES_WANTED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->wanted;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEATURES_ACTIVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->active;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEATURES_NOCHANGE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->nochange;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_features_set_rsp>
ethtool_features_set(ynl_cpp::ynl_socket&  ys, ethtool_features_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_features_set_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_FEATURES_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_features_nest;
	yrs.yarg.rsp_policy = &ethtool_features_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_FEATURES_HEADER, req.header.value());
	if (req.hw.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_FEATURES_HW, req.hw.value());
	if (req.wanted.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_FEATURES_WANTED, req.wanted.value());
	if (req.active.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_FEATURES_ACTIVE, req.active.value());
	if (req.nochange.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_FEATURES_NOCHANGE, req.nochange.value());

	rsp.reset(new ethtool_features_set_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_features_set_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_FEATURES_SET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ============== ETHTOOL_MSG_PRIVFLAGS_GET ============== */
/* ETHTOOL_MSG_PRIVFLAGS_GET - do */
int ethtool_privflags_get_rsp_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	ethtool_privflags_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_privflags_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_PRIVFLAGS_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_PRIVFLAGS_FLAGS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->flags;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_privflags_get_rsp>
ethtool_privflags_get(ynl_cpp::ynl_socket&  ys, ethtool_privflags_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_privflags_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PRIVFLAGS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_privflags_nest;
	yrs.yarg.rsp_policy = &ethtool_privflags_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PRIVFLAGS_HEADER, req.header.value());

	rsp.reset(new ethtool_privflags_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_privflags_get_rsp_parse;
	yrs.rsp_cmd = 14;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_PRIVFLAGS_GET - dump */
std::unique_ptr<ethtool_privflags_get_list>
ethtool_privflags_get_dump(ynl_cpp::ynl_socket&  ys,
			   ethtool_privflags_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_privflags_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_privflags_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_privflags_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_privflags_get_rsp_parse;
	yds.rsp_cmd = 14;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PRIVFLAGS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_privflags_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PRIVFLAGS_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_PRIVFLAGS_GET - notify */
/* ============== ETHTOOL_MSG_PRIVFLAGS_SET ============== */
/* ETHTOOL_MSG_PRIVFLAGS_SET - do */
int ethtool_privflags_set(ynl_cpp::ynl_socket&  ys,
			  ethtool_privflags_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PRIVFLAGS_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_privflags_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PRIVFLAGS_HEADER, req.header.value());
	if (req.flags.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_PRIVFLAGS_FLAGS, req.flags.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_RINGS_GET ============== */
/* ETHTOOL_MSG_RINGS_GET - do */
int ethtool_rings_get_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	ethtool_rings_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_rings_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_RINGS_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_RINGS_RX_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_RX_MINI_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_mini_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_RX_JUMBO_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_jumbo_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_TX_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_RX_MINI) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_mini = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_RX_JUMBO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_jumbo = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_RX_BUF_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_buf_len = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_TCP_DATA_SPLIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tcp_data_split = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_RINGS_CQE_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->cqe_size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_TX_PUSH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_push = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_RINGS_RX_PUSH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_push = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_push_buf_len = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_push_buf_len_max = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_rings_get_rsp>
ethtool_rings_get(ynl_cpp::ynl_socket&  ys, ethtool_rings_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_rings_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_RINGS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_rings_nest;
	yrs.yarg.rsp_policy = &ethtool_rings_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_RINGS_HEADER, req.header.value());

	rsp.reset(new ethtool_rings_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_rings_get_rsp_parse;
	yrs.rsp_cmd = 16;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_RINGS_GET - dump */
std::unique_ptr<ethtool_rings_get_list>
ethtool_rings_get_dump(ynl_cpp::ynl_socket&  ys,
		       ethtool_rings_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_rings_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_rings_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_rings_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_rings_get_rsp_parse;
	yds.rsp_cmd = 16;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_RINGS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_rings_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_RINGS_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_RINGS_GET - notify */
/* ============== ETHTOOL_MSG_RINGS_SET ============== */
/* ETHTOOL_MSG_RINGS_SET - do */
int ethtool_rings_set(ynl_cpp::ynl_socket&  ys, ethtool_rings_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_RINGS_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_rings_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_RINGS_HEADER, req.header.value());
	if (req.rx_max.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_RX_MAX, req.rx_max.value());
	if (req.rx_mini_max.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_RX_MINI_MAX, req.rx_mini_max.value());
	if (req.rx_jumbo_max.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_RX_JUMBO_MAX, req.rx_jumbo_max.value());
	if (req.tx_max.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_TX_MAX, req.tx_max.value());
	if (req.rx.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_RX, req.rx.value());
	if (req.rx_mini.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_RX_MINI, req.rx_mini.value());
	if (req.rx_jumbo.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_RX_JUMBO, req.rx_jumbo.value());
	if (req.tx.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_TX, req.tx.value());
	if (req.rx_buf_len.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_RX_BUF_LEN, req.rx_buf_len.value());
	if (req.tcp_data_split.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_RINGS_TCP_DATA_SPLIT, req.tcp_data_split.value());
	if (req.cqe_size.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_CQE_SIZE, req.cqe_size.value());
	if (req.tx_push.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_RINGS_TX_PUSH, req.tx_push.value());
	if (req.rx_push.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_RINGS_RX_PUSH, req.rx_push.value());
	if (req.tx_push_buf_len.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN, req.tx_push_buf_len.value());
	if (req.tx_push_buf_len_max.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX, req.tx_push_buf_len_max.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_CHANNELS_GET ============== */
/* ETHTOOL_MSG_CHANNELS_GET - do */
int ethtool_channels_get_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	ethtool_channels_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_channels_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_CHANNELS_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_CHANNELS_RX_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_CHANNELS_TX_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_CHANNELS_OTHER_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->other_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_CHANNELS_COMBINED_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->combined_max = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_CHANNELS_RX_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_count = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_CHANNELS_TX_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_count = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_CHANNELS_OTHER_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->other_count = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_CHANNELS_COMBINED_COUNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->combined_count = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_channels_get_rsp>
ethtool_channels_get(ynl_cpp::ynl_socket&  ys, ethtool_channels_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_channels_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_CHANNELS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_channels_nest;
	yrs.yarg.rsp_policy = &ethtool_channels_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_CHANNELS_HEADER, req.header.value());

	rsp.reset(new ethtool_channels_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_channels_get_rsp_parse;
	yrs.rsp_cmd = 18;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_CHANNELS_GET - dump */
std::unique_ptr<ethtool_channels_get_list>
ethtool_channels_get_dump(ynl_cpp::ynl_socket&  ys,
			  ethtool_channels_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_channels_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_channels_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_channels_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_channels_get_rsp_parse;
	yds.rsp_cmd = 18;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_CHANNELS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_channels_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_CHANNELS_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_CHANNELS_GET - notify */
/* ============== ETHTOOL_MSG_CHANNELS_SET ============== */
/* ETHTOOL_MSG_CHANNELS_SET - do */
int ethtool_channels_set(ynl_cpp::ynl_socket&  ys,
			 ethtool_channels_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_CHANNELS_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_channels_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_CHANNELS_HEADER, req.header.value());
	if (req.rx_max.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_RX_MAX, req.rx_max.value());
	if (req.tx_max.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_TX_MAX, req.tx_max.value());
	if (req.other_max.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_OTHER_MAX, req.other_max.value());
	if (req.combined_max.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_COMBINED_MAX, req.combined_max.value());
	if (req.rx_count.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_RX_COUNT, req.rx_count.value());
	if (req.tx_count.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_TX_COUNT, req.tx_count.value());
	if (req.other_count.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_OTHER_COUNT, req.other_count.value());
	if (req.combined_count.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_CHANNELS_COMBINED_COUNT, req.combined_count.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_COALESCE_GET ============== */
/* ETHTOOL_MSG_COALESCE_GET - do */
int ethtool_coalesce_get_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	ethtool_coalesce_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_coalesce_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_COALESCE_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_COALESCE_RX_USECS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_usecs = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_RX_MAX_FRAMES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_max_frames = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_RX_USECS_IRQ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_usecs_irq = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_max_frames_irq = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_USECS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_usecs = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_MAX_FRAMES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_max_frames = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_USECS_IRQ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_usecs_irq = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_max_frames_irq = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_STATS_BLOCK_USECS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->stats_block_usecs = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->use_adaptive_rx = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->use_adaptive_tx = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_COALESCE_PKT_RATE_LOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->pkt_rate_low = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_RX_USECS_LOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_usecs_low = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_max_frames_low = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_USECS_LOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_usecs_low = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_max_frames_low = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_PKT_RATE_HIGH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->pkt_rate_high = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_RX_USECS_HIGH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_usecs_high = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_max_frames_high = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_USECS_HIGH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_usecs_high = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_max_frames_high = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rate_sample_interval = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_USE_CQE_MODE_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->use_cqe_mode_tx = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_COALESCE_USE_CQE_MODE_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->use_cqe_mode_rx = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_aggr_max_bytes = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_aggr_max_frames = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_aggr_time_usecs = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_coalesce_get_rsp>
ethtool_coalesce_get(ynl_cpp::ynl_socket&  ys, ethtool_coalesce_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_coalesce_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_COALESCE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_coalesce_nest;
	yrs.yarg.rsp_policy = &ethtool_coalesce_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_COALESCE_HEADER, req.header.value());

	rsp.reset(new ethtool_coalesce_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_coalesce_get_rsp_parse;
	yrs.rsp_cmd = 20;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_COALESCE_GET - dump */
std::unique_ptr<ethtool_coalesce_get_list>
ethtool_coalesce_get_dump(ynl_cpp::ynl_socket&  ys,
			  ethtool_coalesce_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_coalesce_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_coalesce_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_coalesce_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_coalesce_get_rsp_parse;
	yds.rsp_cmd = 20;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_COALESCE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_coalesce_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_COALESCE_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_COALESCE_GET - notify */
/* ============== ETHTOOL_MSG_COALESCE_SET ============== */
/* ETHTOOL_MSG_COALESCE_SET - do */
int ethtool_coalesce_set(ynl_cpp::ynl_socket&  ys,
			 ethtool_coalesce_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_COALESCE_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_coalesce_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_COALESCE_HEADER, req.header.value());
	if (req.rx_usecs.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_RX_USECS, req.rx_usecs.value());
	if (req.rx_max_frames.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_RX_MAX_FRAMES, req.rx_max_frames.value());
	if (req.rx_usecs_irq.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_RX_USECS_IRQ, req.rx_usecs_irq.value());
	if (req.rx_max_frames_irq.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ, req.rx_max_frames_irq.value());
	if (req.tx_usecs.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_USECS, req.tx_usecs.value());
	if (req.tx_max_frames.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_MAX_FRAMES, req.tx_max_frames.value());
	if (req.tx_usecs_irq.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_USECS_IRQ, req.tx_usecs_irq.value());
	if (req.tx_max_frames_irq.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ, req.tx_max_frames_irq.value());
	if (req.stats_block_usecs.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_STATS_BLOCK_USECS, req.stats_block_usecs.value());
	if (req.use_adaptive_rx.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX, req.use_adaptive_rx.value());
	if (req.use_adaptive_tx.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX, req.use_adaptive_tx.value());
	if (req.pkt_rate_low.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_PKT_RATE_LOW, req.pkt_rate_low.value());
	if (req.rx_usecs_low.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_RX_USECS_LOW, req.rx_usecs_low.value());
	if (req.rx_max_frames_low.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW, req.rx_max_frames_low.value());
	if (req.tx_usecs_low.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_USECS_LOW, req.tx_usecs_low.value());
	if (req.tx_max_frames_low.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW, req.tx_max_frames_low.value());
	if (req.pkt_rate_high.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_PKT_RATE_HIGH, req.pkt_rate_high.value());
	if (req.rx_usecs_high.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_RX_USECS_HIGH, req.rx_usecs_high.value());
	if (req.rx_max_frames_high.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH, req.rx_max_frames_high.value());
	if (req.tx_usecs_high.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_USECS_HIGH, req.tx_usecs_high.value());
	if (req.tx_max_frames_high.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH, req.tx_max_frames_high.value());
	if (req.rate_sample_interval.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL, req.rate_sample_interval.value());
	if (req.use_cqe_mode_tx.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_COALESCE_USE_CQE_MODE_TX, req.use_cqe_mode_tx.value());
	if (req.use_cqe_mode_rx.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_COALESCE_USE_CQE_MODE_RX, req.use_cqe_mode_rx.value());
	if (req.tx_aggr_max_bytes.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES, req.tx_aggr_max_bytes.value());
	if (req.tx_aggr_max_frames.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES, req.tx_aggr_max_frames.value());
	if (req.tx_aggr_time_usecs.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS, req.tx_aggr_time_usecs.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_PAUSE_GET ============== */
/* ETHTOOL_MSG_PAUSE_GET - do */
int ethtool_pause_get_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	ethtool_pause_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_pause_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_PAUSE_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_PAUSE_AUTONEG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->autoneg = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_PAUSE_RX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_PAUSE_TX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_PAUSE_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_pause_stat_nest;
			parg.data = &dst->stats;
			if (ethtool_pause_stat_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_PAUSE_STATS_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->stats_src = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_pause_get_rsp>
ethtool_pause_get(ynl_cpp::ynl_socket&  ys, ethtool_pause_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_pause_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PAUSE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_pause_nest;
	yrs.yarg.rsp_policy = &ethtool_pause_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PAUSE_HEADER, req.header.value());

	rsp.reset(new ethtool_pause_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_pause_get_rsp_parse;
	yrs.rsp_cmd = 22;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_PAUSE_GET - dump */
std::unique_ptr<ethtool_pause_get_list>
ethtool_pause_get_dump(ynl_cpp::ynl_socket&  ys,
		       ethtool_pause_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_pause_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_pause_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_pause_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_pause_get_rsp_parse;
	yds.rsp_cmd = 22;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PAUSE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_pause_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PAUSE_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_PAUSE_GET - notify */
/* ============== ETHTOOL_MSG_PAUSE_SET ============== */
/* ETHTOOL_MSG_PAUSE_SET - do */
int ethtool_pause_set(ynl_cpp::ynl_socket&  ys, ethtool_pause_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PAUSE_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_pause_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PAUSE_HEADER, req.header.value());
	if (req.autoneg.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_PAUSE_AUTONEG, req.autoneg.value());
	if (req.rx.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_PAUSE_RX, req.rx.value());
	if (req.tx.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_PAUSE_TX, req.tx.value());
	if (req.stats.has_value())
		ethtool_pause_stat_put(nlh, ETHTOOL_A_PAUSE_STATS, req.stats.value());
	if (req.stats_src.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_PAUSE_STATS_SRC, req.stats_src.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_EEE_GET ============== */
/* ETHTOOL_MSG_EEE_GET - do */
int ethtool_eee_get_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ethtool_eee_get_rsp *dst;

	dst = (ethtool_eee_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_EEE_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_EEE_MODES_OURS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->modes_ours;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_EEE_MODES_PEER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->modes_peer;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_EEE_ACTIVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->active = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_EEE_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_EEE_TX_LPI_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_lpi_enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_EEE_TX_LPI_TIMER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_lpi_timer = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_eee_get_rsp>
ethtool_eee_get(ynl_cpp::ynl_socket&  ys, ethtool_eee_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_eee_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_EEE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_eee_nest;
	yrs.yarg.rsp_policy = &ethtool_eee_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_EEE_HEADER, req.header.value());

	rsp.reset(new ethtool_eee_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_eee_get_rsp_parse;
	yrs.rsp_cmd = 24;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_EEE_GET - dump */
std::unique_ptr<ethtool_eee_get_list>
ethtool_eee_get_dump(ynl_cpp::ynl_socket&  ys, ethtool_eee_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_eee_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_eee_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_eee_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_eee_get_rsp_parse;
	yds.rsp_cmd = 24;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_EEE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_eee_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_EEE_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_EEE_GET - notify */
/* ============== ETHTOOL_MSG_EEE_SET ============== */
/* ETHTOOL_MSG_EEE_SET - do */
int ethtool_eee_set(ynl_cpp::ynl_socket&  ys, ethtool_eee_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_EEE_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_eee_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_EEE_HEADER, req.header.value());
	if (req.modes_ours.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_EEE_MODES_OURS, req.modes_ours.value());
	if (req.modes_peer.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_EEE_MODES_PEER, req.modes_peer.value());
	if (req.active.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_EEE_ACTIVE, req.active.value());
	if (req.enabled.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_EEE_ENABLED, req.enabled.value());
	if (req.tx_lpi_enabled.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_EEE_TX_LPI_ENABLED, req.tx_lpi_enabled.value());
	if (req.tx_lpi_timer.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_EEE_TX_LPI_TIMER, req.tx_lpi_timer.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_TSINFO_GET ============== */
/* ETHTOOL_MSG_TSINFO_GET - do */
int ethtool_tsinfo_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	ethtool_tsinfo_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_tsinfo_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_TSINFO_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_TSINFO_TIMESTAMPING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->timestamping;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_TSINFO_TX_TYPES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->tx_types;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_TSINFO_RX_FILTERS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->rx_filters;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_TSINFO_PHC_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->phc_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_TSINFO_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_ts_stat_nest;
			parg.data = &dst->stats;
			if (ethtool_ts_stat_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_tsinfo_get_rsp>
ethtool_tsinfo_get(ynl_cpp::ynl_socket&  ys, ethtool_tsinfo_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_tsinfo_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_TSINFO_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_tsinfo_nest;
	yrs.yarg.rsp_policy = &ethtool_tsinfo_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_TSINFO_HEADER, req.header.value());

	rsp.reset(new ethtool_tsinfo_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_tsinfo_get_rsp_parse;
	yrs.rsp_cmd = 26;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_TSINFO_GET - dump */
std::unique_ptr<ethtool_tsinfo_get_list>
ethtool_tsinfo_get_dump(ynl_cpp::ynl_socket&  ys,
			ethtool_tsinfo_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_tsinfo_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_tsinfo_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_tsinfo_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_tsinfo_get_rsp_parse;
	yds.rsp_cmd = 26;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_TSINFO_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_tsinfo_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_TSINFO_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_CABLE_TEST_ACT ============== */
/* ETHTOOL_MSG_CABLE_TEST_ACT - do */
int ethtool_cable_test_act(ynl_cpp::ynl_socket&  ys,
			   ethtool_cable_test_act_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_CABLE_TEST_ACT, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_cable_test_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_CABLE_TEST_HEADER, req.header.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_CABLE_TEST_TDR_ACT ============== */
/* ETHTOOL_MSG_CABLE_TEST_TDR_ACT - do */
int ethtool_cable_test_tdr_act(ynl_cpp::ynl_socket&  ys,
			       ethtool_cable_test_tdr_act_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_CABLE_TEST_TDR_ACT, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_cable_test_tdr_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_CABLE_TEST_TDR_HEADER, req.header.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_TUNNEL_INFO_GET ============== */
/* ETHTOOL_MSG_TUNNEL_INFO_GET - do */
int ethtool_tunnel_info_get_rsp_parse(const struct nlmsghdr *nlh,
				      struct ynl_parse_arg *yarg)
{
	ethtool_tunnel_info_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_tunnel_info_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_TUNNEL_INFO_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_TUNNEL_INFO_UDP_PORTS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_tunnel_udp_nest;
			parg.data = &dst->udp_ports;
			if (ethtool_tunnel_udp_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_tunnel_info_get_rsp>
ethtool_tunnel_info_get(ynl_cpp::ynl_socket&  ys,
			ethtool_tunnel_info_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_tunnel_info_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_TUNNEL_INFO_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_tunnel_info_nest;
	yrs.yarg.rsp_policy = &ethtool_tunnel_info_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_TUNNEL_INFO_HEADER, req.header.value());

	rsp.reset(new ethtool_tunnel_info_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_tunnel_info_get_rsp_parse;
	yrs.rsp_cmd = 29;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_TUNNEL_INFO_GET - dump */
std::unique_ptr<ethtool_tunnel_info_get_list>
ethtool_tunnel_info_get_dump(ynl_cpp::ynl_socket&  ys,
			     ethtool_tunnel_info_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_tunnel_info_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_tunnel_info_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_tunnel_info_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_tunnel_info_get_rsp_parse;
	yds.rsp_cmd = 29;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_TUNNEL_INFO_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_tunnel_info_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_TUNNEL_INFO_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_FEC_GET ============== */
/* ETHTOOL_MSG_FEC_GET - do */
int ethtool_fec_get_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ethtool_fec_get_rsp *dst;

	dst = (ethtool_fec_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_FEC_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEC_MODES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->modes;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_FEC_AUTO) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->auto_ = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_FEC_ACTIVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->active = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_FEC_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_fec_stat_nest;
			parg.data = &dst->stats;
			if (ethtool_fec_stat_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_fec_get_rsp>
ethtool_fec_get(ynl_cpp::ynl_socket&  ys, ethtool_fec_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_fec_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_FEC_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_fec_nest;
	yrs.yarg.rsp_policy = &ethtool_fec_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_FEC_HEADER, req.header.value());

	rsp.reset(new ethtool_fec_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_fec_get_rsp_parse;
	yrs.rsp_cmd = 30;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_FEC_GET - dump */
std::unique_ptr<ethtool_fec_get_list>
ethtool_fec_get_dump(ynl_cpp::ynl_socket&  ys, ethtool_fec_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_fec_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_fec_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_fec_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_fec_get_rsp_parse;
	yds.rsp_cmd = 30;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_FEC_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_fec_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_FEC_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_FEC_GET - notify */
/* ============== ETHTOOL_MSG_FEC_SET ============== */
/* ETHTOOL_MSG_FEC_SET - do */
int ethtool_fec_set(ynl_cpp::ynl_socket&  ys, ethtool_fec_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_FEC_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_fec_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_FEC_HEADER, req.header.value());
	if (req.modes.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_FEC_MODES, req.modes.value());
	if (req.auto_.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_FEC_AUTO, req.auto_.value());
	if (req.active.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_FEC_ACTIVE, req.active.value());
	if (req.stats.has_value())
		ethtool_fec_stat_put(nlh, ETHTOOL_A_FEC_STATS, req.stats.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_MODULE_EEPROM_GET ============== */
/* ETHTOOL_MSG_MODULE_EEPROM_GET - do */
int ethtool_module_eeprom_get_rsp_parse(const struct nlmsghdr *nlh,
					struct ynl_parse_arg *yarg)
{
	ethtool_module_eeprom_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_module_eeprom_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_MODULE_EEPROM_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_MODULE_EEPROM_OFFSET) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->offset = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_MODULE_EEPROM_LENGTH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->length = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_MODULE_EEPROM_PAGE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->page = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_MODULE_EEPROM_BANK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->bank = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->i2c_address = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_MODULE_EEPROM_DATA) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->data.assign(data, data + len);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_module_eeprom_get_rsp>
ethtool_module_eeprom_get(ynl_cpp::ynl_socket&  ys,
			  ethtool_module_eeprom_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_module_eeprom_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_MODULE_EEPROM_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_module_eeprom_nest;
	yrs.yarg.rsp_policy = &ethtool_module_eeprom_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_MODULE_EEPROM_HEADER, req.header.value());

	rsp.reset(new ethtool_module_eeprom_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_module_eeprom_get_rsp_parse;
	yrs.rsp_cmd = 32;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_MODULE_EEPROM_GET - dump */
std::unique_ptr<ethtool_module_eeprom_get_list>
ethtool_module_eeprom_get_dump(ynl_cpp::ynl_socket&  ys,
			       ethtool_module_eeprom_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_module_eeprom_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_module_eeprom_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_module_eeprom_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_module_eeprom_get_rsp_parse;
	yds.rsp_cmd = 32;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_MODULE_EEPROM_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_module_eeprom_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_MODULE_EEPROM_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_STATS_GET ============== */
/* ETHTOOL_MSG_STATS_GET - do */
int ethtool_stats_get_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	ethtool_stats_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_stats_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_STATS_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_STATS_GROUPS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_bitset_nest;
			parg.data = &dst->groups;
			if (ethtool_bitset_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_STATS_GRP) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_stats_grp_nest;
			parg.data = &dst->grp;
			if (ethtool_stats_grp_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_STATS_SRC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->src = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_stats_get_rsp>
ethtool_stats_get(ynl_cpp::ynl_socket&  ys, ethtool_stats_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_stats_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_STATS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_stats_nest;
	yrs.yarg.rsp_policy = &ethtool_stats_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_STATS_HEADER, req.header.value());
	if (req.groups.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_STATS_GROUPS, req.groups.value());

	rsp.reset(new ethtool_stats_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_stats_get_rsp_parse;
	yrs.rsp_cmd = 33;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_STATS_GET - dump */
std::unique_ptr<ethtool_stats_get_list>
ethtool_stats_get_dump(ynl_cpp::ynl_socket&  ys,
		       ethtool_stats_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_stats_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_stats_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_stats_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_stats_get_rsp_parse;
	yds.rsp_cmd = 33;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_STATS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_stats_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_STATS_HEADER, req.header.value());
	if (req.groups.has_value())
		ethtool_bitset_put(nlh, ETHTOOL_A_STATS_GROUPS, req.groups.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_PHC_VCLOCKS_GET ============== */
/* ETHTOOL_MSG_PHC_VCLOCKS_GET - do */
int ethtool_phc_vclocks_get_rsp_parse(const struct nlmsghdr *nlh,
				      struct ynl_parse_arg *yarg)
{
	ethtool_phc_vclocks_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_phc_vclocks_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_PHC_VCLOCKS_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_PHC_VCLOCKS_NUM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->num = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_phc_vclocks_get_rsp>
ethtool_phc_vclocks_get(ynl_cpp::ynl_socket&  ys,
			ethtool_phc_vclocks_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_phc_vclocks_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PHC_VCLOCKS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_phc_vclocks_nest;
	yrs.yarg.rsp_policy = &ethtool_phc_vclocks_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PHC_VCLOCKS_HEADER, req.header.value());

	rsp.reset(new ethtool_phc_vclocks_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_phc_vclocks_get_rsp_parse;
	yrs.rsp_cmd = 34;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_PHC_VCLOCKS_GET - dump */
std::unique_ptr<ethtool_phc_vclocks_get_list>
ethtool_phc_vclocks_get_dump(ynl_cpp::ynl_socket&  ys,
			     ethtool_phc_vclocks_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_phc_vclocks_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_phc_vclocks_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_phc_vclocks_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_phc_vclocks_get_rsp_parse;
	yds.rsp_cmd = 34;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PHC_VCLOCKS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_phc_vclocks_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PHC_VCLOCKS_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_MODULE_GET ============== */
/* ETHTOOL_MSG_MODULE_GET - do */
int ethtool_module_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	ethtool_module_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_module_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_MODULE_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_MODULE_POWER_MODE_POLICY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->power_mode_policy = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_MODULE_POWER_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->power_mode = (__u8)ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_module_get_rsp>
ethtool_module_get(ynl_cpp::ynl_socket&  ys, ethtool_module_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_module_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_MODULE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_module_nest;
	yrs.yarg.rsp_policy = &ethtool_module_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_MODULE_HEADER, req.header.value());

	rsp.reset(new ethtool_module_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_module_get_rsp_parse;
	yrs.rsp_cmd = 35;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_MODULE_GET - dump */
std::unique_ptr<ethtool_module_get_list>
ethtool_module_get_dump(ynl_cpp::ynl_socket&  ys,
			ethtool_module_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_module_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_module_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_module_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_module_get_rsp_parse;
	yds.rsp_cmd = 35;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_MODULE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_module_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_MODULE_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_MODULE_GET - notify */
/* ============== ETHTOOL_MSG_MODULE_SET ============== */
/* ETHTOOL_MSG_MODULE_SET - do */
int ethtool_module_set(ynl_cpp::ynl_socket&  ys, ethtool_module_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_MODULE_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_module_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_MODULE_HEADER, req.header.value());
	if (req.power_mode_policy.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_MODULE_POWER_MODE_POLICY, req.power_mode_policy.value());
	if (req.power_mode.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_MODULE_POWER_MODE, req.power_mode.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_PSE_GET ============== */
/* ETHTOOL_MSG_PSE_GET - do */
int ethtool_pse_get_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ethtool_pse_get_rsp *dst;

	dst = (ethtool_pse_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_PSE_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_PODL_PSE_ADMIN_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->podl_pse_admin_state = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PODL_PSE_ADMIN_CONTROL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->podl_pse_admin_control = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PODL_PSE_PW_D_STATUS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->podl_pse_pw_d_status = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_C33_PSE_ADMIN_STATE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->c33_pse_admin_state = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_C33_PSE_ADMIN_CONTROL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->c33_pse_admin_control = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_C33_PSE_PW_D_STATUS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->c33_pse_pw_d_status = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_pse_get_rsp>
ethtool_pse_get(ynl_cpp::ynl_socket&  ys, ethtool_pse_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_pse_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PSE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_pse_nest;
	yrs.yarg.rsp_policy = &ethtool_pse_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PSE_HEADER, req.header.value());

	rsp.reset(new ethtool_pse_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_pse_get_rsp_parse;
	yrs.rsp_cmd = 37;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_PSE_GET - dump */
std::unique_ptr<ethtool_pse_get_list>
ethtool_pse_get_dump(ynl_cpp::ynl_socket&  ys, ethtool_pse_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_pse_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_pse_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_pse_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_pse_get_rsp_parse;
	yds.rsp_cmd = 37;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PSE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_pse_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PSE_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_PSE_SET ============== */
/* ETHTOOL_MSG_PSE_SET - do */
int ethtool_pse_set(ynl_cpp::ynl_socket&  ys, ethtool_pse_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PSE_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_pse_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PSE_HEADER, req.header.value());
	if (req.podl_pse_admin_state.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_PODL_PSE_ADMIN_STATE, req.podl_pse_admin_state.value());
	if (req.podl_pse_admin_control.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_PODL_PSE_ADMIN_CONTROL, req.podl_pse_admin_control.value());
	if (req.podl_pse_pw_d_status.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_PODL_PSE_PW_D_STATUS, req.podl_pse_pw_d_status.value());
	if (req.c33_pse_admin_state.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_C33_PSE_ADMIN_STATE, req.c33_pse_admin_state.value());
	if (req.c33_pse_admin_control.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_C33_PSE_ADMIN_CONTROL, req.c33_pse_admin_control.value());
	if (req.c33_pse_pw_d_status.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_C33_PSE_PW_D_STATUS, req.c33_pse_pw_d_status.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_RSS_GET ============== */
/* ETHTOOL_MSG_RSS_GET - do */
int ethtool_rss_get_rsp_parse(const struct nlmsghdr *nlh,
			      struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ethtool_rss_get_rsp *dst;

	dst = (ethtool_rss_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_RSS_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_RSS_CONTEXT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->context = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RSS_HFUNC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->hfunc = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_RSS_INDIR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->indir.assign(data, data + len);
		} else if (type == ETHTOOL_A_RSS_HKEY) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->hkey.assign(data, data + len);
		} else if (type == ETHTOOL_A_RSS_INPUT_XFRM) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->input_xfrm = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_rss_get_rsp>
ethtool_rss_get(ynl_cpp::ynl_socket&  ys, ethtool_rss_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_rss_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_RSS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_rss_nest;
	yrs.yarg.rsp_policy = &ethtool_rss_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_RSS_HEADER, req.header.value());

	rsp.reset(new ethtool_rss_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_rss_get_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_RSS_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_RSS_GET - dump */
std::unique_ptr<ethtool_rss_get_list>
ethtool_rss_get_dump(ynl_cpp::ynl_socket&  ys, ethtool_rss_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_rss_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_rss_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_rss_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_rss_get_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_RSS_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_RSS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_rss_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_RSS_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_PLCA_GET_CFG ============== */
/* ETHTOOL_MSG_PLCA_GET_CFG - do */
int ethtool_plca_get_cfg_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	ethtool_plca_get_cfg_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_plca_get_cfg_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_PLCA_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_PLCA_VERSION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->version = (__u16)ynl_attr_get_u16(attr);
		} else if (type == ETHTOOL_A_PLCA_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_PLCA_STATUS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->status = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_PLCA_NODE_CNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->node_cnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PLCA_NODE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->node_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PLCA_TO_TMR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->to_tmr = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PLCA_BURST_CNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->burst_cnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PLCA_BURST_TMR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->burst_tmr = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_plca_get_cfg_rsp>
ethtool_plca_get_cfg(ynl_cpp::ynl_socket&  ys, ethtool_plca_get_cfg_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_plca_get_cfg_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PLCA_GET_CFG, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_plca_nest;
	yrs.yarg.rsp_policy = &ethtool_plca_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PLCA_HEADER, req.header.value());

	rsp.reset(new ethtool_plca_get_cfg_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_plca_get_cfg_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_PLCA_GET_CFG;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_PLCA_GET_CFG - dump */
std::unique_ptr<ethtool_plca_get_cfg_list>
ethtool_plca_get_cfg_dump(ynl_cpp::ynl_socket&  ys,
			  ethtool_plca_get_cfg_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_plca_get_cfg_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_plca_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_plca_get_cfg_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_plca_get_cfg_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_PLCA_GET_CFG;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PLCA_GET_CFG, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_plca_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PLCA_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_PLCA_GET_CFG - notify */
/* ============== ETHTOOL_MSG_PLCA_SET_CFG ============== */
/* ETHTOOL_MSG_PLCA_SET_CFG - do */
int ethtool_plca_set_cfg(ynl_cpp::ynl_socket&  ys,
			 ethtool_plca_set_cfg_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PLCA_SET_CFG, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_plca_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PLCA_HEADER, req.header.value());
	if (req.version.has_value())
		ynl_attr_put_u16(nlh, ETHTOOL_A_PLCA_VERSION, req.version.value());
	if (req.enabled.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_PLCA_ENABLED, req.enabled.value());
	if (req.status.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_PLCA_STATUS, req.status.value());
	if (req.node_cnt.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_PLCA_NODE_CNT, req.node_cnt.value());
	if (req.node_id.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_PLCA_NODE_ID, req.node_id.value());
	if (req.to_tmr.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_PLCA_TO_TMR, req.to_tmr.value());
	if (req.burst_cnt.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_PLCA_BURST_CNT, req.burst_cnt.value());
	if (req.burst_tmr.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_PLCA_BURST_TMR, req.burst_tmr.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== ETHTOOL_MSG_PLCA_GET_STATUS ============== */
/* ETHTOOL_MSG_PLCA_GET_STATUS - do */
int ethtool_plca_get_status_rsp_parse(const struct nlmsghdr *nlh,
				      struct ynl_parse_arg *yarg)
{
	ethtool_plca_get_status_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_plca_get_status_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_PLCA_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_PLCA_VERSION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->version = (__u16)ynl_attr_get_u16(attr);
		} else if (type == ETHTOOL_A_PLCA_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_PLCA_STATUS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->status = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_PLCA_NODE_CNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->node_cnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PLCA_NODE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->node_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PLCA_TO_TMR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->to_tmr = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PLCA_BURST_CNT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->burst_cnt = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_PLCA_BURST_TMR) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->burst_tmr = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_plca_get_status_rsp>
ethtool_plca_get_status(ynl_cpp::ynl_socket&  ys,
			ethtool_plca_get_status_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_plca_get_status_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PLCA_GET_STATUS, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_plca_nest;
	yrs.yarg.rsp_policy = &ethtool_plca_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PLCA_HEADER, req.header.value());

	rsp.reset(new ethtool_plca_get_status_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_plca_get_status_rsp_parse;
	yrs.rsp_cmd = 40;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_PLCA_GET_STATUS - dump */
std::unique_ptr<ethtool_plca_get_status_list>
ethtool_plca_get_status_dump(ynl_cpp::ynl_socket&  ys,
			     ethtool_plca_get_status_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_plca_get_status_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_plca_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_plca_get_status_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_plca_get_status_rsp_parse;
	yds.rsp_cmd = 40;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_PLCA_GET_STATUS, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_plca_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_PLCA_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ============== ETHTOOL_MSG_MM_GET ============== */
/* ETHTOOL_MSG_MM_GET - do */
int ethtool_mm_get_rsp_parse(const struct nlmsghdr *nlh,
			     struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ethtool_mm_get_rsp *dst;

	dst = (ethtool_mm_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_MM_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_MM_PMAC_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->pmac_enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_MM_TX_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_MM_TX_ACTIVE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_active = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_MM_TX_MIN_FRAG_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->tx_min_frag_size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_MM_RX_MIN_FRAG_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->rx_min_frag_size = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_MM_VERIFY_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->verify_enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_MM_VERIFY_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->verify_time = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_MM_MAX_VERIFY_TIME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->max_verify_time = (__u32)ynl_attr_get_u32(attr);
		} else if (type == ETHTOOL_A_MM_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_mm_stat_nest;
			parg.data = &dst->stats;
			if (ethtool_mm_stat_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ethtool_mm_get_rsp>
ethtool_mm_get(ynl_cpp::ynl_socket&  ys, ethtool_mm_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ethtool_mm_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_MM_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_mm_nest;
	yrs.yarg.rsp_policy = &ethtool_mm_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_MM_HEADER, req.header.value());

	rsp.reset(new ethtool_mm_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ethtool_mm_get_rsp_parse;
	yrs.rsp_cmd = ETHTOOL_MSG_MM_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return nullptr;

	return rsp;
}

/* ETHTOOL_MSG_MM_GET - dump */
std::unique_ptr<ethtool_mm_get_list>
ethtool_mm_get_dump(ynl_cpp::ynl_socket&  ys, ethtool_mm_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ethtool_mm_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ethtool_mm_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<ethtool_mm_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ethtool_mm_get_rsp_parse;
	yds.rsp_cmd = ETHTOOL_MSG_MM_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_MM_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_mm_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_MM_HEADER, req.header.value());

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0)
		return nullptr;

	return ret;
}

/* ETHTOOL_MSG_MM_GET - notify */
/* ============== ETHTOOL_MSG_MM_SET ============== */
/* ETHTOOL_MSG_MM_SET - do */
int ethtool_mm_set(ynl_cpp::ynl_socket&  ys, ethtool_mm_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, ETHTOOL_MSG_MM_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ethtool_mm_nest;

	if (req.header.has_value())
		ethtool_header_put(nlh, ETHTOOL_A_MM_HEADER, req.header.value());
	if (req.verify_enabled.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_MM_VERIFY_ENABLED, req.verify_enabled.value());
	if (req.verify_time.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_MM_VERIFY_TIME, req.verify_time.value());
	if (req.tx_enabled.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_MM_TX_ENABLED, req.tx_enabled.value());
	if (req.pmac_enabled.has_value())
		ynl_attr_put_u8(nlh, ETHTOOL_A_MM_PMAC_ENABLED, req.pmac_enabled.value());
	if (req.tx_min_frag_size.has_value())
		ynl_attr_put_u32(nlh, ETHTOOL_A_MM_TX_MIN_FRAG_SIZE, req.tx_min_frag_size.value());

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ETHTOOL_MSG_CABLE_TEST_NTF - event */
int ethtool_cable_test_ntf_rsp_parse(const struct nlmsghdr *nlh,
				     struct ynl_parse_arg *yarg)
{
	ethtool_cable_test_ntf_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_cable_test_ntf_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_CABLE_TEST_NTF_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_CABLE_TEST_NTF_STATUS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->status = (__u8)ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

/* ETHTOOL_MSG_CABLE_TEST_TDR_NTF - event */
int ethtool_cable_test_tdr_ntf_rsp_parse(const struct nlmsghdr *nlh,
					 struct ynl_parse_arg *yarg)
{
	ethtool_cable_test_tdr_ntf_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (ethtool_cable_test_tdr_ntf_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == ETHTOOL_A_CABLE_TEST_TDR_NTF_HEADER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_header_nest;
			parg.data = &dst->header;
			if (ethtool_header_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == ETHTOOL_A_CABLE_TEST_TDR_NTF_STATUS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->status = (__u8)ynl_attr_get_u8(attr);
		} else if (type == ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			parg.rsp_policy = &ethtool_cable_nest_nest;
			parg.data = &dst->nest;
			if (ethtool_cable_nest_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

static constexpr std::array<ynl_ntf_info, ETHTOOL_MSG_MM_NTF + 1> ethtool_ntf_info = []() {
	std::array<ynl_ntf_info, ETHTOOL_MSG_MM_NTF + 1> arr{};
	arr[ETHTOOL_MSG_LINKINFO_NTF] =  {
		.cb		= ethtool_linkinfo_get_rsp_parse,
		.policy		= &ethtool_linkinfo_nest,
	};
	arr[ETHTOOL_MSG_LINKMODES_NTF] =  {
		.cb		= ethtool_linkmodes_get_rsp_parse,
		.policy		= &ethtool_linkmodes_nest,
	};
	arr[ETHTOOL_MSG_DEBUG_NTF] =  {
		.cb		= ethtool_debug_get_rsp_parse,
		.policy		= &ethtool_debug_nest,
	};
	arr[ETHTOOL_MSG_WOL_NTF] =  {
		.cb		= ethtool_wol_get_rsp_parse,
		.policy		= &ethtool_wol_nest,
	};
	arr[ETHTOOL_MSG_FEATURES_NTF] =  {
		.cb		= ethtool_features_get_rsp_parse,
		.policy		= &ethtool_features_nest,
	};
	arr[ETHTOOL_MSG_PRIVFLAGS_NTF] =  {
		.cb		= ethtool_privflags_get_rsp_parse,
		.policy		= &ethtool_privflags_nest,
	};
	arr[ETHTOOL_MSG_RINGS_NTF] =  {
		.cb		= ethtool_rings_get_rsp_parse,
		.policy		= &ethtool_rings_nest,
	};
	arr[ETHTOOL_MSG_CHANNELS_NTF] =  {
		.cb		= ethtool_channels_get_rsp_parse,
		.policy		= &ethtool_channels_nest,
	};
	arr[ETHTOOL_MSG_COALESCE_NTF] =  {
		.cb		= ethtool_coalesce_get_rsp_parse,
		.policy		= &ethtool_coalesce_nest,
	};
	arr[ETHTOOL_MSG_PAUSE_NTF] =  {
		.cb		= ethtool_pause_get_rsp_parse,
		.policy		= &ethtool_pause_nest,
	};
	arr[ETHTOOL_MSG_EEE_NTF] =  {
		.cb		= ethtool_eee_get_rsp_parse,
		.policy		= &ethtool_eee_nest,
	};
	arr[ETHTOOL_MSG_CABLE_TEST_NTF] =  {
		.cb		= ethtool_cable_test_ntf_rsp_parse,
		.policy		= &ethtool_cable_test_ntf_nest,
	};
	arr[ETHTOOL_MSG_CABLE_TEST_TDR_NTF] =  {
		.cb		= ethtool_cable_test_tdr_ntf_rsp_parse,
		.policy		= &ethtool_cable_test_tdr_ntf_nest,
	};
	arr[ETHTOOL_MSG_FEC_NTF] =  {
		.cb		= ethtool_fec_get_rsp_parse,
		.policy		= &ethtool_fec_nest,
	};
	arr[ETHTOOL_MSG_MODULE_NTF] =  {
		.cb		= ethtool_module_get_rsp_parse,
		.policy		= &ethtool_module_nest,
	};
	arr[ETHTOOL_MSG_PLCA_NTF] =  {
		.cb		= ethtool_plca_get_cfg_rsp_parse,
		.policy		= &ethtool_plca_nest,
	};
	arr[ETHTOOL_MSG_MM_NTF] =  {
		.cb		= ethtool_mm_get_rsp_parse,
		.policy		= &ethtool_mm_nest,
	};
	return arr;
} ();

const struct ynl_family ynl_ethtool_family =  {
	.name		= "ethtool",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= ethtool_ntf_info.data(),
	.ntf_info_size	= ethtool_ntf_info.size(),
};
const struct ynl_family& get_ynl_ethtool_family() {
	return ynl_ethtool_family;
};
} //namespace ynl_cpp
