// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "devlink-user.hpp"

#include <array>

#include <linux/devlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, DEVLINK_CMD_SELFTESTS_GET + 1> devlink_op_strmap = []() {
	std::array<std::string_view, DEVLINK_CMD_SELFTESTS_GET + 1> arr{};
	arr[3] = "get";
	arr[DEVLINK_CMD_PORT_NEW] = "port-new";
	arr[13] = "sb-get";
	arr[17] = "sb-pool-get";
	arr[21] = "sb-port-pool-get";
	arr[25] = "sb-tc-pool-bind-get";
	arr[DEVLINK_CMD_ESWITCH_GET] = "eswitch-get";
	arr[DEVLINK_CMD_DPIPE_TABLE_GET] = "dpipe-table-get";
	arr[DEVLINK_CMD_DPIPE_ENTRIES_GET] = "dpipe-entries-get";
	arr[DEVLINK_CMD_DPIPE_HEADERS_GET] = "dpipe-headers-get";
	arr[DEVLINK_CMD_RESOURCE_DUMP] = "resource-dump";
	arr[DEVLINK_CMD_RELOAD] = "reload";
	arr[DEVLINK_CMD_PARAM_GET] = "param-get";
	arr[DEVLINK_CMD_REGION_GET] = "region-get";
	arr[DEVLINK_CMD_REGION_NEW] = "region-new";
	arr[DEVLINK_CMD_REGION_READ] = "region-read";
	arr[DEVLINK_CMD_PORT_PARAM_GET] = "port-param-get";
	arr[DEVLINK_CMD_INFO_GET] = "info-get";
	arr[DEVLINK_CMD_HEALTH_REPORTER_GET] = "health-reporter-get";
	arr[DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET] = "health-reporter-dump-get";
	arr[63] = "trap-get";
	arr[67] = "trap-group-get";
	arr[71] = "trap-policer-get";
	arr[76] = "rate-get";
	arr[80] = "linecard-get";
	arr[DEVLINK_CMD_SELFTESTS_GET] = "selftests-get";
	return arr;
} ();

std::string_view devlink_op_str(int op)
{
	if (op < 0 || op >= (int)(devlink_op_strmap.size())) {
		return "";
	}
	return devlink_op_strmap[op];
}

static constexpr std::array<std::string_view, 1 + 1> devlink_sb_pool_type_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "ingress";
	arr[1] = "egress";
	return arr;
} ();

std::string_view devlink_sb_pool_type_str(devlink_sb_pool_type value)
{
	if (value < 0 || value >= (int)(devlink_sb_pool_type_strmap.size())) {
		return "";
	}
	return devlink_sb_pool_type_strmap[value];
}

static constexpr std::array<std::string_view, 3 + 1> devlink_port_type_strmap = []() {
	std::array<std::string_view, 3 + 1> arr{};
	arr[0] = "notset";
	arr[1] = "auto";
	arr[2] = "eth";
	arr[3] = "ib";
	return arr;
} ();

std::string_view devlink_port_type_str(devlink_port_type value)
{
	if (value < 0 || value >= (int)(devlink_port_type_strmap.size())) {
		return "";
	}
	return devlink_port_type_strmap[value];
}

static constexpr std::array<std::string_view, 7 + 1> devlink_port_flavour_strmap = []() {
	std::array<std::string_view, 7 + 1> arr{};
	arr[0] = "physical";
	arr[1] = "cpu";
	arr[2] = "dsa";
	arr[3] = "pci-pf";
	arr[4] = "pci-vf";
	arr[5] = "virtual";
	arr[6] = "unused";
	arr[7] = "pci-sf";
	return arr;
} ();

std::string_view devlink_port_flavour_str(devlink_port_flavour value)
{
	if (value < 0 || value >= (int)(devlink_port_flavour_strmap.size())) {
		return "";
	}
	return devlink_port_flavour_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> devlink_port_fn_state_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "inactive";
	arr[1] = "active";
	return arr;
} ();

std::string_view devlink_port_fn_state_str(devlink_port_fn_state value)
{
	if (value < 0 || value >= (int)(devlink_port_fn_state_strmap.size())) {
		return "";
	}
	return devlink_port_fn_state_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> devlink_port_fn_opstate_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "detached";
	arr[1] = "attached";
	return arr;
} ();

std::string_view devlink_port_fn_opstate_str(devlink_port_fn_opstate value)
{
	if (value < 0 || value >= (int)(devlink_port_fn_opstate_strmap.size())) {
		return "";
	}
	return devlink_port_fn_opstate_strmap[value];
}

static constexpr std::array<std::string_view, 3 + 1> devlink_port_fn_attr_cap_strmap = []() {
	std::array<std::string_view, 3 + 1> arr{};
	arr[0] = "roce-bit";
	arr[1] = "migratable-bit";
	arr[2] = "ipsec-crypto-bit";
	arr[3] = "ipsec-packet-bit";
	return arr;
} ();

std::string_view devlink_port_fn_attr_cap_str(devlink_port_fn_attr_cap value)
{
	if (value < 0 || value >= (int)(devlink_port_fn_attr_cap_strmap.size())) {
		return "";
	}
	return devlink_port_fn_attr_cap_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> devlink_rate_type_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "leaf";
	arr[1] = "node";
	return arr;
} ();

std::string_view devlink_rate_type_str(devlink_rate_type value)
{
	if (value < 0 || value >= (int)(devlink_rate_type_strmap.size())) {
		return "";
	}
	return devlink_rate_type_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> devlink_sb_threshold_type_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "static";
	arr[1] = "dynamic";
	return arr;
} ();

std::string_view devlink_sb_threshold_type_str(devlink_sb_threshold_type value)
{
	if (value < 0 || value >= (int)(devlink_sb_threshold_type_strmap.size())) {
		return "";
	}
	return devlink_sb_threshold_type_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> devlink_eswitch_mode_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "legacy";
	arr[1] = "switchdev";
	return arr;
} ();

std::string_view devlink_eswitch_mode_str(devlink_eswitch_mode value)
{
	if (value < 0 || value >= (int)(devlink_eswitch_mode_strmap.size())) {
		return "";
	}
	return devlink_eswitch_mode_strmap[value];
}

static constexpr std::array<std::string_view, 3 + 1> devlink_eswitch_inline_mode_strmap = []() {
	std::array<std::string_view, 3 + 1> arr{};
	arr[0] = "none";
	arr[1] = "link";
	arr[2] = "network";
	arr[3] = "transport";
	return arr;
} ();

std::string_view
devlink_eswitch_inline_mode_str(devlink_eswitch_inline_mode value)
{
	if (value < 0 || value >= (int)(devlink_eswitch_inline_mode_strmap.size())) {
		return "";
	}
	return devlink_eswitch_inline_mode_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> devlink_eswitch_encap_mode_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "none";
	arr[1] = "basic";
	return arr;
} ();

std::string_view
devlink_eswitch_encap_mode_str(devlink_eswitch_encap_mode value)
{
	if (value < 0 || value >= (int)(devlink_eswitch_encap_mode_strmap.size())) {
		return "";
	}
	return devlink_eswitch_encap_mode_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> devlink_dpipe_header_id_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "ethernet";
	arr[1] = "ipv4";
	arr[2] = "ipv6";
	return arr;
} ();

std::string_view devlink_dpipe_header_id_str(devlink_dpipe_header_id value)
{
	if (value < 0 || value >= (int)(devlink_dpipe_header_id_strmap.size())) {
		return "";
	}
	return devlink_dpipe_header_id_strmap[value];
}

static constexpr std::array<std::string_view, 0 + 1> devlink_dpipe_match_type_strmap = []() {
	std::array<std::string_view, 0 + 1> arr{};
	arr[0] = "field-exact";
	return arr;
} ();

std::string_view devlink_dpipe_match_type_str(devlink_dpipe_match_type value)
{
	if (value < 0 || value >= (int)(devlink_dpipe_match_type_strmap.size())) {
		return "";
	}
	return devlink_dpipe_match_type_strmap[value];
}

static constexpr std::array<std::string_view, 0 + 1> devlink_dpipe_action_type_strmap = []() {
	std::array<std::string_view, 0 + 1> arr{};
	arr[0] = "field-modify";
	return arr;
} ();

std::string_view devlink_dpipe_action_type_str(devlink_dpipe_action_type value)
{
	if (value < 0 || value >= (int)(devlink_dpipe_action_type_strmap.size())) {
		return "";
	}
	return devlink_dpipe_action_type_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> devlink_dpipe_field_mapping_type_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "none";
	arr[1] = "ifindex";
	return arr;
} ();

std::string_view
devlink_dpipe_field_mapping_type_str(devlink_dpipe_field_mapping_type value)
{
	if (value < 0 || value >= (int)(devlink_dpipe_field_mapping_type_strmap.size())) {
		return "";
	}
	return devlink_dpipe_field_mapping_type_strmap[value];
}

static constexpr std::array<std::string_view, 0 + 1> devlink_resource_unit_strmap = []() {
	std::array<std::string_view, 0 + 1> arr{};
	arr[0] = "entry";
	return arr;
} ();

std::string_view devlink_resource_unit_str(devlink_resource_unit value)
{
	if (value < 0 || value >= (int)(devlink_resource_unit_strmap.size())) {
		return "";
	}
	return devlink_resource_unit_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> devlink_reload_action_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[1] = "driver-reinit";
	arr[2] = "fw-activate";
	return arr;
} ();

std::string_view devlink_reload_action_str(devlink_reload_action value)
{
	if (value < 0 || value >= (int)(devlink_reload_action_strmap.size())) {
		return "";
	}
	return devlink_reload_action_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> devlink_param_cmode_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "runtime";
	arr[1] = "driverinit";
	arr[2] = "permanent";
	return arr;
} ();

std::string_view devlink_param_cmode_str(devlink_param_cmode value)
{
	if (value < 0 || value >= (int)(devlink_param_cmode_strmap.size())) {
		return "";
	}
	return devlink_param_cmode_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> devlink_flash_overwrite_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "settings-bit";
	arr[1] = "identifiers-bit";
	return arr;
} ();

std::string_view devlink_flash_overwrite_str(devlink_flash_overwrite value)
{
	if (value < 0 || value >= (int)(devlink_flash_overwrite_strmap.size())) {
		return "";
	}
	return devlink_flash_overwrite_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> devlink_trap_action_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "drop";
	arr[1] = "trap";
	arr[2] = "mirror";
	return arr;
} ();

std::string_view devlink_trap_action_str(devlink_trap_action value)
{
	if (value < 0 || value >= (int)(devlink_trap_action_strmap.size())) {
		return "";
	}
	return devlink_trap_action_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> devlink_trap_type_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "drop";
	arr[1] = "exception";
	arr[2] = "control";
	return arr;
} ();

std::string_view devlink_trap_type_str(devlink_trap_type value)
{
	if (value < 0 || value >= (int)(devlink_trap_type_strmap.size())) {
		return "";
	}
	return devlink_trap_type_strmap[value];
}

static constexpr std::array<std::string_view, 11 + 1> devlink_var_attr_type_strmap = []() {
	std::array<std::string_view, 11 + 1> arr{};
	arr[1] = "u8";
	arr[2] = "u16";
	arr[3] = "u32";
	arr[4] = "u64";
	arr[5] = "string";
	arr[6] = "flag";
	arr[10] = "nul-string";
	arr[11] = "binary";
	return arr;
} ();

std::string_view devlink_var_attr_type_str(devlink_var_attr_type value)
{
	if (value < 0 || value >= (int)(devlink_var_attr_type_strmap.size())) {
		return "";
	}
	return devlink_var_attr_type_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_match_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_MATCH_TYPE].name = "dpipe-match-type";
	arr[DEVLINK_ATTR_DPIPE_MATCH_TYPE].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_HEADER_ID].name = "dpipe-header-id";
	arr[DEVLINK_ATTR_DPIPE_HEADER_ID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL].name = "dpipe-header-global";
	arr[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_DPIPE_HEADER_INDEX].name = "dpipe-header-index";
	arr[DEVLINK_ATTR_DPIPE_HEADER_INDEX].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_FIELD_ID].name = "dpipe-field-id";
	arr[DEVLINK_ATTR_DPIPE_FIELD_ID].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_match_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_match_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_match_value_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_MATCH].name = "dpipe-match";
	arr[DEVLINK_ATTR_DPIPE_MATCH].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_MATCH].nest = &devlink_dl_dpipe_match_nest;
	arr[DEVLINK_ATTR_DPIPE_VALUE].name = "dpipe-value";
	arr[DEVLINK_ATTR_DPIPE_VALUE].type = YNL_PT_BINARY;
	arr[DEVLINK_ATTR_DPIPE_VALUE_MASK].name = "dpipe-value-mask";
	arr[DEVLINK_ATTR_DPIPE_VALUE_MASK].type = YNL_PT_BINARY;
	arr[DEVLINK_ATTR_DPIPE_VALUE_MAPPING].name = "dpipe-value-mapping";
	arr[DEVLINK_ATTR_DPIPE_VALUE_MAPPING].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_match_value_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_match_value_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_action_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_ACTION_TYPE].name = "dpipe-action-type";
	arr[DEVLINK_ATTR_DPIPE_ACTION_TYPE].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_HEADER_ID].name = "dpipe-header-id";
	arr[DEVLINK_ATTR_DPIPE_HEADER_ID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL].name = "dpipe-header-global";
	arr[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_DPIPE_HEADER_INDEX].name = "dpipe-header-index";
	arr[DEVLINK_ATTR_DPIPE_HEADER_INDEX].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_FIELD_ID].name = "dpipe-field-id";
	arr[DEVLINK_ATTR_DPIPE_FIELD_ID].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_action_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_action_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_action_value_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_ACTION].name = "dpipe-action";
	arr[DEVLINK_ATTR_DPIPE_ACTION].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ACTION].nest = &devlink_dl_dpipe_action_nest;
	arr[DEVLINK_ATTR_DPIPE_VALUE].name = "dpipe-value";
	arr[DEVLINK_ATTR_DPIPE_VALUE].type = YNL_PT_BINARY;
	arr[DEVLINK_ATTR_DPIPE_VALUE_MASK].name = "dpipe-value-mask";
	arr[DEVLINK_ATTR_DPIPE_VALUE_MASK].type = YNL_PT_BINARY;
	arr[DEVLINK_ATTR_DPIPE_VALUE_MAPPING].name = "dpipe-value-mapping";
	arr[DEVLINK_ATTR_DPIPE_VALUE_MAPPING].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_action_value_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_action_value_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_field_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_FIELD_NAME].name = "dpipe-field-name";
	arr[DEVLINK_ATTR_DPIPE_FIELD_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_DPIPE_FIELD_ID].name = "dpipe-field-id";
	arr[DEVLINK_ATTR_DPIPE_FIELD_ID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH].name = "dpipe-field-bitwidth";
	arr[DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE].name = "dpipe-field-mapping-type";
	arr[DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_field_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_field_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_resource_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_RESOURCE_NAME].name = "resource-name";
	arr[DEVLINK_ATTR_RESOURCE_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_RESOURCE_ID].name = "resource-id";
	arr[DEVLINK_ATTR_RESOURCE_ID].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE].name = "resource-size";
	arr[DEVLINK_ATTR_RESOURCE_SIZE].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_NEW].name = "resource-size-new";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_NEW].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_VALID].name = "resource-size-valid";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_VALID].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_MIN].name = "resource-size-min";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_MIN].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_MAX].name = "resource-size-max";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_MAX].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_GRAN].name = "resource-size-gran";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_GRAN].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_UNIT].name = "resource-unit";
	arr[DEVLINK_ATTR_RESOURCE_UNIT].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_RESOURCE_OCC].name = "resource-occ";
	arr[DEVLINK_ATTR_RESOURCE_OCC].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_resource_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_resource_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_param_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_PARAM_NAME].name = "param-name";
	arr[DEVLINK_ATTR_PARAM_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_PARAM_GENERIC].name = "param-generic";
	arr[DEVLINK_ATTR_PARAM_GENERIC].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_PARAM_TYPE].name = "param-type";
	arr[DEVLINK_ATTR_PARAM_TYPE].type = YNL_PT_U8;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_param_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_param_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_region_snapshot_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_REGION_SNAPSHOT_ID].name = "region-snapshot-id";
	arr[DEVLINK_ATTR_REGION_SNAPSHOT_ID].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_region_snapshot_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_region_snapshot_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_region_chunk_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_REGION_CHUNK_DATA].name = "region-chunk-data";
	arr[DEVLINK_ATTR_REGION_CHUNK_DATA].type = YNL_PT_BINARY;
	arr[DEVLINK_ATTR_REGION_CHUNK_ADDR].name = "region-chunk-addr";
	arr[DEVLINK_ATTR_REGION_CHUNK_ADDR].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_region_chunk_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_region_chunk_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_info_version_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_INFO_VERSION_NAME].name = "info-version-name";
	arr[DEVLINK_ATTR_INFO_VERSION_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_INFO_VERSION_VALUE].name = "info-version-value";
	arr[DEVLINK_ATTR_INFO_VERSION_VALUE].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_info_version_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_info_version_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_fmsg_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_FMSG_OBJ_NEST_START].name = "fmsg-obj-nest-start";
	arr[DEVLINK_ATTR_FMSG_OBJ_NEST_START].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_FMSG_PAIR_NEST_START].name = "fmsg-pair-nest-start";
	arr[DEVLINK_ATTR_FMSG_PAIR_NEST_START].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_FMSG_ARR_NEST_START].name = "fmsg-arr-nest-start";
	arr[DEVLINK_ATTR_FMSG_ARR_NEST_START].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_FMSG_NEST_END].name = "fmsg-nest-end";
	arr[DEVLINK_ATTR_FMSG_NEST_END].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_FMSG_OBJ_NAME].name = "fmsg-obj-name";
	arr[DEVLINK_ATTR_FMSG_OBJ_NAME].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_fmsg_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_fmsg_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_health_reporter_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_HEALTH_REPORTER_NAME].name = "health-reporter-name";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_STATE].name = "health-reporter-state";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_STATE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT].name = "health-reporter-err-count";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT].name = "health-reporter-recover-count";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD].name = "health-reporter-graceful-period";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER].name = "health-reporter-auto-recover";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS].name = "health-reporter-dump-ts";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS].name = "health-reporter-dump-ts-ns";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP].name = "health-reporter-auto-dump";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_BURST_PERIOD].name = "health-reporter-burst-period";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_BURST_PERIOD].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_health_reporter_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_health_reporter_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_attr_stats_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_STATS_RX_PACKETS].name = "stats-rx-packets";
	arr[DEVLINK_ATTR_STATS_RX_PACKETS].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_STATS_RX_BYTES].name = "stats-rx-bytes";
	arr[DEVLINK_ATTR_STATS_RX_BYTES].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_STATS_RX_DROPPED].name = "stats-rx-dropped";
	arr[DEVLINK_ATTR_STATS_RX_DROPPED].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_attr_stats_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_attr_stats_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_trap_metadata_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT].name = "trap-metadata-type-in-port";
	arr[DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_TRAP_METADATA_TYPE_FA_COOKIE].name = "trap-metadata-type-fa-cookie";
	arr[DEVLINK_ATTR_TRAP_METADATA_TYPE_FA_COOKIE].type = YNL_PT_FLAG;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_trap_metadata_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_trap_metadata_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_PORT_FUNCTION_ATTR_MAX + 1> devlink_dl_port_function_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_PORT_FUNCTION_ATTR_MAX + 1> arr{};
	arr[DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR].name = "hw-addr";
	arr[DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR].type = YNL_PT_BINARY;
	arr[DEVLINK_PORT_FN_ATTR_STATE].name = "state";
	arr[DEVLINK_PORT_FN_ATTR_STATE].type = YNL_PT_U8;
	arr[DEVLINK_PORT_FN_ATTR_OPSTATE].name = "opstate";
	arr[DEVLINK_PORT_FN_ATTR_OPSTATE].type = YNL_PT_U8;
	arr[DEVLINK_PORT_FN_ATTR_CAPS].name = "caps";
	arr[DEVLINK_PORT_FN_ATTR_CAPS].type = YNL_PT_BITFIELD32;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_port_function_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_PORT_FUNCTION_ATTR_MAX),
	.table = devlink_dl_port_function_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_reload_stats_entry_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_RELOAD_STATS_LIMIT].name = "reload-stats-limit";
	arr[DEVLINK_ATTR_RELOAD_STATS_LIMIT].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_RELOAD_STATS_VALUE].name = "reload-stats-value";
	arr[DEVLINK_ATTR_RELOAD_STATS_VALUE].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_reload_stats_entry_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_reload_stats_entry_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_reload_act_stats_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_RELOAD_STATS_ENTRY].name = "reload-stats-entry";
	arr[DEVLINK_ATTR_RELOAD_STATS_ENTRY].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RELOAD_STATS_ENTRY].nest = &devlink_dl_reload_stats_entry_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_reload_act_stats_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_reload_act_stats_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_linecard_supported_types_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_LINECARD_TYPE].name = "linecard-type";
	arr[DEVLINK_ATTR_LINECARD_TYPE].type  = YNL_PT_NUL_STR;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_linecard_supported_types_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_linecard_supported_types_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_SELFTEST_ID_MAX + 1> devlink_dl_selftest_id_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_SELFTEST_ID_MAX + 1> arr{};
	arr[DEVLINK_ATTR_SELFTEST_ID_FLASH].name = "flash";
	arr[DEVLINK_ATTR_SELFTEST_ID_FLASH].type = YNL_PT_FLAG;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_selftest_id_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_SELFTEST_ID_MAX),
	.table = devlink_dl_selftest_id_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_RATE_TC_ATTR_MAX + 1> devlink_dl_rate_tc_bws_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_RATE_TC_ATTR_MAX + 1> arr{};
	arr[DEVLINK_RATE_TC_ATTR_INDEX].name = "index";
	arr[DEVLINK_RATE_TC_ATTR_INDEX].type = YNL_PT_U8;
	arr[DEVLINK_RATE_TC_ATTR_BW].name = "bw";
	arr[DEVLINK_RATE_TC_ATTR_BW].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_rate_tc_bws_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_RATE_TC_ATTR_MAX),
	.table = devlink_dl_rate_tc_bws_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_table_matches_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_MATCH].name = "dpipe-match";
	arr[DEVLINK_ATTR_DPIPE_MATCH].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_MATCH].nest = &devlink_dl_dpipe_match_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_table_matches_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_table_matches_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_table_actions_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_ACTION].name = "dpipe-action";
	arr[DEVLINK_ATTR_DPIPE_ACTION].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ACTION].nest = &devlink_dl_dpipe_action_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_table_actions_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_table_actions_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_entry_match_values_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_MATCH_VALUE].name = "dpipe-match-value";
	arr[DEVLINK_ATTR_DPIPE_MATCH_VALUE].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_MATCH_VALUE].nest = &devlink_dl_dpipe_match_value_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_entry_match_values_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_entry_match_values_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_entry_action_values_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_ACTION_VALUE].name = "dpipe-action-value";
	arr[DEVLINK_ATTR_DPIPE_ACTION_VALUE].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ACTION_VALUE].nest = &devlink_dl_dpipe_action_value_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_entry_action_values_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_entry_action_values_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_header_fields_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_FIELD].name = "dpipe-field";
	arr[DEVLINK_ATTR_DPIPE_FIELD].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_FIELD].nest = &devlink_dl_dpipe_field_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_header_fields_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_header_fields_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_resource_list_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_RESOURCE].name = "resource";
	arr[DEVLINK_ATTR_RESOURCE].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RESOURCE].nest = &devlink_dl_resource_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_resource_list_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_resource_list_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_region_snapshots_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_REGION_SNAPSHOT].name = "region-snapshot";
	arr[DEVLINK_ATTR_REGION_SNAPSHOT].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_REGION_SNAPSHOT].nest = &devlink_dl_region_snapshot_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_region_snapshots_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_region_snapshots_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_region_chunks_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_REGION_CHUNK].name = "region-chunk";
	arr[DEVLINK_ATTR_REGION_CHUNK].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_REGION_CHUNK].nest = &devlink_dl_region_chunk_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_region_chunks_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_region_chunks_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_reload_act_info_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_RELOAD_ACTION].name = "reload-action";
	arr[DEVLINK_ATTR_RELOAD_ACTION].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_RELOAD_ACTION_STATS].name = "reload-action-stats";
	arr[DEVLINK_ATTR_RELOAD_ACTION_STATS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RELOAD_ACTION_STATS].nest = &devlink_dl_reload_act_stats_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_reload_act_info_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_reload_act_info_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_table_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_TABLE_NAME].name = "dpipe-table-name";
	arr[DEVLINK_ATTR_DPIPE_TABLE_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_DPIPE_TABLE_SIZE].name = "dpipe-table-size";
	arr[DEVLINK_ATTR_DPIPE_TABLE_SIZE].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_DPIPE_TABLE_MATCHES].name = "dpipe-table-matches";
	arr[DEVLINK_ATTR_DPIPE_TABLE_MATCHES].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_TABLE_MATCHES].nest = &devlink_dl_dpipe_table_matches_nest;
	arr[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS].name = "dpipe-table-actions";
	arr[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS].nest = &devlink_dl_dpipe_table_actions_nest;
	arr[DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED].name = "dpipe-table-counters-enabled";
	arr[DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID].name = "dpipe-table-resource-id";
	arr[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS].name = "dpipe-table-resource-units";
	arr[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_table_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_table_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_entry_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_ENTRY_INDEX].name = "dpipe-entry-index";
	arr[DEVLINK_ATTR_DPIPE_ENTRY_INDEX].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES].name = "dpipe-entry-match-values";
	arr[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES].nest = &devlink_dl_dpipe_entry_match_values_nest;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES].name = "dpipe-entry-action-values";
	arr[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES].nest = &devlink_dl_dpipe_entry_action_values_nest;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_COUNTER].name = "dpipe-entry-counter";
	arr[DEVLINK_ATTR_DPIPE_ENTRY_COUNTER].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_entry_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_entry_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_header_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_HEADER_NAME].name = "dpipe-header-name";
	arr[DEVLINK_ATTR_DPIPE_HEADER_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_DPIPE_HEADER_ID].name = "dpipe-header-id";
	arr[DEVLINK_ATTR_DPIPE_HEADER_ID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL].name = "dpipe-header-global";
	arr[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_DPIPE_HEADER_FIELDS].name = "dpipe-header-fields";
	arr[DEVLINK_ATTR_DPIPE_HEADER_FIELDS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_HEADER_FIELDS].nest = &devlink_dl_dpipe_header_fields_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_header_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_header_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_reload_stats_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_RELOAD_ACTION_INFO].name = "reload-action-info";
	arr[DEVLINK_ATTR_RELOAD_ACTION_INFO].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RELOAD_ACTION_INFO].nest = &devlink_dl_reload_act_info_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_reload_stats_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_reload_stats_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_tables_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_TABLE].name = "dpipe-table";
	arr[DEVLINK_ATTR_DPIPE_TABLE].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_TABLE].nest = &devlink_dl_dpipe_table_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_tables_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_tables_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_entries_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_ENTRY].name = "dpipe-entry";
	arr[DEVLINK_ATTR_DPIPE_ENTRY].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ENTRY].nest = &devlink_dl_dpipe_entry_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_entries_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_entries_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dpipe_headers_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_DPIPE_HEADER].name = "dpipe-header";
	arr[DEVLINK_ATTR_DPIPE_HEADER].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_HEADER].nest = &devlink_dl_dpipe_header_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dpipe_headers_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dpipe_headers_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_dl_dev_stats_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_RELOAD_STATS].name = "reload-stats";
	arr[DEVLINK_ATTR_RELOAD_STATS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RELOAD_STATS].nest = &devlink_dl_reload_stats_nest;
	arr[DEVLINK_ATTR_REMOTE_RELOAD_STATS].name = "remote-reload-stats";
	arr[DEVLINK_ATTR_REMOTE_RELOAD_STATS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_REMOTE_RELOAD_STATS].nest = &devlink_dl_reload_stats_nest;
	return arr;
} ();

struct ynl_policy_nest devlink_dl_dev_stats_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_dl_dev_stats_policy.data(),
};

static std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> devlink_policy = []() {
	std::array<ynl_policy_attr,DEVLINK_ATTR_MAX + 1> arr{};
	arr[DEVLINK_ATTR_BUS_NAME].name = "bus-name";
	arr[DEVLINK_ATTR_BUS_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_DEV_NAME].name = "dev-name";
	arr[DEVLINK_ATTR_DEV_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_PORT_INDEX].name = "port-index";
	arr[DEVLINK_ATTR_PORT_INDEX].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_PORT_TYPE].name = "port-type";
	arr[DEVLINK_ATTR_PORT_TYPE].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_PORT_DESIRED_TYPE].name = "port-desired-type";
	arr[DEVLINK_ATTR_PORT_DESIRED_TYPE].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_PORT_NETDEV_IFINDEX].name = "port-netdev-ifindex";
	arr[DEVLINK_ATTR_PORT_NETDEV_IFINDEX].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_PORT_NETDEV_NAME].name = "port-netdev-name";
	arr[DEVLINK_ATTR_PORT_NETDEV_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_PORT_IBDEV_NAME].name = "port-ibdev-name";
	arr[DEVLINK_ATTR_PORT_IBDEV_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_PORT_SPLIT_COUNT].name = "port-split-count";
	arr[DEVLINK_ATTR_PORT_SPLIT_COUNT].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_PORT_SPLIT_GROUP].name = "port-split-group";
	arr[DEVLINK_ATTR_PORT_SPLIT_GROUP].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_SB_INDEX].name = "sb-index";
	arr[DEVLINK_ATTR_SB_INDEX].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_SB_SIZE].name = "sb-size";
	arr[DEVLINK_ATTR_SB_SIZE].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_SB_INGRESS_POOL_COUNT].name = "sb-ingress-pool-count";
	arr[DEVLINK_ATTR_SB_INGRESS_POOL_COUNT].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_SB_EGRESS_POOL_COUNT].name = "sb-egress-pool-count";
	arr[DEVLINK_ATTR_SB_EGRESS_POOL_COUNT].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_SB_INGRESS_TC_COUNT].name = "sb-ingress-tc-count";
	arr[DEVLINK_ATTR_SB_INGRESS_TC_COUNT].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_SB_EGRESS_TC_COUNT].name = "sb-egress-tc-count";
	arr[DEVLINK_ATTR_SB_EGRESS_TC_COUNT].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_SB_POOL_INDEX].name = "sb-pool-index";
	arr[DEVLINK_ATTR_SB_POOL_INDEX].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_SB_POOL_TYPE].name = "sb-pool-type";
	arr[DEVLINK_ATTR_SB_POOL_TYPE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_SB_POOL_SIZE].name = "sb-pool-size";
	arr[DEVLINK_ATTR_SB_POOL_SIZE].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE].name = "sb-pool-threshold-type";
	arr[DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_SB_THRESHOLD].name = "sb-threshold";
	arr[DEVLINK_ATTR_SB_THRESHOLD].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_SB_TC_INDEX].name = "sb-tc-index";
	arr[DEVLINK_ATTR_SB_TC_INDEX].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_SB_OCC_CUR].name = "sb-occ-cur";
	arr[DEVLINK_ATTR_SB_OCC_CUR].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_SB_OCC_MAX].name = "sb-occ-max";
	arr[DEVLINK_ATTR_SB_OCC_MAX].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_ESWITCH_MODE].name = "eswitch-mode";
	arr[DEVLINK_ATTR_ESWITCH_MODE].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_ESWITCH_INLINE_MODE].name = "eswitch-inline-mode";
	arr[DEVLINK_ATTR_ESWITCH_INLINE_MODE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_DPIPE_TABLES].name = "dpipe-tables";
	arr[DEVLINK_ATTR_DPIPE_TABLES].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_TABLES].nest = &devlink_dl_dpipe_tables_nest;
	arr[DEVLINK_ATTR_DPIPE_TABLE].name = "dpipe-table";
	arr[DEVLINK_ATTR_DPIPE_TABLE].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_TABLE].nest = &devlink_dl_dpipe_table_nest;
	arr[DEVLINK_ATTR_DPIPE_TABLE_NAME].name = "dpipe-table-name";
	arr[DEVLINK_ATTR_DPIPE_TABLE_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_DPIPE_TABLE_SIZE].name = "dpipe-table-size";
	arr[DEVLINK_ATTR_DPIPE_TABLE_SIZE].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_DPIPE_TABLE_MATCHES].name = "dpipe-table-matches";
	arr[DEVLINK_ATTR_DPIPE_TABLE_MATCHES].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_TABLE_MATCHES].nest = &devlink_dl_dpipe_table_matches_nest;
	arr[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS].name = "dpipe-table-actions";
	arr[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS].nest = &devlink_dl_dpipe_table_actions_nest;
	arr[DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED].name = "dpipe-table-counters-enabled";
	arr[DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_DPIPE_ENTRIES].name = "dpipe-entries";
	arr[DEVLINK_ATTR_DPIPE_ENTRIES].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ENTRIES].nest = &devlink_dl_dpipe_entries_nest;
	arr[DEVLINK_ATTR_DPIPE_ENTRY].name = "dpipe-entry";
	arr[DEVLINK_ATTR_DPIPE_ENTRY].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ENTRY].nest = &devlink_dl_dpipe_entry_nest;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_INDEX].name = "dpipe-entry-index";
	arr[DEVLINK_ATTR_DPIPE_ENTRY_INDEX].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES].name = "dpipe-entry-match-values";
	arr[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES].nest = &devlink_dl_dpipe_entry_match_values_nest;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES].name = "dpipe-entry-action-values";
	arr[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES].nest = &devlink_dl_dpipe_entry_action_values_nest;
	arr[DEVLINK_ATTR_DPIPE_ENTRY_COUNTER].name = "dpipe-entry-counter";
	arr[DEVLINK_ATTR_DPIPE_ENTRY_COUNTER].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_DPIPE_MATCH].name = "dpipe-match";
	arr[DEVLINK_ATTR_DPIPE_MATCH].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_MATCH].nest = &devlink_dl_dpipe_match_nest;
	arr[DEVLINK_ATTR_DPIPE_MATCH_VALUE].name = "dpipe-match-value";
	arr[DEVLINK_ATTR_DPIPE_MATCH_VALUE].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_MATCH_VALUE].nest = &devlink_dl_dpipe_match_value_nest;
	arr[DEVLINK_ATTR_DPIPE_MATCH_TYPE].name = "dpipe-match-type";
	arr[DEVLINK_ATTR_DPIPE_MATCH_TYPE].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_ACTION].name = "dpipe-action";
	arr[DEVLINK_ATTR_DPIPE_ACTION].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ACTION].nest = &devlink_dl_dpipe_action_nest;
	arr[DEVLINK_ATTR_DPIPE_ACTION_VALUE].name = "dpipe-action-value";
	arr[DEVLINK_ATTR_DPIPE_ACTION_VALUE].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_ACTION_VALUE].nest = &devlink_dl_dpipe_action_value_nest;
	arr[DEVLINK_ATTR_DPIPE_ACTION_TYPE].name = "dpipe-action-type";
	arr[DEVLINK_ATTR_DPIPE_ACTION_TYPE].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_VALUE].name = "dpipe-value";
	arr[DEVLINK_ATTR_DPIPE_VALUE].type = YNL_PT_BINARY;
	arr[DEVLINK_ATTR_DPIPE_VALUE_MASK].name = "dpipe-value-mask";
	arr[DEVLINK_ATTR_DPIPE_VALUE_MASK].type = YNL_PT_BINARY;
	arr[DEVLINK_ATTR_DPIPE_VALUE_MAPPING].name = "dpipe-value-mapping";
	arr[DEVLINK_ATTR_DPIPE_VALUE_MAPPING].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_HEADERS].name = "dpipe-headers";
	arr[DEVLINK_ATTR_DPIPE_HEADERS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_HEADERS].nest = &devlink_dl_dpipe_headers_nest;
	arr[DEVLINK_ATTR_DPIPE_HEADER].name = "dpipe-header";
	arr[DEVLINK_ATTR_DPIPE_HEADER].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_HEADER].nest = &devlink_dl_dpipe_header_nest;
	arr[DEVLINK_ATTR_DPIPE_HEADER_NAME].name = "dpipe-header-name";
	arr[DEVLINK_ATTR_DPIPE_HEADER_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_DPIPE_HEADER_ID].name = "dpipe-header-id";
	arr[DEVLINK_ATTR_DPIPE_HEADER_ID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_HEADER_FIELDS].name = "dpipe-header-fields";
	arr[DEVLINK_ATTR_DPIPE_HEADER_FIELDS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_HEADER_FIELDS].nest = &devlink_dl_dpipe_header_fields_nest;
	arr[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL].name = "dpipe-header-global";
	arr[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_DPIPE_HEADER_INDEX].name = "dpipe-header-index";
	arr[DEVLINK_ATTR_DPIPE_HEADER_INDEX].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_FIELD].name = "dpipe-field";
	arr[DEVLINK_ATTR_DPIPE_FIELD].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DPIPE_FIELD].nest = &devlink_dl_dpipe_field_nest;
	arr[DEVLINK_ATTR_DPIPE_FIELD_NAME].name = "dpipe-field-name";
	arr[DEVLINK_ATTR_DPIPE_FIELD_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_DPIPE_FIELD_ID].name = "dpipe-field-id";
	arr[DEVLINK_ATTR_DPIPE_FIELD_ID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH].name = "dpipe-field-bitwidth";
	arr[DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE].name = "dpipe-field-mapping-type";
	arr[DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_PAD].name = "pad";
	arr[DEVLINK_ATTR_PAD].type = YNL_PT_IGNORE;
	arr[DEVLINK_ATTR_ESWITCH_ENCAP_MODE].name = "eswitch-encap-mode";
	arr[DEVLINK_ATTR_ESWITCH_ENCAP_MODE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_RESOURCE_LIST].name = "resource-list";
	arr[DEVLINK_ATTR_RESOURCE_LIST].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RESOURCE_LIST].nest = &devlink_dl_resource_list_nest;
	arr[DEVLINK_ATTR_RESOURCE].name = "resource";
	arr[DEVLINK_ATTR_RESOURCE].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RESOURCE].nest = &devlink_dl_resource_nest;
	arr[DEVLINK_ATTR_RESOURCE_NAME].name = "resource-name";
	arr[DEVLINK_ATTR_RESOURCE_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_RESOURCE_ID].name = "resource-id";
	arr[DEVLINK_ATTR_RESOURCE_ID].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE].name = "resource-size";
	arr[DEVLINK_ATTR_RESOURCE_SIZE].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_NEW].name = "resource-size-new";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_NEW].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_VALID].name = "resource-size-valid";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_VALID].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_MIN].name = "resource-size-min";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_MIN].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_MAX].name = "resource-size-max";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_MAX].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_SIZE_GRAN].name = "resource-size-gran";
	arr[DEVLINK_ATTR_RESOURCE_SIZE_GRAN].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RESOURCE_UNIT].name = "resource-unit";
	arr[DEVLINK_ATTR_RESOURCE_UNIT].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_RESOURCE_OCC].name = "resource-occ";
	arr[DEVLINK_ATTR_RESOURCE_OCC].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID].name = "dpipe-table-resource-id";
	arr[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS].name = "dpipe-table-resource-units";
	arr[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_PORT_FLAVOUR].name = "port-flavour";
	arr[DEVLINK_ATTR_PORT_FLAVOUR].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_PORT_NUMBER].name = "port-number";
	arr[DEVLINK_ATTR_PORT_NUMBER].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER].name = "port-split-subport-number";
	arr[DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_PARAM].name = "param";
	arr[DEVLINK_ATTR_PARAM].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_PARAM].nest = &devlink_dl_param_nest;
	arr[DEVLINK_ATTR_PARAM_NAME].name = "param-name";
	arr[DEVLINK_ATTR_PARAM_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_PARAM_GENERIC].name = "param-generic";
	arr[DEVLINK_ATTR_PARAM_GENERIC].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_PARAM_TYPE].name = "param-type";
	arr[DEVLINK_ATTR_PARAM_TYPE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_PARAM_VALUE_CMODE].name = "param-value-cmode";
	arr[DEVLINK_ATTR_PARAM_VALUE_CMODE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_REGION_NAME].name = "region-name";
	arr[DEVLINK_ATTR_REGION_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_REGION_SIZE].name = "region-size";
	arr[DEVLINK_ATTR_REGION_SIZE].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_REGION_SNAPSHOTS].name = "region-snapshots";
	arr[DEVLINK_ATTR_REGION_SNAPSHOTS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_REGION_SNAPSHOTS].nest = &devlink_dl_region_snapshots_nest;
	arr[DEVLINK_ATTR_REGION_SNAPSHOT].name = "region-snapshot";
	arr[DEVLINK_ATTR_REGION_SNAPSHOT].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_REGION_SNAPSHOT].nest = &devlink_dl_region_snapshot_nest;
	arr[DEVLINK_ATTR_REGION_SNAPSHOT_ID].name = "region-snapshot-id";
	arr[DEVLINK_ATTR_REGION_SNAPSHOT_ID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_REGION_CHUNKS].name = "region-chunks";
	arr[DEVLINK_ATTR_REGION_CHUNKS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_REGION_CHUNKS].nest = &devlink_dl_region_chunks_nest;
	arr[DEVLINK_ATTR_REGION_CHUNK].name = "region-chunk";
	arr[DEVLINK_ATTR_REGION_CHUNK].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_REGION_CHUNK].nest = &devlink_dl_region_chunk_nest;
	arr[DEVLINK_ATTR_REGION_CHUNK_DATA].name = "region-chunk-data";
	arr[DEVLINK_ATTR_REGION_CHUNK_DATA].type = YNL_PT_BINARY;
	arr[DEVLINK_ATTR_REGION_CHUNK_ADDR].name = "region-chunk-addr";
	arr[DEVLINK_ATTR_REGION_CHUNK_ADDR].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_REGION_CHUNK_LEN].name = "region-chunk-len";
	arr[DEVLINK_ATTR_REGION_CHUNK_LEN].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_INFO_DRIVER_NAME].name = "info-driver-name";
	arr[DEVLINK_ATTR_INFO_DRIVER_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_INFO_SERIAL_NUMBER].name = "info-serial-number";
	arr[DEVLINK_ATTR_INFO_SERIAL_NUMBER].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_INFO_VERSION_FIXED].name = "info-version-fixed";
	arr[DEVLINK_ATTR_INFO_VERSION_FIXED].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_INFO_VERSION_FIXED].nest = &devlink_dl_info_version_nest;
	arr[DEVLINK_ATTR_INFO_VERSION_RUNNING].name = "info-version-running";
	arr[DEVLINK_ATTR_INFO_VERSION_RUNNING].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_INFO_VERSION_RUNNING].nest = &devlink_dl_info_version_nest;
	arr[DEVLINK_ATTR_INFO_VERSION_STORED].name = "info-version-stored";
	arr[DEVLINK_ATTR_INFO_VERSION_STORED].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_INFO_VERSION_STORED].nest = &devlink_dl_info_version_nest;
	arr[DEVLINK_ATTR_INFO_VERSION_NAME].name = "info-version-name";
	arr[DEVLINK_ATTR_INFO_VERSION_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_INFO_VERSION_VALUE].name = "info-version-value";
	arr[DEVLINK_ATTR_INFO_VERSION_VALUE].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_SB_POOL_CELL_SIZE].name = "sb-pool-cell-size";
	arr[DEVLINK_ATTR_SB_POOL_CELL_SIZE].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_FMSG].name = "fmsg";
	arr[DEVLINK_ATTR_FMSG].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_FMSG].nest = &devlink_dl_fmsg_nest;
	arr[DEVLINK_ATTR_FMSG_OBJ_NEST_START].name = "fmsg-obj-nest-start";
	arr[DEVLINK_ATTR_FMSG_OBJ_NEST_START].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_FMSG_PAIR_NEST_START].name = "fmsg-pair-nest-start";
	arr[DEVLINK_ATTR_FMSG_PAIR_NEST_START].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_FMSG_ARR_NEST_START].name = "fmsg-arr-nest-start";
	arr[DEVLINK_ATTR_FMSG_ARR_NEST_START].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_FMSG_NEST_END].name = "fmsg-nest-end";
	arr[DEVLINK_ATTR_FMSG_NEST_END].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_FMSG_OBJ_NAME].name = "fmsg-obj-name";
	arr[DEVLINK_ATTR_FMSG_OBJ_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE].name = "fmsg-obj-value-type";
	arr[DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_HEALTH_REPORTER].name = "health-reporter";
	arr[DEVLINK_ATTR_HEALTH_REPORTER].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_HEALTH_REPORTER].nest = &devlink_dl_health_reporter_nest;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_NAME].name = "health-reporter-name";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_STATE].name = "health-reporter-state";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_STATE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT].name = "health-reporter-err-count";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT].name = "health-reporter-recover-count";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS].name = "health-reporter-dump-ts";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD].name = "health-reporter-graceful-period";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER].name = "health-reporter-auto-recover";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME].name = "flash-update-file-name";
	arr[DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_FLASH_UPDATE_COMPONENT].name = "flash-update-component";
	arr[DEVLINK_ATTR_FLASH_UPDATE_COMPONENT].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG].name = "flash-update-status-msg";
	arr[DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE].name = "flash-update-status-done";
	arr[DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL].name = "flash-update-status-total";
	arr[DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_PORT_PCI_PF_NUMBER].name = "port-pci-pf-number";
	arr[DEVLINK_ATTR_PORT_PCI_PF_NUMBER].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_PORT_PCI_VF_NUMBER].name = "port-pci-vf-number";
	arr[DEVLINK_ATTR_PORT_PCI_VF_NUMBER].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_STATS].name = "stats";
	arr[DEVLINK_ATTR_STATS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_STATS].nest = &devlink_dl_attr_stats_nest;
	arr[DEVLINK_ATTR_TRAP_NAME].name = "trap-name";
	arr[DEVLINK_ATTR_TRAP_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_TRAP_ACTION].name = "trap-action";
	arr[DEVLINK_ATTR_TRAP_ACTION].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_TRAP_TYPE].name = "trap-type";
	arr[DEVLINK_ATTR_TRAP_TYPE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_TRAP_GENERIC].name = "trap-generic";
	arr[DEVLINK_ATTR_TRAP_GENERIC].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_TRAP_METADATA].name = "trap-metadata";
	arr[DEVLINK_ATTR_TRAP_METADATA].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_TRAP_METADATA].nest = &devlink_dl_trap_metadata_nest;
	arr[DEVLINK_ATTR_TRAP_GROUP_NAME].name = "trap-group-name";
	arr[DEVLINK_ATTR_TRAP_GROUP_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_RELOAD_FAILED].name = "reload-failed";
	arr[DEVLINK_ATTR_RELOAD_FAILED].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS].name = "health-reporter-dump-ts-ns";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_NETNS_FD].name = "netns-fd";
	arr[DEVLINK_ATTR_NETNS_FD].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_NETNS_PID].name = "netns-pid";
	arr[DEVLINK_ATTR_NETNS_PID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_NETNS_ID].name = "netns-id";
	arr[DEVLINK_ATTR_NETNS_ID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP].name = "health-reporter-auto-dump";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_TRAP_POLICER_ID].name = "trap-policer-id";
	arr[DEVLINK_ATTR_TRAP_POLICER_ID].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_TRAP_POLICER_RATE].name = "trap-policer-rate";
	arr[DEVLINK_ATTR_TRAP_POLICER_RATE].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_TRAP_POLICER_BURST].name = "trap-policer-burst";
	arr[DEVLINK_ATTR_TRAP_POLICER_BURST].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_PORT_FUNCTION].name = "port-function";
	arr[DEVLINK_ATTR_PORT_FUNCTION].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_PORT_FUNCTION].nest = &devlink_dl_port_function_nest;
	arr[DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER].name = "info-board-serial-number";
	arr[DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_PORT_LANES].name = "port-lanes";
	arr[DEVLINK_ATTR_PORT_LANES].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_PORT_SPLITTABLE].name = "port-splittable";
	arr[DEVLINK_ATTR_PORT_SPLITTABLE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_PORT_EXTERNAL].name = "port-external";
	arr[DEVLINK_ATTR_PORT_EXTERNAL].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_PORT_CONTROLLER_NUMBER].name = "port-controller-number";
	arr[DEVLINK_ATTR_PORT_CONTROLLER_NUMBER].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT].name = "flash-update-status-timeout";
	arr[DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK].name = "flash-update-overwrite-mask";
	arr[DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK].type = YNL_PT_BITFIELD32;
	arr[DEVLINK_ATTR_RELOAD_ACTION].name = "reload-action";
	arr[DEVLINK_ATTR_RELOAD_ACTION].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED].name = "reload-actions-performed";
	arr[DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED].type = YNL_PT_BITFIELD32;
	arr[DEVLINK_ATTR_RELOAD_LIMITS].name = "reload-limits";
	arr[DEVLINK_ATTR_RELOAD_LIMITS].type = YNL_PT_BITFIELD32;
	arr[DEVLINK_ATTR_DEV_STATS].name = "dev-stats";
	arr[DEVLINK_ATTR_DEV_STATS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_DEV_STATS].nest = &devlink_dl_dev_stats_nest;
	arr[DEVLINK_ATTR_RELOAD_STATS].name = "reload-stats";
	arr[DEVLINK_ATTR_RELOAD_STATS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RELOAD_STATS].nest = &devlink_dl_reload_stats_nest;
	arr[DEVLINK_ATTR_RELOAD_STATS_ENTRY].name = "reload-stats-entry";
	arr[DEVLINK_ATTR_RELOAD_STATS_ENTRY].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RELOAD_STATS_ENTRY].nest = &devlink_dl_reload_stats_entry_nest;
	arr[DEVLINK_ATTR_RELOAD_STATS_LIMIT].name = "reload-stats-limit";
	arr[DEVLINK_ATTR_RELOAD_STATS_LIMIT].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_RELOAD_STATS_VALUE].name = "reload-stats-value";
	arr[DEVLINK_ATTR_RELOAD_STATS_VALUE].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_REMOTE_RELOAD_STATS].name = "remote-reload-stats";
	arr[DEVLINK_ATTR_REMOTE_RELOAD_STATS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_REMOTE_RELOAD_STATS].nest = &devlink_dl_reload_stats_nest;
	arr[DEVLINK_ATTR_RELOAD_ACTION_INFO].name = "reload-action-info";
	arr[DEVLINK_ATTR_RELOAD_ACTION_INFO].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RELOAD_ACTION_INFO].nest = &devlink_dl_reload_act_info_nest;
	arr[DEVLINK_ATTR_RELOAD_ACTION_STATS].name = "reload-action-stats";
	arr[DEVLINK_ATTR_RELOAD_ACTION_STATS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RELOAD_ACTION_STATS].nest = &devlink_dl_reload_act_stats_nest;
	arr[DEVLINK_ATTR_PORT_PCI_SF_NUMBER].name = "port-pci-sf-number";
	arr[DEVLINK_ATTR_PORT_PCI_SF_NUMBER].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_RATE_TYPE].name = "rate-type";
	arr[DEVLINK_ATTR_RATE_TYPE].type = YNL_PT_U16;
	arr[DEVLINK_ATTR_RATE_TX_SHARE].name = "rate-tx-share";
	arr[DEVLINK_ATTR_RATE_TX_SHARE].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RATE_TX_MAX].name = "rate-tx-max";
	arr[DEVLINK_ATTR_RATE_TX_MAX].type = YNL_PT_U64;
	arr[DEVLINK_ATTR_RATE_NODE_NAME].name = "rate-node-name";
	arr[DEVLINK_ATTR_RATE_NODE_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_RATE_PARENT_NODE_NAME].name = "rate-parent-node-name";
	arr[DEVLINK_ATTR_RATE_PARENT_NODE_NAME].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_REGION_MAX_SNAPSHOTS].name = "region-max-snapshots";
	arr[DEVLINK_ATTR_REGION_MAX_SNAPSHOTS].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_LINECARD_INDEX].name = "linecard-index";
	arr[DEVLINK_ATTR_LINECARD_INDEX].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_LINECARD_STATE].name = "linecard-state";
	arr[DEVLINK_ATTR_LINECARD_STATE].type = YNL_PT_U8;
	arr[DEVLINK_ATTR_LINECARD_TYPE].name = "linecard-type";
	arr[DEVLINK_ATTR_LINECARD_TYPE].type  = YNL_PT_NUL_STR;
	arr[DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES].name = "linecard-supported-types";
	arr[DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES].nest = &devlink_dl_linecard_supported_types_nest;
	arr[DEVLINK_ATTR_SELFTESTS].name = "selftests";
	arr[DEVLINK_ATTR_SELFTESTS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_SELFTESTS].nest = &devlink_dl_selftest_id_nest;
	arr[DEVLINK_ATTR_RATE_TX_PRIORITY].name = "rate-tx-priority";
	arr[DEVLINK_ATTR_RATE_TX_PRIORITY].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_RATE_TX_WEIGHT].name = "rate-tx-weight";
	arr[DEVLINK_ATTR_RATE_TX_WEIGHT].type = YNL_PT_U32;
	arr[DEVLINK_ATTR_REGION_DIRECT].name = "region-direct";
	arr[DEVLINK_ATTR_REGION_DIRECT].type = YNL_PT_FLAG;
	arr[DEVLINK_ATTR_RATE_TC_BWS].name = "rate-tc-bws";
	arr[DEVLINK_ATTR_RATE_TC_BWS].type = YNL_PT_NEST;
	arr[DEVLINK_ATTR_RATE_TC_BWS].nest = &devlink_dl_rate_tc_bws_nest;
	arr[DEVLINK_ATTR_HEALTH_REPORTER_BURST_PERIOD].name = "health-reporter-burst-period";
	arr[DEVLINK_ATTR_HEALTH_REPORTER_BURST_PERIOD].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest devlink_nest = {
	.max_attr = static_cast<unsigned int>(DEVLINK_ATTR_MAX),
	.table = devlink_policy.data(),
};

/* Common nested types */
int devlink_dl_dpipe_match_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	devlink_dl_dpipe_match *dst = (devlink_dl_dpipe_match *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_MATCH_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_match_type = (enum devlink_dpipe_match_type)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_header_id = (enum devlink_dpipe_header_id)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_GLOBAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_header_global = (__u8)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_header_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_field_id = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int devlink_dl_dpipe_match_value_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	devlink_dl_dpipe_match_value *dst = (devlink_dl_dpipe_match_value *)yarg->data;
	unsigned int n_dpipe_match = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_match.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-match-value.dpipe-match)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_MATCH) {
			n_dpipe_match++;
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->dpipe_value.assign(data, data + len);
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->dpipe_value_mask.assign(data, data + len);
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE_MAPPING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_value_mapping = (__u32)ynl_attr_get_u32(attr);
		}
	}

	if (n_dpipe_match) {
		dst->dpipe_match.resize(n_dpipe_match);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_match_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_MATCH) {
				parg.data = &dst->dpipe_match[i];
				if (devlink_dl_dpipe_match_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_action_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	devlink_dl_dpipe_action *dst = (devlink_dl_dpipe_action *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ACTION_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_action_type = (enum devlink_dpipe_action_type)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_header_id = (enum devlink_dpipe_header_id)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_GLOBAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_header_global = (__u8)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_header_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_field_id = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int devlink_dl_dpipe_action_value_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	devlink_dl_dpipe_action_value *dst = (devlink_dl_dpipe_action_value *)yarg->data;
	unsigned int n_dpipe_action = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_action.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-action-value.dpipe-action)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ACTION) {
			n_dpipe_action++;
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->dpipe_value.assign(data, data + len);
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->dpipe_value_mask.assign(data, data + len);
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE_MAPPING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_value_mapping = (__u32)ynl_attr_get_u32(attr);
		}
	}

	if (n_dpipe_action) {
		dst->dpipe_action.resize(n_dpipe_action);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_action_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_ACTION) {
				parg.data = &dst->dpipe_action[i];
				if (devlink_dl_dpipe_action_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_field_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	devlink_dl_dpipe_field *dst = (devlink_dl_dpipe_field *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_FIELD_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_field_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_field_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_field_bitwidth = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_field_mapping_type = (enum devlink_dpipe_field_mapping_type)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int devlink_dl_resource_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	devlink_dl_resource *dst = (devlink_dl_resource *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RESOURCE_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_RESOURCE_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_id = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_size = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_NEW) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_size_new = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_VALID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_size_valid = (__u8)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_MIN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_size_min = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_MAX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_size_max = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_GRAN) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_size_gran = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_UNIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_unit = (enum devlink_resource_unit)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_OCC) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->resource_occ = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int devlink_dl_info_version_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	devlink_dl_info_version *dst = (devlink_dl_info_version *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_INFO_VERSION_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->info_version_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_INFO_VERSION_VALUE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->info_version_value.assign(ynl_attr_get_str(attr));
		}
	}

	return 0;
}

int devlink_dl_fmsg_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	devlink_dl_fmsg *dst = (devlink_dl_fmsg *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_FMSG_OBJ_NEST_START) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == DEVLINK_ATTR_FMSG_PAIR_NEST_START) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == DEVLINK_ATTR_FMSG_ARR_NEST_START) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == DEVLINK_ATTR_FMSG_NEST_END) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == DEVLINK_ATTR_FMSG_OBJ_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->fmsg_obj_name.assign(ynl_attr_get_str(attr));
		}
	}

	return 0;
}

int devlink_dl_port_function_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 const devlink_dl_port_function&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.hw_addr.size() > 0) {
		ynl_attr_put(nlh, DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR, obj.hw_addr.data(), obj.hw_addr.size());
	}
	if (obj.state.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_PORT_FN_ATTR_STATE, obj.state.value());
	}
	if (obj.opstate.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_PORT_FN_ATTR_OPSTATE, obj.opstate.value());
	}
	if (obj.caps.has_value()) {
		ynl_attr_put(nlh, DEVLINK_PORT_FN_ATTR_CAPS, &(*obj.caps), sizeof(struct nla_bitfield32));
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int devlink_dl_reload_stats_entry_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	devlink_dl_reload_stats_entry *dst = (devlink_dl_reload_stats_entry *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_STATS_LIMIT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->reload_stats_limit = (__u8)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_RELOAD_STATS_VALUE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->reload_stats_value = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int devlink_dl_reload_act_stats_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	devlink_dl_reload_act_stats *dst = (devlink_dl_reload_act_stats *)yarg->data;
	unsigned int n_reload_stats_entry = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->reload_stats_entry.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-reload-act-stats.reload-stats-entry)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_STATS_ENTRY) {
			n_reload_stats_entry++;
		}
	}

	if (n_reload_stats_entry) {
		dst->reload_stats_entry.resize(n_reload_stats_entry);
		i = 0;
		parg.rsp_policy = &devlink_dl_reload_stats_entry_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_RELOAD_STATS_ENTRY) {
				parg.data = &dst->reload_stats_entry[i];
				if (devlink_dl_reload_stats_entry_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_selftest_id_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       const devlink_dl_selftest_id&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.flash) {
		ynl_attr_put(nlh, DEVLINK_ATTR_SELFTEST_ID_FLASH, NULL, 0);
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int devlink_dl_rate_tc_bws_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       const devlink_dl_rate_tc_bws&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.index.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_RATE_TC_ATTR_INDEX, obj.index.value());
	}
	if (obj.bw.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_RATE_TC_ATTR_BW, obj.bw.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int devlink_dl_dpipe_table_matches_parse(struct ynl_parse_arg *yarg,
					 const struct nlattr *nested)
{
	devlink_dl_dpipe_table_matches *dst = (devlink_dl_dpipe_table_matches *)yarg->data;
	unsigned int n_dpipe_match = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_match.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-table-matches.dpipe-match)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_MATCH) {
			n_dpipe_match++;
		}
	}

	if (n_dpipe_match) {
		dst->dpipe_match.resize(n_dpipe_match);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_match_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_MATCH) {
				parg.data = &dst->dpipe_match[i];
				if (devlink_dl_dpipe_match_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_table_actions_parse(struct ynl_parse_arg *yarg,
					 const struct nlattr *nested)
{
	devlink_dl_dpipe_table_actions *dst = (devlink_dl_dpipe_table_actions *)yarg->data;
	unsigned int n_dpipe_action = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_action.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-table-actions.dpipe-action)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ACTION) {
			n_dpipe_action++;
		}
	}

	if (n_dpipe_action) {
		dst->dpipe_action.resize(n_dpipe_action);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_action_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_ACTION) {
				parg.data = &dst->dpipe_action[i];
				if (devlink_dl_dpipe_action_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_entry_match_values_parse(struct ynl_parse_arg *yarg,
					      const struct nlattr *nested)
{
	devlink_dl_dpipe_entry_match_values *dst = (devlink_dl_dpipe_entry_match_values *)yarg->data;
	unsigned int n_dpipe_match_value = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_match_value.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-entry-match-values.dpipe-match-value)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_MATCH_VALUE) {
			n_dpipe_match_value++;
		}
	}

	if (n_dpipe_match_value) {
		dst->dpipe_match_value.resize(n_dpipe_match_value);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_match_value_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_MATCH_VALUE) {
				parg.data = &dst->dpipe_match_value[i];
				if (devlink_dl_dpipe_match_value_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_entry_action_values_parse(struct ynl_parse_arg *yarg,
					       const struct nlattr *nested)
{
	devlink_dl_dpipe_entry_action_values *dst = (devlink_dl_dpipe_entry_action_values *)yarg->data;
	unsigned int n_dpipe_action_value = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_action_value.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-entry-action-values.dpipe-action-value)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ACTION_VALUE) {
			n_dpipe_action_value++;
		}
	}

	if (n_dpipe_action_value) {
		dst->dpipe_action_value.resize(n_dpipe_action_value);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_action_value_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_ACTION_VALUE) {
				parg.data = &dst->dpipe_action_value[i];
				if (devlink_dl_dpipe_action_value_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_header_fields_parse(struct ynl_parse_arg *yarg,
					 const struct nlattr *nested)
{
	devlink_dl_dpipe_header_fields *dst = (devlink_dl_dpipe_header_fields *)yarg->data;
	unsigned int n_dpipe_field = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_field.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-header-fields.dpipe-field)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_FIELD) {
			n_dpipe_field++;
		}
	}

	if (n_dpipe_field) {
		dst->dpipe_field.resize(n_dpipe_field);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_field_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_FIELD) {
				parg.data = &dst->dpipe_field[i];
				if (devlink_dl_dpipe_field_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_resource_list_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	devlink_dl_resource_list *dst = (devlink_dl_resource_list *)yarg->data;
	unsigned int n_resource = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->resource.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-resource-list.resource)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RESOURCE) {
			n_resource++;
		}
	}

	if (n_resource) {
		dst->resource.resize(n_resource);
		i = 0;
		parg.rsp_policy = &devlink_dl_resource_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_RESOURCE) {
				parg.data = &dst->resource[i];
				if (devlink_dl_resource_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_reload_act_info_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	devlink_dl_reload_act_info *dst = (devlink_dl_reload_act_info *)yarg->data;
	unsigned int n_reload_action_stats = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->reload_action_stats.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-reload-act-info.reload-action-stats)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_ACTION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->reload_action = (enum devlink_reload_action)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_RELOAD_ACTION_STATS) {
			n_reload_action_stats++;
		}
	}

	if (n_reload_action_stats) {
		dst->reload_action_stats.resize(n_reload_action_stats);
		i = 0;
		parg.rsp_policy = &devlink_dl_reload_act_stats_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_RELOAD_ACTION_STATS) {
				parg.data = &dst->reload_action_stats[i];
				if (devlink_dl_reload_act_stats_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_table_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	devlink_dl_dpipe_table *dst = (devlink_dl_dpipe_table *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_TABLE_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_table_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_SIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_table_size = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_MATCHES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_dpipe_table_matches_nest;
			parg.data = &dst->dpipe_table_matches.emplace();
			if (devlink_dl_dpipe_table_matches_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_ACTIONS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_dpipe_table_actions_nest;
			parg.data = &dst->dpipe_table_actions.emplace();
			if (devlink_dl_dpipe_table_actions_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_table_counters_enabled = (__u8)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_table_resource_id = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_table_resource_units = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int devlink_dl_dpipe_entry_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	devlink_dl_dpipe_entry *dst = (devlink_dl_dpipe_entry *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ENTRY_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_entry_index = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_dpipe_entry_match_values_nest;
			parg.data = &dst->dpipe_entry_match_values.emplace();
			if (devlink_dl_dpipe_entry_match_values_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_dpipe_entry_action_values_nest;
			parg.data = &dst->dpipe_entry_action_values.emplace();
			if (devlink_dl_dpipe_entry_action_values_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == DEVLINK_ATTR_DPIPE_ENTRY_COUNTER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_entry_counter = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int devlink_dl_dpipe_header_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	devlink_dl_dpipe_header *dst = (devlink_dl_dpipe_header *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_HEADER_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_header_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_header_id = (enum devlink_dpipe_header_id)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_GLOBAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dpipe_header_global = (__u8)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_FIELDS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_dpipe_header_fields_nest;
			parg.data = &dst->dpipe_header_fields.emplace();
			if (devlink_dl_dpipe_header_fields_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

int devlink_dl_reload_stats_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	devlink_dl_reload_stats *dst = (devlink_dl_reload_stats *)yarg->data;
	unsigned int n_reload_action_info = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->reload_action_info.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-reload-stats.reload-action-info)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_ACTION_INFO) {
			n_reload_action_info++;
		}
	}

	if (n_reload_action_info) {
		dst->reload_action_info.resize(n_reload_action_info);
		i = 0;
		parg.rsp_policy = &devlink_dl_reload_act_info_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_RELOAD_ACTION_INFO) {
				parg.data = &dst->reload_action_info[i];
				if (devlink_dl_reload_act_info_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_tables_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	devlink_dl_dpipe_tables *dst = (devlink_dl_dpipe_tables *)yarg->data;
	unsigned int n_dpipe_table = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_table.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-tables.dpipe-table)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_TABLE) {
			n_dpipe_table++;
		}
	}

	if (n_dpipe_table) {
		dst->dpipe_table.resize(n_dpipe_table);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_table_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_TABLE) {
				parg.data = &dst->dpipe_table[i];
				if (devlink_dl_dpipe_table_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_entries_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	devlink_dl_dpipe_entries *dst = (devlink_dl_dpipe_entries *)yarg->data;
	unsigned int n_dpipe_entry = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_entry.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-entries.dpipe-entry)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ENTRY) {
			n_dpipe_entry++;
		}
	}

	if (n_dpipe_entry) {
		dst->dpipe_entry.resize(n_dpipe_entry);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_entry_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_ENTRY) {
				parg.data = &dst->dpipe_entry[i];
				if (devlink_dl_dpipe_entry_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dpipe_headers_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	devlink_dl_dpipe_headers *dst = (devlink_dl_dpipe_headers *)yarg->data;
	unsigned int n_dpipe_header = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_header.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-headers.dpipe-header)");
	}

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_HEADER) {
			n_dpipe_header++;
		}
	}

	if (n_dpipe_header) {
		dst->dpipe_header.resize(n_dpipe_header);
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_header_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_HEADER) {
				parg.data = &dst->dpipe_header[i];
				if (devlink_dl_dpipe_header_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return 0;
}

int devlink_dl_dev_stats_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested)
{
	devlink_dl_dev_stats *dst = (devlink_dl_dev_stats *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_reload_stats_nest;
			parg.data = &dst->reload_stats.emplace();
			if (devlink_dl_reload_stats_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == DEVLINK_ATTR_REMOTE_RELOAD_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_reload_stats_nest;
			parg.data = &dst->remote_reload_stats.emplace();
			if (devlink_dl_reload_stats_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

/* ============== DEVLINK_CMD_GET ============== */
/* DEVLINK_CMD_GET - do */
int devlink_get_rsp_parse(const struct nlmsghdr *nlh,
			  struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	devlink_get_rsp *dst;

	dst = (devlink_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_RELOAD_FAILED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->reload_failed = (__u8)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DEV_STATS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_dev_stats_nest;
			parg.data = &dst->dev_stats.emplace();
			if (devlink_dl_dev_stats_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_get_rsp>
devlink_get(ynl_cpp::ynl_socket& ys, devlink_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	rsp.reset(new devlink_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_get_rsp_parse;
	yrs.rsp_cmd = 3;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_GET - dump */
std::unique_ptr<devlink_get_list> devlink_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_get_rsp_parse;
	yds.rsp_cmd = 3;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_GET, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_PORT_GET ============== */
/* DEVLINK_CMD_PORT_GET - do */
int devlink_port_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	devlink_port_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_port_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_port_get_rsp>
devlink_port_get(ynl_cpp::ynl_socket& ys, devlink_port_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_port_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}

	rsp.reset(new devlink_port_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_port_get_rsp_parse;
	yrs.rsp_cmd = 7;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_PORT_GET - dump */
int devlink_port_get_rsp_dump_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	devlink_port_get_rsp_dump *dst;
	const struct nlattr *attr;

	dst = (devlink_port_get_rsp_dump*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_port_get_rsp_list>
devlink_port_get_dump(ynl_cpp::ynl_socket& ys, devlink_port_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_port_get_rsp_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_port_get_rsp_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_port_get_rsp_dump_parse;
	yds.rsp_cmd = 7;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_PORT_SET ============== */
/* DEVLINK_CMD_PORT_SET - do */
int devlink_port_set(ynl_cpp::ynl_socket& ys, devlink_port_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.port_type.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_PORT_TYPE, req.port_type.value());
	}
	if (req.port_function.has_value()) {
		devlink_dl_port_function_put(nlh, DEVLINK_ATTR_PORT_FUNCTION, req.port_function.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_PORT_NEW ============== */
/* DEVLINK_CMD_PORT_NEW - do */
int devlink_port_new_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	devlink_port_new_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_port_new_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_port_new_rsp>
devlink_port_new(ynl_cpp::ynl_socket& ys, devlink_port_new_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_port_new_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_NEW, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.port_flavour.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_PORT_FLAVOUR, req.port_flavour.value());
	}
	if (req.port_pci_pf_number.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_PORT_PCI_PF_NUMBER, req.port_pci_pf_number.value());
	}
	if (req.port_pci_sf_number.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_PCI_SF_NUMBER, req.port_pci_sf_number.value());
	}
	if (req.port_controller_number.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_CONTROLLER_NUMBER, req.port_controller_number.value());
	}

	rsp.reset(new devlink_port_new_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_port_new_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_PORT_NEW;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== DEVLINK_CMD_PORT_DEL ============== */
/* DEVLINK_CMD_PORT_DEL - do */
int devlink_port_del(ynl_cpp::ynl_socket& ys, devlink_port_del_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_DEL, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_PORT_SPLIT ============== */
/* DEVLINK_CMD_PORT_SPLIT - do */
int devlink_port_split(ynl_cpp::ynl_socket& ys, devlink_port_split_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_SPLIT, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.port_split_count.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_SPLIT_COUNT, req.port_split_count.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_PORT_UNSPLIT ============== */
/* DEVLINK_CMD_PORT_UNSPLIT - do */
int devlink_port_unsplit(ynl_cpp::ynl_socket& ys,
			 devlink_port_unsplit_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_UNSPLIT, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_SB_GET ============== */
/* DEVLINK_CMD_SB_GET - do */
int devlink_sb_get_rsp_parse(const struct nlmsghdr *nlh,
			     struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	devlink_sb_get_rsp *dst;

	dst = (devlink_sb_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_SB_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sb_index = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_sb_get_rsp>
devlink_sb_get(ynl_cpp::ynl_socket& ys, devlink_sb_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_sb_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.sb_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req.sb_index.value());
	}

	rsp.reset(new devlink_sb_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_sb_get_rsp_parse;
	yrs.rsp_cmd = 13;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_SB_GET - dump */
std::unique_ptr<devlink_sb_get_list>
devlink_sb_get_dump(ynl_cpp::ynl_socket& ys, devlink_sb_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_sb_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_sb_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_sb_get_rsp_parse;
	yds.rsp_cmd = 13;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_SB_POOL_GET ============== */
/* DEVLINK_CMD_SB_POOL_GET - do */
int devlink_sb_pool_get_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	devlink_sb_pool_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_sb_pool_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_SB_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sb_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_POOL_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sb_pool_index = (__u16)ynl_attr_get_u16(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_sb_pool_get_rsp>
devlink_sb_pool_get(ynl_cpp::ynl_socket& ys, devlink_sb_pool_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_sb_pool_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_POOL_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.sb_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req.sb_index.value());
	}
	if (req.sb_pool_index.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req.sb_pool_index.value());
	}

	rsp.reset(new devlink_sb_pool_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_sb_pool_get_rsp_parse;
	yrs.rsp_cmd = 17;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_SB_POOL_GET - dump */
std::unique_ptr<devlink_sb_pool_get_list>
devlink_sb_pool_get_dump(ynl_cpp::ynl_socket& ys,
			 devlink_sb_pool_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_sb_pool_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_sb_pool_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_sb_pool_get_rsp_parse;
	yds.rsp_cmd = 17;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_POOL_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_SB_POOL_SET ============== */
/* DEVLINK_CMD_SB_POOL_SET - do */
int devlink_sb_pool_set(ynl_cpp::ynl_socket& ys, devlink_sb_pool_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_POOL_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.sb_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req.sb_index.value());
	}
	if (req.sb_pool_index.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req.sb_pool_index.value());
	}
	if (req.sb_pool_threshold_type.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE, req.sb_pool_threshold_type.value());
	}
	if (req.sb_pool_size.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_POOL_SIZE, req.sb_pool_size.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_SB_PORT_POOL_GET ============== */
/* DEVLINK_CMD_SB_PORT_POOL_GET - do */
int devlink_sb_port_pool_get_rsp_parse(const struct nlmsghdr *nlh,
				       struct ynl_parse_arg *yarg)
{
	devlink_sb_port_pool_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_sb_port_pool_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sb_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_POOL_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sb_pool_index = (__u16)ynl_attr_get_u16(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_sb_port_pool_get_rsp>
devlink_sb_port_pool_get(ynl_cpp::ynl_socket& ys,
			 devlink_sb_port_pool_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_sb_port_pool_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_PORT_POOL_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.sb_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req.sb_index.value());
	}
	if (req.sb_pool_index.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req.sb_pool_index.value());
	}

	rsp.reset(new devlink_sb_port_pool_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_sb_port_pool_get_rsp_parse;
	yrs.rsp_cmd = 21;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_SB_PORT_POOL_GET - dump */
std::unique_ptr<devlink_sb_port_pool_get_list>
devlink_sb_port_pool_get_dump(ynl_cpp::ynl_socket& ys,
			      devlink_sb_port_pool_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_sb_port_pool_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_sb_port_pool_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_sb_port_pool_get_rsp_parse;
	yds.rsp_cmd = 21;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_PORT_POOL_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_SB_PORT_POOL_SET ============== */
/* DEVLINK_CMD_SB_PORT_POOL_SET - do */
int devlink_sb_port_pool_set(ynl_cpp::ynl_socket& ys,
			     devlink_sb_port_pool_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_PORT_POOL_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.sb_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req.sb_index.value());
	}
	if (req.sb_pool_index.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req.sb_pool_index.value());
	}
	if (req.sb_threshold.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_THRESHOLD, req.sb_threshold.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_SB_TC_POOL_BIND_GET ============== */
/* DEVLINK_CMD_SB_TC_POOL_BIND_GET - do */
int devlink_sb_tc_pool_bind_get_rsp_parse(const struct nlmsghdr *nlh,
					  struct ynl_parse_arg *yarg)
{
	devlink_sb_tc_pool_bind_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_sb_tc_pool_bind_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sb_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_POOL_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sb_pool_type = (enum devlink_sb_pool_type)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_SB_TC_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sb_tc_index = (__u16)ynl_attr_get_u16(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_sb_tc_pool_bind_get_rsp>
devlink_sb_tc_pool_bind_get(ynl_cpp::ynl_socket& ys,
			    devlink_sb_tc_pool_bind_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_sb_tc_pool_bind_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_TC_POOL_BIND_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.sb_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req.sb_index.value());
	}
	if (req.sb_pool_type.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_SB_POOL_TYPE, req.sb_pool_type.value());
	}
	if (req.sb_tc_index.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_TC_INDEX, req.sb_tc_index.value());
	}

	rsp.reset(new devlink_sb_tc_pool_bind_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_sb_tc_pool_bind_get_rsp_parse;
	yrs.rsp_cmd = 25;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_SB_TC_POOL_BIND_GET - dump */
std::unique_ptr<devlink_sb_tc_pool_bind_get_list>
devlink_sb_tc_pool_bind_get_dump(ynl_cpp::ynl_socket& ys,
				 devlink_sb_tc_pool_bind_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_sb_tc_pool_bind_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_sb_tc_pool_bind_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_sb_tc_pool_bind_get_rsp_parse;
	yds.rsp_cmd = 25;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_TC_POOL_BIND_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_SB_TC_POOL_BIND_SET ============== */
/* DEVLINK_CMD_SB_TC_POOL_BIND_SET - do */
int devlink_sb_tc_pool_bind_set(ynl_cpp::ynl_socket& ys,
				devlink_sb_tc_pool_bind_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_TC_POOL_BIND_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.sb_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req.sb_index.value());
	}
	if (req.sb_pool_index.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req.sb_pool_index.value());
	}
	if (req.sb_pool_type.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_SB_POOL_TYPE, req.sb_pool_type.value());
	}
	if (req.sb_tc_index.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_TC_INDEX, req.sb_tc_index.value());
	}
	if (req.sb_threshold.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_THRESHOLD, req.sb_threshold.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_SB_OCC_SNAPSHOT ============== */
/* DEVLINK_CMD_SB_OCC_SNAPSHOT - do */
int devlink_sb_occ_snapshot(ynl_cpp::ynl_socket& ys,
			    devlink_sb_occ_snapshot_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_OCC_SNAPSHOT, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.sb_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req.sb_index.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_SB_OCC_MAX_CLEAR ============== */
/* DEVLINK_CMD_SB_OCC_MAX_CLEAR - do */
int devlink_sb_occ_max_clear(ynl_cpp::ynl_socket& ys,
			     devlink_sb_occ_max_clear_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SB_OCC_MAX_CLEAR, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.sb_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req.sb_index.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_ESWITCH_GET ============== */
/* DEVLINK_CMD_ESWITCH_GET - do */
int devlink_eswitch_get_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	devlink_eswitch_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_eswitch_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_ESWITCH_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->eswitch_mode = (enum devlink_eswitch_mode)ynl_attr_get_u16(attr);
		} else if (type == DEVLINK_ATTR_ESWITCH_INLINE_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->eswitch_inline_mode = (enum devlink_eswitch_inline_mode)ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_ESWITCH_ENCAP_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->eswitch_encap_mode = (enum devlink_eswitch_encap_mode)ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_eswitch_get_rsp>
devlink_eswitch_get(ynl_cpp::ynl_socket& ys, devlink_eswitch_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_eswitch_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_ESWITCH_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	rsp.reset(new devlink_eswitch_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_eswitch_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_ESWITCH_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== DEVLINK_CMD_ESWITCH_SET ============== */
/* DEVLINK_CMD_ESWITCH_SET - do */
int devlink_eswitch_set(ynl_cpp::ynl_socket& ys, devlink_eswitch_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_ESWITCH_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.eswitch_mode.has_value()) {
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_ESWITCH_MODE, req.eswitch_mode.value());
	}
	if (req.eswitch_inline_mode.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_ESWITCH_INLINE_MODE, req.eswitch_inline_mode.value());
	}
	if (req.eswitch_encap_mode.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_ESWITCH_ENCAP_MODE, req.eswitch_encap_mode.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_DPIPE_TABLE_GET ============== */
/* DEVLINK_CMD_DPIPE_TABLE_GET - do */
int devlink_dpipe_table_get_rsp_parse(const struct nlmsghdr *nlh,
				      struct ynl_parse_arg *yarg)
{
	devlink_dpipe_table_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (devlink_dpipe_table_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DPIPE_TABLES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_dpipe_tables_nest;
			parg.data = &dst->dpipe_tables.emplace();
			if (devlink_dl_dpipe_tables_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_dpipe_table_get_rsp>
devlink_dpipe_table_get(ynl_cpp::ynl_socket& ys,
			devlink_dpipe_table_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_dpipe_table_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_DPIPE_TABLE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.dpipe_table_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DPIPE_TABLE_NAME, req.dpipe_table_name.data());
	}

	rsp.reset(new devlink_dpipe_table_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_dpipe_table_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_DPIPE_TABLE_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== DEVLINK_CMD_DPIPE_ENTRIES_GET ============== */
/* DEVLINK_CMD_DPIPE_ENTRIES_GET - do */
int devlink_dpipe_entries_get_rsp_parse(const struct nlmsghdr *nlh,
					struct ynl_parse_arg *yarg)
{
	devlink_dpipe_entries_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (devlink_dpipe_entries_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DPIPE_ENTRIES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_dpipe_entries_nest;
			parg.data = &dst->dpipe_entries.emplace();
			if (devlink_dl_dpipe_entries_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_dpipe_entries_get_rsp>
devlink_dpipe_entries_get(ynl_cpp::ynl_socket& ys,
			  devlink_dpipe_entries_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_dpipe_entries_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_DPIPE_ENTRIES_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.dpipe_table_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DPIPE_TABLE_NAME, req.dpipe_table_name.data());
	}

	rsp.reset(new devlink_dpipe_entries_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_dpipe_entries_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_DPIPE_ENTRIES_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== DEVLINK_CMD_DPIPE_HEADERS_GET ============== */
/* DEVLINK_CMD_DPIPE_HEADERS_GET - do */
int devlink_dpipe_headers_get_rsp_parse(const struct nlmsghdr *nlh,
					struct ynl_parse_arg *yarg)
{
	devlink_dpipe_headers_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (devlink_dpipe_headers_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DPIPE_HEADERS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_dpipe_headers_nest;
			parg.data = &dst->dpipe_headers.emplace();
			if (devlink_dl_dpipe_headers_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_dpipe_headers_get_rsp>
devlink_dpipe_headers_get(ynl_cpp::ynl_socket& ys,
			  devlink_dpipe_headers_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_dpipe_headers_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_DPIPE_HEADERS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	rsp.reset(new devlink_dpipe_headers_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_dpipe_headers_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_DPIPE_HEADERS_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET ============== */
/* DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET - do */
int devlink_dpipe_table_counters_set(ynl_cpp::ynl_socket& ys,
				     devlink_dpipe_table_counters_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.dpipe_table_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DPIPE_TABLE_NAME, req.dpipe_table_name.data());
	}
	if (req.dpipe_table_counters_enabled.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED, req.dpipe_table_counters_enabled.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_RESOURCE_SET ============== */
/* DEVLINK_CMD_RESOURCE_SET - do */
int devlink_resource_set(ynl_cpp::ynl_socket& ys,
			 devlink_resource_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_RESOURCE_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.resource_id.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RESOURCE_ID, req.resource_id.value());
	}
	if (req.resource_size.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RESOURCE_SIZE, req.resource_size.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_RESOURCE_DUMP ============== */
/* DEVLINK_CMD_RESOURCE_DUMP - do */
int devlink_resource_dump_rsp_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	devlink_resource_dump_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (devlink_resource_dump_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_RESOURCE_LIST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_resource_list_nest;
			parg.data = &dst->resource_list.emplace();
			if (devlink_dl_resource_list_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_resource_dump_rsp>
devlink_resource_dump(ynl_cpp::ynl_socket& ys, devlink_resource_dump_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_resource_dump_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_RESOURCE_DUMP, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	rsp.reset(new devlink_resource_dump_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_resource_dump_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_RESOURCE_DUMP;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== DEVLINK_CMD_RELOAD ============== */
/* DEVLINK_CMD_RELOAD - do */
int devlink_reload_rsp_parse(const struct nlmsghdr *nlh,
			     struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	devlink_reload_rsp *dst;

	dst = (devlink_reload_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			memcpy(&dst->reload_actions_performed, ynl_attr_data(attr), sizeof(struct nla_bitfield32));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_reload_rsp>
devlink_reload(ynl_cpp::ynl_socket& ys, devlink_reload_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_reload_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_RELOAD, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.reload_action.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_RELOAD_ACTION, req.reload_action.value());
	}
	if (req.reload_limits.has_value()) {
		ynl_attr_put(nlh, DEVLINK_ATTR_RELOAD_LIMITS, &(*req.reload_limits), sizeof(struct nla_bitfield32));
	}
	if (req.netns_pid.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_NETNS_PID, req.netns_pid.value());
	}
	if (req.netns_fd.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_NETNS_FD, req.netns_fd.value());
	}
	if (req.netns_id.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_NETNS_ID, req.netns_id.value());
	}

	rsp.reset(new devlink_reload_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_reload_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_RELOAD;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== DEVLINK_CMD_PARAM_GET ============== */
/* DEVLINK_CMD_PARAM_GET - do */
int devlink_param_get_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	devlink_param_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_param_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PARAM_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->param_name.assign(ynl_attr_get_str(attr));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_param_get_rsp>
devlink_param_get(ynl_cpp::ynl_socket& ys, devlink_param_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_param_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PARAM_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.param_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_PARAM_NAME, req.param_name.data());
	}

	rsp.reset(new devlink_param_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_param_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_PARAM_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_PARAM_GET - dump */
std::unique_ptr<devlink_param_get_list>
devlink_param_get_dump(ynl_cpp::ynl_socket& ys,
		       devlink_param_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_param_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_param_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_param_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_PARAM_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PARAM_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_PARAM_SET ============== */
/* DEVLINK_CMD_PARAM_SET - do */
int devlink_param_set(ynl_cpp::ynl_socket& ys, devlink_param_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PARAM_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.param_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_PARAM_NAME, req.param_name.data());
	}
	if (req.param_type.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_PARAM_TYPE, req.param_type.value());
	}
	if (req.param_value_cmode.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_PARAM_VALUE_CMODE, req.param_value_cmode.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_REGION_GET ============== */
/* DEVLINK_CMD_REGION_GET - do */
int devlink_region_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	devlink_region_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_region_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_REGION_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->region_name.assign(ynl_attr_get_str(attr));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_region_get_rsp>
devlink_region_get(ynl_cpp::ynl_socket& ys, devlink_region_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_region_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_REGION_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.region_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_REGION_NAME, req.region_name.data());
	}

	rsp.reset(new devlink_region_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_region_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_REGION_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_REGION_GET - dump */
std::unique_ptr<devlink_region_get_list>
devlink_region_get_dump(ynl_cpp::ynl_socket& ys,
			devlink_region_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_region_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_region_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_region_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_REGION_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_REGION_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_REGION_NEW ============== */
/* DEVLINK_CMD_REGION_NEW - do */
int devlink_region_new_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	devlink_region_new_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_region_new_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_REGION_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->region_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_REGION_SNAPSHOT_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->region_snapshot_id = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_region_new_rsp>
devlink_region_new(ynl_cpp::ynl_socket& ys, devlink_region_new_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_region_new_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_REGION_NEW, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.region_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_REGION_NAME, req.region_name.data());
	}
	if (req.region_snapshot_id.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, req.region_snapshot_id.value());
	}

	rsp.reset(new devlink_region_new_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_region_new_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_REGION_NEW;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== DEVLINK_CMD_REGION_DEL ============== */
/* DEVLINK_CMD_REGION_DEL - do */
int devlink_region_del(ynl_cpp::ynl_socket& ys, devlink_region_del_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_REGION_DEL, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.region_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_REGION_NAME, req.region_name.data());
	}
	if (req.region_snapshot_id.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, req.region_snapshot_id.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_REGION_READ ============== */
/* DEVLINK_CMD_REGION_READ - dump */
int devlink_region_read_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	devlink_region_read_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_region_read_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_REGION_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->region_name.assign(ynl_attr_get_str(attr));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_region_read_list>
devlink_region_read_dump(ynl_cpp::ynl_socket& ys, devlink_region_read_req& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_region_read_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_region_read_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_region_read_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_REGION_READ;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_REGION_READ, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.region_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_REGION_NAME, req.region_name.data());
	}
	if (req.region_snapshot_id.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, req.region_snapshot_id.value());
	}
	if (req.region_direct) {
		ynl_attr_put(nlh, DEVLINK_ATTR_REGION_DIRECT, NULL, 0);
	}
	if (req.region_chunk_addr.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_REGION_CHUNK_ADDR, req.region_chunk_addr.value());
	}
	if (req.region_chunk_len.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_REGION_CHUNK_LEN, req.region_chunk_len.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_PORT_PARAM_GET ============== */
/* DEVLINK_CMD_PORT_PARAM_GET - do */
int devlink_port_param_get_rsp_parse(const struct nlmsghdr *nlh,
				     struct ynl_parse_arg *yarg)
{
	devlink_port_param_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_port_param_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_port_param_get_rsp>
devlink_port_param_get(ynl_cpp::ynl_socket& ys,
		       devlink_port_param_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_port_param_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_PARAM_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}

	rsp.reset(new devlink_port_param_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_port_param_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_PORT_PARAM_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_PORT_PARAM_GET - dump */
std::unique_ptr<devlink_port_param_get_list>
devlink_port_param_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_port_param_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_port_param_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_port_param_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_PORT_PARAM_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_PARAM_GET, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_PORT_PARAM_SET ============== */
/* DEVLINK_CMD_PORT_PARAM_SET - do */
int devlink_port_param_set(ynl_cpp::ynl_socket& ys,
			   devlink_port_param_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_PORT_PARAM_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_INFO_GET ============== */
/* DEVLINK_CMD_INFO_GET - do */
int devlink_info_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	unsigned int n_info_version_running = 0;
	unsigned int n_info_version_stored = 0;
	unsigned int n_info_version_fixed = 0;
	devlink_info_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = (devlink_info_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->info_version_fixed.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (devlink.info-version-fixed)");
	}
	if (dst->info_version_running.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (devlink.info-version-running)");
	}
	if (dst->info_version_stored.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (devlink.info-version-stored)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_INFO_DRIVER_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->info_driver_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_INFO_SERIAL_NUMBER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->info_serial_number.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_INFO_VERSION_FIXED) {
			n_info_version_fixed++;
		} else if (type == DEVLINK_ATTR_INFO_VERSION_RUNNING) {
			n_info_version_running++;
		} else if (type == DEVLINK_ATTR_INFO_VERSION_STORED) {
			n_info_version_stored++;
		} else if (type == DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->info_board_serial_number.assign(ynl_attr_get_str(attr));
		}
	}

	if (n_info_version_fixed) {
		dst->info_version_fixed.resize(n_info_version_fixed);
		i = 0;
		parg.rsp_policy = &devlink_dl_info_version_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_INFO_VERSION_FIXED) {
				parg.data = &dst->info_version_fixed[i];
				if (devlink_dl_info_version_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}
	if (n_info_version_running) {
		dst->info_version_running.resize(n_info_version_running);
		i = 0;
		parg.rsp_policy = &devlink_dl_info_version_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_INFO_VERSION_RUNNING) {
				parg.data = &dst->info_version_running[i];
				if (devlink_dl_info_version_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}
	if (n_info_version_stored) {
		dst->info_version_stored.resize(n_info_version_stored);
		i = 0;
		parg.rsp_policy = &devlink_dl_info_version_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_INFO_VERSION_STORED) {
				parg.data = &dst->info_version_stored[i];
				if (devlink_dl_info_version_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_info_get_rsp>
devlink_info_get(ynl_cpp::ynl_socket& ys, devlink_info_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_info_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_INFO_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	rsp.reset(new devlink_info_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_info_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_INFO_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_INFO_GET - dump */
std::unique_ptr<devlink_info_get_list>
devlink_info_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_info_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_info_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_info_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_INFO_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_INFO_GET, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_GET ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_GET - do */
int devlink_health_reporter_get_rsp_parse(const struct nlmsghdr *nlh,
					  struct ynl_parse_arg *yarg)
{
	devlink_health_reporter_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_health_reporter_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_HEALTH_REPORTER_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->health_reporter_name.assign(ynl_attr_get_str(attr));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_health_reporter_get_rsp>
devlink_health_reporter_get(ynl_cpp::ynl_socket& ys,
			    devlink_health_reporter_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_health_reporter_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_HEALTH_REPORTER_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.health_reporter_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req.health_reporter_name.data());
	}

	rsp.reset(new devlink_health_reporter_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_health_reporter_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_HEALTH_REPORTER_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_HEALTH_REPORTER_GET - dump */
std::unique_ptr<devlink_health_reporter_get_list>
devlink_health_reporter_get_dump(ynl_cpp::ynl_socket& ys,
				 devlink_health_reporter_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_health_reporter_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_health_reporter_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_health_reporter_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_HEALTH_REPORTER_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_HEALTH_REPORTER_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_SET ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_SET - do */
int devlink_health_reporter_set(ynl_cpp::ynl_socket& ys,
				devlink_health_reporter_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_HEALTH_REPORTER_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.health_reporter_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req.health_reporter_name.data());
	}
	if (req.health_reporter_graceful_period.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD, req.health_reporter_graceful_period.value());
	}
	if (req.health_reporter_auto_recover.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER, req.health_reporter_auto_recover.value());
	}
	if (req.health_reporter_auto_dump.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP, req.health_reporter_auto_dump.value());
	}
	if (req.health_reporter_burst_period.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_HEALTH_REPORTER_BURST_PERIOD, req.health_reporter_burst_period.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_RECOVER ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_RECOVER - do */
int devlink_health_reporter_recover(ynl_cpp::ynl_socket& ys,
				    devlink_health_reporter_recover_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_HEALTH_REPORTER_RECOVER, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.health_reporter_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req.health_reporter_name.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE - do */
int devlink_health_reporter_diagnose(ynl_cpp::ynl_socket& ys,
				     devlink_health_reporter_diagnose_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.health_reporter_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req.health_reporter_name.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET - dump */
int devlink_health_reporter_dump_get_rsp_parse(const struct nlmsghdr *nlh,
					       struct ynl_parse_arg *yarg)
{
	devlink_health_reporter_dump_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (devlink_health_reporter_dump_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_FMSG) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &devlink_dl_fmsg_nest;
			parg.data = &dst->fmsg.emplace();
			if (devlink_dl_fmsg_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_health_reporter_dump_get_list>
devlink_health_reporter_dump_get_dump(ynl_cpp::ynl_socket& ys,
				      devlink_health_reporter_dump_get_req& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_health_reporter_dump_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_health_reporter_dump_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_health_reporter_dump_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.health_reporter_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req.health_reporter_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR - do */
int devlink_health_reporter_dump_clear(ynl_cpp::ynl_socket& ys,
				       devlink_health_reporter_dump_clear_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.health_reporter_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req.health_reporter_name.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_FLASH_UPDATE ============== */
/* DEVLINK_CMD_FLASH_UPDATE - do */
int devlink_flash_update(ynl_cpp::ynl_socket& ys,
			 devlink_flash_update_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_FLASH_UPDATE, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.flash_update_file_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME, req.flash_update_file_name.data());
	}
	if (req.flash_update_component.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_FLASH_UPDATE_COMPONENT, req.flash_update_component.data());
	}
	if (req.flash_update_overwrite_mask.has_value()) {
		ynl_attr_put(nlh, DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK, &(*req.flash_update_overwrite_mask), sizeof(struct nla_bitfield32));
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_TRAP_GET ============== */
/* DEVLINK_CMD_TRAP_GET - do */
int devlink_trap_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	devlink_trap_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_trap_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_TRAP_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->trap_name.assign(ynl_attr_get_str(attr));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_trap_get_rsp>
devlink_trap_get(ynl_cpp::ynl_socket& ys, devlink_trap_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_trap_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_TRAP_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.trap_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_TRAP_NAME, req.trap_name.data());
	}

	rsp.reset(new devlink_trap_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_trap_get_rsp_parse;
	yrs.rsp_cmd = 63;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_TRAP_GET - dump */
std::unique_ptr<devlink_trap_get_list>
devlink_trap_get_dump(ynl_cpp::ynl_socket& ys, devlink_trap_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_trap_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_trap_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_trap_get_rsp_parse;
	yds.rsp_cmd = 63;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_TRAP_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_TRAP_SET ============== */
/* DEVLINK_CMD_TRAP_SET - do */
int devlink_trap_set(ynl_cpp::ynl_socket& ys, devlink_trap_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_TRAP_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.trap_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_TRAP_NAME, req.trap_name.data());
	}
	if (req.trap_action.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_TRAP_ACTION, req.trap_action.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_TRAP_GROUP_GET ============== */
/* DEVLINK_CMD_TRAP_GROUP_GET - do */
int devlink_trap_group_get_rsp_parse(const struct nlmsghdr *nlh,
				     struct ynl_parse_arg *yarg)
{
	devlink_trap_group_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_trap_group_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_TRAP_GROUP_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->trap_group_name.assign(ynl_attr_get_str(attr));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_trap_group_get_rsp>
devlink_trap_group_get(ynl_cpp::ynl_socket& ys,
		       devlink_trap_group_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_trap_group_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_TRAP_GROUP_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.trap_group_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_TRAP_GROUP_NAME, req.trap_group_name.data());
	}

	rsp.reset(new devlink_trap_group_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_trap_group_get_rsp_parse;
	yrs.rsp_cmd = 67;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_TRAP_GROUP_GET - dump */
std::unique_ptr<devlink_trap_group_get_list>
devlink_trap_group_get_dump(ynl_cpp::ynl_socket& ys,
			    devlink_trap_group_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_trap_group_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_trap_group_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_trap_group_get_rsp_parse;
	yds.rsp_cmd = 67;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_TRAP_GROUP_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_TRAP_GROUP_SET ============== */
/* DEVLINK_CMD_TRAP_GROUP_SET - do */
int devlink_trap_group_set(ynl_cpp::ynl_socket& ys,
			   devlink_trap_group_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_TRAP_GROUP_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.trap_group_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_TRAP_GROUP_NAME, req.trap_group_name.data());
	}
	if (req.trap_action.has_value()) {
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_TRAP_ACTION, req.trap_action.value());
	}
	if (req.trap_policer_id.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_TRAP_POLICER_ID, req.trap_policer_id.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_TRAP_POLICER_GET ============== */
/* DEVLINK_CMD_TRAP_POLICER_GET - do */
int devlink_trap_policer_get_rsp_parse(const struct nlmsghdr *nlh,
				       struct ynl_parse_arg *yarg)
{
	devlink_trap_policer_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_trap_policer_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_TRAP_POLICER_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->trap_policer_id = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_trap_policer_get_rsp>
devlink_trap_policer_get(ynl_cpp::ynl_socket& ys,
			 devlink_trap_policer_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_trap_policer_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_TRAP_POLICER_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.trap_policer_id.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_TRAP_POLICER_ID, req.trap_policer_id.value());
	}

	rsp.reset(new devlink_trap_policer_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_trap_policer_get_rsp_parse;
	yrs.rsp_cmd = 71;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_TRAP_POLICER_GET - dump */
std::unique_ptr<devlink_trap_policer_get_list>
devlink_trap_policer_get_dump(ynl_cpp::ynl_socket& ys,
			      devlink_trap_policer_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_trap_policer_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_trap_policer_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_trap_policer_get_rsp_parse;
	yds.rsp_cmd = 71;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_TRAP_POLICER_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_TRAP_POLICER_SET ============== */
/* DEVLINK_CMD_TRAP_POLICER_SET - do */
int devlink_trap_policer_set(ynl_cpp::ynl_socket& ys,
			     devlink_trap_policer_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_TRAP_POLICER_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.trap_policer_id.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_TRAP_POLICER_ID, req.trap_policer_id.value());
	}
	if (req.trap_policer_rate.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_TRAP_POLICER_RATE, req.trap_policer_rate.value());
	}
	if (req.trap_policer_burst.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_TRAP_POLICER_BURST, req.trap_policer_burst.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_TEST ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_TEST - do */
int devlink_health_reporter_test(ynl_cpp::ynl_socket& ys,
				 devlink_health_reporter_test_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_HEALTH_REPORTER_TEST, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.health_reporter_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req.health_reporter_name.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_RATE_GET ============== */
/* DEVLINK_CMD_RATE_GET - do */
int devlink_rate_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	devlink_rate_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_rate_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->port_index = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_RATE_NODE_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->rate_node_name.assign(ynl_attr_get_str(attr));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_rate_get_rsp>
devlink_rate_get(ynl_cpp::ynl_socket& ys, devlink_rate_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_rate_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_RATE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}
	if (req.rate_node_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_NODE_NAME, req.rate_node_name.data());
	}

	rsp.reset(new devlink_rate_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_rate_get_rsp_parse;
	yrs.rsp_cmd = 76;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_RATE_GET - dump */
std::unique_ptr<devlink_rate_get_list>
devlink_rate_get_dump(ynl_cpp::ynl_socket& ys, devlink_rate_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_rate_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_rate_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_rate_get_rsp_parse;
	yds.rsp_cmd = 76;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_RATE_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_RATE_SET ============== */
/* DEVLINK_CMD_RATE_SET - do */
int devlink_rate_set(ynl_cpp::ynl_socket& ys, devlink_rate_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_RATE_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.rate_node_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_NODE_NAME, req.rate_node_name.data());
	}
	if (req.rate_tx_share.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RATE_TX_SHARE, req.rate_tx_share.value());
	}
	if (req.rate_tx_max.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RATE_TX_MAX, req.rate_tx_max.value());
	}
	if (req.rate_tx_priority.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_RATE_TX_PRIORITY, req.rate_tx_priority.value());
	}
	if (req.rate_tx_weight.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_RATE_TX_WEIGHT, req.rate_tx_weight.value());
	}
	if (req.rate_parent_node_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_PARENT_NODE_NAME, req.rate_parent_node_name.data());
	}
	for (unsigned int i = 0; i < req.rate_tc_bws.size(); i++) {
		devlink_dl_rate_tc_bws_put(nlh, DEVLINK_ATTR_RATE_TC_BWS, req.rate_tc_bws[i]);
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_RATE_NEW ============== */
/* DEVLINK_CMD_RATE_NEW - do */
int devlink_rate_new(ynl_cpp::ynl_socket& ys, devlink_rate_new_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_RATE_NEW, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.rate_node_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_NODE_NAME, req.rate_node_name.data());
	}
	if (req.rate_tx_share.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RATE_TX_SHARE, req.rate_tx_share.value());
	}
	if (req.rate_tx_max.has_value()) {
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RATE_TX_MAX, req.rate_tx_max.value());
	}
	if (req.rate_tx_priority.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_RATE_TX_PRIORITY, req.rate_tx_priority.value());
	}
	if (req.rate_tx_weight.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_RATE_TX_WEIGHT, req.rate_tx_weight.value());
	}
	if (req.rate_parent_node_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_PARENT_NODE_NAME, req.rate_parent_node_name.data());
	}
	for (unsigned int i = 0; i < req.rate_tc_bws.size(); i++) {
		devlink_dl_rate_tc_bws_put(nlh, DEVLINK_ATTR_RATE_TC_BWS, req.rate_tc_bws[i]);
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_RATE_DEL ============== */
/* DEVLINK_CMD_RATE_DEL - do */
int devlink_rate_del(ynl_cpp::ynl_socket& ys, devlink_rate_del_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_RATE_DEL, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.rate_node_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_NODE_NAME, req.rate_node_name.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_LINECARD_GET ============== */
/* DEVLINK_CMD_LINECARD_GET - do */
int devlink_linecard_get_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	devlink_linecard_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_linecard_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_LINECARD_INDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->linecard_index = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_linecard_get_rsp>
devlink_linecard_get(ynl_cpp::ynl_socket& ys, devlink_linecard_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_linecard_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_LINECARD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.linecard_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_LINECARD_INDEX, req.linecard_index.value());
	}

	rsp.reset(new devlink_linecard_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_linecard_get_rsp_parse;
	yrs.rsp_cmd = 80;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_LINECARD_GET - dump */
std::unique_ptr<devlink_linecard_get_list>
devlink_linecard_get_dump(ynl_cpp::ynl_socket& ys,
			  devlink_linecard_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_linecard_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_linecard_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_linecard_get_rsp_parse;
	yds.rsp_cmd = 80;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_LINECARD_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_LINECARD_SET ============== */
/* DEVLINK_CMD_LINECARD_SET - do */
int devlink_linecard_set(ynl_cpp::ynl_socket& ys,
			 devlink_linecard_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_LINECARD_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.linecard_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_LINECARD_INDEX, req.linecard_index.value());
	}
	if (req.linecard_type.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_LINECARD_TYPE, req.linecard_type.data());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_SELFTESTS_GET ============== */
/* DEVLINK_CMD_SELFTESTS_GET - do */
int devlink_selftests_get_rsp_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	devlink_selftests_get_rsp *dst;
	const struct nlattr *attr;

	dst = (devlink_selftests_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bus_name.assign(ynl_attr_get_str(attr));
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_name.assign(ynl_attr_get_str(attr));
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<devlink_selftests_get_rsp>
devlink_selftests_get(ynl_cpp::ynl_socket& ys, devlink_selftests_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<devlink_selftests_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SELFTESTS_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}

	rsp.reset(new devlink_selftests_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = devlink_selftests_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_SELFTESTS_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEVLINK_CMD_SELFTESTS_GET - dump */
std::unique_ptr<devlink_selftests_get_list>
devlink_selftests_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<devlink_selftests_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<devlink_selftests_get_list*>(arg)->objs.emplace_back());};
	yds.cb = devlink_selftests_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_SELFTESTS_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SELFTESTS_GET, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEVLINK_CMD_SELFTESTS_RUN ============== */
/* DEVLINK_CMD_SELFTESTS_RUN - do */
int devlink_selftests_run(ynl_cpp::ynl_socket& ys,
			  devlink_selftests_run_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_SELFTESTS_RUN, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.selftests.has_value()) {
		devlink_dl_selftest_id_put(nlh, DEVLINK_ATTR_SELFTESTS, req.selftests.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== DEVLINK_CMD_NOTIFY_FILTER_SET ============== */
/* DEVLINK_CMD_NOTIFY_FILTER_SET - do */
int devlink_notify_filter_set(ynl_cpp::ynl_socket& ys,
			      devlink_notify_filter_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEVLINK_CMD_NOTIFY_FILTER_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &devlink_nest;

	if (req.bus_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req.bus_name.data());
	}
	if (req.dev_name.size() > 0) {
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req.dev_name.data());
	}
	if (req.port_index.has_value()) {
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req.port_index.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

const struct ynl_family ynl_devlink_family =  {
	.name		= "devlink",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_devlink_family() {
	return ynl_devlink_family;
};
} //namespace ynl_cpp
