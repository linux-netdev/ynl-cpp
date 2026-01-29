/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_DPLL_GEN_H
#define _LINUX_DPLL_GEN_H

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

namespace ynl_cpp {
const struct ynl_family& get_ynl_dpll_family();

/* Enums */
std::string_view dpll_op_str(int op);
std::string_view dpll_mode_str(dpll_mode value);
std::string_view dpll_lock_status_str(dpll_lock_status value);
std::string_view dpll_lock_status_error_str(dpll_lock_status_error value);
std::string_view dpll_clock_quality_level_str(dpll_clock_quality_level value);
std::string_view dpll_type_str(dpll_type value);
std::string_view dpll_pin_type_str(dpll_pin_type value);
std::string_view dpll_pin_direction_str(dpll_pin_direction value);
std::string_view dpll_pin_state_str(dpll_pin_state value);
std::string_view dpll_pin_capabilities_str(dpll_pin_capabilities value);
std::string_view dpll_feature_state_str(dpll_feature_state value);

/* Common nested types */
struct dpll_frequency_range {
	std::optional<__u64> frequency_min;
	std::optional<__u64> frequency_max;
};

struct dpll_pin_parent_device {
	std::optional<__u32> parent_id;
	std::optional<enum dpll_pin_direction> direction;
	std::optional<__u32> prio;
	std::optional<enum dpll_pin_state> state;
	std::optional<__s64> phase_offset;
};

struct dpll_pin_parent_pin {
	std::optional<__u32> parent_id;
	std::optional<enum dpll_pin_state> state;
};

struct dpll_reference_sync {
	std::optional<__u32> id;
	std::optional<enum dpll_pin_state> state;
};

/* ============== DPLL_CMD_DEVICE_ID_GET ============== */
/* DPLL_CMD_DEVICE_ID_GET - do */
struct dpll_device_id_get_req {
	std::string module_name;
	std::optional<__u64> clock_id;
	std::optional<enum dpll_type> type;
};

struct dpll_device_id_get_rsp {
	std::optional<__u32> id;
};

/*
 * Get id of dpll device that matches given attributes

 */
std::unique_ptr<dpll_device_id_get_rsp>
dpll_device_id_get(ynl_cpp::ynl_socket& ys, dpll_device_id_get_req& req);

/* ============== DPLL_CMD_DEVICE_GET ============== */
/* DPLL_CMD_DEVICE_GET - do */
struct dpll_device_get_req {
	std::optional<__u32> id;
};

struct dpll_device_get_rsp {
	std::optional<__u32> id;
	std::string module_name;
	std::optional<enum dpll_mode> mode;
	std::vector<__u32> mode_supported;
	std::optional<enum dpll_lock_status> lock_status;
	std::optional<enum dpll_lock_status_error> lock_status_error;
	std::optional<__s32> temp;
	std::optional<__u64> clock_id;
	std::optional<enum dpll_type> type;
	std::optional<enum dpll_feature_state> phase_offset_monitor;
	std::optional<__u32> phase_offset_avg_factor;
};

/*
 * Get list of DPLL devices (dump) or attributes of a single dpll device

 */
std::unique_ptr<dpll_device_get_rsp>
dpll_device_get(ynl_cpp::ynl_socket& ys, dpll_device_get_req& req);

/* DPLL_CMD_DEVICE_GET - dump */
struct dpll_device_get_list {
	std::list<dpll_device_get_rsp> objs;
};

std::unique_ptr<dpll_device_get_list>
dpll_device_get_dump(ynl_cpp::ynl_socket& ys);

/* DPLL_CMD_DEVICE_GET - notify */
struct dpll_device_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	dpll_device_get_rsp obj __attribute__((aligned(8)));
};

/* ============== DPLL_CMD_DEVICE_SET ============== */
/* DPLL_CMD_DEVICE_SET - do */
struct dpll_device_set_req {
	std::optional<__u32> id;
	std::optional<enum dpll_feature_state> phase_offset_monitor;
	std::optional<__u32> phase_offset_avg_factor;
};

/*
 * Set attributes for a DPLL device
 */
int dpll_device_set(ynl_cpp::ynl_socket& ys, dpll_device_set_req& req);

/* ============== DPLL_CMD_PIN_ID_GET ============== */
/* DPLL_CMD_PIN_ID_GET - do */
struct dpll_pin_id_get_req {
	std::string module_name;
	std::optional<__u64> clock_id;
	std::string board_label;
	std::string panel_label;
	std::string package_label;
	std::optional<enum dpll_pin_type> type;
};

struct dpll_pin_id_get_rsp {
	std::optional<__u32> id;
};

/*
 * Get id of a pin that matches given attributes

 */
std::unique_ptr<dpll_pin_id_get_rsp>
dpll_pin_id_get(ynl_cpp::ynl_socket& ys, dpll_pin_id_get_req& req);

/* ============== DPLL_CMD_PIN_GET ============== */
/* DPLL_CMD_PIN_GET - do */
struct dpll_pin_get_req {
	std::optional<__u32> id;
};

struct dpll_pin_get_rsp {
	std::optional<__u32> id;
	std::string module_name;
	std::optional<__u64> clock_id;
	std::string board_label;
	std::string panel_label;
	std::string package_label;
	std::optional<enum dpll_pin_type> type;
	std::optional<__u64> frequency;
	std::vector<dpll_frequency_range> frequency_supported;
	std::optional<__u32> capabilities;
	std::vector<dpll_pin_parent_device> parent_device;
	std::vector<dpll_pin_parent_pin> parent_pin;
	std::optional<__u32> phase_adjust_gran;
	std::optional<__s32> phase_adjust_min;
	std::optional<__s32> phase_adjust_max;
	std::optional<__s32> phase_adjust;
	std::optional<__s64> fractional_frequency_offset;
	std::optional<__u64> esync_frequency;
	std::vector<dpll_frequency_range> esync_frequency_supported;
	std::optional<__u32> esync_pulse;
	std::vector<dpll_reference_sync> reference_sync;
};

/*
 * Get list of pins and its attributes.

- dump request without any attributes given - list all the pins in the
  system
- dump request with target dpll - list all the pins registered with
  a given dpll device
- do request with target dpll and target pin - single pin attributes

 */
std::unique_ptr<dpll_pin_get_rsp>
dpll_pin_get(ynl_cpp::ynl_socket& ys, dpll_pin_get_req& req);

/* DPLL_CMD_PIN_GET - dump */
struct dpll_pin_get_req_dump {
	std::optional<__u32> id;
};

struct dpll_pin_get_list {
	std::list<dpll_pin_get_rsp> objs;
};

std::unique_ptr<dpll_pin_get_list>
dpll_pin_get_dump(ynl_cpp::ynl_socket& ys, dpll_pin_get_req_dump& req);

/* DPLL_CMD_PIN_GET - notify */
struct dpll_pin_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	dpll_pin_get_rsp obj __attribute__((aligned(8)));
};

/* ============== DPLL_CMD_PIN_SET ============== */
/* DPLL_CMD_PIN_SET - do */
struct dpll_pin_set_req {
	std::optional<__u32> id;
	std::optional<__u64> frequency;
	std::optional<enum dpll_pin_direction> direction;
	std::optional<__u32> prio;
	std::optional<enum dpll_pin_state> state;
	std::vector<dpll_pin_parent_device> parent_device;
	std::vector<dpll_pin_parent_pin> parent_pin;
	std::optional<__s32> phase_adjust;
	std::optional<__u64> esync_frequency;
	std::vector<dpll_reference_sync> reference_sync;
};

/*
 * Set attributes of a target pin
 */
int dpll_pin_set(ynl_cpp::ynl_socket& ys, dpll_pin_set_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_DPLL_GEN_H */
