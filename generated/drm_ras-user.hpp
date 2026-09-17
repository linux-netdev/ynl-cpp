/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_DRM_RAS_GEN_H
#define _LINUX_DRM_RAS_GEN_H

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

#include <drm/drm_ras.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_drm_ras_family();

/* Enums */
std::string_view drm_ras_op_str(int op);
std::string_view drm_ras_node_type_str(drm_ras_node_type value);

/* Common nested types */
/* ============== DRM_RAS_CMD_LIST_NODES ============== */
/* DRM_RAS_CMD_LIST_NODES - dump */
struct drm_ras_list_nodes_rsp {
	std::optional<__u32> node_id;
	std::string device_name;
	std::string node_name;
	std::optional<enum drm_ras_node_type> node_type;
};

struct drm_ras_list_nodes_list {
	std::list<drm_ras_list_nodes_rsp> objs;
};

std::unique_ptr<drm_ras_list_nodes_list>
drm_ras_list_nodes_dump(ynl_cpp::ynl_socket& ys);

/* ============== DRM_RAS_CMD_GET_ERROR_COUNTER ============== */
/* DRM_RAS_CMD_GET_ERROR_COUNTER - do */
struct drm_ras_get_error_counter_req {
	std::optional<__u32> node_id;
	std::optional<__u32> error_id;
};

struct drm_ras_get_error_counter_rsp {
	std::optional<__u32> error_id;
	std::string error_name;
	std::optional<__u32> error_value;
};

/*
 * Retrieve error counter for a given node. The response includes the id, the name, and even the current value of each counter.
 */
std::unique_ptr<drm_ras_get_error_counter_rsp>
drm_ras_get_error_counter(ynl_cpp::ynl_socket& ys,
			  drm_ras_get_error_counter_req& req);

/* DRM_RAS_CMD_GET_ERROR_COUNTER - dump */
struct drm_ras_get_error_counter_req_dump {
	std::optional<__u32> node_id;
};

struct drm_ras_get_error_counter_list {
	std::list<drm_ras_get_error_counter_rsp> objs;
};

std::unique_ptr<drm_ras_get_error_counter_list>
drm_ras_get_error_counter_dump(ynl_cpp::ynl_socket& ys,
			       drm_ras_get_error_counter_req_dump& req);

/* ============== DRM_RAS_CMD_CLEAR_ERROR_COUNTER ============== */
/* DRM_RAS_CMD_CLEAR_ERROR_COUNTER - do */
struct drm_ras_clear_error_counter_req {
	std::optional<__u32> node_id;
	std::optional<__u32> error_id;
};

/*
 * Clear error counter for a given node. The request includes the error-id and node-id of the counter to be cleared.
 */
int drm_ras_clear_error_counter(ynl_cpp::ynl_socket& ys,
				drm_ras_clear_error_counter_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_DRM_RAS_GEN_H */
