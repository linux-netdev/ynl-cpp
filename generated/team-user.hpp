/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_TEAM_GEN_H
#define _LINUX_TEAM_GEN_H

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

#include <linux/if_team.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_team_family();

/* Enums */
std::string_view team_op_str(int op);

/* Common nested types */
struct team_attr_option {
	std::string name;
	bool changed{};
	std::optional<__u8> type;
	std::vector<__u8> data;
	bool removed{};
	std::optional<__u32> port_ifindex;
	std::optional<__u32> array_index;
};

struct team_attr_port {
	std::optional<__u32> ifindex;
	bool changed{};
	bool linkup{};
	std::optional<__u32> speed;
	std::optional<__u8> duplex;
	bool removed{};
};

struct team_item_option {
	std::optional<team_attr_option> option;
};

struct team_item_port {
	std::optional<team_attr_port> port;
};

/* ============== TEAM_CMD_NOOP ============== */
/* TEAM_CMD_NOOP - do */

struct team_noop_rsp {
	std::optional<__u32> team_ifindex;
};

/*
 * No operation
 */
std::unique_ptr<team_noop_rsp> team_noop(ynl_cpp::ynl_socket& ys);

/* ============== TEAM_CMD_OPTIONS_SET ============== */
/* TEAM_CMD_OPTIONS_SET - do */
struct team_options_set_req {
	std::optional<__u32> team_ifindex;
	std::optional<team_item_option> list_option;
};

struct team_options_set_rsp {
	std::optional<__u32> team_ifindex;
	std::optional<team_item_option> list_option;
};

/*
 * Set team options
 */
std::unique_ptr<team_options_set_rsp>
team_options_set(ynl_cpp::ynl_socket& ys, team_options_set_req& req);

/* ============== TEAM_CMD_OPTIONS_GET ============== */
/* TEAM_CMD_OPTIONS_GET - do */
struct team_options_get_req {
	std::optional<__u32> team_ifindex;
};

struct team_options_get_rsp {
	std::optional<__u32> team_ifindex;
	std::optional<team_item_option> list_option;
};

/*
 * Get team options info
 */
std::unique_ptr<team_options_get_rsp>
team_options_get(ynl_cpp::ynl_socket& ys, team_options_get_req& req);

/* ============== TEAM_CMD_PORT_LIST_GET ============== */
/* TEAM_CMD_PORT_LIST_GET - do */
struct team_port_list_get_req {
	std::optional<__u32> team_ifindex;
};

struct team_port_list_get_rsp {
	std::optional<__u32> team_ifindex;
	std::optional<team_item_port> list_port;
};

/*
 * Get team ports info
 */
std::unique_ptr<team_port_list_get_rsp>
team_port_list_get(ynl_cpp::ynl_socket& ys, team_port_list_get_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_TEAM_GEN_H */
