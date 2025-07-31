/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_LOCKD_GEN_H
#define _LINUX_LOCKD_GEN_H

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

#include <linux/lockd_netlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_lockd_family();

/* Enums */
std::string_view lockd_op_str(int op);

/* Common nested types */
/* ============== LOCKD_CMD_SERVER_SET ============== */
/* LOCKD_CMD_SERVER_SET - do */
struct lockd_server_set_req {
	std::optional<__u32> gracetime;
	std::optional<__u16> tcp_port;
	std::optional<__u16> udp_port;
};

/*
 * set the lockd server parameters
 */
int lockd_server_set(ynl_cpp::ynl_socket& ys, lockd_server_set_req& req);

/* ============== LOCKD_CMD_SERVER_GET ============== */
/* LOCKD_CMD_SERVER_GET - do */

struct lockd_server_get_rsp {
	std::optional<__u32> gracetime;
	std::optional<__u16> tcp_port;
	std::optional<__u16> udp_port;
};

/*
 * get the lockd server parameters
 */
std::unique_ptr<lockd_server_get_rsp>
lockd_server_get(ynl_cpp::ynl_socket& ys);

} //namespace ynl_cpp
#endif /* _LINUX_LOCKD_GEN_H */
