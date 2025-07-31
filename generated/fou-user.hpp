/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_FOU_GEN_H
#define _LINUX_FOU_GEN_H

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

#include <linux/fou.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_fou_family();

/* Enums */
std::string_view fou_op_str(int op);
std::string_view fou_encap_type_str(int value);

/* Common nested types */
/* ============== FOU_CMD_ADD ============== */
/* FOU_CMD_ADD - do */
struct fou_add_req {
	std::optional<__u16> port /* big-endian */;
	std::optional<__u8> ipproto;
	std::optional<__u8> type;
	bool remcsum_nopartial{};
	std::optional<__u32> local_v4;
	std::optional<__u32> peer_v4;
	std::vector<__u8> local_v6;
	std::vector<__u8> peer_v6;
	std::optional<__u16> peer_port /* big-endian */;
	std::optional<__s32> ifindex;
};

/*
 * Add port.
 */
int fou_add(ynl_cpp::ynl_socket& ys, fou_add_req& req);

/* ============== FOU_CMD_DEL ============== */
/* FOU_CMD_DEL - do */
struct fou_del_req {
	std::optional<__u8> af;
	std::optional<__s32> ifindex;
	std::optional<__u16> port /* big-endian */;
	std::optional<__u16> peer_port /* big-endian */;
	std::optional<__u32> local_v4;
	std::optional<__u32> peer_v4;
	std::vector<__u8> local_v6;
	std::vector<__u8> peer_v6;
};

/*
 * Delete port.
 */
int fou_del(ynl_cpp::ynl_socket& ys, fou_del_req& req);

/* ============== FOU_CMD_GET ============== */
/* FOU_CMD_GET - do */
struct fou_get_req {
	std::optional<__u8> af;
	std::optional<__s32> ifindex;
	std::optional<__u16> port /* big-endian */;
	std::optional<__u16> peer_port /* big-endian */;
	std::optional<__u32> local_v4;
	std::optional<__u32> peer_v4;
	std::vector<__u8> local_v6;
	std::vector<__u8> peer_v6;
};

struct fou_get_rsp {
	std::optional<__u16> port /* big-endian */;
	std::optional<__u8> ipproto;
	std::optional<__u8> type;
	bool remcsum_nopartial{};
	std::optional<__u32> local_v4;
	std::optional<__u32> peer_v4;
	std::vector<__u8> local_v6;
	std::vector<__u8> peer_v6;
	std::optional<__u16> peer_port /* big-endian */;
	std::optional<__s32> ifindex;
};

/*
 * Get tunnel info.
 */
std::unique_ptr<fou_get_rsp>
fou_get(ynl_cpp::ynl_socket& ys, fou_get_req& req);

/* FOU_CMD_GET - dump */
struct fou_get_list {
	std::list<fou_get_rsp> objs;
};

std::unique_ptr<fou_get_list> fou_get_dump(ynl_cpp::ynl_socket& ys);

} //namespace ynl_cpp
#endif /* _LINUX_FOU_GEN_H */
