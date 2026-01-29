/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_BINDER_GEN_H
#define _LINUX_BINDER_GEN_H

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

#include <linux/android/binder_netlink.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_binder_family();

/* Enums */
std::string_view binder_op_str(int op);

/* Common nested types */
/* BINDER_CMD_REPORT - event */
struct binder_report_rsp {
	std::optional<__u32> error;
	std::string context;
	std::optional<__u32> from_pid;
	std::optional<__u32> from_tid;
	std::optional<__u32> to_pid;
	std::optional<__u32> to_tid;
	bool is_reply{};
	std::optional<__u32> flags;
	std::optional<__u32> code;
	std::optional<__u32> data_size;
};

struct binder_report {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	binder_report_rsp obj __attribute__((aligned(8)));
};

} //namespace ynl_cpp
#endif /* _LINUX_BINDER_GEN_H */
