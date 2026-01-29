// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "binder-user.hpp"

#include <array>

#include <linux/android/binder_netlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, BINDER_CMD_REPORT + 1> binder_op_strmap = []() {
	std::array<std::string_view, BINDER_CMD_REPORT + 1> arr{};
	arr[BINDER_CMD_REPORT] = "report";
	return arr;
} ();

std::string_view binder_op_str(int op)
{
	if (op < 0 || op >= (int)(binder_op_strmap.size())) {
		return "";
	}
	return binder_op_strmap[op];
}

/* Policies */
static std::array<ynl_policy_attr,BINDER_A_REPORT_MAX + 1> binder_report_policy = []() {
	std::array<ynl_policy_attr,BINDER_A_REPORT_MAX + 1> arr{};
	arr[BINDER_A_REPORT_ERROR].name = "error";
	arr[BINDER_A_REPORT_ERROR].type = YNL_PT_U32;
	arr[BINDER_A_REPORT_CONTEXT].name = "context";
	arr[BINDER_A_REPORT_CONTEXT].type  = YNL_PT_NUL_STR;
	arr[BINDER_A_REPORT_FROM_PID].name = "from-pid";
	arr[BINDER_A_REPORT_FROM_PID].type = YNL_PT_U32;
	arr[BINDER_A_REPORT_FROM_TID].name = "from-tid";
	arr[BINDER_A_REPORT_FROM_TID].type = YNL_PT_U32;
	arr[BINDER_A_REPORT_TO_PID].name = "to-pid";
	arr[BINDER_A_REPORT_TO_PID].type = YNL_PT_U32;
	arr[BINDER_A_REPORT_TO_TID].name = "to-tid";
	arr[BINDER_A_REPORT_TO_TID].type = YNL_PT_U32;
	arr[BINDER_A_REPORT_IS_REPLY].name = "is-reply";
	arr[BINDER_A_REPORT_IS_REPLY].type = YNL_PT_FLAG;
	arr[BINDER_A_REPORT_FLAGS].name = "flags";
	arr[BINDER_A_REPORT_FLAGS].type = YNL_PT_U32;
	arr[BINDER_A_REPORT_CODE].name = "code";
	arr[BINDER_A_REPORT_CODE].type = YNL_PT_U32;
	arr[BINDER_A_REPORT_DATA_SIZE].name = "data-size";
	arr[BINDER_A_REPORT_DATA_SIZE].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest binder_report_nest = {
	.max_attr = static_cast<unsigned int>(BINDER_A_REPORT_MAX),
	.table = binder_report_policy.data(),
};

/* Common nested types */
/* BINDER_CMD_REPORT - event */
int binder_report_rsp_parse(const struct nlmsghdr *nlh,
			    struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	binder_report_rsp *dst;

	dst = (binder_report_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == BINDER_A_REPORT_ERROR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->error = (__u32)ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_CONTEXT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->context.assign(ynl_attr_get_str(attr));
		} else if (type == BINDER_A_REPORT_FROM_PID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->from_pid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_FROM_TID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->from_tid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_TO_PID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->to_pid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_TO_TID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->to_tid = (__u32)ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_IS_REPLY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == BINDER_A_REPORT_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_CODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->code = (__u32)ynl_attr_get_u32(attr);
		} else if (type == BINDER_A_REPORT_DATA_SIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->data_size = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

static void binder_report_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<binder_report*>(ntf);
	typed_ntf->obj.~binder_report_rsp();
	free(ntf);
}

static constexpr std::array<ynl_ntf_info, BINDER_CMD_REPORT + 1> binder_ntf_info = []() {
	std::array<ynl_ntf_info, BINDER_CMD_REPORT + 1> arr{};
	arr[BINDER_CMD_REPORT].policy		= &binder_report_nest;
	arr[BINDER_CMD_REPORT].cb		= binder_report_rsp_parse;
	arr[BINDER_CMD_REPORT].alloc_sz	= sizeof(binder_report);
	arr[BINDER_CMD_REPORT].free		= binder_report_free;
	return arr;
} ();

const struct ynl_family ynl_binder_family =  {
	.name		= "binder",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= binder_ntf_info.data(),
	.ntf_info_size	= binder_ntf_info.size(),
};
const struct ynl_family& get_ynl_binder_family() {
	return ynl_binder_family;
};
} //namespace ynl_cpp
