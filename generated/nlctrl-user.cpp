// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "nlctrl-user.hpp"

#include <array>

#include <linux/genetlink.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, CTRL_CMD_GETPOLICY + 1> nlctrl_op_strmap = []() {
	std::array<std::string_view, CTRL_CMD_GETPOLICY + 1> arr{};
	arr[1] = "getfamily";
	arr[CTRL_CMD_GETPOLICY] = "getpolicy";
	return arr;
} ();

std::string_view nlctrl_op_str(int op)
{
	if (op < 0 || op >= (int)(nlctrl_op_strmap.size())) {
		return "";
	}
	return nlctrl_op_strmap[op];
}

static constexpr std::array<std::string_view, 4 + 1> nlctrl_op_flags_strmap = []() {
	std::array<std::string_view, 4 + 1> arr{};
	arr[0] = "admin-perm";
	arr[1] = "cmd-cap-do";
	arr[2] = "cmd-cap-dump";
	arr[3] = "cmd-cap-haspol";
	arr[4] = "uns-admin-perm";
	return arr;
} ();

std::string_view nlctrl_op_flags_str(int value)
{
	value = (int)(ffs(value) - 1);
	if (value < 0 || value >= (int)(nlctrl_op_flags_strmap.size())) {
		return "";
	}
	return nlctrl_op_flags_strmap[value];
}

static constexpr std::array<std::string_view, 17 + 1> nlctrl_attr_type_strmap = []() {
	std::array<std::string_view, 17 + 1> arr{};
	arr[0] = "invalid";
	arr[1] = "flag";
	arr[2] = "u8";
	arr[3] = "u16";
	arr[4] = "u32";
	arr[5] = "u64";
	arr[6] = "s8";
	arr[7] = "s16";
	arr[8] = "s32";
	arr[9] = "s64";
	arr[10] = "binary";
	arr[11] = "string";
	arr[12] = "nul-string";
	arr[13] = "nested";
	arr[14] = "nested-array";
	arr[15] = "bitfield32";
	arr[16] = "sint";
	arr[17] = "uint";
	return arr;
} ();

std::string_view nlctrl_attr_type_str(netlink_attribute_type value)
{
	if (value < 0 || value >= (int)(nlctrl_attr_type_strmap.size())) {
		return "";
	}
	return nlctrl_attr_type_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,CTRL_ATTR_OP_MAX + 1> nlctrl_op_attrs_policy = []() {
	std::array<ynl_policy_attr,CTRL_ATTR_OP_MAX + 1> arr{};
	arr[CTRL_ATTR_OP_ID].name = "id";
	arr[CTRL_ATTR_OP_ID].type = YNL_PT_U32;
	arr[CTRL_ATTR_OP_FLAGS].name = "flags";
	arr[CTRL_ATTR_OP_FLAGS].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nlctrl_op_attrs_nest = {
	.max_attr = static_cast<unsigned int>(CTRL_ATTR_OP_MAX),
	.table = nlctrl_op_attrs_policy.data(),
};

static std::array<ynl_policy_attr,CTRL_ATTR_MCAST_GRP_MAX + 1> nlctrl_mcast_group_attrs_policy = []() {
	std::array<ynl_policy_attr,CTRL_ATTR_MCAST_GRP_MAX + 1> arr{};
	arr[CTRL_ATTR_MCAST_GRP_NAME].name = "name";
	arr[CTRL_ATTR_MCAST_GRP_NAME].type  = YNL_PT_NUL_STR;
	arr[CTRL_ATTR_MCAST_GRP_ID].name = "id";
	arr[CTRL_ATTR_MCAST_GRP_ID].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nlctrl_mcast_group_attrs_nest = {
	.max_attr = static_cast<unsigned int>(CTRL_ATTR_MCAST_GRP_MAX),
	.table = nlctrl_mcast_group_attrs_policy.data(),
};

static std::array<ynl_policy_attr,NL_POLICY_TYPE_ATTR_MAX + 1> nlctrl_policy_attrs_policy = []() {
	std::array<ynl_policy_attr,NL_POLICY_TYPE_ATTR_MAX + 1> arr{};
	arr[NL_POLICY_TYPE_ATTR_TYPE].name = "type";
	arr[NL_POLICY_TYPE_ATTR_TYPE].type = YNL_PT_U32;
	arr[NL_POLICY_TYPE_ATTR_MIN_VALUE_S].name = "min-value-s";
	arr[NL_POLICY_TYPE_ATTR_MIN_VALUE_S].type = YNL_PT_U64;
	arr[NL_POLICY_TYPE_ATTR_MAX_VALUE_S].name = "max-value-s";
	arr[NL_POLICY_TYPE_ATTR_MAX_VALUE_S].type = YNL_PT_U64;
	arr[NL_POLICY_TYPE_ATTR_MIN_VALUE_U].name = "min-value-u";
	arr[NL_POLICY_TYPE_ATTR_MIN_VALUE_U].type = YNL_PT_U64;
	arr[NL_POLICY_TYPE_ATTR_MAX_VALUE_U].name = "max-value-u";
	arr[NL_POLICY_TYPE_ATTR_MAX_VALUE_U].type = YNL_PT_U64;
	arr[NL_POLICY_TYPE_ATTR_MIN_LENGTH].name = "min-length";
	arr[NL_POLICY_TYPE_ATTR_MIN_LENGTH].type = YNL_PT_U32;
	arr[NL_POLICY_TYPE_ATTR_MAX_LENGTH].name = "max-length";
	arr[NL_POLICY_TYPE_ATTR_MAX_LENGTH].type = YNL_PT_U32;
	arr[NL_POLICY_TYPE_ATTR_POLICY_IDX].name = "policy-idx";
	arr[NL_POLICY_TYPE_ATTR_POLICY_IDX].type = YNL_PT_U32;
	arr[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE].name = "policy-maxtype";
	arr[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE].type = YNL_PT_U32;
	arr[NL_POLICY_TYPE_ATTR_BITFIELD32_MASK].name = "bitfield32-mask";
	arr[NL_POLICY_TYPE_ATTR_BITFIELD32_MASK].type = YNL_PT_U32;
	arr[NL_POLICY_TYPE_ATTR_MASK].name = "mask";
	arr[NL_POLICY_TYPE_ATTR_MASK].type = YNL_PT_U64;
	arr[NL_POLICY_TYPE_ATTR_PAD].name = "pad";
	arr[NL_POLICY_TYPE_ATTR_PAD].type = YNL_PT_IGNORE;
	return arr;
} ();

struct ynl_policy_nest nlctrl_policy_attrs_nest = {
	.max_attr = static_cast<unsigned int>(NL_POLICY_TYPE_ATTR_MAX),
	.table = nlctrl_policy_attrs_policy.data(),
};

static std::array<ynl_policy_attr,CTRL_ATTR_POLICY_MAX + 1> nlctrl_op_policy_attrs_policy = []() {
	std::array<ynl_policy_attr,CTRL_ATTR_POLICY_MAX + 1> arr{};
	arr[CTRL_ATTR_POLICY_DO].name = "do";
	arr[CTRL_ATTR_POLICY_DO].type = YNL_PT_U32;
	arr[CTRL_ATTR_POLICY_DUMP].name = "dump";
	arr[CTRL_ATTR_POLICY_DUMP].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nlctrl_op_policy_attrs_nest = {
	.max_attr = static_cast<unsigned int>(CTRL_ATTR_POLICY_MAX),
	.table = nlctrl_op_policy_attrs_policy.data(),
};

static std::array<ynl_policy_attr,CTRL_ATTR_MAX + 1> nlctrl_ctrl_attrs_policy = []() {
	std::array<ynl_policy_attr,CTRL_ATTR_MAX + 1> arr{};
	arr[CTRL_ATTR_FAMILY_ID].name = "family-id";
	arr[CTRL_ATTR_FAMILY_ID].type = YNL_PT_U16;
	arr[CTRL_ATTR_FAMILY_NAME].name = "family-name";
	arr[CTRL_ATTR_FAMILY_NAME].type  = YNL_PT_NUL_STR;
	arr[CTRL_ATTR_VERSION].name = "version";
	arr[CTRL_ATTR_VERSION].type = YNL_PT_U32;
	arr[CTRL_ATTR_HDRSIZE].name = "hdrsize";
	arr[CTRL_ATTR_HDRSIZE].type = YNL_PT_U32;
	arr[CTRL_ATTR_MAXATTR].name = "maxattr";
	arr[CTRL_ATTR_MAXATTR].type = YNL_PT_U32;
	arr[CTRL_ATTR_OPS].name = "ops";
	arr[CTRL_ATTR_OPS].type = YNL_PT_NEST;
	arr[CTRL_ATTR_OPS].nest = &nlctrl_op_attrs_nest;
	arr[CTRL_ATTR_MCAST_GROUPS].name = "mcast-groups";
	arr[CTRL_ATTR_MCAST_GROUPS].type = YNL_PT_NEST;
	arr[CTRL_ATTR_MCAST_GROUPS].nest = &nlctrl_mcast_group_attrs_nest;
	arr[CTRL_ATTR_POLICY].name = "policy";
	arr[CTRL_ATTR_POLICY].type = YNL_PT_NEST;
	arr[CTRL_ATTR_POLICY].nest = &nlctrl_policy_attrs_nest;
	arr[CTRL_ATTR_OP_POLICY].name = "op-policy";
	arr[CTRL_ATTR_OP_POLICY].type = YNL_PT_NEST;
	arr[CTRL_ATTR_OP_POLICY].nest = &nlctrl_op_policy_attrs_nest;
	arr[CTRL_ATTR_OP].name = "op";
	arr[CTRL_ATTR_OP].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest nlctrl_ctrl_attrs_nest = {
	.max_attr = static_cast<unsigned int>(CTRL_ATTR_MAX),
	.table = nlctrl_ctrl_attrs_policy.data(),
};

/* Common nested types */
int nlctrl_op_attrs_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested, __u32 idx)
{
	nlctrl_op_attrs *dst = (nlctrl_op_attrs *)yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_OP_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == CTRL_ATTR_OP_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int nlctrl_mcast_group_attrs_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested, __u32 idx)
{
	nlctrl_mcast_group_attrs *dst = (nlctrl_mcast_group_attrs *)yarg->data;
	const struct nlattr *attr;

	dst->idx = idx;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_MCAST_GRP_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->name.assign(ynl_attr_get_str(attr));
		} else if (type == CTRL_ATTR_MCAST_GRP_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

int nlctrl_policy_attrs_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested, __u32 attr_id,
			      __u32 policy_id)
{
	nlctrl_policy_attrs *dst = (nlctrl_policy_attrs *)yarg->data;
	const struct nlattr *attr;

	dst->attr_id = attr_id;
	dst->policy_id = policy_id;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == NL_POLICY_TYPE_ATTR_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->type = (enum netlink_attribute_type)ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MIN_VALUE_S) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->min_value_s = (__s64)ynl_attr_get_s64(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MAX_VALUE_S) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->max_value_s = (__s64)ynl_attr_get_s64(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MIN_VALUE_U) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->min_value_u = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MAX_VALUE_U) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->max_value_u = (__u64)ynl_attr_get_u64(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MIN_LENGTH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->min_length = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MAX_LENGTH) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->max_length = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_POLICY_IDX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->policy_idx = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->policy_maxtype = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_BITFIELD32_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->bitfield32_mask = (__u32)ynl_attr_get_u32(attr);
		} else if (type == NL_POLICY_TYPE_ATTR_MASK) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->mask = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

int nlctrl_op_policy_attrs_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested, __u32 op_id)
{
	nlctrl_op_policy_attrs *dst = (nlctrl_op_policy_attrs *)yarg->data;
	const struct nlattr *attr;

	dst->op_id = op_id;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_POLICY_DO) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->do_ = (__u32)ynl_attr_get_u32(attr);
		} else if (type == CTRL_ATTR_POLICY_DUMP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dump = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

/* ============== CTRL_CMD_GETFAMILY ============== */
/* CTRL_CMD_GETFAMILY - do */
int nlctrl_getfamily_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr_mcast_groups;
	unsigned int n_mcast_groups = 0;
	const struct nlattr *attr_ops;
	nlctrl_getfamily_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int n_ops = 0;
	int i;

	dst = (nlctrl_getfamily_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->mcast_groups.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (ctrl-attrs.mcast-groups)");
	}
	if (dst->ops.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (ctrl-attrs.ops)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_FAMILY_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->family_id = (__u16)ynl_attr_get_u16(attr);
		} else if (type == CTRL_ATTR_FAMILY_NAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->family_name.assign(ynl_attr_get_str(attr));
		} else if (type == CTRL_ATTR_HDRSIZE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->hdrsize = (__u32)ynl_attr_get_u32(attr);
		} else if (type == CTRL_ATTR_MAXATTR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->maxattr = (__u32)ynl_attr_get_u32(attr);
		} else if (type == CTRL_ATTR_MCAST_GROUPS) {
			const struct nlattr *attr2;

			attr_mcast_groups = attr;
		} else if (type == CTRL_ATTR_OPS) {
			const struct nlattr *attr2;

			attr_ops = attr;
		} else if (type == CTRL_ATTR_VERSION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->version = (__u32)ynl_attr_get_u32(attr);
		}
	}

	if (n_mcast_groups) {
		dst->mcast_groups.resize(n_mcast_groups);
		i = 0;
		parg.rsp_policy = &nlctrl_mcast_group_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_mcast_groups) {
			parg.data = &dst->mcast_groups[i];
			if (nlctrl_mcast_group_attrs_parse(&parg, attr, ynl_attr_type(attr))) {
				return YNL_PARSE_CB_ERROR;
			}
			i++;
		}
	}
	if (n_ops) {
		dst->ops.resize(n_ops);
		i = 0;
		parg.rsp_policy = &nlctrl_op_attrs_nest;
		ynl_attr_for_each_nested(attr, attr_ops) {
			parg.data = &dst->ops[i];
			if (nlctrl_op_attrs_parse(&parg, attr, ynl_attr_type(attr))) {
				return YNL_PARSE_CB_ERROR;
			}
			i++;
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nlctrl_getfamily_rsp>
nlctrl_getfamily(ynl_cpp::ynl_socket& ys, nlctrl_getfamily_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<nlctrl_getfamily_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, CTRL_CMD_GETFAMILY, 1);
	((struct ynl_sock*)ys)->req_policy = &nlctrl_ctrl_attrs_nest;
	yrs.yarg.rsp_policy = &nlctrl_ctrl_attrs_nest;

	if (req.family_name.size() > 0) {
		ynl_attr_put_str(nlh, CTRL_ATTR_FAMILY_NAME, req.family_name.data());
	}

	rsp.reset(new nlctrl_getfamily_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = nlctrl_getfamily_rsp_parse;
	yrs.rsp_cmd = 1;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* CTRL_CMD_GETFAMILY - dump */
std::unique_ptr<nlctrl_getfamily_list>
nlctrl_getfamily_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<nlctrl_getfamily_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nlctrl_ctrl_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<nlctrl_getfamily_list*>(arg)->objs.emplace_back());};
	yds.cb = nlctrl_getfamily_rsp_parse;
	yds.rsp_cmd = 1;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, CTRL_CMD_GETFAMILY, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== CTRL_CMD_GETPOLICY ============== */
/* CTRL_CMD_GETPOLICY - dump */
int nlctrl_getpolicy_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	nlctrl_getpolicy_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = (nlctrl_getpolicy_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == CTRL_ATTR_FAMILY_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->family_id = (__u16)ynl_attr_get_u16(attr);
		} else if (type == CTRL_ATTR_OP_POLICY) {
			const struct nlattr *attr_op_id;
			__u32 op_id;

			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &nlctrl_op_policy_attrs_nest;
			parg.data = &dst->op_policy.emplace();
			attr_op_id = (const struct nlattr*)ynl_attr_data(attr);
			op_id = ynl_attr_type(attr_op_id);
			nlctrl_op_policy_attrs_parse(&parg, attr_op_id, op_id);
		} else if (type == CTRL_ATTR_POLICY) {
			const struct nlattr *attr_policy_id, *attr_attr_id;
			__u32 policy_id, attr_id;

			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &nlctrl_policy_attrs_nest;
			parg.data = &dst->policy.emplace();
			attr_policy_id = (const struct nlattr*)ynl_attr_data(attr);
			policy_id = ynl_attr_type(attr_policy_id);
			attr_attr_id = (const struct nlattr*)ynl_attr_data(attr_policy_id);
			attr_id = ynl_attr_type(attr_attr_id);
			nlctrl_policy_attrs_parse(&parg, attr_attr_id, policy_id, attr_id);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<nlctrl_getpolicy_list>
nlctrl_getpolicy_dump(ynl_cpp::ynl_socket& ys, nlctrl_getpolicy_req& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<nlctrl_getpolicy_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &nlctrl_ctrl_attrs_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<nlctrl_getpolicy_list*>(arg)->objs.emplace_back());};
	yds.cb = nlctrl_getpolicy_rsp_parse;
	yds.rsp_cmd = CTRL_CMD_GETPOLICY;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, CTRL_CMD_GETPOLICY, 1);
	((struct ynl_sock*)ys)->req_policy = &nlctrl_ctrl_attrs_nest;

	if (req.family_name.size() > 0) {
		ynl_attr_put_str(nlh, CTRL_ATTR_FAMILY_NAME, req.family_name.data());
	}
	if (req.family_id.has_value()) {
		ynl_attr_put_u16(nlh, CTRL_ATTR_FAMILY_ID, req.family_id.value());
	}
	if (req.op.has_value()) {
		ynl_attr_put_u32(nlh, CTRL_ATTR_OP, req.op.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

const struct ynl_family ynl_nlctrl_family =  {
	.name		= "nlctrl",
	.hdr_len	= sizeof(struct genlmsghdr),
};
const struct ynl_family& get_ynl_nlctrl_family() {
	return ynl_nlctrl_family;
};
} //namespace ynl_cpp
