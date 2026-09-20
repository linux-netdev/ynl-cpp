// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "dev-energymodel-user.hpp"

#include <array>

#include <linux/dev_energymodel.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED + 1> dev_energymodel_op_strmap = []() {
	std::array<std::string_view, DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED + 1> arr{};
	arr[DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS] = "get-perf-domains";
	arr[DEV_ENERGYMODEL_CMD_GET_PERF_TABLE] = "get-perf-table";
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_CREATED] = "perf-domain-created";
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_UPDATED] = "perf-domain-updated";
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED] = "perf-domain-deleted";
	return arr;
} ();

std::string_view dev_energymodel_op_str(int op)
{
	if ((int)op < 0 || (int)op >= (int)(dev_energymodel_op_strmap.size())) {
		return "";
	}
	return dev_energymodel_op_strmap[op];
}

static constexpr std::array<std::string_view, 0 + 1> dev_energymodel_perf_state_flags_strmap = []() {
	std::array<std::string_view, 0 + 1> arr{};
	arr[0] = "perf-state-inefficient";
	return arr;
} ();

std::string_view
dev_energymodel_perf_state_flags_str(dev_energymodel_perf_state_flags value)
{
	value = (dev_energymodel_perf_state_flags)(ffs(value) - 1);
	if ((int)value < 0 || (int)value >= (int)(dev_energymodel_perf_state_flags_strmap.size())) {
		return "";
	}
	return dev_energymodel_perf_state_flags_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> dev_energymodel_perf_domain_flags_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "perf-domain-microwatts";
	arr[1] = "perf-domain-skip-inefficiencies";
	arr[2] = "perf-domain-artificial";
	return arr;
} ();

std::string_view
dev_energymodel_perf_domain_flags_str(dev_energymodel_perf_domain_flags value)
{
	value = (dev_energymodel_perf_domain_flags)(ffs(value) - 1);
	if ((int)value < 0 || (int)value >= (int)(dev_energymodel_perf_domain_flags_strmap.size())) {
		return "";
	}
	return dev_energymodel_perf_domain_flags_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,DEV_ENERGYMODEL_A_PERF_STATE_MAX + 1> dev_energymodel_perf_state_policy = []() {
	std::array<ynl_policy_attr,DEV_ENERGYMODEL_A_PERF_STATE_MAX + 1> arr{};
	arr[DEV_ENERGYMODEL_A_PERF_STATE_PAD].name = "pad";
	arr[DEV_ENERGYMODEL_A_PERF_STATE_PAD].type = YNL_PT_IGNORE;
	arr[DEV_ENERGYMODEL_A_PERF_STATE_PERFORMANCE].name = "performance";
	arr[DEV_ENERGYMODEL_A_PERF_STATE_PERFORMANCE].type = YNL_PT_U64;
	arr[DEV_ENERGYMODEL_A_PERF_STATE_FREQUENCY].name = "frequency";
	arr[DEV_ENERGYMODEL_A_PERF_STATE_FREQUENCY].type = YNL_PT_U64;
	arr[DEV_ENERGYMODEL_A_PERF_STATE_POWER].name = "power";
	arr[DEV_ENERGYMODEL_A_PERF_STATE_POWER].type = YNL_PT_U64;
	arr[DEV_ENERGYMODEL_A_PERF_STATE_COST].name = "cost";
	arr[DEV_ENERGYMODEL_A_PERF_STATE_COST].type = YNL_PT_U64;
	arr[DEV_ENERGYMODEL_A_PERF_STATE_FLAGS].name = "flags";
	arr[DEV_ENERGYMODEL_A_PERF_STATE_FLAGS].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest dev_energymodel_perf_state_nest = {
	.max_attr = static_cast<unsigned int>(DEV_ENERGYMODEL_A_PERF_STATE_MAX),
	.table = dev_energymodel_perf_state_policy.data(),
};

static std::array<ynl_policy_attr,DEV_ENERGYMODEL_A_PERF_DOMAIN_MAX + 1> dev_energymodel_perf_domain_policy = []() {
	std::array<ynl_policy_attr,DEV_ENERGYMODEL_A_PERF_DOMAIN_MAX + 1> arr{};
	arr[DEV_ENERGYMODEL_A_PERF_DOMAIN_PAD].name = "pad";
	arr[DEV_ENERGYMODEL_A_PERF_DOMAIN_PAD].type = YNL_PT_IGNORE;
	arr[DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID].name = "perf-domain-id";
	arr[DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID].type = YNL_PT_U32;
	arr[DEV_ENERGYMODEL_A_PERF_DOMAIN_FLAGS].name = "flags";
	arr[DEV_ENERGYMODEL_A_PERF_DOMAIN_FLAGS].type = YNL_PT_U64;
	arr[DEV_ENERGYMODEL_A_PERF_DOMAIN_CPUS].name = "cpus";
	arr[DEV_ENERGYMODEL_A_PERF_DOMAIN_CPUS].type = YNL_PT_U64;
	return arr;
} ();

struct ynl_policy_nest dev_energymodel_perf_domain_nest = {
	.max_attr = static_cast<unsigned int>(DEV_ENERGYMODEL_A_PERF_DOMAIN_MAX),
	.table = dev_energymodel_perf_domain_policy.data(),
};

static std::array<ynl_policy_attr,DEV_ENERGYMODEL_A_PERF_TABLE_MAX + 1> dev_energymodel_perf_table_policy = []() {
	std::array<ynl_policy_attr,DEV_ENERGYMODEL_A_PERF_TABLE_MAX + 1> arr{};
	arr[DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID].name = "perf-domain-id";
	arr[DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID].type = YNL_PT_U32;
	arr[DEV_ENERGYMODEL_A_PERF_TABLE_PERF_STATE].name = "perf-state";
	arr[DEV_ENERGYMODEL_A_PERF_TABLE_PERF_STATE].type = YNL_PT_NEST;
	arr[DEV_ENERGYMODEL_A_PERF_TABLE_PERF_STATE].nest = &dev_energymodel_perf_state_nest;
	return arr;
} ();

struct ynl_policy_nest dev_energymodel_perf_table_nest = {
	.max_attr = static_cast<unsigned int>(DEV_ENERGYMODEL_A_PERF_TABLE_MAX),
	.table = dev_energymodel_perf_table_policy.data(),
};

/* Common nested types */
int dev_energymodel_perf_state_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	dev_energymodel_perf_state *dst = (dev_energymodel_perf_state *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEV_ENERGYMODEL_A_PERF_STATE_PERFORMANCE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->performance = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEV_ENERGYMODEL_A_PERF_STATE_FREQUENCY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->frequency = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEV_ENERGYMODEL_A_PERF_STATE_POWER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->power = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEV_ENERGYMODEL_A_PERF_STATE_COST) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cost = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEV_ENERGYMODEL_A_PERF_STATE_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u64)ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

/* ============== DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS ============== */
/* DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS - do */
int dev_energymodel_get_perf_domains_rsp_parse(const struct nlmsghdr *nlh,
					       struct ynl_parse_arg *yarg)
{
	dev_energymodel_get_perf_domains_rsp *dst;
	const struct nlattr *attr;
	unsigned int n_cpus = 0;
	int i;

	dst = (dev_energymodel_get_perf_domains_rsp*)yarg->data;

	if (dst->cpus.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (perf-domain.cpus)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->perf_domain_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEV_ENERGYMODEL_A_PERF_DOMAIN_FLAGS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->flags = (__u64)ynl_attr_get_u64(attr);
		} else if (type == DEV_ENERGYMODEL_A_PERF_DOMAIN_CPUS) {
			n_cpus++;
		}
	}

	if (n_cpus) {
		dst->cpus.resize(n_cpus);
		i = 0;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == DEV_ENERGYMODEL_A_PERF_DOMAIN_CPUS) {
				dst->cpus[i] = ynl_attr_get_u64(attr);
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<dev_energymodel_get_perf_domains_rsp>
dev_energymodel_get_perf_domains(ynl_cpp::ynl_socket& ys,
				 dev_energymodel_get_perf_domains_req& req)
{
	std::unique_ptr<dev_energymodel_get_perf_domains_rsp> rsp;
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS, 1);
	((struct ynl_sock*)ys)->req_policy = &dev_energymodel_perf_domain_nest;
	yrs.yarg.rsp_policy = &dev_energymodel_perf_domain_nest;

	if (req.perf_domain_id.has_value()) {
		ynl_attr_put_u32(nlh, DEV_ENERGYMODEL_A_PERF_DOMAIN_PERF_DOMAIN_ID, req.perf_domain_id.value());
	}

	rsp.reset(new dev_energymodel_get_perf_domains_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = dev_energymodel_get_perf_domains_rsp_parse;
	yrs.rsp_cmd = DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS - dump */
std::unique_ptr<dev_energymodel_get_perf_domains_list>
dev_energymodel_get_perf_domains_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<dev_energymodel_get_perf_domains_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &dev_energymodel_perf_domain_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<dev_energymodel_get_perf_domains_list*>(arg)->objs.emplace_back());};
	yds.cb = dev_energymodel_get_perf_domains_rsp_parse;
	yds.rsp_cmd = DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, DEV_ENERGYMODEL_CMD_GET_PERF_DOMAINS, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* ============== DEV_ENERGYMODEL_CMD_GET_PERF_TABLE ============== */
/* DEV_ENERGYMODEL_CMD_GET_PERF_TABLE - do */
int dev_energymodel_get_perf_table_rsp_parse(const struct nlmsghdr *nlh,
					     struct ynl_parse_arg *yarg)
{
	dev_energymodel_get_perf_table_rsp *dst;
	unsigned int n_perf_state = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = (dev_energymodel_get_perf_table_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->perf_state.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (perf-table.perf-state)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->perf_domain_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == DEV_ENERGYMODEL_A_PERF_TABLE_PERF_STATE) {
			n_perf_state++;
		}
	}

	if (n_perf_state) {
		dst->perf_state.resize(n_perf_state);
		i = 0;
		parg.rsp_policy = &dev_energymodel_perf_state_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == DEV_ENERGYMODEL_A_PERF_TABLE_PERF_STATE) {
				parg.data = &dst->perf_state[i];
				if (dev_energymodel_perf_state_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<dev_energymodel_get_perf_table_rsp>
dev_energymodel_get_perf_table(ynl_cpp::ynl_socket& ys,
			       dev_energymodel_get_perf_table_req& req)
{
	std::unique_ptr<dev_energymodel_get_perf_table_rsp> rsp;
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, DEV_ENERGYMODEL_CMD_GET_PERF_TABLE, 1);
	((struct ynl_sock*)ys)->req_policy = &dev_energymodel_perf_table_nest;
	yrs.yarg.rsp_policy = &dev_energymodel_perf_table_nest;

	if (req.perf_domain_id.has_value()) {
		ynl_attr_put_u32(nlh, DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID, req.perf_domain_id.value());
	}

	rsp.reset(new dev_energymodel_get_perf_table_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = dev_energymodel_get_perf_table_rsp_parse;
	yrs.rsp_cmd = DEV_ENERGYMODEL_CMD_GET_PERF_TABLE;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* DEV_ENERGYMODEL_CMD_GET_PERF_TABLE - notify */
static void dev_energymodel_get_perf_table_ntf_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<dev_energymodel_get_perf_table_ntf*>(ntf);
	typed_ntf->obj.~dev_energymodel_get_perf_table_rsp();
	free(ntf);
}

/* DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED - event */
int dev_energymodel_perf_domain_deleted_rsp_parse(const struct nlmsghdr *nlh,
						  struct ynl_parse_arg *yarg)
{
	dev_energymodel_perf_domain_deleted_rsp *dst;
	const struct nlattr *attr;

	dst = (dev_energymodel_perf_domain_deleted_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEV_ENERGYMODEL_A_PERF_TABLE_PERF_DOMAIN_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->perf_domain_id = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

static void dev_energymodel_perf_domain_deleted_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<dev_energymodel_perf_domain_deleted*>(ntf);
	typed_ntf->obj.~dev_energymodel_perf_domain_deleted_rsp();
	free(ntf);
}

static constexpr std::array<ynl_ntf_info, DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED + 1> dev_energymodel_ntf_info = []() {
	std::array<ynl_ntf_info, DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED + 1> arr{};
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_CREATED].policy		= &dev_energymodel_perf_table_nest;
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_CREATED].cb		= dev_energymodel_get_perf_table_rsp_parse;
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_CREATED].alloc_sz	= sizeof(dev_energymodel_get_perf_table_ntf);
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_CREATED].free		= dev_energymodel_get_perf_table_ntf_free;
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_UPDATED].policy		= &dev_energymodel_perf_table_nest;
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_UPDATED].cb		= dev_energymodel_get_perf_table_rsp_parse;
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_UPDATED].alloc_sz	= sizeof(dev_energymodel_get_perf_table_ntf);
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_UPDATED].free		= dev_energymodel_get_perf_table_ntf_free;
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED].policy		= &dev_energymodel_perf_table_nest;
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED].cb		= dev_energymodel_perf_domain_deleted_rsp_parse;
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED].alloc_sz	= sizeof(dev_energymodel_perf_domain_deleted);
	arr[DEV_ENERGYMODEL_CMD_PERF_DOMAIN_DELETED].free		= dev_energymodel_perf_domain_deleted_free;
	return arr;
} ();

const struct ynl_family ynl_dev_energymodel_family =  {
	.name		= "dev_energymodel",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= dev_energymodel_ntf_info.data(),
	.ntf_info_size	= dev_energymodel_ntf_info.size(),
};
const struct ynl_family& get_ynl_dev_energymodel_family() {
	return ynl_dev_energymodel_family;
};
} //namespace ynl_cpp
