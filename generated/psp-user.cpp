// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "psp-user.hpp"

#include <array>

#include <linux/psp.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, PSP_CMD_GET_STATS + 1> psp_op_strmap = []() {
	std::array<std::string_view, PSP_CMD_GET_STATS + 1> arr{};
	arr[PSP_CMD_DEV_GET] = "dev-get";
	arr[PSP_CMD_DEV_ADD_NTF] = "dev-add-ntf";
	arr[PSP_CMD_DEV_DEL_NTF] = "dev-del-ntf";
	arr[PSP_CMD_DEV_SET] = "dev-set";
	arr[PSP_CMD_DEV_CHANGE_NTF] = "dev-change-ntf";
	arr[PSP_CMD_KEY_ROTATE] = "key-rotate";
	arr[PSP_CMD_KEY_ROTATE_NTF] = "key-rotate-ntf";
	arr[PSP_CMD_RX_ASSOC] = "rx-assoc";
	arr[PSP_CMD_TX_ASSOC] = "tx-assoc";
	arr[PSP_CMD_GET_STATS] = "get-stats";
	return arr;
} ();

std::string_view psp_op_str(int op)
{
	if (op < 0 || op >= (int)(psp_op_strmap.size())) {
		return "";
	}
	return psp_op_strmap[op];
}

static constexpr std::array<std::string_view, 3 + 1> psp_version_strmap = []() {
	std::array<std::string_view, 3 + 1> arr{};
	arr[0] = "hdr0-aes-gcm-128";
	arr[1] = "hdr0-aes-gcm-256";
	arr[2] = "hdr0-aes-gmac-128";
	arr[3] = "hdr0-aes-gmac-256";
	return arr;
} ();

std::string_view psp_version_str(psp_version value)
{
	if (value < 0 || value >= (int)(psp_version_strmap.size())) {
		return "";
	}
	return psp_version_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,PSP_A_KEYS_MAX + 1> psp_keys_policy = []() {
	std::array<ynl_policy_attr,PSP_A_KEYS_MAX + 1> arr{};
	arr[PSP_A_KEYS_KEY].name = "key";
	arr[PSP_A_KEYS_KEY].type = YNL_PT_BINARY;
	arr[PSP_A_KEYS_SPI].name = "spi";
	arr[PSP_A_KEYS_SPI].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest psp_keys_nest = {
	.max_attr = static_cast<unsigned int>(PSP_A_KEYS_MAX),
	.table = psp_keys_policy.data(),
};

static std::array<ynl_policy_attr,PSP_A_DEV_MAX + 1> psp_dev_policy = []() {
	std::array<ynl_policy_attr,PSP_A_DEV_MAX + 1> arr{};
	arr[PSP_A_DEV_ID].name = "id";
	arr[PSP_A_DEV_ID].type = YNL_PT_U32;
	arr[PSP_A_DEV_IFINDEX].name = "ifindex";
	arr[PSP_A_DEV_IFINDEX].type = YNL_PT_U32;
	arr[PSP_A_DEV_PSP_VERSIONS_CAP].name = "psp-versions-cap";
	arr[PSP_A_DEV_PSP_VERSIONS_CAP].type = YNL_PT_U32;
	arr[PSP_A_DEV_PSP_VERSIONS_ENA].name = "psp-versions-ena";
	arr[PSP_A_DEV_PSP_VERSIONS_ENA].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest psp_dev_nest = {
	.max_attr = static_cast<unsigned int>(PSP_A_DEV_MAX),
	.table = psp_dev_policy.data(),
};

static std::array<ynl_policy_attr,PSP_A_ASSOC_MAX + 1> psp_assoc_policy = []() {
	std::array<ynl_policy_attr,PSP_A_ASSOC_MAX + 1> arr{};
	arr[PSP_A_ASSOC_DEV_ID].name = "dev-id";
	arr[PSP_A_ASSOC_DEV_ID].type = YNL_PT_U32;
	arr[PSP_A_ASSOC_VERSION].name = "version";
	arr[PSP_A_ASSOC_VERSION].type = YNL_PT_U32;
	arr[PSP_A_ASSOC_RX_KEY].name = "rx-key";
	arr[PSP_A_ASSOC_RX_KEY].type = YNL_PT_NEST;
	arr[PSP_A_ASSOC_RX_KEY].nest = &psp_keys_nest;
	arr[PSP_A_ASSOC_TX_KEY].name = "tx-key";
	arr[PSP_A_ASSOC_TX_KEY].type = YNL_PT_NEST;
	arr[PSP_A_ASSOC_TX_KEY].nest = &psp_keys_nest;
	arr[PSP_A_ASSOC_SOCK_FD].name = "sock-fd";
	arr[PSP_A_ASSOC_SOCK_FD].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest psp_assoc_nest = {
	.max_attr = static_cast<unsigned int>(PSP_A_ASSOC_MAX),
	.table = psp_assoc_policy.data(),
};

static std::array<ynl_policy_attr,PSP_A_STATS_MAX + 1> psp_stats_policy = []() {
	std::array<ynl_policy_attr,PSP_A_STATS_MAX + 1> arr{};
	arr[PSP_A_STATS_DEV_ID].name = "dev-id";
	arr[PSP_A_STATS_DEV_ID].type = YNL_PT_U32;
	arr[PSP_A_STATS_KEY_ROTATIONS].name = "key-rotations";
	arr[PSP_A_STATS_KEY_ROTATIONS].type = YNL_PT_UINT;
	arr[PSP_A_STATS_STALE_EVENTS].name = "stale-events";
	arr[PSP_A_STATS_STALE_EVENTS].type = YNL_PT_UINT;
	arr[PSP_A_STATS_RX_PACKETS].name = "rx-packets";
	arr[PSP_A_STATS_RX_PACKETS].type = YNL_PT_UINT;
	arr[PSP_A_STATS_RX_BYTES].name = "rx-bytes";
	arr[PSP_A_STATS_RX_BYTES].type = YNL_PT_UINT;
	arr[PSP_A_STATS_RX_AUTH_FAIL].name = "rx-auth-fail";
	arr[PSP_A_STATS_RX_AUTH_FAIL].type = YNL_PT_UINT;
	arr[PSP_A_STATS_RX_ERROR].name = "rx-error";
	arr[PSP_A_STATS_RX_ERROR].type = YNL_PT_UINT;
	arr[PSP_A_STATS_RX_BAD].name = "rx-bad";
	arr[PSP_A_STATS_RX_BAD].type = YNL_PT_UINT;
	arr[PSP_A_STATS_TX_PACKETS].name = "tx-packets";
	arr[PSP_A_STATS_TX_PACKETS].type = YNL_PT_UINT;
	arr[PSP_A_STATS_TX_BYTES].name = "tx-bytes";
	arr[PSP_A_STATS_TX_BYTES].type = YNL_PT_UINT;
	arr[PSP_A_STATS_TX_ERROR].name = "tx-error";
	arr[PSP_A_STATS_TX_ERROR].type = YNL_PT_UINT;
	return arr;
} ();

struct ynl_policy_nest psp_stats_nest = {
	.max_attr = static_cast<unsigned int>(PSP_A_STATS_MAX),
	.table = psp_stats_policy.data(),
};

/* Common nested types */
int psp_keys_put(struct nlmsghdr *nlh, unsigned int attr_type,
		 const psp_keys&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.key.size() > 0) {
		ynl_attr_put(nlh, PSP_A_KEYS_KEY, obj.key.data(), obj.key.size());
	}
	if (obj.spi.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_KEYS_SPI, obj.spi.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int psp_keys_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	psp_keys *dst = (psp_keys *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_KEYS_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->key.assign(data, data + len);
		} else if (type == PSP_A_KEYS_SPI) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->spi = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

/* ============== PSP_CMD_DEV_GET ============== */
/* PSP_CMD_DEV_GET - do */
int psp_dev_get_rsp_parse(const struct nlmsghdr *nlh,
			  struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	psp_dev_get_rsp *dst;

	dst = (psp_dev_get_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_DEV_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == PSP_A_DEV_IFINDEX) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->ifindex = (__u32)ynl_attr_get_u32(attr);
		} else if (type == PSP_A_DEV_PSP_VERSIONS_CAP) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->psp_versions_cap = (__u32)ynl_attr_get_u32(attr);
		} else if (type == PSP_A_DEV_PSP_VERSIONS_ENA) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->psp_versions_ena = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<psp_dev_get_rsp>
psp_dev_get(ynl_cpp::ynl_socket& ys, psp_dev_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<psp_dev_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, PSP_CMD_DEV_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &psp_dev_nest;
	yrs.yarg.rsp_policy = &psp_dev_nest;

	if (req.id.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_DEV_ID, req.id.value());
	}

	rsp.reset(new psp_dev_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = psp_dev_get_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_DEV_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* PSP_CMD_DEV_GET - dump */
std::unique_ptr<psp_dev_get_list> psp_dev_get_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<psp_dev_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &psp_dev_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<psp_dev_get_list*>(arg)->objs.emplace_back());};
	yds.cb = psp_dev_get_rsp_parse;
	yds.rsp_cmd = PSP_CMD_DEV_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, PSP_CMD_DEV_GET, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* PSP_CMD_DEV_GET - notify */
/* ============== PSP_CMD_DEV_SET ============== */
/* PSP_CMD_DEV_SET - do */
int psp_dev_set_rsp_parse(const struct nlmsghdr *nlh,
			  struct ynl_parse_arg *yarg)
{
	return YNL_PARSE_CB_OK;
}

std::unique_ptr<psp_dev_set_rsp>
psp_dev_set(ynl_cpp::ynl_socket& ys, psp_dev_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<psp_dev_set_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, PSP_CMD_DEV_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &psp_dev_nest;
	yrs.yarg.rsp_policy = &psp_dev_nest;

	if (req.id.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_DEV_ID, req.id.value());
	}
	if (req.psp_versions_ena.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_DEV_PSP_VERSIONS_ENA, req.psp_versions_ena.value());
	}

	rsp.reset(new psp_dev_set_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = psp_dev_set_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_DEV_SET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== PSP_CMD_KEY_ROTATE ============== */
/* PSP_CMD_KEY_ROTATE - do */
int psp_key_rotate_rsp_parse(const struct nlmsghdr *nlh,
			     struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	psp_key_rotate_rsp *dst;

	dst = (psp_key_rotate_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_DEV_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u32)ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<psp_key_rotate_rsp>
psp_key_rotate(ynl_cpp::ynl_socket& ys, psp_key_rotate_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<psp_key_rotate_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, PSP_CMD_KEY_ROTATE, 1);
	((struct ynl_sock*)ys)->req_policy = &psp_dev_nest;
	yrs.yarg.rsp_policy = &psp_dev_nest;

	if (req.id.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_DEV_ID, req.id.value());
	}

	rsp.reset(new psp_key_rotate_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = psp_key_rotate_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_KEY_ROTATE;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* PSP_CMD_KEY_ROTATE - notify */
/* ============== PSP_CMD_RX_ASSOC ============== */
/* PSP_CMD_RX_ASSOC - do */
int psp_rx_assoc_rsp_parse(const struct nlmsghdr *nlh,
			   struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	psp_rx_assoc_rsp *dst;

	dst = (psp_rx_assoc_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_ASSOC_DEV_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == PSP_A_ASSOC_VERSION) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->version = (enum psp_version)ynl_attr_get_u32(attr);
		} else if (type == PSP_A_ASSOC_RX_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &psp_keys_nest;
			parg.data = &dst->rx_key.emplace();
			if (psp_keys_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<psp_rx_assoc_rsp>
psp_rx_assoc(ynl_cpp::ynl_socket& ys, psp_rx_assoc_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<psp_rx_assoc_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, PSP_CMD_RX_ASSOC, 1);
	((struct ynl_sock*)ys)->req_policy = &psp_assoc_nest;
	yrs.yarg.rsp_policy = &psp_assoc_nest;

	if (req.dev_id.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_DEV_ID, req.dev_id.value());
	}
	if (req.version.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_VERSION, req.version.value());
	}
	if (req.sock_fd.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_SOCK_FD, req.sock_fd.value());
	}

	rsp.reset(new psp_rx_assoc_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = psp_rx_assoc_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_RX_ASSOC;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== PSP_CMD_TX_ASSOC ============== */
/* PSP_CMD_TX_ASSOC - do */
int psp_tx_assoc_rsp_parse(const struct nlmsghdr *nlh,
			   struct ynl_parse_arg *yarg)
{
	return YNL_PARSE_CB_OK;
}

std::unique_ptr<psp_tx_assoc_rsp>
psp_tx_assoc(ynl_cpp::ynl_socket& ys, psp_tx_assoc_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<psp_tx_assoc_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, PSP_CMD_TX_ASSOC, 1);
	((struct ynl_sock*)ys)->req_policy = &psp_assoc_nest;
	yrs.yarg.rsp_policy = &psp_assoc_nest;

	if (req.dev_id.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_DEV_ID, req.dev_id.value());
	}
	if (req.version.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_VERSION, req.version.value());
	}
	if (req.tx_key.has_value()) {
		psp_keys_put(nlh, PSP_A_ASSOC_TX_KEY, req.tx_key.value());
	}
	if (req.sock_fd.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_ASSOC_SOCK_FD, req.sock_fd.value());
	}

	rsp.reset(new psp_tx_assoc_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = psp_tx_assoc_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_TX_ASSOC;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* ============== PSP_CMD_GET_STATS ============== */
/* PSP_CMD_GET_STATS - do */
int psp_get_stats_rsp_parse(const struct nlmsghdr *nlh,
			    struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	psp_get_stats_rsp *dst;

	dst = (psp_get_stats_rsp*)yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == PSP_A_STATS_DEV_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->dev_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == PSP_A_STATS_KEY_ROTATIONS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->key_rotations = (__u64)ynl_attr_get_uint(attr);
		} else if (type == PSP_A_STATS_STALE_EVENTS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->stale_events = (__u64)ynl_attr_get_uint(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<psp_get_stats_rsp>
psp_get_stats(ynl_cpp::ynl_socket& ys, psp_get_stats_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<psp_get_stats_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, PSP_CMD_GET_STATS, 1);
	((struct ynl_sock*)ys)->req_policy = &psp_stats_nest;
	yrs.yarg.rsp_policy = &psp_stats_nest;

	if (req.dev_id.has_value()) {
		ynl_attr_put_u32(nlh, PSP_A_STATS_DEV_ID, req.dev_id.value());
	}

	rsp.reset(new psp_get_stats_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = psp_get_stats_rsp_parse;
	yrs.rsp_cmd = PSP_CMD_GET_STATS;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* PSP_CMD_GET_STATS - dump */
std::unique_ptr<psp_get_stats_list> psp_get_stats_dump(ynl_cpp::ynl_socket& ys)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<psp_get_stats_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &psp_stats_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void*{return &(static_cast<psp_get_stats_list*>(arg)->objs.emplace_back());};
	yds.cb = psp_get_stats_rsp_parse;
	yds.rsp_cmd = PSP_CMD_GET_STATS;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, PSP_CMD_GET_STATS, 1);

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

static constexpr std::array<ynl_ntf_info, PSP_CMD_KEY_ROTATE_NTF + 1> psp_ntf_info = []() {
	std::array<ynl_ntf_info, PSP_CMD_KEY_ROTATE_NTF + 1> arr{};
	arr[PSP_CMD_DEV_ADD_NTF].policy		= &psp_dev_nest;
	arr[PSP_CMD_DEV_ADD_NTF].cb		= psp_dev_get_rsp_parse;
	arr[PSP_CMD_DEV_DEL_NTF].policy		= &psp_dev_nest;
	arr[PSP_CMD_DEV_DEL_NTF].cb		= psp_dev_get_rsp_parse;
	arr[PSP_CMD_DEV_CHANGE_NTF].policy		= &psp_dev_nest;
	arr[PSP_CMD_DEV_CHANGE_NTF].cb		= psp_dev_get_rsp_parse;
	arr[PSP_CMD_KEY_ROTATE_NTF].policy		= &psp_dev_nest;
	arr[PSP_CMD_KEY_ROTATE_NTF].cb		= psp_key_rotate_rsp_parse;
	return arr;
} ();

const struct ynl_family ynl_psp_family =  {
	.name		= "psp",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= psp_ntf_info.data(),
	.ntf_info_size	= psp_ntf_info.size(),
};
const struct ynl_family& get_ynl_psp_family() {
	return ynl_psp_family;
};
} //namespace ynl_cpp
