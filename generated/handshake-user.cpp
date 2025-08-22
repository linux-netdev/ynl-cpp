// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "handshake-user.hpp"

#include <array>

#include <linux/handshake.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, HANDSHAKE_CMD_DONE + 1> handshake_op_strmap = []() {
	std::array<std::string_view, HANDSHAKE_CMD_DONE + 1> arr{};
	arr[HANDSHAKE_CMD_READY] = "ready";
	arr[HANDSHAKE_CMD_ACCEPT] = "accept";
	arr[HANDSHAKE_CMD_DONE] = "done";
	return arr;
} ();

std::string_view handshake_op_str(int op)
{
	if (op < 0 || op >= (int)(handshake_op_strmap.size())) {
		return "";
	}
	return handshake_op_strmap[op];
}

static constexpr std::array<std::string_view, 2 + 1> handshake_handler_class_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "none";
	arr[1] = "tlshd";
	arr[2] = "max";
	return arr;
} ();

std::string_view handshake_handler_class_str(handshake_handler_class value)
{
	if (value < 0 || value >= (int)(handshake_handler_class_strmap.size())) {
		return "";
	}
	return handshake_handler_class_strmap[value];
}

static constexpr std::array<std::string_view, 2 + 1> handshake_msg_type_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "unspec";
	arr[1] = "clienthello";
	arr[2] = "serverhello";
	return arr;
} ();

std::string_view handshake_msg_type_str(handshake_msg_type value)
{
	if (value < 0 || value >= (int)(handshake_msg_type_strmap.size())) {
		return "";
	}
	return handshake_msg_type_strmap[value];
}

static constexpr std::array<std::string_view, 3 + 1> handshake_auth_strmap = []() {
	std::array<std::string_view, 3 + 1> arr{};
	arr[0] = "unspec";
	arr[1] = "unauth";
	arr[2] = "psk";
	arr[3] = "x509";
	return arr;
} ();

std::string_view handshake_auth_str(handshake_auth value)
{
	if (value < 0 || value >= (int)(handshake_auth_strmap.size())) {
		return "";
	}
	return handshake_auth_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,HANDSHAKE_A_X509_MAX + 1> handshake_x509_policy = []() {
	std::array<ynl_policy_attr,HANDSHAKE_A_X509_MAX + 1> arr{};
	arr[HANDSHAKE_A_X509_CERT].name = "cert";
	arr[HANDSHAKE_A_X509_CERT].type = YNL_PT_U32;
	arr[HANDSHAKE_A_X509_PRIVKEY].name = "privkey";
	arr[HANDSHAKE_A_X509_PRIVKEY].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest handshake_x509_nest = {
	.max_attr = static_cast<unsigned int>(HANDSHAKE_A_X509_MAX),
	.table = handshake_x509_policy.data(),
};

static std::array<ynl_policy_attr,HANDSHAKE_A_ACCEPT_MAX + 1> handshake_accept_policy = []() {
	std::array<ynl_policy_attr,HANDSHAKE_A_ACCEPT_MAX + 1> arr{};
	arr[HANDSHAKE_A_ACCEPT_SOCKFD].name = "sockfd";
	arr[HANDSHAKE_A_ACCEPT_SOCKFD].type = YNL_PT_U32;
	arr[HANDSHAKE_A_ACCEPT_HANDLER_CLASS].name = "handler-class";
	arr[HANDSHAKE_A_ACCEPT_HANDLER_CLASS].type = YNL_PT_U32;
	arr[HANDSHAKE_A_ACCEPT_MESSAGE_TYPE].name = "message-type";
	arr[HANDSHAKE_A_ACCEPT_MESSAGE_TYPE].type = YNL_PT_U32;
	arr[HANDSHAKE_A_ACCEPT_TIMEOUT].name = "timeout";
	arr[HANDSHAKE_A_ACCEPT_TIMEOUT].type = YNL_PT_U32;
	arr[HANDSHAKE_A_ACCEPT_AUTH_MODE].name = "auth-mode";
	arr[HANDSHAKE_A_ACCEPT_AUTH_MODE].type = YNL_PT_U32;
	arr[HANDSHAKE_A_ACCEPT_PEER_IDENTITY].name = "peer-identity";
	arr[HANDSHAKE_A_ACCEPT_PEER_IDENTITY].type = YNL_PT_U32;
	arr[HANDSHAKE_A_ACCEPT_CERTIFICATE].name = "certificate";
	arr[HANDSHAKE_A_ACCEPT_CERTIFICATE].type = YNL_PT_NEST;
	arr[HANDSHAKE_A_ACCEPT_CERTIFICATE].nest = &handshake_x509_nest;
	arr[HANDSHAKE_A_ACCEPT_PEERNAME].name = "peername";
	arr[HANDSHAKE_A_ACCEPT_PEERNAME].type  = YNL_PT_NUL_STR;
	arr[HANDSHAKE_A_ACCEPT_KEYRING].name = "keyring";
	arr[HANDSHAKE_A_ACCEPT_KEYRING].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest handshake_accept_nest = {
	.max_attr = static_cast<unsigned int>(HANDSHAKE_A_ACCEPT_MAX),
	.table = handshake_accept_policy.data(),
};

static std::array<ynl_policy_attr,HANDSHAKE_A_DONE_MAX + 1> handshake_done_policy = []() {
	std::array<ynl_policy_attr,HANDSHAKE_A_DONE_MAX + 1> arr{};
	arr[HANDSHAKE_A_DONE_STATUS].name = "status";
	arr[HANDSHAKE_A_DONE_STATUS].type = YNL_PT_U32;
	arr[HANDSHAKE_A_DONE_SOCKFD].name = "sockfd";
	arr[HANDSHAKE_A_DONE_SOCKFD].type = YNL_PT_U32;
	arr[HANDSHAKE_A_DONE_REMOTE_AUTH].name = "remote-auth";
	arr[HANDSHAKE_A_DONE_REMOTE_AUTH].type = YNL_PT_U32;
	return arr;
} ();

struct ynl_policy_nest handshake_done_nest = {
	.max_attr = static_cast<unsigned int>(HANDSHAKE_A_DONE_MAX),
	.table = handshake_done_policy.data(),
};

/* Common nested types */
int handshake_x509_parse(struct ynl_parse_arg *yarg,
			 const struct nlattr *nested)
{
	handshake_x509 *dst = (handshake_x509 *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == HANDSHAKE_A_X509_CERT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cert = (__s32)ynl_attr_get_s32(attr);
		} else if (type == HANDSHAKE_A_X509_PRIVKEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->privkey = (__s32)ynl_attr_get_s32(attr);
		}
	}

	return 0;
}

/* ============== HANDSHAKE_CMD_ACCEPT ============== */
/* HANDSHAKE_CMD_ACCEPT - do */
int handshake_accept_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	unsigned int n_peer_identity = 0;
	unsigned int n_certificate = 0;
	handshake_accept_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	dst = (handshake_accept_rsp*)yarg->data;
	parg.ys = yarg->ys;

	if (dst->certificate.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (accept.certificate)");
	}
	if (dst->peer_identity.size() > 0) {
		return ynl_error_parse(yarg, "attribute already present (accept.peer-identity)");
	}

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == HANDSHAKE_A_ACCEPT_SOCKFD) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->sockfd = (__s32)ynl_attr_get_s32(attr);
		} else if (type == HANDSHAKE_A_ACCEPT_MESSAGE_TYPE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->message_type = (enum handshake_msg_type)ynl_attr_get_u32(attr);
		} else if (type == HANDSHAKE_A_ACCEPT_TIMEOUT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->timeout = (__u32)ynl_attr_get_u32(attr);
		} else if (type == HANDSHAKE_A_ACCEPT_AUTH_MODE) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->auth_mode = (enum handshake_auth)ynl_attr_get_u32(attr);
		} else if (type == HANDSHAKE_A_ACCEPT_PEER_IDENTITY) {
			n_peer_identity++;
		} else if (type == HANDSHAKE_A_ACCEPT_CERTIFICATE) {
			n_certificate++;
		} else if (type == HANDSHAKE_A_ACCEPT_PEERNAME) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->peername.assign(ynl_attr_get_str(attr));
		} else if (type == HANDSHAKE_A_ACCEPT_KEYRING) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->keyring = (__u32)ynl_attr_get_u32(attr);
		}
	}

	if (n_certificate) {
		dst->certificate.resize(n_certificate);
		i = 0;
		parg.rsp_policy = &handshake_x509_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == HANDSHAKE_A_ACCEPT_CERTIFICATE) {
				parg.data = &dst->certificate[i];
				if (handshake_x509_parse(&parg, attr)) {
					return YNL_PARSE_CB_ERROR;
				}
				i++;
			}
		}
	}
	if (n_peer_identity) {
		dst->peer_identity.resize(n_peer_identity);
		i = 0;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == HANDSHAKE_A_ACCEPT_PEER_IDENTITY) {
				dst->peer_identity[i] = ynl_attr_get_u32(attr);
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<handshake_accept_rsp>
handshake_accept(ynl_cpp::ynl_socket& ys, handshake_accept_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<handshake_accept_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, HANDSHAKE_CMD_ACCEPT, 1);
	((struct ynl_sock*)ys)->req_policy = &handshake_accept_nest;
	yrs.yarg.rsp_policy = &handshake_accept_nest;

	if (req.handler_class.has_value()) {
		ynl_attr_put_u32(nlh, HANDSHAKE_A_ACCEPT_HANDLER_CLASS, req.handler_class.value());
	}

	rsp.reset(new handshake_accept_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = handshake_accept_rsp_parse;
	yrs.rsp_cmd = HANDSHAKE_CMD_ACCEPT;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* HANDSHAKE_CMD_ACCEPT - notify */
/* ============== HANDSHAKE_CMD_DONE ============== */
/* HANDSHAKE_CMD_DONE - do */
int handshake_done(ynl_cpp::ynl_socket& ys, handshake_done_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, HANDSHAKE_CMD_DONE, 1);
	((struct ynl_sock*)ys)->req_policy = &handshake_done_nest;

	if (req.status.has_value()) {
		ynl_attr_put_u32(nlh, HANDSHAKE_A_DONE_STATUS, req.status.value());
	}
	if (req.sockfd.has_value()) {
		ynl_attr_put_s32(nlh, HANDSHAKE_A_DONE_SOCKFD, req.sockfd.value());
	}
	for (unsigned int i = 0; i < req.remote_auth.size(); i++) {
		ynl_attr_put_u32(nlh, HANDSHAKE_A_DONE_REMOTE_AUTH, req.remote_auth[i]);
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

static constexpr std::array<ynl_ntf_info, HANDSHAKE_CMD_READY + 1> handshake_ntf_info = []() {
	std::array<ynl_ntf_info, HANDSHAKE_CMD_READY + 1> arr{};
	arr[HANDSHAKE_CMD_READY].policy		= &handshake_accept_nest;
	arr[HANDSHAKE_CMD_READY].cb		= handshake_accept_rsp_parse;
	return arr;
} ();

const struct ynl_family ynl_handshake_family =  {
	.name		= "handshake",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= handshake_ntf_info.data(),
	.ntf_info_size	= handshake_ntf_info.size(),
};
const struct ynl_family& get_ynl_handshake_family() {
	return ynl_handshake_family;
};
} //namespace ynl_cpp
