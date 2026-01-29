/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_HANDSHAKE_GEN_H
#define _LINUX_HANDSHAKE_GEN_H

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

#include <linux/handshake.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_handshake_family();

/* Enums */
std::string_view handshake_op_str(int op);
std::string_view handshake_handler_class_str(handshake_handler_class value);
std::string_view handshake_msg_type_str(handshake_msg_type value);
std::string_view handshake_auth_str(handshake_auth value);

/* Common nested types */
struct handshake_x509 {
	std::optional<__s32> cert;
	std::optional<__s32> privkey;
};

/* ============== HANDSHAKE_CMD_ACCEPT ============== */
/* HANDSHAKE_CMD_ACCEPT - do */
struct handshake_accept_req {
	std::optional<enum handshake_handler_class> handler_class;
};

struct handshake_accept_rsp {
	std::optional<__s32> sockfd;
	std::optional<enum handshake_msg_type> message_type;
	std::optional<__u32> timeout;
	std::optional<enum handshake_auth> auth_mode;
	std::vector<__u32> peer_identity;
	std::vector<handshake_x509> certificate;
	std::string peername;
	std::optional<__u32> keyring;
};

/*
 * Handler retrieves next queued handshake request
 */
std::unique_ptr<handshake_accept_rsp>
handshake_accept(ynl_cpp::ynl_socket& ys, handshake_accept_req& req);

/* HANDSHAKE_CMD_ACCEPT - notify */
struct handshake_accept_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	handshake_accept_rsp obj __attribute__((aligned(8)));
};

/* ============== HANDSHAKE_CMD_DONE ============== */
/* HANDSHAKE_CMD_DONE - do */
struct handshake_done_req {
	std::optional<__u32> status;
	std::optional<__s32> sockfd;
	std::vector<__u32> remote_auth;
};

/*
 * Handler reports handshake completion
 */
int handshake_done(ynl_cpp::ynl_socket& ys, handshake_done_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_HANDSHAKE_GEN_H */
