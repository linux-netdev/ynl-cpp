/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_OVPN_GEN_H
#define _LINUX_OVPN_GEN_H

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

#include <linux/ovpn.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_ovpn_family();

/* Enums */
std::string_view ovpn_op_str(int op);
std::string_view ovpn_cipher_alg_str(ovpn_cipher_alg value);
std::string_view ovpn_del_peer_reason_str(ovpn_del_peer_reason value);
std::string_view ovpn_key_slot_str(ovpn_key_slot value);

/* Common nested types */
struct ovpn_peer {
	std::optional<__u32> id;
	std::optional<__u32> remote_ipv4 /* big-endian */;
	std::vector<__u8> remote_ipv6;
	std::optional<__u32> remote_ipv6_scope_id;
	std::optional<__u16> remote_port /* big-endian */;
	std::optional<__u32> socket;
	std::optional<__s32> socket_netnsid;
	std::optional<__u32> vpn_ipv4 /* big-endian */;
	std::vector<__u8> vpn_ipv6;
	std::optional<__u32> local_ipv4 /* big-endian */;
	std::vector<__u8> local_ipv6;
	std::optional<__u16> local_port /* big-endian */;
	std::optional<__u32> keepalive_interval;
	std::optional<__u32> keepalive_timeout;
	std::optional<enum ovpn_del_peer_reason> del_reason;
	std::optional<__u64> vpn_rx_bytes;
	std::optional<__u64> vpn_tx_bytes;
	std::optional<__u64> vpn_rx_packets;
	std::optional<__u64> vpn_tx_packets;
	std::optional<__u64> link_rx_bytes;
	std::optional<__u64> link_tx_bytes;
	std::optional<__u64> link_rx_packets;
	std::optional<__u64> link_tx_packets;
};

struct ovpn_keydir {
	std::vector<__u8> cipher_key;
	std::vector<__u8> nonce_tail;
};

struct ovpn_keyconf {
	std::optional<__u32> peer_id;
	std::optional<enum ovpn_key_slot> slot;
	std::optional<__u32> key_id;
	std::optional<enum ovpn_cipher_alg> cipher_alg;
	std::optional<ovpn_keydir> encrypt_dir;
	std::optional<ovpn_keydir> decrypt_dir;
};

/* ============== OVPN_CMD_PEER_NEW ============== */
/* OVPN_CMD_PEER_NEW - do */
struct ovpn_peer_new_req {
	std::optional<__u32> ifindex;
	std::optional<ovpn_peer> peer;
};

/*
 * Add a remote peer
 */
int ovpn_peer_new(ynl_cpp::ynl_socket& ys, ovpn_peer_new_req& req);

/* ============== OVPN_CMD_PEER_SET ============== */
/* OVPN_CMD_PEER_SET - do */
struct ovpn_peer_set_req {
	std::optional<__u32> ifindex;
	std::optional<ovpn_peer> peer;
};

/*
 * modify a remote peer
 */
int ovpn_peer_set(ynl_cpp::ynl_socket& ys, ovpn_peer_set_req& req);

/* ============== OVPN_CMD_PEER_GET ============== */
/* OVPN_CMD_PEER_GET - do */
struct ovpn_peer_get_req {
	std::optional<__u32> ifindex;
	std::optional<ovpn_peer> peer;
};

struct ovpn_peer_get_rsp {
	std::optional<ovpn_peer> peer;
};

/*
 * Retrieve data about existing remote peers (or a specific one)
 */
std::unique_ptr<ovpn_peer_get_rsp>
ovpn_peer_get(ynl_cpp::ynl_socket& ys, ovpn_peer_get_req& req);

/* OVPN_CMD_PEER_GET - dump */
struct ovpn_peer_get_req_dump {
	std::optional<__u32> ifindex;
};

struct ovpn_peer_get_list {
	std::list<ovpn_peer_get_rsp> objs;
};

std::unique_ptr<ovpn_peer_get_list>
ovpn_peer_get_dump(ynl_cpp::ynl_socket& ys, ovpn_peer_get_req_dump& req);

/* OVPN_CMD_PEER_GET - notify */
struct ovpn_peer_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ovpn_peer_get_rsp obj __attribute__((aligned(8)));
};

/* ============== OVPN_CMD_PEER_DEL ============== */
/* OVPN_CMD_PEER_DEL - do */
struct ovpn_peer_del_req {
	std::optional<__u32> ifindex;
	std::optional<ovpn_peer> peer;
};

/*
 * Delete existing remote peer
 */
int ovpn_peer_del(ynl_cpp::ynl_socket& ys, ovpn_peer_del_req& req);

/* ============== OVPN_CMD_KEY_NEW ============== */
/* OVPN_CMD_KEY_NEW - do */
struct ovpn_key_new_req {
	std::optional<__u32> ifindex;
	std::optional<ovpn_keyconf> keyconf;
};

/*
 * Add a cipher key for a specific peer
 */
int ovpn_key_new(ynl_cpp::ynl_socket& ys, ovpn_key_new_req& req);

/* ============== OVPN_CMD_KEY_GET ============== */
/* OVPN_CMD_KEY_GET - do */
struct ovpn_key_get_req {
	std::optional<__u32> ifindex;
	std::optional<ovpn_keyconf> keyconf;
};

struct ovpn_key_get_rsp {
	std::optional<ovpn_keyconf> keyconf;
};

/*
 * Retrieve non-sensitive data about peer key and cipher
 */
std::unique_ptr<ovpn_key_get_rsp>
ovpn_key_get(ynl_cpp::ynl_socket& ys, ovpn_key_get_req& req);

/* OVPN_CMD_KEY_GET - notify */
struct ovpn_key_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	ovpn_key_get_rsp obj __attribute__((aligned(8)));
};

/* ============== OVPN_CMD_KEY_SWAP ============== */
/* OVPN_CMD_KEY_SWAP - do */
struct ovpn_key_swap_req {
	std::optional<__u32> ifindex;
	std::optional<ovpn_keyconf> keyconf;
};

/*
 * Swap primary and secondary session keys for a specific peer
 */
int ovpn_key_swap(ynl_cpp::ynl_socket& ys, ovpn_key_swap_req& req);

/* ============== OVPN_CMD_KEY_DEL ============== */
/* OVPN_CMD_KEY_DEL - do */
struct ovpn_key_del_req {
	std::optional<__u32> ifindex;
	std::optional<ovpn_keyconf> keyconf;
};

/*
 * Delete cipher key for a specific peer
 */
int ovpn_key_del(ynl_cpp::ynl_socket& ys, ovpn_key_del_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_OVPN_GEN_H */
