// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "ovpn-user.hpp"

#include <array>

#include <linux/ovpn.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view, OVPN_CMD_KEY_DEL + 1> ovpn_op_strmap = []() {
	std::array<std::string_view, OVPN_CMD_KEY_DEL + 1> arr{};
	arr[OVPN_CMD_PEER_NEW] = "peer-new";
	arr[OVPN_CMD_PEER_SET] = "peer-set";
	arr[OVPN_CMD_PEER_GET] = "peer-get";
	arr[OVPN_CMD_PEER_DEL] = "peer-del";
	arr[OVPN_CMD_PEER_DEL_NTF] = "peer-del-ntf";
	arr[OVPN_CMD_KEY_NEW] = "key-new";
	arr[OVPN_CMD_KEY_GET] = "key-get";
	arr[OVPN_CMD_KEY_SWAP] = "key-swap";
	arr[OVPN_CMD_KEY_SWAP_NTF] = "key-swap-ntf";
	arr[OVPN_CMD_KEY_DEL] = "key-del";
	return arr;
} ();

std::string_view ovpn_op_str(int op)
{
	if (op < 0 || op >= (int)(ovpn_op_strmap.size())) {
		return "";
	}
	return ovpn_op_strmap[op];
}

static constexpr std::array<std::string_view, 2 + 1> ovpn_cipher_alg_strmap = []() {
	std::array<std::string_view, 2 + 1> arr{};
	arr[0] = "none";
	arr[1] = "aes-gcm";
	arr[2] = "chacha20-poly1305";
	return arr;
} ();

std::string_view ovpn_cipher_alg_str(ovpn_cipher_alg value)
{
	if (value < 0 || value >= (int)(ovpn_cipher_alg_strmap.size())) {
		return "";
	}
	return ovpn_cipher_alg_strmap[value];
}

static constexpr std::array<std::string_view, 4 + 1> ovpn_del_peer_reason_strmap = []() {
	std::array<std::string_view, 4 + 1> arr{};
	arr[0] = "teardown";
	arr[1] = "userspace";
	arr[2] = "expired";
	arr[3] = "transport-error";
	arr[4] = "transport-disconnect";
	return arr;
} ();

std::string_view ovpn_del_peer_reason_str(ovpn_del_peer_reason value)
{
	if (value < 0 || value >= (int)(ovpn_del_peer_reason_strmap.size())) {
		return "";
	}
	return ovpn_del_peer_reason_strmap[value];
}

static constexpr std::array<std::string_view, 1 + 1> ovpn_key_slot_strmap = []() {
	std::array<std::string_view, 1 + 1> arr{};
	arr[0] = "primary";
	arr[1] = "secondary";
	return arr;
} ();

std::string_view ovpn_key_slot_str(ovpn_key_slot value)
{
	if (value < 0 || value >= (int)(ovpn_key_slot_strmap.size())) {
		return "";
	}
	return ovpn_key_slot_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr,OVPN_A_PEER_MAX + 1> ovpn_peer_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_PEER_MAX + 1> arr{};
	arr[OVPN_A_PEER_ID].name = "id";
	arr[OVPN_A_PEER_ID].type = YNL_PT_U32;
	arr[OVPN_A_PEER_REMOTE_IPV4].name = "remote-ipv4";
	arr[OVPN_A_PEER_REMOTE_IPV4].type = YNL_PT_U32;
	arr[OVPN_A_PEER_REMOTE_IPV6].name = "remote-ipv6";
	arr[OVPN_A_PEER_REMOTE_IPV6].type = YNL_PT_BINARY;
	arr[OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID].name = "remote-ipv6-scope-id";
	arr[OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID].type = YNL_PT_U32;
	arr[OVPN_A_PEER_REMOTE_PORT].name = "remote-port";
	arr[OVPN_A_PEER_REMOTE_PORT].type = YNL_PT_U16;
	arr[OVPN_A_PEER_SOCKET].name = "socket";
	arr[OVPN_A_PEER_SOCKET].type = YNL_PT_U32;
	arr[OVPN_A_PEER_SOCKET_NETNSID].name = "socket-netnsid";
	arr[OVPN_A_PEER_SOCKET_NETNSID].type = YNL_PT_U32;
	arr[OVPN_A_PEER_VPN_IPV4].name = "vpn-ipv4";
	arr[OVPN_A_PEER_VPN_IPV4].type = YNL_PT_U32;
	arr[OVPN_A_PEER_VPN_IPV6].name = "vpn-ipv6";
	arr[OVPN_A_PEER_VPN_IPV6].type = YNL_PT_BINARY;
	arr[OVPN_A_PEER_LOCAL_IPV4].name = "local-ipv4";
	arr[OVPN_A_PEER_LOCAL_IPV4].type = YNL_PT_U32;
	arr[OVPN_A_PEER_LOCAL_IPV6].name = "local-ipv6";
	arr[OVPN_A_PEER_LOCAL_IPV6].type = YNL_PT_BINARY;
	arr[OVPN_A_PEER_LOCAL_PORT].name = "local-port";
	arr[OVPN_A_PEER_LOCAL_PORT].type = YNL_PT_U16;
	arr[OVPN_A_PEER_KEEPALIVE_INTERVAL].name = "keepalive-interval";
	arr[OVPN_A_PEER_KEEPALIVE_INTERVAL].type = YNL_PT_U32;
	arr[OVPN_A_PEER_KEEPALIVE_TIMEOUT].name = "keepalive-timeout";
	arr[OVPN_A_PEER_KEEPALIVE_TIMEOUT].type = YNL_PT_U32;
	arr[OVPN_A_PEER_DEL_REASON].name = "del-reason";
	arr[OVPN_A_PEER_DEL_REASON].type = YNL_PT_U32;
	arr[OVPN_A_PEER_VPN_RX_BYTES].name = "vpn-rx-bytes";
	arr[OVPN_A_PEER_VPN_RX_BYTES].type = YNL_PT_UINT;
	arr[OVPN_A_PEER_VPN_TX_BYTES].name = "vpn-tx-bytes";
	arr[OVPN_A_PEER_VPN_TX_BYTES].type = YNL_PT_UINT;
	arr[OVPN_A_PEER_VPN_RX_PACKETS].name = "vpn-rx-packets";
	arr[OVPN_A_PEER_VPN_RX_PACKETS].type = YNL_PT_UINT;
	arr[OVPN_A_PEER_VPN_TX_PACKETS].name = "vpn-tx-packets";
	arr[OVPN_A_PEER_VPN_TX_PACKETS].type = YNL_PT_UINT;
	arr[OVPN_A_PEER_LINK_RX_BYTES].name = "link-rx-bytes";
	arr[OVPN_A_PEER_LINK_RX_BYTES].type = YNL_PT_UINT;
	arr[OVPN_A_PEER_LINK_TX_BYTES].name = "link-tx-bytes";
	arr[OVPN_A_PEER_LINK_TX_BYTES].type = YNL_PT_UINT;
	arr[OVPN_A_PEER_LINK_RX_PACKETS].name = "link-rx-packets";
	arr[OVPN_A_PEER_LINK_RX_PACKETS].type = YNL_PT_UINT;
	arr[OVPN_A_PEER_LINK_TX_PACKETS].name = "link-tx-packets";
	arr[OVPN_A_PEER_LINK_TX_PACKETS].type = YNL_PT_UINT;
	return arr;
} ();

struct ynl_policy_nest ovpn_peer_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_PEER_MAX),
	.table = ovpn_peer_policy.data(),
};

static std::array<ynl_policy_attr,OVPN_A_KEYDIR_MAX + 1> ovpn_keydir_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_KEYDIR_MAX + 1> arr{};
	arr[OVPN_A_KEYDIR_CIPHER_KEY].name = "cipher-key";
	arr[OVPN_A_KEYDIR_CIPHER_KEY].type = YNL_PT_BINARY;
	arr[OVPN_A_KEYDIR_NONCE_TAIL].name = "nonce-tail";
	arr[OVPN_A_KEYDIR_NONCE_TAIL].type = YNL_PT_BINARY;
	return arr;
} ();

struct ynl_policy_nest ovpn_keydir_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_KEYDIR_MAX),
	.table = ovpn_keydir_policy.data(),
};

static std::array<ynl_policy_attr,OVPN_A_KEYCONF_MAX + 1> ovpn_keyconf_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_KEYCONF_MAX + 1> arr{};
	arr[OVPN_A_KEYCONF_PEER_ID].name = "peer-id";
	arr[OVPN_A_KEYCONF_PEER_ID].type = YNL_PT_U32;
	arr[OVPN_A_KEYCONF_SLOT].name = "slot";
	arr[OVPN_A_KEYCONF_SLOT].type = YNL_PT_U32;
	arr[OVPN_A_KEYCONF_KEY_ID].name = "key-id";
	arr[OVPN_A_KEYCONF_KEY_ID].type = YNL_PT_U32;
	arr[OVPN_A_KEYCONF_CIPHER_ALG].name = "cipher-alg";
	arr[OVPN_A_KEYCONF_CIPHER_ALG].type = YNL_PT_U32;
	arr[OVPN_A_KEYCONF_ENCRYPT_DIR].name = "encrypt-dir";
	arr[OVPN_A_KEYCONF_ENCRYPT_DIR].type = YNL_PT_NEST;
	arr[OVPN_A_KEYCONF_ENCRYPT_DIR].nest = &ovpn_keydir_nest;
	arr[OVPN_A_KEYCONF_DECRYPT_DIR].name = "decrypt-dir";
	arr[OVPN_A_KEYCONF_DECRYPT_DIR].type = YNL_PT_NEST;
	arr[OVPN_A_KEYCONF_DECRYPT_DIR].nest = &ovpn_keydir_nest;
	return arr;
} ();

struct ynl_policy_nest ovpn_keyconf_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_KEYCONF_MAX),
	.table = ovpn_keyconf_policy.data(),
};

static std::array<ynl_policy_attr,OVPN_A_MAX + 1> ovpn_ovpn_peer_new_input_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_MAX + 1> arr{};
	arr[OVPN_A_IFINDEX].name = "ifindex";
	arr[OVPN_A_IFINDEX].type = YNL_PT_U32;
	arr[OVPN_A_PEER].name = "peer";
	arr[OVPN_A_PEER].type = YNL_PT_NEST;
	arr[OVPN_A_PEER].nest = &ovpn_peer_nest;
	return arr;
} ();

struct ynl_policy_nest ovpn_ovpn_peer_new_input_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_MAX),
	.table = ovpn_ovpn_peer_new_input_policy.data(),
};

static std::array<ynl_policy_attr,OVPN_A_MAX + 1> ovpn_ovpn_peer_set_input_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_MAX + 1> arr{};
	arr[OVPN_A_IFINDEX].name = "ifindex";
	arr[OVPN_A_IFINDEX].type = YNL_PT_U32;
	arr[OVPN_A_PEER].name = "peer";
	arr[OVPN_A_PEER].type = YNL_PT_NEST;
	arr[OVPN_A_PEER].nest = &ovpn_peer_nest;
	return arr;
} ();

struct ynl_policy_nest ovpn_ovpn_peer_set_input_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_MAX),
	.table = ovpn_ovpn_peer_set_input_policy.data(),
};

static std::array<ynl_policy_attr,OVPN_A_MAX + 1> ovpn_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_MAX + 1> arr{};
	arr[OVPN_A_IFINDEX].name = "ifindex";
	arr[OVPN_A_IFINDEX].type = YNL_PT_U32;
	arr[OVPN_A_PEER].name = "peer";
	arr[OVPN_A_PEER].type = YNL_PT_NEST;
	arr[OVPN_A_PEER].nest = &ovpn_peer_nest;
	arr[OVPN_A_KEYCONF].name = "keyconf";
	arr[OVPN_A_KEYCONF].type = YNL_PT_NEST;
	arr[OVPN_A_KEYCONF].nest = &ovpn_keyconf_nest;
	return arr;
} ();

struct ynl_policy_nest ovpn_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_MAX),
	.table = ovpn_policy.data(),
};

static std::array<ynl_policy_attr,OVPN_A_MAX + 1> ovpn_ovpn_peer_del_input_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_MAX + 1> arr{};
	arr[OVPN_A_IFINDEX].name = "ifindex";
	arr[OVPN_A_IFINDEX].type = YNL_PT_U32;
	arr[OVPN_A_PEER].name = "peer";
	arr[OVPN_A_PEER].type = YNL_PT_NEST;
	arr[OVPN_A_PEER].nest = &ovpn_peer_nest;
	return arr;
} ();

struct ynl_policy_nest ovpn_ovpn_peer_del_input_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_MAX),
	.table = ovpn_ovpn_peer_del_input_policy.data(),
};

static std::array<ynl_policy_attr,OVPN_A_MAX + 1> ovpn_ovpn_keyconf_get_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_MAX + 1> arr{};
	arr[OVPN_A_IFINDEX].name = "ifindex";
	arr[OVPN_A_IFINDEX].type = YNL_PT_U32;
	arr[OVPN_A_KEYCONF].name = "keyconf";
	arr[OVPN_A_KEYCONF].type = YNL_PT_NEST;
	arr[OVPN_A_KEYCONF].nest = &ovpn_keyconf_nest;
	return arr;
} ();

struct ynl_policy_nest ovpn_ovpn_keyconf_get_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_MAX),
	.table = ovpn_ovpn_keyconf_get_policy.data(),
};

static std::array<ynl_policy_attr,OVPN_A_MAX + 1> ovpn_ovpn_keyconf_swap_input_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_MAX + 1> arr{};
	arr[OVPN_A_IFINDEX].name = "ifindex";
	arr[OVPN_A_IFINDEX].type = YNL_PT_U32;
	arr[OVPN_A_KEYCONF].name = "keyconf";
	arr[OVPN_A_KEYCONF].type = YNL_PT_NEST;
	arr[OVPN_A_KEYCONF].nest = &ovpn_keyconf_nest;
	return arr;
} ();

struct ynl_policy_nest ovpn_ovpn_keyconf_swap_input_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_MAX),
	.table = ovpn_ovpn_keyconf_swap_input_policy.data(),
};

static std::array<ynl_policy_attr,OVPN_A_MAX + 1> ovpn_ovpn_keyconf_del_input_policy = []() {
	std::array<ynl_policy_attr,OVPN_A_MAX + 1> arr{};
	arr[OVPN_A_IFINDEX].name = "ifindex";
	arr[OVPN_A_IFINDEX].type = YNL_PT_U32;
	arr[OVPN_A_KEYCONF].name = "keyconf";
	arr[OVPN_A_KEYCONF].type = YNL_PT_NEST;
	arr[OVPN_A_KEYCONF].nest = &ovpn_keyconf_nest;
	return arr;
} ();

struct ynl_policy_nest ovpn_ovpn_keyconf_del_input_nest = {
	.max_attr = static_cast<unsigned int>(OVPN_A_MAX),
	.table = ovpn_ovpn_keyconf_del_input_policy.data(),
};

/* Common nested types */
int ovpn_peer_put(struct nlmsghdr *nlh, unsigned int attr_type,
		  const ovpn_peer&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.id.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_PEER_ID, obj.id.value());
	}
	if (obj.remote_ipv4.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_PEER_REMOTE_IPV4, obj.remote_ipv4.value());
	}
	if (obj.remote_ipv6.size() > 0) {
		ynl_attr_put(nlh, OVPN_A_PEER_REMOTE_IPV6, obj.remote_ipv6.data(), obj.remote_ipv6.size());
	}
	if (obj.remote_ipv6_scope_id.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID, obj.remote_ipv6_scope_id.value());
	}
	if (obj.remote_port.has_value()) {
		ynl_attr_put_u16(nlh, OVPN_A_PEER_REMOTE_PORT, obj.remote_port.value());
	}
	if (obj.socket.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_PEER_SOCKET, obj.socket.value());
	}
	if (obj.socket_netnsid.has_value()) {
		ynl_attr_put_s32(nlh, OVPN_A_PEER_SOCKET_NETNSID, obj.socket_netnsid.value());
	}
	if (obj.vpn_ipv4.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_PEER_VPN_IPV4, obj.vpn_ipv4.value());
	}
	if (obj.vpn_ipv6.size() > 0) {
		ynl_attr_put(nlh, OVPN_A_PEER_VPN_IPV6, obj.vpn_ipv6.data(), obj.vpn_ipv6.size());
	}
	if (obj.local_ipv4.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_PEER_LOCAL_IPV4, obj.local_ipv4.value());
	}
	if (obj.local_ipv6.size() > 0) {
		ynl_attr_put(nlh, OVPN_A_PEER_LOCAL_IPV6, obj.local_ipv6.data(), obj.local_ipv6.size());
	}
	if (obj.local_port.has_value()) {
		ynl_attr_put_u16(nlh, OVPN_A_PEER_LOCAL_PORT, obj.local_port.value());
	}
	if (obj.keepalive_interval.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_PEER_KEEPALIVE_INTERVAL, obj.keepalive_interval.value());
	}
	if (obj.keepalive_timeout.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_PEER_KEEPALIVE_TIMEOUT, obj.keepalive_timeout.value());
	}
	if (obj.del_reason.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_PEER_DEL_REASON, obj.del_reason.value());
	}
	if (obj.vpn_rx_bytes.has_value()) {
		ynl_attr_put_uint(nlh, OVPN_A_PEER_VPN_RX_BYTES, obj.vpn_rx_bytes.value());
	}
	if (obj.vpn_tx_bytes.has_value()) {
		ynl_attr_put_uint(nlh, OVPN_A_PEER_VPN_TX_BYTES, obj.vpn_tx_bytes.value());
	}
	if (obj.vpn_rx_packets.has_value()) {
		ynl_attr_put_uint(nlh, OVPN_A_PEER_VPN_RX_PACKETS, obj.vpn_rx_packets.value());
	}
	if (obj.vpn_tx_packets.has_value()) {
		ynl_attr_put_uint(nlh, OVPN_A_PEER_VPN_TX_PACKETS, obj.vpn_tx_packets.value());
	}
	if (obj.link_rx_bytes.has_value()) {
		ynl_attr_put_uint(nlh, OVPN_A_PEER_LINK_RX_BYTES, obj.link_rx_bytes.value());
	}
	if (obj.link_tx_bytes.has_value()) {
		ynl_attr_put_uint(nlh, OVPN_A_PEER_LINK_TX_BYTES, obj.link_tx_bytes.value());
	}
	if (obj.link_rx_packets.has_value()) {
		ynl_attr_put_uint(nlh, OVPN_A_PEER_LINK_RX_PACKETS, obj.link_rx_packets.value());
	}
	if (obj.link_tx_packets.has_value()) {
		ynl_attr_put_uint(nlh, OVPN_A_PEER_LINK_TX_PACKETS, obj.link_tx_packets.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovpn_peer_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	ovpn_peer *dst = (ovpn_peer *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVPN_A_PEER_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_REMOTE_IPV4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->remote_ipv4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_REMOTE_IPV6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->remote_ipv6.assign(data, data + len);
		} else if (type == OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->remote_ipv6_scope_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_REMOTE_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->remote_port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVPN_A_PEER_SOCKET) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->socket = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_SOCKET_NETNSID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->socket_netnsid = (__s32)ynl_attr_get_s32(attr);
		} else if (type == OVPN_A_PEER_VPN_IPV4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vpn_ipv4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_VPN_IPV6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->vpn_ipv6.assign(data, data + len);
		} else if (type == OVPN_A_PEER_LOCAL_IPV4) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->local_ipv4 = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_LOCAL_IPV6) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->local_ipv6.assign(data, data + len);
		} else if (type == OVPN_A_PEER_LOCAL_PORT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->local_port = (__u16)ynl_attr_get_u16(attr);
		} else if (type == OVPN_A_PEER_KEEPALIVE_INTERVAL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->keepalive_interval = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_KEEPALIVE_TIMEOUT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->keepalive_timeout = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_DEL_REASON) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->del_reason = (enum ovpn_del_peer_reason)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_PEER_VPN_RX_BYTES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vpn_rx_bytes = (__u64)ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_VPN_TX_BYTES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vpn_tx_bytes = (__u64)ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_VPN_RX_PACKETS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vpn_rx_packets = (__u64)ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_VPN_TX_PACKETS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->vpn_tx_packets = (__u64)ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_LINK_RX_BYTES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link_rx_bytes = (__u64)ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_LINK_TX_BYTES) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link_tx_bytes = (__u64)ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_LINK_RX_PACKETS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link_rx_packets = (__u64)ynl_attr_get_uint(attr);
		} else if (type == OVPN_A_PEER_LINK_TX_PACKETS) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->link_tx_packets = (__u64)ynl_attr_get_uint(attr);
		}
	}

	return 0;
}

int ovpn_keydir_put(struct nlmsghdr *nlh, unsigned int attr_type,
		    const ovpn_keydir&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.cipher_key.size() > 0) {
		ynl_attr_put(nlh, OVPN_A_KEYDIR_CIPHER_KEY, obj.cipher_key.data(), obj.cipher_key.size());
	}
	if (obj.nonce_tail.size() > 0) {
		ynl_attr_put(nlh, OVPN_A_KEYDIR_NONCE_TAIL, obj.nonce_tail.data(), obj.nonce_tail.size());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovpn_keydir_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	ovpn_keydir *dst = (ovpn_keydir *)yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVPN_A_KEYDIR_CIPHER_KEY) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->cipher_key.assign(data, data + len);
		} else if (type == OVPN_A_KEYDIR_NONCE_TAIL) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			unsigned int len = ynl_attr_data_len(attr);
			__u8 *data = (__u8*)ynl_attr_data(attr);
			dst->nonce_tail.assign(data, data + len);
		}
	}

	return 0;
}

int ovpn_keyconf_put(struct nlmsghdr *nlh, unsigned int attr_type,
		     const ovpn_keyconf&  obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj.peer_id.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_PEER_ID, obj.peer_id.value());
	}
	if (obj.slot.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_SLOT, obj.slot.value());
	}
	if (obj.key_id.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_KEY_ID, obj.key_id.value());
	}
	if (obj.cipher_alg.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_KEYCONF_CIPHER_ALG, obj.cipher_alg.value());
	}
	if (obj.encrypt_dir.has_value()) {
		ovpn_keydir_put(nlh, OVPN_A_KEYCONF_ENCRYPT_DIR, obj.encrypt_dir.value());
	}
	if (obj.decrypt_dir.has_value()) {
		ovpn_keydir_put(nlh, OVPN_A_KEYCONF_DECRYPT_DIR, obj.decrypt_dir.value());
	}
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

int ovpn_keyconf_parse(struct ynl_parse_arg *yarg, const struct nlattr *nested)
{
	ovpn_keyconf *dst = (ovpn_keyconf *)yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVPN_A_KEYCONF_PEER_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->peer_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_KEYCONF_SLOT) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->slot = (enum ovpn_key_slot)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_KEYCONF_KEY_ID) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->key_id = (__u32)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_KEYCONF_CIPHER_ALG) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
			dst->cipher_alg = (enum ovpn_cipher_alg)ynl_attr_get_u32(attr);
		} else if (type == OVPN_A_KEYCONF_ENCRYPT_DIR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovpn_keydir_nest;
			parg.data = &dst->encrypt_dir.emplace();
			if (ovpn_keydir_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		} else if (type == OVPN_A_KEYCONF_DECRYPT_DIR) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovpn_keydir_nest;
			parg.data = &dst->decrypt_dir.emplace();
			if (ovpn_keydir_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return 0;
}

/* ============== OVPN_CMD_PEER_NEW ============== */
/* OVPN_CMD_PEER_NEW - do */
int ovpn_peer_new(ynl_cpp::ynl_socket& ys, ovpn_peer_new_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVPN_CMD_PEER_NEW, 1);
	((struct ynl_sock*)ys)->req_policy = &ovpn_ovpn_peer_new_input_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req.ifindex.value());
	}
	if (req.peer.has_value()) {
		ovpn_peer_put(nlh, OVPN_A_PEER, req.peer.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== OVPN_CMD_PEER_SET ============== */
/* OVPN_CMD_PEER_SET - do */
int ovpn_peer_set(ynl_cpp::ynl_socket& ys, ovpn_peer_set_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVPN_CMD_PEER_SET, 1);
	((struct ynl_sock*)ys)->req_policy = &ovpn_ovpn_peer_set_input_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req.ifindex.value());
	}
	if (req.peer.has_value()) {
		ovpn_peer_put(nlh, OVPN_A_PEER, req.peer.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== OVPN_CMD_PEER_GET ============== */
/* OVPN_CMD_PEER_GET - do */
int ovpn_peer_get_rsp_parse(const struct nlmsghdr *nlh,
			    struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ovpn_peer_get_rsp *dst;

	dst = (ovpn_peer_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVPN_A_PEER) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovpn_peer_nest;
			parg.data = &dst->peer.emplace();
			if (ovpn_peer_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ovpn_peer_get_rsp>
ovpn_peer_get(ynl_cpp::ynl_socket& ys, ovpn_peer_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ovpn_peer_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVPN_CMD_PEER_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ovpn_nest;
	yrs.yarg.rsp_policy = &ovpn_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req.ifindex.value());
	}
	if (req.peer.has_value()) {
		ovpn_peer_put(nlh, OVPN_A_PEER, req.peer.value());
	}

	rsp.reset(new ovpn_peer_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ovpn_peer_get_rsp_parse;
	yrs.rsp_cmd = OVPN_CMD_PEER_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* OVPN_CMD_PEER_GET - dump */
std::unique_ptr<ovpn_peer_get_list>
ovpn_peer_get_dump(ynl_cpp::ynl_socket& ys, ovpn_peer_get_req_dump& req)
{
	struct ynl_dump_no_alloc_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	auto ret = std::make_unique<ovpn_peer_get_list>();
	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &ovpn_nest;
	yds.yarg.data = ret.get();
	yds.alloc_cb = [](void* arg)->void* {return &(static_cast<ovpn_peer_get_list*>(arg)->objs.emplace_back());};
	yds.cb = ovpn_peer_get_rsp_parse;
	yds.rsp_cmd = OVPN_CMD_PEER_GET;

	nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock*)ys)->family_id, OVPN_CMD_PEER_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ovpn_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req.ifindex.value());
	}

	err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
	if (err < 0) {
		return nullptr;
	}

	return ret;
}

/* OVPN_CMD_PEER_GET - notify */
static void ovpn_peer_get_ntf_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<ovpn_peer_get_ntf*>(ntf);
	typed_ntf->obj.~ovpn_peer_get_rsp();
	free(ntf);
}

/* ============== OVPN_CMD_PEER_DEL ============== */
/* OVPN_CMD_PEER_DEL - do */
int ovpn_peer_del(ynl_cpp::ynl_socket& ys, ovpn_peer_del_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVPN_CMD_PEER_DEL, 1);
	((struct ynl_sock*)ys)->req_policy = &ovpn_ovpn_peer_del_input_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req.ifindex.value());
	}
	if (req.peer.has_value()) {
		ovpn_peer_put(nlh, OVPN_A_PEER, req.peer.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== OVPN_CMD_KEY_NEW ============== */
/* OVPN_CMD_KEY_NEW - do */
int ovpn_key_new(ynl_cpp::ynl_socket& ys, ovpn_key_new_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVPN_CMD_KEY_NEW, 1);
	((struct ynl_sock*)ys)->req_policy = &ovpn_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req.ifindex.value());
	}
	if (req.keyconf.has_value()) {
		ovpn_keyconf_put(nlh, OVPN_A_KEYCONF, req.keyconf.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== OVPN_CMD_KEY_GET ============== */
/* OVPN_CMD_KEY_GET - do */
int ovpn_key_get_rsp_parse(const struct nlmsghdr *nlh,
			   struct ynl_parse_arg *yarg)
{
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	ovpn_key_get_rsp *dst;

	dst = (ovpn_key_get_rsp*)yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == OVPN_A_KEYCONF) {
			if (ynl_attr_validate(yarg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}

			parg.rsp_policy = &ovpn_keyconf_nest;
			parg.data = &dst->keyconf.emplace();
			if (ovpn_keyconf_parse(&parg, attr)) {
				return YNL_PARSE_CB_ERROR;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

std::unique_ptr<ovpn_key_get_rsp>
ovpn_key_get(ynl_cpp::ynl_socket& ys, ovpn_key_get_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	std::unique_ptr<ovpn_key_get_rsp> rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVPN_CMD_KEY_GET, 1);
	((struct ynl_sock*)ys)->req_policy = &ovpn_ovpn_keyconf_get_nest;
	yrs.yarg.rsp_policy = &ovpn_ovpn_keyconf_get_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req.ifindex.value());
	}
	if (req.keyconf.has_value()) {
		ovpn_keyconf_put(nlh, OVPN_A_KEYCONF, req.keyconf.value());
	}

	rsp.reset(new ovpn_key_get_rsp());
	yrs.yarg.data = rsp.get();
	yrs.cb = ovpn_key_get_rsp_parse;
	yrs.rsp_cmd = OVPN_CMD_KEY_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return nullptr;
	}

	return rsp;
}

/* OVPN_CMD_KEY_GET - notify */
static void ovpn_key_get_ntf_free(struct ynl_ntf_base_type* ntf) {
	auto* typed_ntf = reinterpret_cast<ovpn_key_get_ntf*>(ntf);
	typed_ntf->obj.~ovpn_key_get_rsp();
	free(ntf);
}

/* ============== OVPN_CMD_KEY_SWAP ============== */
/* OVPN_CMD_KEY_SWAP - do */
int ovpn_key_swap(ynl_cpp::ynl_socket& ys, ovpn_key_swap_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVPN_CMD_KEY_SWAP, 1);
	((struct ynl_sock*)ys)->req_policy = &ovpn_ovpn_keyconf_swap_input_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req.ifindex.value());
	}
	if (req.keyconf.has_value()) {
		ovpn_keyconf_put(nlh, OVPN_A_KEYCONF, req.keyconf.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

/* ============== OVPN_CMD_KEY_DEL ============== */
/* OVPN_CMD_KEY_DEL - do */
int ovpn_key_del(ynl_cpp::ynl_socket& ys, ovpn_key_del_req& req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock*)ys)->family_id, OVPN_CMD_KEY_DEL, 1);
	((struct ynl_sock*)ys)->req_policy = &ovpn_ovpn_keyconf_del_input_nest;

	if (req.ifindex.has_value()) {
		ynl_attr_put_u32(nlh, OVPN_A_IFINDEX, req.ifindex.value());
	}
	if (req.keyconf.has_value()) {
		ovpn_keyconf_put(nlh, OVPN_A_KEYCONF, req.keyconf.value());
	}

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0) {
		return -1;
	}

	return 0;
}

static constexpr std::array<ynl_ntf_info, OVPN_CMD_KEY_SWAP_NTF + 1> ovpn_ntf_info = []() {
	std::array<ynl_ntf_info, OVPN_CMD_KEY_SWAP_NTF + 1> arr{};
	arr[OVPN_CMD_PEER_DEL_NTF].policy		= &ovpn_nest;
	arr[OVPN_CMD_PEER_DEL_NTF].cb		= ovpn_peer_get_rsp_parse;
	arr[OVPN_CMD_PEER_DEL_NTF].alloc_sz	= sizeof(ovpn_peer_get_ntf);
	arr[OVPN_CMD_PEER_DEL_NTF].free		= ovpn_peer_get_ntf_free;
	arr[OVPN_CMD_KEY_SWAP_NTF].policy		= &ovpn_ovpn_keyconf_get_nest;
	arr[OVPN_CMD_KEY_SWAP_NTF].cb		= ovpn_key_get_rsp_parse;
	arr[OVPN_CMD_KEY_SWAP_NTF].alloc_sz	= sizeof(ovpn_key_get_ntf);
	arr[OVPN_CMD_KEY_SWAP_NTF].free		= ovpn_key_get_ntf_free;
	return arr;
} ();

const struct ynl_family ynl_ovpn_family =  {
	.name		= "ovpn",
	.hdr_len	= sizeof(struct genlmsghdr),
	.ntf_info	= ovpn_ntf_info.data(),
	.ntf_info_size	= ovpn_ntf_info.size(),
};
const struct ynl_family& get_ynl_ovpn_family() {
	return ynl_ovpn_family;
};
} //namespace ynl_cpp
