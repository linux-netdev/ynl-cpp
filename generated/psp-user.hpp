/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_PSP_GEN_H
#define _LINUX_PSP_GEN_H

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

#include <linux/psp.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_psp_family();

/* Enums */
std::string_view psp_op_str(int op);
std::string_view psp_version_str(psp_version value);

/* Common nested types */
struct psp_keys {
	std::vector<__u8> key;
	std::optional<__u32> spi;
};

/* ============== PSP_CMD_DEV_GET ============== */
/* PSP_CMD_DEV_GET - do */
struct psp_dev_get_req {
	std::optional<__u32> id;
};

struct psp_dev_get_rsp {
	std::optional<__u32> id;
	std::optional<__u32> ifindex;
	std::optional<__u32> psp_versions_cap;
	std::optional<__u32> psp_versions_ena;
};

/*
 * Get / dump information about PSP capable devices on the system.
 */
std::unique_ptr<psp_dev_get_rsp>
psp_dev_get(ynl_cpp::ynl_socket& ys, psp_dev_get_req& req);

/* PSP_CMD_DEV_GET - dump */
struct psp_dev_get_list {
	std::list<psp_dev_get_rsp> objs;
};

std::unique_ptr<psp_dev_get_list> psp_dev_get_dump(ynl_cpp::ynl_socket& ys);

/* PSP_CMD_DEV_GET - notify */
struct psp_dev_get_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	psp_dev_get_rsp obj __attribute__((aligned(8)));
};

/* ============== PSP_CMD_DEV_SET ============== */
/* PSP_CMD_DEV_SET - do */
struct psp_dev_set_req {
	std::optional<__u32> id;
	std::optional<__u32> psp_versions_ena;
};

struct psp_dev_set_rsp {
};

/*
 * Set the configuration of a PSP device.
 */
std::unique_ptr<psp_dev_set_rsp>
psp_dev_set(ynl_cpp::ynl_socket& ys, psp_dev_set_req& req);

/* ============== PSP_CMD_KEY_ROTATE ============== */
/* PSP_CMD_KEY_ROTATE - do */
struct psp_key_rotate_req {
	std::optional<__u32> id;
};

struct psp_key_rotate_rsp {
	std::optional<__u32> id;
};

/*
 * Rotate the device key.
 */
std::unique_ptr<psp_key_rotate_rsp>
psp_key_rotate(ynl_cpp::ynl_socket& ys, psp_key_rotate_req& req);

/* PSP_CMD_KEY_ROTATE - notify */
struct psp_key_rotate_ntf {
	__u16 family;
	__u8 cmd;
	struct ynl_ntf_base_type* next;
	void (*free)(struct ynl_ntf_base_type* ntf);
	psp_key_rotate_rsp obj __attribute__((aligned(8)));
};

/* ============== PSP_CMD_RX_ASSOC ============== */
/* PSP_CMD_RX_ASSOC - do */
struct psp_rx_assoc_req {
	std::optional<__u32> dev_id;
	std::optional<enum psp_version> version;
	std::optional<__u32> sock_fd;
};

struct psp_rx_assoc_rsp {
	std::optional<__u32> dev_id;
	std::optional<psp_keys> rx_key;
};

/*
 * Allocate a new Rx key + SPI pair, associate it with a socket.
 */
std::unique_ptr<psp_rx_assoc_rsp>
psp_rx_assoc(ynl_cpp::ynl_socket& ys, psp_rx_assoc_req& req);

/* ============== PSP_CMD_TX_ASSOC ============== */
/* PSP_CMD_TX_ASSOC - do */
struct psp_tx_assoc_req {
	std::optional<__u32> dev_id;
	std::optional<enum psp_version> version;
	std::optional<psp_keys> tx_key;
	std::optional<__u32> sock_fd;
};

struct psp_tx_assoc_rsp {
};

/*
 * Add a PSP Tx association.
 */
std::unique_ptr<psp_tx_assoc_rsp>
psp_tx_assoc(ynl_cpp::ynl_socket& ys, psp_tx_assoc_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_PSP_GEN_H */
