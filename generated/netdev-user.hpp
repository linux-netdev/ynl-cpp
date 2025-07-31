/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_NETDEV_GEN_H
#define _LINUX_NETDEV_GEN_H

#include <linux/types.h>
#include <stdlib.h>
#include <string.h>

#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ynl.hpp"

#include <linux/netdev.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_netdev_family();

/* Enums */
std::string_view netdev_op_str(int op);
std::string_view netdev_xdp_act_str(netdev_xdp_act value);
std::string_view netdev_xdp_rx_metadata_str(netdev_xdp_rx_metadata value);
std::string_view netdev_xsk_flags_str(netdev_xsk_flags value);
std::string_view netdev_queue_type_str(netdev_queue_type value);
std::string_view netdev_qstats_scope_str(netdev_qstats_scope value);
std::string_view netdev_napi_threaded_str(netdev_napi_threaded value);

/* Common nested types */
struct netdev_io_uring_provider_info {
};

struct netdev_page_pool_info {
	std::optional<__u64> id;
	std::optional<__u32> ifindex;
};

struct netdev_xsk_info {
};

struct netdev_queue_id {
	std::optional<__u32> id;
	std::optional<enum netdev_queue_type> type;
};

/* ============== NETDEV_CMD_DEV_GET ============== */
/* NETDEV_CMD_DEV_GET - do */
struct netdev_dev_get_req {
	std::optional<__u32> ifindex;
};

struct netdev_dev_get_rsp {
	std::optional<__u32> ifindex;
	std::optional<__u64> xdp_features;
	std::optional<__u32> xdp_zc_max_segs;
	std::optional<__u64> xdp_rx_metadata_features;
	std::optional<__u64> xsk_features;
};

/*
 * Get / dump information about a netdev.
 */
std::unique_ptr<netdev_dev_get_rsp>
netdev_dev_get(ynl_cpp::ynl_socket& ys, netdev_dev_get_req& req);

/* NETDEV_CMD_DEV_GET - dump */
struct netdev_dev_get_list {
	std::list<netdev_dev_get_rsp> objs;
};

std::unique_ptr<netdev_dev_get_list>
netdev_dev_get_dump(ynl_cpp::ynl_socket& ys);

/* NETDEV_CMD_DEV_GET - notify */
struct netdev_dev_get_ntf {
};

/* ============== NETDEV_CMD_PAGE_POOL_GET ============== */
/* NETDEV_CMD_PAGE_POOL_GET - do */
struct netdev_page_pool_get_req {
	std::optional<__u64> id;
};

struct netdev_page_pool_get_rsp {
	std::optional<__u64> id;
	std::optional<__u32> ifindex;
	std::optional<__u64> napi_id;
	std::optional<__u64> inflight;
	std::optional<__u64> inflight_mem;
	std::optional<__u64> detach_time;
	std::optional<__u32> dmabuf;
	std::optional<netdev_io_uring_provider_info> io_uring;
};

/*
 * Get / dump information about Page Pools.
(Only Page Pools associated with a net_device can be listed.)

 */
std::unique_ptr<netdev_page_pool_get_rsp>
netdev_page_pool_get(ynl_cpp::ynl_socket& ys, netdev_page_pool_get_req& req);

/* NETDEV_CMD_PAGE_POOL_GET - dump */
struct netdev_page_pool_get_list {
	std::list<netdev_page_pool_get_rsp> objs;
};

std::unique_ptr<netdev_page_pool_get_list>
netdev_page_pool_get_dump(ynl_cpp::ynl_socket& ys);

/* NETDEV_CMD_PAGE_POOL_GET - notify */
struct netdev_page_pool_get_ntf {
};

/* ============== NETDEV_CMD_PAGE_POOL_STATS_GET ============== */
/* NETDEV_CMD_PAGE_POOL_STATS_GET - do */
struct netdev_page_pool_stats_get_req {
	std::optional<netdev_page_pool_info> info;
};

struct netdev_page_pool_stats_get_rsp {
	std::optional<netdev_page_pool_info> info;
	std::optional<__u64> alloc_fast;
	std::optional<__u64> alloc_slow;
	std::optional<__u64> alloc_slow_high_order;
	std::optional<__u64> alloc_empty;
	std::optional<__u64> alloc_refill;
	std::optional<__u64> alloc_waive;
	std::optional<__u64> recycle_cached;
	std::optional<__u64> recycle_cache_full;
	std::optional<__u64> recycle_ring;
	std::optional<__u64> recycle_ring_full;
	std::optional<__u64> recycle_released_refcnt;
};

/*
 * Get page pool statistics.
 */
std::unique_ptr<netdev_page_pool_stats_get_rsp>
netdev_page_pool_stats_get(ynl_cpp::ynl_socket& ys,
			   netdev_page_pool_stats_get_req& req);

/* NETDEV_CMD_PAGE_POOL_STATS_GET - dump */
struct netdev_page_pool_stats_get_list {
	std::list<netdev_page_pool_stats_get_rsp> objs;
};

std::unique_ptr<netdev_page_pool_stats_get_list>
netdev_page_pool_stats_get_dump(ynl_cpp::ynl_socket& ys);

/* ============== NETDEV_CMD_QUEUE_GET ============== */
/* NETDEV_CMD_QUEUE_GET - do */
struct netdev_queue_get_req {
	std::optional<__u32> ifindex;
	std::optional<enum netdev_queue_type> type;
	std::optional<__u32> id;
};

struct netdev_queue_get_rsp {
	std::optional<__u32> id;
	std::optional<enum netdev_queue_type> type;
	std::optional<__u32> napi_id;
	std::optional<__u32> ifindex;
	std::optional<__u32> dmabuf;
	std::optional<netdev_io_uring_provider_info> io_uring;
	std::optional<netdev_xsk_info> xsk;
};

/*
 * Get queue information from the kernel. Only configured queues will be reported (as opposed to all available hardware queues).
 */
std::unique_ptr<netdev_queue_get_rsp>
netdev_queue_get(ynl_cpp::ynl_socket& ys, netdev_queue_get_req& req);

/* NETDEV_CMD_QUEUE_GET - dump */
struct netdev_queue_get_req_dump {
	std::optional<__u32> ifindex;
};

struct netdev_queue_get_list {
	std::list<netdev_queue_get_rsp> objs;
};

std::unique_ptr<netdev_queue_get_list>
netdev_queue_get_dump(ynl_cpp::ynl_socket& ys, netdev_queue_get_req_dump& req);

/* ============== NETDEV_CMD_NAPI_GET ============== */
/* NETDEV_CMD_NAPI_GET - do */
struct netdev_napi_get_req {
	std::optional<__u32> id;
};

struct netdev_napi_get_rsp {
	std::optional<__u32> id;
	std::optional<__u32> ifindex;
	std::optional<__u32> irq;
	std::optional<__u32> pid;
	std::optional<__u32> defer_hard_irqs;
	std::optional<__u64> gro_flush_timeout;
	std::optional<__u64> irq_suspend_timeout;
	std::optional<enum netdev_napi_threaded> threaded;
};

/*
 * Get information about NAPI instances configured on the system.
 */
std::unique_ptr<netdev_napi_get_rsp>
netdev_napi_get(ynl_cpp::ynl_socket& ys, netdev_napi_get_req& req);

/* NETDEV_CMD_NAPI_GET - dump */
struct netdev_napi_get_req_dump {
	std::optional<__u32> ifindex;
};

struct netdev_napi_get_list {
	std::list<netdev_napi_get_rsp> objs;
};

std::unique_ptr<netdev_napi_get_list>
netdev_napi_get_dump(ynl_cpp::ynl_socket& ys, netdev_napi_get_req_dump& req);

/* ============== NETDEV_CMD_QSTATS_GET ============== */
/* NETDEV_CMD_QSTATS_GET - dump */
struct netdev_qstats_get_req_dump {
	std::optional<__u32> ifindex;
	std::optional<__u64> scope;
};

struct netdev_qstats_get_rsp_dump {
	std::optional<__u32> ifindex;
	std::optional<enum netdev_queue_type> queue_type;
	std::optional<__u32> queue_id;
	std::optional<__u64> rx_packets;
	std::optional<__u64> rx_bytes;
	std::optional<__u64> tx_packets;
	std::optional<__u64> tx_bytes;
};

struct netdev_qstats_get_rsp_list {
	std::list<netdev_qstats_get_rsp_dump> objs;
};

std::unique_ptr<netdev_qstats_get_rsp_list>
netdev_qstats_get_dump(ynl_cpp::ynl_socket& ys,
		       netdev_qstats_get_req_dump& req);

/* ============== NETDEV_CMD_BIND_RX ============== */
/* NETDEV_CMD_BIND_RX - do */
struct netdev_bind_rx_req {
	std::optional<__u32> ifindex;
	std::optional<__u32> fd;
	std::vector<netdev_queue_id> queues;
};

struct netdev_bind_rx_rsp {
	std::optional<__u32> id;
};

/*
 * Bind dmabuf to netdev
 */
std::unique_ptr<netdev_bind_rx_rsp>
netdev_bind_rx(ynl_cpp::ynl_socket& ys, netdev_bind_rx_req& req);

/* ============== NETDEV_CMD_NAPI_SET ============== */
/* NETDEV_CMD_NAPI_SET - do */
struct netdev_napi_set_req {
	std::optional<__u32> id;
	std::optional<__u32> defer_hard_irqs;
	std::optional<__u64> gro_flush_timeout;
	std::optional<__u64> irq_suspend_timeout;
	std::optional<enum netdev_napi_threaded> threaded;
};

/*
 * Set configurable NAPI instance settings.
 */
int netdev_napi_set(ynl_cpp::ynl_socket& ys, netdev_napi_set_req& req);

/* ============== NETDEV_CMD_BIND_TX ============== */
/* NETDEV_CMD_BIND_TX - do */
struct netdev_bind_tx_req {
	std::optional<__u32> ifindex;
	std::optional<__u32> fd;
};

struct netdev_bind_tx_rsp {
	std::optional<__u32> id;
};

/*
 * Bind dmabuf to netdev for TX
 */
std::unique_ptr<netdev_bind_tx_rsp>
netdev_bind_tx(ynl_cpp::ynl_socket& ys, netdev_bind_tx_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_NETDEV_GEN_H */
