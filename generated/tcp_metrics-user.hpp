/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_TCP_METRICS_GEN_H
#define _LINUX_TCP_METRICS_GEN_H

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

#include <linux/tcp_metrics.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_tcp_metrics_family();

/* Enums */
std::string_view tcp_metrics_op_str(int op);

/* Common nested types */
struct tcp_metrics_metrics {
	std::optional<__u32> rtt;
	std::optional<__u32> rttvar;
	std::optional<__u32> ssthresh;
	std::optional<__u32> cwnd;
	std::optional<__u32> reodering;
	std::optional<__u32> rtt_us;
	std::optional<__u32> rttvar_us;
};

/* ============== TCP_METRICS_CMD_GET ============== */
/* TCP_METRICS_CMD_GET - do */
struct tcp_metrics_get_req {
	std::optional<__u32> addr_ipv4 /* big-endian */;
	std::vector<__u8> addr_ipv6;
	std::optional<__u32> saddr_ipv4 /* big-endian */;
	std::vector<__u8> saddr_ipv6;
};

struct tcp_metrics_get_rsp {
	std::optional<__u32> addr_ipv4 /* big-endian */;
	std::vector<__u8> addr_ipv6;
	std::optional<__u32> saddr_ipv4 /* big-endian */;
	std::vector<__u8> saddr_ipv6;
	std::optional<__u64> age;
	std::optional<tcp_metrics_metrics> vals;
	std::optional<__u16> fopen_mss;
	std::optional<__u16> fopen_syn_drops;
	std::optional<__u64> fopen_syn_drop_ts;
	std::vector<__u8> fopen_cookie;
};

/*
 * Retrieve metrics.
 */
std::unique_ptr<tcp_metrics_get_rsp>
tcp_metrics_get(ynl_cpp::ynl_socket& ys, tcp_metrics_get_req& req);

/* TCP_METRICS_CMD_GET - dump */
struct tcp_metrics_get_list {
	std::list<tcp_metrics_get_rsp> objs;
};

std::unique_ptr<tcp_metrics_get_list>
tcp_metrics_get_dump(ynl_cpp::ynl_socket& ys);

/* ============== TCP_METRICS_CMD_DEL ============== */
/* TCP_METRICS_CMD_DEL - do */
struct tcp_metrics_del_req {
	std::optional<__u32> addr_ipv4 /* big-endian */;
	std::vector<__u8> addr_ipv6;
	std::optional<__u32> saddr_ipv4 /* big-endian */;
	std::vector<__u8> saddr_ipv6;
};

/*
 * Delete metrics.
 */
int tcp_metrics_del(ynl_cpp::ynl_socket& ys, tcp_metrics_del_req& req);

} //namespace ynl_cpp
#endif /* _LINUX_TCP_METRICS_GEN_H */
