/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user header */

#ifndef _LINUX_NET_SHAPER_GEN_H
#define _LINUX_NET_SHAPER_GEN_H

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

#include <linux/net_shaper.h>

namespace ynl_cpp {
const struct ynl_family& get_ynl_net_shaper_family();

/* Enums */
std::string_view net_shaper_op_str(int op);
std::string_view net_shaper_scope_str(net_shaper_scope value);
std::string_view net_shaper_metric_str(net_shaper_metric value);

/* Common nested types */
struct net_shaper_handle {
	std::optional<enum net_shaper_scope> scope;
	std::optional<__u32> id;
};

struct net_shaper_leaf_info {
	std::optional<net_shaper_handle> handle;
	std::optional<__u32> priority;
	std::optional<__u32> weight;
};

/* ============== NET_SHAPER_CMD_GET ============== */
/* NET_SHAPER_CMD_GET - do */
struct net_shaper_get_req {
	std::optional<__u32> ifindex;
	std::optional<net_shaper_handle> handle;
};

struct net_shaper_get_rsp {
	std::optional<__u32> ifindex;
	std::optional<net_shaper_handle> parent;
	std::optional<net_shaper_handle> handle;
	std::optional<enum net_shaper_metric> metric;
	std::optional<__u64> bw_min;
	std::optional<__u64> bw_max;
	std::optional<__u64> burst;
	std::optional<__u32> priority;
	std::optional<__u32> weight;
};

/*
 * Get information about a shaper for a given device.

 */
std::unique_ptr<net_shaper_get_rsp>
net_shaper_get(ynl_cpp::ynl_socket& ys, net_shaper_get_req& req);

/* NET_SHAPER_CMD_GET - dump */
struct net_shaper_get_req_dump {
	std::optional<__u32> ifindex;
};

struct net_shaper_get_list {
	std::list<net_shaper_get_rsp> objs;
};

std::unique_ptr<net_shaper_get_list>
net_shaper_get_dump(ynl_cpp::ynl_socket& ys, net_shaper_get_req_dump& req);

/* ============== NET_SHAPER_CMD_SET ============== */
/* NET_SHAPER_CMD_SET - do */
struct net_shaper_set_req {
	std::optional<__u32> ifindex;
	std::optional<net_shaper_handle> handle;
	std::optional<enum net_shaper_metric> metric;
	std::optional<__u64> bw_min;
	std::optional<__u64> bw_max;
	std::optional<__u64> burst;
	std::optional<__u32> priority;
	std::optional<__u32> weight;
};

/*
 * Create or update the specified shaper.
The set operation can't be used to create a @node scope shaper,
use the @group operation instead.

 */
int net_shaper_set(ynl_cpp::ynl_socket& ys, net_shaper_set_req& req);

/* ============== NET_SHAPER_CMD_DELETE ============== */
/* NET_SHAPER_CMD_DELETE - do */
struct net_shaper_delete_req {
	std::optional<__u32> ifindex;
	std::optional<net_shaper_handle> handle;
};

/*
 * Clear (remove) the specified shaper. When deleting
a @node shaper, reattach all the node's leaves to the
deleted node's parent.
If, after the removal, the parent shaper has no more
leaves and the parent shaper scope is @node, the parent
node is deleted, recursively.
When deleting a @queue shaper or a @netdev shaper,
the shaper disappears from the hierarchy, but the
queue/device can still send traffic: it has an implicit
node with infinite bandwidth. The queue's implicit node
feeds an implicit RR node at the root of the hierarchy.

 */
int net_shaper_delete(ynl_cpp::ynl_socket& ys, net_shaper_delete_req& req);

/* ============== NET_SHAPER_CMD_GROUP ============== */
/* NET_SHAPER_CMD_GROUP - do */
struct net_shaper_group_req {
	std::optional<__u32> ifindex;
	std::optional<net_shaper_handle> parent;
	std::optional<net_shaper_handle> handle;
	std::optional<enum net_shaper_metric> metric;
	std::optional<__u64> bw_min;
	std::optional<__u64> bw_max;
	std::optional<__u64> burst;
	std::optional<__u32> priority;
	std::optional<__u32> weight;
	std::vector<net_shaper_leaf_info> leaves;
};

struct net_shaper_group_rsp {
	std::optional<__u32> ifindex;
	std::optional<net_shaper_handle> handle;
};

/*
 * Create or update a scheduling group, attaching the specified
@leaves shapers under the specified node identified by @handle.
The @leaves shapers scope must be @queue and the node shaper
scope must be either @node or @netdev.
When the node shaper has @node scope, if the @handle @id is not
specified, a new shaper of such scope is created, otherwise the
specified node must already exist.
When updating an existing node shaper, the specified @leaves are
added to the existing node; such node will also retain any preexisting
leave.
The @parent handle for a new node shaper defaults to the parent
of all the leaves, provided all the leaves share the same parent.
Otherwise @parent handle must be specified.
The user can optionally provide shaping attributes for the node
shaper.
The operation is atomic, on failure no change is applied to
the device shaping configuration, otherwise the @node shaper
full identifier, comprising @binding and @handle, is provided
as the reply.

 */
std::unique_ptr<net_shaper_group_rsp>
net_shaper_group(ynl_cpp::ynl_socket& ys, net_shaper_group_req& req);

/* ============== NET_SHAPER_CMD_CAP_GET ============== */
/* NET_SHAPER_CMD_CAP_GET - do */
struct net_shaper_cap_get_req {
	std::optional<__u32> ifindex;
	std::optional<enum net_shaper_scope> scope;
};

struct net_shaper_cap_get_rsp {
	std::optional<__u32> ifindex;
	std::optional<enum net_shaper_scope> scope;
	bool support_metric_bps{};
	bool support_metric_pps{};
	bool support_nesting{};
	bool support_bw_min{};
	bool support_bw_max{};
	bool support_burst{};
	bool support_priority{};
	bool support_weight{};
};

/*
 * Get the shaper capabilities supported by the given device
for the specified scope.

 */
std::unique_ptr<net_shaper_cap_get_rsp>
net_shaper_cap_get(ynl_cpp::ynl_socket& ys, net_shaper_cap_get_req& req);

/* NET_SHAPER_CMD_CAP_GET - dump */
struct net_shaper_cap_get_req_dump {
	std::optional<__u32> ifindex;
};

struct net_shaper_cap_get_list {
	std::list<net_shaper_cap_get_rsp> objs;
};

std::unique_ptr<net_shaper_cap_get_list>
net_shaper_cap_get_dump(ynl_cpp::ynl_socket& ys,
			net_shaper_cap_get_req_dump& req);

} //namespace ynl_cpp
#endif /* _LINUX_NET_SHAPER_GEN_H */
