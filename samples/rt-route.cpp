// SPDX-License-Identifier: GPL-2.0
#include <iomanip>
#include <iostream>
#include <rt-route-user.hpp>
#include <ynl.hpp>
#include <arpa/inet.h>
#include <net/if.h>

std::ostream &operator<<(std::ostream &os,
                         const ynl_cpp::rt_route_getroute_rsp &rsp)
{
  char ifname[IF_NAMESIZE];
  char route_str[64];

  /* Ignore local */
  if (rsp._hdr.rtm_table == RT_TABLE_LOCAL)
    return os;

  if (rsp.oif)
  {
    auto name = if_indextoname(*rsp.oif, ifname);
    if (name)
      os << "oif: " << std::setw(16) << name;
  }

  if (rsp.dst.size())
  {
    auto route = inet_ntop(rsp._hdr.rtm_family, rsp.dst.data(),
                           route_str, sizeof(route_str));
    os << " dst: " << route << "/" << (int)rsp._hdr.rtm_dst_len;
  }

  if (rsp.gateway.size())
  {
    auto route = inet_ntop(rsp._hdr.rtm_family, rsp.gateway.data(),
                           route_str, sizeof(route_str));
    os << " gateway: " << route;
  }

  os << std::endl;
  return os;
}

int main(int argc, char **argv)
{
  ynl_error yerr;
  ynl_cpp::ynl_socket ys(ynl_cpp::get_ynl_rt_route_family(), &yerr);
  if (!ys)
  {
    std::cerr << yerr.msg << std::endl;
    return -1;
  }

  ynl_cpp::rt_route_getroute_req_dump req = {};
  std::unique_ptr<ynl_cpp::rt_route_getroute_list> rsp =
      ynl_cpp::rt_route_getroute_dump(ys, req);
  if (rsp == nullptr)
  {
    std::cerr << "Error: rt-route getroute dump fails" << std::endl;
    return 2;
  }

  if (ynl_dump_empty(rsp.get()))
    std::cerr << "Error: no routeesses reported" << std::endl;
  for (const auto &route : rsp->objs)
    std::cout << route;

  return 0;
}
