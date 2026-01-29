// SPDX-License-Identifier: GPL-2.0
#include <psp-user.hpp>
#include <ynl.hpp>

#include <cstring>
#include <iostream>
#include <linux/psp.h>
#include <poll.h>
#include <signal.h>

static volatile bool running = true;

static void signal_handler(int sig) {
  (void)sig;
  running = false;
}

static void print_dev(const ynl_cpp::psp_dev_get_rsp& dev) {
  if (dev.id.has_value()) {
    std::cout << "id=" << dev.id.value();
  }
  if (dev.ifindex.has_value()) {
    std::cout << " ifindex=" << dev.ifindex.value();
  }
  if (dev.psp_versions_cap.has_value()) {
    std::cout << " versions_cap=0x" << std::hex << dev.psp_versions_cap.value()
              << std::dec;
  }
  if (dev.psp_versions_ena.has_value()) {
    std::cout << " versions_ena=0x" << std::hex << dev.psp_versions_ena.value()
              << std::dec;
  }
  std::cout << std::endl;
}

static void print_dev_notification(
    const char* event_type,
    const ynl_cpp::psp_dev_get_rsp& dev) {
  std::cout << event_type << ": ";
  print_dev(dev);
}

static int do_dump(ynl_cpp::ynl_socket& ys) {
  auto devs = ynl_cpp::psp_dev_get_dump(ys);
  if (!devs) {
    std::cerr << "Failed to dump PSP devices" << std::endl;
    return -1;
  }

  if (devs->objs.empty()) {
    std::cout << "No PSP devices found" << std::endl;
    return 0;
  }

  for (const auto& dev : devs->objs) {
    print_dev(dev);
  }
  return 0;
}

static int do_ntf(ynl_cpp::ynl_socket& ys) {
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  struct ynl_sock* sock = static_cast<struct ynl_sock*>(ys);
  if (ynl_subscribe(sock, PSP_MCGRP_MGMT) < 0) {
    std::cerr << "Failed to subscribe to mgmt multicast group: " << sock->err.msg
              << std::endl;
    return -1;
  }

  std::cout << "Listening for PSP notifications (Ctrl+C to exit)..."
            << std::endl;

  int fd = ynl_socket_get_fd(sock);

  while (running) {
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    int ret = poll(&pfd, 1, 1000);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      std::cerr << "poll() failed: " << strerror(errno) << std::endl;
      break;
    }

    if (ret == 0) {
      continue;
    }

    if (pfd.revents & POLLIN) {
      ret = ynl_ntf_check(sock);
      if (ret < 0) {
        std::cerr << "Error checking notifications: " << sock->err.msg
                  << std::endl;
        continue;
      }

      while (ynl_has_ntf(sock)) {
        struct ynl_ntf_base_type* ntf = ynl_ntf_dequeue(sock);
        if (!ntf) {
          break;
        }

        const auto* dev =
            reinterpret_cast<const ynl_cpp::psp_dev_get_rsp*>(ntf->data);

        switch (ntf->cmd) {
          case PSP_CMD_DEV_ADD_NTF:
            print_dev_notification("DEV_ADD", *dev);
            break;
          case PSP_CMD_DEV_DEL_NTF:
            print_dev_notification("DEV_DEL", *dev);
            break;
          case PSP_CMD_DEV_CHANGE_NTF:
            print_dev_notification("DEV_CHANGE", *dev);
            break;
          default:
            std::cout << "Unknown notification cmd=" << (int)ntf->cmd
                      << std::endl;
            break;
        }

        ynl_ntf_free(ntf);
      }
    }
  }

  return 0;
}

int main(int argc, char* argv[]) {
  bool ntf_mode = false;

  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--ntf") == 0) {
      ntf_mode = true;
    }
  }

  ynl_error yerr;
  ynl_cpp::ynl_socket ys(ynl_cpp::get_ynl_psp_family(), &yerr);
  if (!ys) {
    std::cerr << "Failed to open PSP netlink socket: " << yerr.msg << std::endl;
    std::cerr << "(This requires a kernel with PSP support and a PSP device)"
              << std::endl;
    return -1;
  }

  if (ntf_mode) {
    return do_ntf(ys);
  } else {
    return do_dump(ys);
  }
}
