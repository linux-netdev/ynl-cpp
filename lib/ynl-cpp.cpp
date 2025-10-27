// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "ynl.hpp"

namespace ynl_cpp {
ynl_socket::ynl_socket(const ynl_family& family, struct ynl_error* err) {
  sock_ = ynl_sock_create(&family, err);
}

ynl_socket::ynl_socket(ynl_socket&& other) noexcept : sock_(other.sock_) {
  other.sock_ = nullptr;
}

ynl_socket& ynl_socket::operator=(ynl_socket&& other) noexcept {
  if (this == &other)
    return *this;

  if (sock_)
    ynl_sock_destroy(sock_);

  sock_ = other.sock_;
  other.sock_ = nullptr;
  return *this;
}

ynl_socket::~ynl_socket() {
  if (sock_) {
    ynl_sock_destroy(sock_);
  }
}

} // namespace ynl_cpp
