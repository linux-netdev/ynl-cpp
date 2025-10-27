// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __YNL_CPP_H
#define __YNL_CPP_H 1

#include <string.h>

#include <iostream>
#include <vector>
extern "C" {
#include "ynl.h"
}

namespace ynl_cpp {
class ynl_socket {
 public:
  explicit ynl_socket(const ynl_family& family, ynl_error* err = nullptr);

  ynl_socket(const ynl_socket&) = delete;
  ynl_socket& operator=(const ynl_socket&) = delete;

  ynl_socket(ynl_socket&& other) noexcept;
  ynl_socket& operator=(ynl_socket&& other) noexcept;

  ~ynl_socket();

  operator bool() const {
    return sock_ != nullptr;
  }

  operator struct ynl_sock *() {
    return sock_;
  }

 private:
  struct ynl_sock* sock_{nullptr};
};
} // namespace ynl_cpp

#endif
