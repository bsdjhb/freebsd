// Copyright 2024 The Kyua Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
// * Neither the name of Google Inc. nor the names of its contributors
//   may be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/// \file engine/execenv/execenv_host.hpp
/// Default execution environment.

#if !defined(ENGINE_EXECENV_EXECENV_HOST_HPP)
#define ENGINE_EXECENV_EXECENV_HOST_HPP

#include "engine/execenv/execenv.hpp"

#include "utils/process/operations_fwd.hpp"

namespace execenv = engine::execenv;

using utils::process::args_vector;

namespace engine {
namespace execenv {


class execenv_host : public execenv::interface {
public:
    execenv_host(const model::test_program& test_program,
                 const std::string& test_case_name) :
        execenv::interface(test_program, test_case_name)
    {}

    void init() const;
    void cleanup() const;
    void exec(const args_vector& args) const UTILS_NORETURN;
};


}  // namespace execenv
}  // namespace engine

#endif  // !defined(ENGINE_EXECENV_EXECENV_HOST_HPP)
