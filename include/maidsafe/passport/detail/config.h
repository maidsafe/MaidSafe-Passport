/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_PASSPORT_DETAIL_CONFIG_H_
#define MAIDSAFE_PASSPORT_DETAIL_CONFIG_H_

#include <cstdint>
#include <string>

namespace maidsafe {

namespace passport {

namespace detail {

struct AnmaidTag {
  static const std::uint32_t type_id = 2;
};

struct MaidTag {
  static const std::uint32_t type_id = 3;
};

struct AnpmidTag {
  static const std::uint32_t type_id = 4;
};

struct PmidTag {
  static const std::uint32_t type_id = 5;
};

struct AnmpidTag {
  static const std::uint32_t type_id = 6;
};

struct MpidTag {
  static const std::uint32_t type_id = 7;
};

template <typename TagType, class Enable = void>
class Fob {};

// Keys are by default self-signed.
template <typename TagType>
struct SignerFob {
  using Tag = TagType;
};

// Maid is signed by Anmaid
template <>
struct SignerFob<MaidTag> {
  using Tag = AnmaidTag;
};

// Pmid is signed by Anpmid
template <>
struct SignerFob<PmidTag> {
  using Tag = AnpmidTag;
};

// Mpid is signed by Anmpid
template <>
struct SignerFob<MpidTag> {
  using Tag = AnmpidTag;
};

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_CONFIG_H_
