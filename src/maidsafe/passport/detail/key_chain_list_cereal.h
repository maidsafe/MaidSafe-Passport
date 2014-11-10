/*  Copyright 2014 MaidSafe.net limited

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

#ifndef MAIDSAFE_PASSPORT_DETAIL_KEY_CHAIN_LIST_CEREAL_H_
#define MAIDSAFE_PASSPORT_DETAIL_KEY_CHAIN_LIST_CEREAL_H_

#include <string>
#include <vector>

namespace maidsafe {

namespace passport {

namespace detail {

struct KeyChainListKeyChainCereal {
  KeyChainListKeyChainCereal()
    : anmaid_ {},
      maid_ {},
      anpmid_ {},
      pmid_ {}
  { }

  template<typename Archive>
  Archive& serialize(Archive& ref_archive) {
    return ref_archive(anmaid_, maid_, anpmid_, pmid_);
  }

  std::string anmaid_;
  std::string maid_;
  std::string anpmid_;
  std::string pmid_;
};

struct KeyChainListCereal {
  KeyChainListCereal()
    : keychains_ {}
  { }

  template<typename Archive>
  Archive& serialize(Archive& ref_archive) {
    return ref_archive(keychains_);
  }

  using KeyChainCereal = KeyChainListKeyChainCereal;

  std::vector<KeyChainCereal> keychains_;
};

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_KEY_CHAIN_LIST_CEREAL_H_
