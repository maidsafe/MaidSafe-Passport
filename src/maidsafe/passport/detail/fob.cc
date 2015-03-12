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

#include "maidsafe/passport/detail/fob.h"

#include "maidsafe/common/utils.h"

#include "maidsafe/passport/types.h"

namespace maidsafe {

namespace passport {

namespace detail {

#ifndef _MSC_VER

const std::uint32_t AnmaidTag::type_id;
const std::uint32_t MaidTag::type_id;
const std::uint32_t AnpmidTag::type_id;
const std::uint32_t PmidTag::type_id;
const std::uint32_t AnmpidTag::type_id;
const std::uint32_t MpidTag::type_id;

#endif

asymm::PlainText GetRandomString() { return asymm::PlainText(RandomBytes(100, 200)); }

#ifdef TESTING

std::vector<Fob<PmidTag>> ReadPmidList(const boost::filesystem::path& file_path) {
  auto contents(ReadFile(file_path));
  InputVectorStream binary_input_stream(contents.value());
  std::uint32_t pmid_list_size(Parse<std::uint32_t>(binary_input_stream));
  std::vector<Fob<PmidTag>> pmid_list;
  crypto::AES256KeyAndIV symm_key_and_iv(
      std::vector<byte>(crypto::AES256_KeySize + crypto::AES256_IVSize, 0));
  for (std::uint32_t i = 0; i < pmid_list_size; ++i)
    pmid_list.emplace_back(Parse<crypto::CipherText>(binary_input_stream), symm_key_and_iv);
  return pmid_list;
}

bool WritePmidList(const boost::filesystem::path& file_path,
                   const std::vector<Fob<PmidTag>>& pmid_list) {
  OutputVectorStream binary_output_stream;
  Serialise(binary_output_stream, static_cast<std::uint32_t>(pmid_list.size()));
  crypto::AES256KeyAndIV symm_key_and_iv(
      std::vector<byte>(crypto::AES256_KeySize + crypto::AES256_IVSize, 0));
  for (const auto& pmid : pmid_list)
    Serialise(binary_output_stream, pmid.Encrypt(symm_key_and_iv));
  return WriteFile(file_path, binary_output_stream.vector());
}

std::vector<AnmaidToPmid> ReadKeyChainList(const boost::filesystem::path& file_path) {
  auto contents(ReadFile(file_path));
  InputVectorStream binary_input_stream(SerialisedData(contents.value()));
  std::uint32_t keychain_list_size(Parse<std::uint32_t>(binary_input_stream));
  std::vector<AnmaidToPmid> keychain_list;
  crypto::AES256KeyAndIV symm_key_and_iv(
      std::vector<byte>(crypto::AES256_KeySize + crypto::AES256_IVSize, 0));
  for (std::uint32_t i = 0; i < keychain_list_size; ++i) {
    crypto::CipherText encrypted_anmaid(Parse<crypto::CipherText>(binary_input_stream));
    crypto::CipherText encrypted_maid(Parse<crypto::CipherText>(binary_input_stream));
    crypto::CipherText encrypted_anpmid(Parse<crypto::CipherText>(binary_input_stream));
    crypto::CipherText encrypted_pmid(Parse<crypto::CipherText>(binary_input_stream));
    keychain_list.emplace_back(Anmaid(std::move(encrypted_anmaid), symm_key_and_iv),
                               Maid(std::move(encrypted_maid), symm_key_and_iv),
                               Anpmid(std::move(encrypted_anpmid), symm_key_and_iv),
                               Pmid(std::move(encrypted_pmid), symm_key_and_iv));
  }
  return keychain_list;
}

bool WriteKeyChainList(const boost::filesystem::path& file_path,
                       const std::vector<AnmaidToPmid>& keychain_list) {
  OutputVectorStream binary_output_stream;
  Serialise(binary_output_stream, static_cast<std::uint32_t>(keychain_list.size()));
  crypto::AES256KeyAndIV symm_key_and_iv(
      std::vector<byte>(crypto::AES256_KeySize + crypto::AES256_IVSize, 0));
  for (const auto& keychain : keychain_list) {
    Serialise(binary_output_stream, keychain.anmaid.Encrypt(symm_key_and_iv),
              keychain.maid.Encrypt(symm_key_and_iv), keychain.anpmid.Encrypt(symm_key_and_iv),
              keychain.pmid.Encrypt(symm_key_and_iv));
  }
  return WriteFile(file_path, binary_output_stream.vector());
}

#endif  // TESTING

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
