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

#include "maidsafe/passport/detail/pmid_list_cereal.h"
#include "maidsafe/passport/detail/key_chain_list_cereal.h"

namespace maidsafe {

namespace passport {

namespace detail {

Identity CreateFobName(const asymm::PublicKey& public_key,
                       const asymm::Signature& validation_token) {
  return Identity{ crypto::Hash<crypto::SHA512>(asymm::EncodeKey(public_key) + validation_token) };
}

Identity CreateMpidName(const NonEmptyString& chosen_name) {
  return Identity{ crypto::Hash<crypto::SHA512>(chosen_name) };
}

void ValidateFobDeserialisation(DataTagValue enum_value, asymm::Keys& keys,
                     asymm::Signature& validation_token, Identity& name, std::uint32_t type) {
  asymm::PlainText plain{ RandomString(64) };
  if ((enum_value != MpidTag::kValue && CreateFobName(keys.public_key, validation_token) != name)
      || asymm::Decrypt(asymm::Encrypt(plain, keys.public_key), keys.private_key) != plain ||
      enum_value != DataTagValue(type)) {
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
  }
}

Fob<MpidTag>::Fob(const NonEmptyString& chosen_name, const Signer& signing_fob)
    : keys_(asymm::GenerateKeyPair()),
      validation_token_(asymm::Sign(asymm::PlainText{ asymm::EncodeKey(keys_.public_key) },
                                    signing_fob.private_key())),
      name_(CreateMpidName(chosen_name)) {}

Fob<MpidTag>::Fob(const Fob<MpidTag>& other)
    : keys_(other.keys_), validation_token_(other.validation_token_), name_(other.name_) {}

Fob<MpidTag>::Fob(Fob<MpidTag>&& other)
    : keys_(std::move(other.keys_)),
      validation_token_(std::move(other.validation_token_)),
      name_(std::move(other.name_)) {}

Fob<MpidTag>& Fob<MpidTag>::operator=(Fob<MpidTag> other) {
  swap(*this, other);
  return *this;
}

Fob<MpidTag>::Fob(const std::string& binary_stream) : keys_(), validation_token_(), name_() {
  try {maidsafe::ConvertFromString(binary_stream, *this);}
  catch(...) {BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));}
}

std::string Fob<MpidTag>::ToCereal() const {
  return maidsafe::ConvertToString(*this);
}

namespace {

template <typename TagType>
crypto::CipherText Encrypt(const Fob<TagType>& fob, const crypto::AES256Key& symm_key,
                           const crypto::AES256InitialisationVector& symm_iv) {
  return crypto::SymmEncrypt(crypto::PlainText{ fob.ToCereal() }, symm_key, symm_iv);
}

template <typename TagType>
Fob<TagType> Decrypt(const crypto::CipherText& encrypted_fob, const crypto::AES256Key& symm_key,
                     const crypto::AES256InitialisationVector& symm_iv) {
  return Fob<TagType> {crypto::SymmDecrypt(encrypted_fob, symm_key, symm_iv).string()};
}

}  // unnamed namespace

crypto::CipherText EncryptMaid(const Fob<MaidTag>& maid, const crypto::AES256Key& symm_key,
                               const crypto::AES256InitialisationVector& symm_iv) {
  return Encrypt(maid, symm_key, symm_iv);
}

crypto::CipherText EncryptAnpmid(const Fob<AnpmidTag>& anpmid, const crypto::AES256Key& symm_key,
                                 const crypto::AES256InitialisationVector& symm_iv) {
  return Encrypt(anpmid, symm_key, symm_iv);
}

crypto::CipherText EncryptPmid(const Fob<PmidTag>& pmid, const crypto::AES256Key& symm_key,
                               const crypto::AES256InitialisationVector& symm_iv) {
  return Encrypt(pmid, symm_key, symm_iv);
}

Fob<MaidTag> DecryptMaid(const crypto::CipherText& encrypted_maid,
                         const crypto::AES256Key& symm_key,
                         const crypto::AES256InitialisationVector& symm_iv) {
  return Decrypt<MaidTag>(encrypted_maid, symm_key, symm_iv);
}

Fob<AnpmidTag> DecryptAnpmid(const crypto::CipherText& encrypted_anpmid,
                             const crypto::AES256Key& symm_key,
                             const crypto::AES256InitialisationVector& symm_iv) {
  return Decrypt<AnpmidTag>(encrypted_anpmid, symm_key, symm_iv);
}

Fob<PmidTag> DecryptPmid(const crypto::CipherText& encrypted_pmid,
                         const crypto::AES256Key& symm_key,
                         const crypto::AES256InitialisationVector& symm_iv) {
  return Decrypt<PmidTag>(encrypted_pmid, symm_key, symm_iv);
}



#ifdef TESTING

NonEmptyString SerialiseAnmaid(const Fob<AnmaidTag>& anmaid) {
  return NonEmptyString{ anmaid.ToCereal() };
}

Fob<AnmaidTag> ParseAnmaid(const NonEmptyString& serialised_anmaid) {
  return Fob<AnmaidTag>{ serialised_anmaid.string() };
}

NonEmptyString SerialiseMaid(const Fob<MaidTag>& maid) {
  return NonEmptyString{ maid.ToCereal() };
}

Fob<MaidTag> ParseMaid(const NonEmptyString& serialised_maid) {
  return Fob<MaidTag>{ serialised_maid.string() };
}

NonEmptyString SerialiseAnpmid(const Fob<AnpmidTag>& anpmid) {
  return NonEmptyString{ anpmid.ToCereal() };
}

Fob<AnpmidTag> ParseAnpmid(const NonEmptyString& serialised_anpmid) {
  return Fob<AnpmidTag>{ serialised_anpmid.string() };
}

NonEmptyString SerialisePmid(const Fob<PmidTag>& pmid) {
  return NonEmptyString{ pmid.ToCereal() };
}

Fob<PmidTag> ParsePmid(const NonEmptyString& serialised_pmid) {
  return Fob<PmidTag>{ serialised_pmid.string() };
}

std::vector<Fob<PmidTag>> ReadPmidList(const boost::filesystem::path& file_path) {
  std::vector<Fob<PmidTag>> pmid_list;
  PmidListCereal pmid_list_msg;
  maidsafe::ConvertFromString(ReadFile(file_path).string(), pmid_list_msg);
  for (std::size_t i = 0; i < pmid_list_msg.pmids_.size(); ++i)
    pmid_list.emplace_back(ParsePmid(NonEmptyString{ pmid_list_msg.pmids_[i] }));
  return pmid_list;
}

bool WritePmidList(const boost::filesystem::path& file_path,
                   const std::vector<Fob<PmidTag>>& pmid_list) {
  PmidListCereal pmid_list_msg;
  for (const auto& pmid : pmid_list)
    ((pmid_list_msg.pmids_.emplace_back(),
      &pmid_list_msg.pmids_[pmid_list_msg.pmids_.size() - 1]))->assign(
        SerialisePmid(pmid).string());
  return WriteFile(file_path, maidsafe::ConvertToString(pmid_list_msg));
}

AnmaidToPmid ParseKeys(const KeyChainListCereal::KeyChainCereal& key_chain) {
  return std::move(AnmaidToPmid(ParseAnmaid(NonEmptyString{ key_chain.anmaid_ }),
                                ParseMaid(NonEmptyString{ key_chain.maid_}),
                                ParseAnpmid(NonEmptyString{ key_chain.anpmid_ }),
                                ParsePmid(NonEmptyString{ key_chain.pmid_ })));
}

std::vector<AnmaidToPmid> ReadKeyChainList(const boost::filesystem::path& file_path) {
  std::vector<AnmaidToPmid> keychain_list;
  KeyChainListCereal keychain_list_msg;
  maidsafe::ConvertFromString(ReadFile(file_path).string(), keychain_list_msg);
  for (std::size_t i = 0; i < keychain_list_msg.keychains_.size(); ++i)
    keychain_list.emplace_back(ParseKeys(keychain_list_msg.keychains_[i]));
  return keychain_list;
}

bool WriteKeyChainList(const boost::filesystem::path& file_path,
                       const std::vector<AnmaidToPmid>& keychain_list) {
  KeyChainListCereal keychain_list_msg;
  for (const auto& keychain : keychain_list) {
    auto entry = ((keychain_list_msg.keychains_.emplace_back(),
                   &keychain_list_msg.keychains_[keychain_list_msg.keychains_.size() - 1]));
    entry->anmaid_ = SerialiseAnmaid(keychain.anmaid).string();
    entry->maid_ = SerialiseMaid(keychain.maid).string();
    entry->anpmid_ = SerialiseAnpmid(keychain.anpmid).string();
    entry->pmid_ = SerialisePmid(keychain.pmid).string();
  }
  return WriteFile(file_path, maidsafe::ConvertToString(keychain_list_msg));
}

template <>
std::string DebugString<Fob<AnmaidTag>::Name>(const Fob<AnmaidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Anmaid]";
}

template <>
std::string DebugString<Fob<MaidTag>::Name>(const Fob<MaidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Maid]  ";
}

template <>
std::string DebugString<Fob<AnpmidTag>::Name>(const Fob<AnpmidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Anpmid]";
}

template <>
std::string DebugString<Fob<PmidTag>::Name>(const Fob<PmidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Pmid]  ";
}

template <>
std::string DebugString<Fob<AnmpidTag>::Name>(const Fob<AnmpidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Anmpid]";
}

template <>
std::string DebugString<Fob<MpidTag>::Name>(const Fob<MpidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Mpid]  ";
}

#endif  // TESTING

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
