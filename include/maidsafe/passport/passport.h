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

#ifndef MAIDSAFE_PASSPORT_PASSPORT_H_
#define MAIDSAFE_PASSPORT_PASSPORT_H_

#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>
#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/types.h"

namespace maidsafe {

namespace authentication {
struct UserCredentials;
}

namespace passport {

// The Passport API is a realisation of a Public Key Infrastructure, PKI, free from central
// authority and the notion of a web of trust. In fact, based on the precepts inherent in the DHT,
// https://github.com/maidsafe/MaidSafe-Routing/wiki, and vault
// https://github.com/maidsafe/MaidSafe-Vault/wiki libraries, all nodes on the network are assumed
// to be operating in a hostile environment. In contrast, cooperating/collaborating nodes are
// essential for network stability and health. To resolve these conflicting notions, groups of nodes
// close to a given network addressable element, NAE, determine the validity of requests to/from any
// other node with respect to that NAE. The Passport library provides the necessary types and
// methods required for this, including secure communications/transactions, and private/public
// resource sharing and self-authentication on the network.

// Password-Based Key Derivation Function 2, PBKDF2, methods for cryptographically hashing client
// session data from input user details. The PBKDF2 implementation is based on the PKCS #5 v2.0
// standard from RSA laboratories, http://www.rsa.com/rsalabs, see also the cryptographic component
// of the https://github.com/maidsafe/MaidSafe-Common/wiki project. The following methods are used
// for self-authenticated network identity' storage/retrieval on the network.

// Functions for serialising/parsing identities.
crypto::CipherText EncryptMaid(const Maid& maid, const crypto::AES256KeyAndIV& symm_key_and_iv);
crypto::CipherText EncryptAnpmid(const Anpmid& anpmid,
                                 const crypto::AES256KeyAndIV& symm_key_and_iv);
crypto::CipherText EncryptPmid(const Pmid& pmid, const crypto::AES256KeyAndIV& symm_key_and_iv);
Maid DecryptMaid(const crypto::CipherText& encrypted_maid,
                 const crypto::AES256KeyAndIV& symm_key_and_iv);
Anpmid DecryptAnpmid(const crypto::CipherText& encrypted_anpmid,
                     const crypto::AES256KeyAndIV& symm_key_and_iv);
Pmid DecryptPmid(const crypto::CipherText& encrypted_pmid,
                 const crypto::AES256KeyAndIV& symm_key_and_iv);

using MaidAndSigner = std::pair<Maid, Maid::Signer>;
using PmidAndSigner = std::pair<Pmid, Pmid::Signer>;
using MpidAndSigner = std::pair<Mpid, Mpid::Signer>;
// Utility functions to create keys and signers.
MaidAndSigner CreateMaidAndSigner();
PmidAndSigner CreatePmidAndSigner();
MpidAndSigner CreateMpidAndSigner();

// The Passport class contains identity types for the various network related tasks available, see
// types.h for details about the identity types.
class Passport {
 public:
  explicit Passport(MaidAndSigner maid_and_signer);

  // Constructs from a previously-encrypted passport.  All fields of 'user_credentials' must be
  // identical to those used during the encryption.  Throws if unable to decrypt and parse.
  Passport(const crypto::CipherText& encrypted_passport,
           const authentication::UserCredentials& user_credentials);
  // Serialises and encrypts the entire contents of the passport.  Throws if any of the user
  // credential fields are null, or if the passport doesn't contain a Maid.
  crypto::CipherText Encrypt(const authentication::UserCredentials& user_credentials) const;

  // Throws if the passport doesn't contain a Maid.
  Maid GetMaid() const;

  // Throws if key or signing key already exists.
  void AddKeyAndSigner(PmidAndSigner pmid_and_signer);
  void AddKeyAndSigner(MpidAndSigner mpid_and_signer);

  // Returns all the keys of the given type (may be empty).  Doesn't throw.
  std::vector<Pmid> GetPmids() const;
  std::vector<Mpid> GetMpids() const;

  // To invalidate a key on the network, the revocation message must be signed by the corresponding
  // signer key.  This function returns the original signing key for 'key_to_be_removed'.  If 'Key'
  // type is Maid, the passport can no longer be serialised via 'Encrypt' (used when destroying an
  // account).  Throws if 'key_to_be_removed' doesn't exist in the passport.
  template <typename Key>
  typename Key::Signer RemoveKeyAndSigner(const Key& key_to_be_removed);

  // To invalidate a key on the network, the revocation message must be signed by the corresponding
  // signer key.  This function returns the original signing key for 'maid_to_be_replaced'.  Throws
  // if 'maid_to_be_replaced' doesn't exist or if either of the replacements is the same as the
  // original.
  Maid::Signer ReplaceMaidAndSigner(const Maid& maid_to_be_replaced,
                                    MaidAndSigner new_maid_and_signer);

 private:
  Passport(const Passport&) = delete;
  Passport(Passport&&) = delete;
  Passport& operator=(Passport) = delete;

  void FromString(const NonEmptyString& serialised_passport,
                  const crypto::AES256KeyAndIV& symm_key_and_iv);
  NonEmptyString ToString(const crypto::AES256KeyAndIV& symm_key_and_iv) const;

  void Decrypt(const crypto::CipherText& encrypted_passport,
               const authentication::UserCredentials& user_credentials);

  std::unique_ptr<MaidAndSigner> maid_and_signer_;
  std::vector<PmidAndSigner> pmids_and_signers_;
  std::vector<MpidAndSigner> mpids_and_signers_;
  mutable std::mutex mutex_;
};

template <>
Maid::Signer Passport::RemoveKeyAndSigner<Maid>(const Maid& key_to_be_removed);
template <>
Pmid::Signer Passport::RemoveKeyAndSigner<Pmid>(const Pmid& key_to_be_removed);
template <>
Mpid::Signer Passport::RemoveKeyAndSigner<Mpid>(const Mpid& key_to_be_removed);

template <typename Key>
typename Key::Signer Passport::RemoveKeyAndSigner(const Key&) {
  return Key::Key_type_can_only_be_Maid_Pmid_or_Mpid;
}

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_
