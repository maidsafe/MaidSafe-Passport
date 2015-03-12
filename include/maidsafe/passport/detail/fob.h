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

#ifndef MAIDSAFE_PASSPORT_DETAIL_FOB_H_
#define MAIDSAFE_PASSPORT_DETAIL_FOB_H_

#include <type_traits>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/serialisation/serialisation.h"

#include "maidsafe/passport/detail/config.h"

namespace maidsafe {

namespace passport {

namespace detail {

template <typename TagType>
struct is_self_signed {
  using type = typename std::is_same<typename SignerFob<TagType>::Tag, TagType>::type;
};

asymm::PlainText GetRandomString();



// ========== Self-signed Fob ======================================================================
template <typename TagType>
class Fob<TagType, typename std::enable_if<is_self_signed<TagType>::type::value>::type> {
 public:
  using Signer = Fob<typename SignerFob<TagType>::Tag>;
  using Tag = TagType;
  using ValidationToken = asymm::Signature;

  // This constructor is only available to this specialisation (i.e. self-signed fob).
  Fob()
      : keys_(asymm::GenerateKeyPair()),
        validation_token_(CreateValidationToken()),
        name_(CreateName()) {
    static_assert(std::is_same<Fob<Tag>, Signer>::value,
                  "This constructor is only applicable for self-signing fobs.");
  }

  Fob(const Fob& other)
      : keys_(other.keys_), validation_token_(other.validation_token_), name_(other.name_) {}

  Fob(Fob&& other)
      : keys_(std::move(other.keys_)),
        validation_token_(std::move(other.validation_token_)),
        name_(std::move(other.name_)) {}

  friend void swap(Fob& lhs, Fob& rhs) {
    using std::swap;
    swap(lhs.keys_, rhs.keys_);
    swap(lhs.validation_token_, rhs.validation_token_);
    swap(lhs.name_, rhs.name_);
  }

  Fob& operator=(Fob other) {
    swap(*this, other);
    return *this;
  }

  Fob(const crypto::CipherText& encrypted_fob, const crypto::AES256KeyAndIV& symm_key_and_iv)
      : keys_(), validation_token_(), name_() {
    try {
      SerialisedData serialised_fob(crypto::SymmDecrypt(encrypted_fob, symm_key_and_iv).string());
      Parse(serialised_fob, keys_, validation_token_, name_);
    } catch (const std::exception&) {
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    }
    ValidateToken();
  }

  crypto::CipherText Encrypt(const crypto::AES256KeyAndIV& symm_key_and_iv) const {
    crypto::PlainText serialised_fob(Serialise(keys_, validation_token_, name_));
    return crypto::SymmEncrypt(serialised_fob, symm_key_and_iv);
  }

  Identity name() const { return name_; }
  ValidationToken validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  Identity CreateName() const {
    return crypto::Hash<crypto::SHA512>(Serialise(keys_.public_key, validation_token_));
  }

  ValidationToken CreateValidationToken() const {
    return asymm::Sign(asymm::PlainText(Serialise(keys_.public_key, Tag::type_id)),
                       keys_.private_key);
  }

  void ValidateToken() const {
    // Check the validation token is valid
    if (!asymm::CheckSignature(asymm::PlainText(Serialise(keys_.public_key, Tag::type_id)),
                               validation_token_, keys_.public_key)) {
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    }
    // Check the private key hasn't been replaced
    asymm::PlainText plain(GetRandomString());
    if (asymm::Decrypt(asymm::Encrypt(plain, keys_.public_key), keys_.private_key) != plain)
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    // Check the name is the hash of the public key + validation token
    if (CreateName() != name_)
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
  }

  asymm::Keys keys_;
  ValidationToken validation_token_;
  Identity name_;
};



// ========== Non-self-signed Fob ==================================================================
template <typename TagType>
class Fob<TagType, typename std::enable_if<!is_self_signed<TagType>::type::value>::type> {
 public:
  using Signer = Fob<typename SignerFob<TagType>::Tag>;
  using Tag = TagType;

  struct ValidationToken {
    ValidationToken() = default;

    ValidationToken(const ValidationToken&) = default;

    ValidationToken(ValidationToken&& other)
        : signature_of_public_key(std::move(other.signature_of_public_key)),
          self_signature(std::move(other.self_signature)) {}

    friend void swap(ValidationToken& lhs, ValidationToken& rhs) {
      using std::swap;
      swap(lhs.signature_of_public_key, rhs.signature_of_public_key);
      swap(lhs.self_signature, rhs.self_signature);
    }

    ValidationToken& operator=(ValidationToken other) {
      swap(*this, other);
      return *this;
    }

    friend bool operator==(const ValidationToken& lhs, const ValidationToken& rhs) {
      return lhs.signature_of_public_key == rhs.signature_of_public_key &&
             lhs.self_signature == rhs.self_signature;
    }

    friend bool operator!=(const ValidationToken& lhs, const ValidationToken& rhs) {
      return !operator==(lhs, rhs);
    }

    template <typename Archive>
    void serialize(Archive& archive) {
      archive(signature_of_public_key, self_signature);
    }

    asymm::Signature signature_of_public_key;
    asymm::Signature self_signature;
  };

  Fob() = delete;

  // This constructor is only available to this specialisation (i.e. non-self-signed fob)
  explicit Fob(const Signer& signing_fob,
               typename std::enable_if<!std::is_same<Fob<Tag>, Signer>::value>::type* = 0)
      : keys_(asymm::GenerateKeyPair()),
        validation_token_(CreateValidationToken(signing_fob.private_key())),
        name_(CreateName()) {}

  Fob(const Fob& other)
      : keys_(other.keys_), validation_token_(other.validation_token_), name_(other.name_) {}

  Fob(Fob&& other)
      : keys_(std::move(other.keys_)),
        validation_token_(std::move(other.validation_token_)),
        name_(std::move(other.name_)) {}

  friend void swap(Fob& lhs, Fob& rhs) {
    using std::swap;
    swap(lhs.keys_, rhs.keys_);
    swap(lhs.validation_token_, rhs.validation_token_);
    swap(lhs.name_, rhs.name_);
  }

  Fob& operator=(Fob other) {
    swap(*this, other);
    return *this;
  }

  Fob(const crypto::CipherText& encrypted_fob, const crypto::AES256KeyAndIV& symm_key_and_iv)
      : keys_(), validation_token_(), name_() {
    try {
      SerialisedData serialised_fob(crypto::SymmDecrypt(encrypted_fob, symm_key_and_iv).string());
      Parse(serialised_fob, keys_, validation_token_, name_);
    } catch (const std::exception&) {
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    }
    ValidateToken();
  }

  crypto::CipherText Encrypt(const crypto::AES256KeyAndIV& symm_key_and_iv) const {
    crypto::PlainText serialised_fob(Serialise(keys_, validation_token_, name_));
    return crypto::SymmEncrypt(serialised_fob, symm_key_and_iv);
  }

  Identity name() const { return name_; }
  ValidationToken validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  Identity CreateName() const {
    return crypto::Hash<crypto::SHA512>(Serialise(keys_.public_key, validation_token_));
  }

  ValidationToken CreateValidationToken(const asymm::PrivateKey& signing_key) const {
    ValidationToken token;
    SerialisedData serialised_public_key(Serialise(keys_.public_key));
    token.signature_of_public_key =
        asymm::Sign(asymm::PlainText(serialised_public_key), signing_key);

    SerialisedData self(token.signature_of_public_key.string());
    self.insert(self.end(), serialised_public_key.begin(), serialised_public_key.end());
    SerialisedData type_id(Serialise(Tag::type_id));
    self.insert(self.end(), type_id.begin(), type_id.end());
    token.self_signature = asymm::Sign(asymm::PlainText(self), keys_.private_key);
    return token;
  }

  void ValidateToken() const {
    // Check the validation token is valid
    SerialisedData self(validation_token_.signature_of_public_key.string());
    SerialisedData serialised_public_key(Serialise(keys_.public_key));
    self.insert(self.end(), serialised_public_key.begin(), serialised_public_key.end());
    SerialisedData type_id(Serialise(Tag::type_id));
    self.insert(self.end(), type_id.begin(), type_id.end());
    if (!asymm::CheckSignature(asymm::PlainText(self), validation_token_.self_signature,
                               keys_.public_key)) {
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    }
    // Check the private key hasn't been replaced
    asymm::PlainText plain(GetRandomString());
    if (asymm::Decrypt(asymm::Encrypt(plain, keys_.public_key), keys_.private_key) != plain)
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    // Check the name is the hash of the public key + validation token
    if (CreateName() != name_)
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
  }

  asymm::Keys keys_;
  ValidationToken validation_token_;
  Identity name_;
};


// ========== General ==============================================================================
crypto::CipherText EncryptMaid(const Fob<MaidTag>& maid,
                               const crypto::AES256KeyAndIV& symm_key_and_iv);
crypto::CipherText EncryptAnpmid(const Fob<AnpmidTag>& anpmid,
                                 const crypto::AES256KeyAndIV& symm_key_and_iv);
crypto::CipherText EncryptPmid(const Fob<PmidTag>& pmid,
                               const crypto::AES256KeyAndIV& symm_key_and_iv);
Fob<MaidTag> DecryptMaid(const crypto::CipherText& encrypted_maid,
                         const crypto::AES256KeyAndIV& symm_key_and_iv);
Fob<AnpmidTag> DecryptAnpmid(const crypto::CipherText& encrypted_anpmid,
                             const crypto::AES256KeyAndIV& symm_key_and_iv);
Fob<PmidTag> DecryptPmid(const crypto::CipherText& encrypted_pmid,
                         const crypto::AES256KeyAndIV& symm_key_and_iv);

#ifdef TESTING

std::vector<Fob<PmidTag>> ReadPmidList(const boost::filesystem::path& file_path);

bool WritePmidList(const boost::filesystem::path& file_path,
                   const std::vector<Fob<PmidTag>>& pmid_list);  // NOLINT (Fraser)

struct AnmaidToPmid {
  AnmaidToPmid(Fob<AnmaidTag> anmaid_in, Fob<MaidTag> maid_in, Fob<AnpmidTag> anpmid_in,
               Fob<PmidTag> pmid_in)
      : anmaid(std::move(anmaid_in)),
        maid(std::move(maid_in)),
        anpmid(std::move(anpmid_in)),
        pmid(std::move(pmid_in)) {}
  AnmaidToPmid() : anmaid(), maid(anmaid), anpmid(), pmid(anpmid) {}
  Fob<AnmaidTag> anmaid;
  Fob<MaidTag> maid;
  Fob<AnpmidTag> anpmid;
  Fob<PmidTag> pmid;
};

std::vector<AnmaidToPmid> ReadKeyChainList(const boost::filesystem::path& file_path);

bool WriteKeyChainList(const boost::filesystem::path& file_path,
                       const std::vector<AnmaidToPmid>& keychain_list);

#endif

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_FOB_H_
