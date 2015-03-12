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

#ifndef MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_
#define MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_

#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "boost/optional/optional.hpp"
#include "cereal/access.hpp"
#include "cereal/types/base_class.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/data_types/data.h"
// We must include all archives which this polymorphic type will be used with *before* the
// CEREAL_REGISTER_TYPE call below.
#include "maidsafe/common/serialisation/binary_archive.h"
#include "maidsafe/common/serialisation/serialisation.h"

#include "maidsafe/passport/detail/config.h"
#include "maidsafe/passport/detail/fob.h"

namespace maidsafe {

namespace passport {

namespace detail {

template <typename TagType>
class PublicFob : public Data {
 public:
  using Tag = TagType;
  using Signer = Fob<typename SignerFob<TagType>::Tag>;
  using ValidationToken = typename Fob<Tag>::ValidationToken;

  explicit PublicFob(const Fob<Tag>& fob)
      : Data(fob.name()),
        public_key_(fob.public_key()),
        validation_token_(fob.validation_token()) {}

  PublicFob() = default;

  PublicFob(const PublicFob& other) = default;

  PublicFob(PublicFob&& other)
      : Data(std::move(other)),
        public_key_(std::move(other.public_key_)),
        validation_token_(std::move(other.validation_token_)) {}

  PublicFob& operator=(const PublicFob&) = default;

  PublicFob& operator=(PublicFob&& other) {
    Data::operator=(std::move(other));
    public_key_ = std::move(other.public_key_);
    validation_token_ = std::move(other.validation_token_);
    return *this;
  }

  virtual ~PublicFob() final = default;

  asymm::PublicKey public_key() const {
    if (!IsInitialised())
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::uninitialised));
    return public_key_;
  }

  ValidationToken validation_token() const {
    if (!IsInitialised())
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::uninitialised));
    return validation_token_;
  }

  template <typename Archive>
  Archive& save(Archive& archive) const {
    archive(cereal::base_class<Data>(this));  // Do this first to check IsInitialised() == true.
    return archive(asymm::EncodeKey(public_key_).string(), validation_token_);
  }

  template <typename Archive>
  Archive& load(Archive& archive) {
    SerialisedData temp_raw_public_key;
    try {
      archive(cereal::base_class<Data>(this), temp_raw_public_key, validation_token_);
      public_key_ = asymm::DecodeKey(asymm::EncodedPublicKey(temp_raw_public_key));
    } catch (const std::exception&) {
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    }
    ValidateToken();
    return archive;
  }

 private:
  virtual std::uint32_t ThisTypeId() const final { return TagType::type_id; }

  // For self-signed keys
  template <typename T = TagType>
  void ValidateToken(
      typename std::enable_if<std::is_same<Fob<T>, Signer>::value>::type* = 0) const {
    try {
      // Check the validation token is valid
      if (!asymm::CheckSignature(asymm::PlainText(Serialise(public_key_, Tag::type_id)),
                                 validation_token_, public_key_)) {
        BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
      }
      // Check the name is the hash of the public key + validation token
      if (crypto::Hash<crypto::SHA512>(Serialise(public_key_, validation_token_)) != name_) {
        BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
      }
    } catch (const std::exception& e) {
      LOG(kWarning) << "Error validating public key token: " << boost::diagnostic_information(e);
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    }
  }

  // For non-self-signed keys
  template <typename T = TagType>
  void ValidateToken(
      typename std::enable_if<!std::is_same<Fob<T>, Signer>::value>::type* = 0) const {
    try {
      // Check the validation token is valid
      SerialisedData self(validation_token_.signature_of_public_key.string());
      SerialisedData serialised_public_key(Serialise(public_key_));
      self.insert(self.end(), serialised_public_key.begin(), serialised_public_key.end());
      SerialisedData type_id(Serialise(Tag::type_id));
      self.insert(self.end(), type_id.begin(), type_id.end());
      if (!asymm::CheckSignature(asymm::PlainText(self), validation_token_.self_signature,
                                 public_key_)) {
        BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
      }
      // Check the name is the hash of the public key + validation token
      if (crypto::Hash<crypto::SHA512>(Serialise(public_key_, validation_token_)) != name_)
        BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    } catch (const std::exception& e) {
      LOG(kWarning) << "Error validating public key token: " << boost::diagnostic_information(e);
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    }
  }

  asymm::PublicKey public_key_;
  ValidationToken validation_token_;
};

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_
