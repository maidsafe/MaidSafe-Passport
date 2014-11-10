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

#include <string>
#include <type_traits>

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"
#include "maidsafe/passport/detail/fob.h"

#include "maidsafe/common/serialisation.h"

namespace maidsafe {

namespace passport {

namespace detail {

template <typename TagType>
class PublicFob {
 public:
  typedef maidsafe::detail::Name<PublicFob> Name;
  typedef TagType Tag;
  typedef Fob<typename SignerFob<TagType>::Tag> Signer;
  typedef TaggedValue<NonEmptyString, Tag> serialised_type;

  PublicFob() = delete;

  PublicFob(const PublicFob& other)
      : name_(other.name_),
        public_key_(other.public_key_),
        validation_token_(other.validation_token_) {}

  PublicFob(PublicFob&& other)
      : name_(std::move(other.name_)),
        public_key_(std::move(other.public_key_)),
        validation_token_(std::move(other.validation_token_)) {}

  friend void swap(PublicFob& lhs, PublicFob& rhs) {
    using std::swap;
    swap(lhs.name_, rhs.name_);
    swap(lhs.public_key_, rhs.public_key_);
    swap(lhs.validation_token_, rhs.validation_token_);
  }

  PublicFob& operator=(PublicFob other) {
    swap(*this, other);
    return *this;
  }

  explicit PublicFob(const Fob<Tag>& fob)
      : name_(fob.name()),
        public_key_(fob.public_key()),
        validation_token_(fob.validation_token()) {}

  PublicFob(Name name, const serialised_type& serialised_public_fob)
      : name_(std::move(name)), public_key_(), validation_token_() {
    if (!name_->IsInitialised())
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));

    try { maidsafe::ConvertFromString(serialised_public_fob.data.string(), *this); }
    catch(...) { BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error)); }
  }

  serialised_type Serialise() const {
    return serialised_type(NonEmptyString {maidsafe::ConvertToString(*this)});
  }

  Name name() const { return name_; }
  asymm::PublicKey public_key() const { return public_key_; }
  asymm::Signature validation_token() const { return validation_token_; }

  template<typename Archive>
  Archive& load(Archive& ref_archive) {
    std::uint32_t temp_tag;
    std::string temp_raw_public_key;
    auto& archive = ref_archive(temp_tag, temp_raw_public_key, validation_token_);

    if (temp_tag != static_cast<std::uint32_t>(Tag::kValue)) {
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    }

    public_key_ = asymm::DecodeKey(asymm::EncodedPublicKey {std::move(temp_raw_public_key)});
    return archive;
  }

  template<typename Archive>
  Archive& save(Archive& ref_archive) const {
    return ref_archive(static_cast<std::uint32_t>(Tag::kValue),
                       asymm::EncodeKey(public_key_).string(),
                       validation_token_);
  }

 private:
  Name name_;
  asymm::PublicKey public_key_;
  asymm::Signature validation_token_;
};

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_
