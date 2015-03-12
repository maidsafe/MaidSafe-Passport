/*  Copyright 2015 MaidSafe.net limited

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

#ifndef MAIDSAFE_PASSPORT_TESTS_TEST_UTILS_H_
#define MAIDSAFE_PASSPORT_TESTS_TEST_UTILS_H_

#include "maidsafe/passport/detail/fob.h"

namespace maidsafe {

namespace passport {

namespace test {

typedef testing::Types<detail::AnmaidTag, detail::MaidTag, detail::AnpmidTag, detail::PmidTag,
                       detail::AnmpidTag, detail::MpidTag> FobTagTypes;

template <typename TagType>
testing::AssertionResult Equal(const detail::Fob<TagType>& lhs, const detail::Fob<TagType>& rhs) {
  if (lhs.name() != rhs.name())
    return testing::AssertionFailure() << "Name mismatch.";
  if (!asymm::MatchingKeys(lhs.private_key(), rhs.private_key()))
    return testing::AssertionFailure() << "Private key mismatch.";
  if (!asymm::MatchingKeys(lhs.public_key(), rhs.public_key()))
    return testing::AssertionFailure() << "Public key mismatch.";
  if (lhs.validation_token() != rhs.validation_token())
    return testing::AssertionFailure() << "Validation token mismatch.";
  return testing::AssertionSuccess();
}

template <typename TagType>
testing::AssertionResult Equal(const detail::PublicFob<TagType>& lhs,
                               const detail::PublicFob<TagType>& rhs) {
  if (lhs.IsInitialised() != rhs.IsInitialised())
    return testing::AssertionFailure() << "One PublicFob is uninitialised.";
  if (!lhs.IsInitialised() && !rhs.IsInitialised())
    return testing::AssertionSuccess();
  if (lhs.Name() != rhs.Name())
    return testing::AssertionFailure() << "Name mismatch.";
  if (!asymm::MatchingKeys(lhs.public_key(), rhs.public_key()))
    return testing::AssertionFailure() << "Public key mismatch.";
  if (lhs.validation_token() != rhs.validation_token())
    return testing::AssertionFailure() << "Validation token mismatch.";
  return testing::AssertionSuccess();
}

template <typename TagType>
testing::AssertionResult Match(const detail::Fob<TagType>& fob,
                               const detail::PublicFob<TagType>& public_fob) {
  if (!public_fob.IsInitialised())
    return testing::AssertionFailure() << "PublicFob is uninitialised.";
  if (fob.name() != public_fob.Name())
    return testing::AssertionFailure() << "Name mismatch.";
  if (!asymm::MatchingKeys(fob.public_key(), public_fob.public_key()))
    return testing::AssertionFailure() << "Public key mismatch.";
  if (fob.validation_token() != public_fob.validation_token())
    return testing::AssertionFailure() << "Validation token mismatch.";
  return testing::AssertionSuccess();
}

// For self-signed keys
template <typename TagType>
detail::Fob<TagType> CreateFob(
    typename std::enable_if<
        std::is_same<detail::Fob<TagType>, typename detail::Fob<TagType>::Signer>::value>::type* =
        0) {
  return detail::Fob<TagType>();
}

// For non-self-signed keys
template <typename TagType>
detail::Fob<TagType> CreateFob(
    typename std::enable_if<
        !std::is_same<detail::Fob<TagType>, typename detail::Fob<TagType>::Signer>::value>::type* =
        0) {
  typename detail::Fob<TagType>::Signer signer_fob;
  return detail::Fob<TagType>(signer_fob);
}

template <typename TagType>
struct InvalidType;

template <>
struct InvalidType<detail::AnmaidTag> {
  using Tag = detail::AnmpidTag;
};

template <>
struct InvalidType<detail::MaidTag> {
  using Tag = detail::AnmpidTag;
};

template <>
struct InvalidType<detail::AnpmidTag> {
  using Tag = detail::AnmpidTag;
};

template <>
struct InvalidType<detail::PmidTag> {
  using Tag = detail::AnmpidTag;
};

template <>
struct InvalidType<detail::AnmpidTag> {
  using Tag = detail::AnmaidTag;
};

template <>
struct InvalidType<detail::MpidTag> {
  using Tag = detail::AnmpidTag;
};

}  // namespace test

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_TESTS_TEST_UTILS_H_
