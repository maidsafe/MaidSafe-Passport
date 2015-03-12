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

#include "maidsafe/passport/detail/public_fob.h"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/serialisation/serialisation.h"

#include "maidsafe/passport/types.h"
#include "maidsafe/passport/tests/test_utils.h"

namespace maidsafe {

namespace passport {

namespace test {

TEST(PublicFobStaticTest, BEH_Cacheability) {
  static_assert(!is_short_term_cacheable<PublicAnmaid>::value, "");
  static_assert(is_short_term_cacheable<PublicMaid>::value, "");
  static_assert(!is_short_term_cacheable<PublicAnpmid>::value, "");
  static_assert(is_short_term_cacheable<PublicPmid>::value, "");
  static_assert(!is_short_term_cacheable<PublicAnmpid>::value, "");
  static_assert(is_short_term_cacheable<PublicMpid>::value, "");
  static_assert(!is_long_term_cacheable<PublicAnmaid>::value, "");
  static_assert(!is_long_term_cacheable<PublicMaid>::value, "");
  static_assert(!is_long_term_cacheable<PublicAnpmid>::value, "");
  static_assert(!is_long_term_cacheable<PublicPmid>::value, "");
  static_assert(!is_long_term_cacheable<PublicAnmpid>::value, "");
  static_assert(!is_long_term_cacheable<PublicMpid>::value, "");
}

template <typename TagType>
class PublicFobTest : public testing::Test {
 protected:
  using Fob = detail::Fob<TagType>;
  using PublicFob = detail::PublicFob<TagType>;
  using WrongTagType = typename InvalidType<TagType>::Tag;
  using WrongFob = detail::Fob<WrongTagType>;
  using WrongPublicFob = detail::PublicFob<WrongTagType>;
};

TYPED_TEST_CASE(PublicFobTest, FobTagTypes);

TYPED_TEST(PublicFobTest, BEH_ConstructAssignAndSwap) {
  using TestPublicFob = typename TestFixture::PublicFob;

  typename TestFixture::Fob fob1(CreateFob<TypeParam>());
  typename TestFixture::Fob fob2(CreateFob<TypeParam>());
  ASSERT_FALSE(Equal(fob1, fob2));

  // Construct from Fob
  TestPublicFob public_fob1(fob1);
  EXPECT_TRUE(Match(fob1, public_fob1));
  TestPublicFob public_fob2(fob2);
  EXPECT_TRUE(Match(fob2, public_fob2));
  EXPECT_FALSE(Equal(public_fob1, public_fob2));

  // Copy construct
  TestPublicFob copied_public_fob(public_fob1);
  EXPECT_TRUE(Match(fob1, copied_public_fob));
  EXPECT_TRUE(Equal(public_fob1, copied_public_fob));

  // Move construct
  TestPublicFob moved_public_fob(std::move(copied_public_fob));
  EXPECT_TRUE(Match(fob1, moved_public_fob));
  EXPECT_TRUE(Equal(public_fob1, moved_public_fob));

  // Copy assign
  copied_public_fob = public_fob2;
  EXPECT_TRUE(Match(fob2, copied_public_fob));
  EXPECT_TRUE(Equal(public_fob2, copied_public_fob));

  // Move assign
  moved_public_fob = std::move(copied_public_fob);
  EXPECT_TRUE(Match(fob2, moved_public_fob));
  EXPECT_TRUE(Equal(public_fob2, moved_public_fob));

  // Swap
  copied_public_fob = public_fob1;
  std::swap(copied_public_fob, moved_public_fob);
  EXPECT_TRUE(Match(fob2, copied_public_fob));
  EXPECT_TRUE(Equal(public_fob2, copied_public_fob));
  EXPECT_TRUE(Match(fob1, moved_public_fob));
  EXPECT_TRUE(Equal(public_fob1, moved_public_fob));
}

TYPED_TEST(PublicFobTest, BEH_SerialisationAndParsing) {
  using TestPublicFob = typename TestFixture::PublicFob;

  typename TestFixture::Fob fob(CreateFob<TypeParam>());
  TestPublicFob public_fob(fob);

  // Valid serialisation and parsing
  SerialisedData serialised_public_fob(Serialise(public_fob));
  TestPublicFob parsed_public_fob(Parse<TestPublicFob>(serialised_public_fob));
  EXPECT_TRUE(Equal(public_fob, parsed_public_fob));

  // Modfiy serialised data and try to parse
  ++serialised_public_fob[RandomUint32() % serialised_public_fob.size()];
  EXPECT_THROW(Parse<TestPublicFob>(serialised_public_fob), common_error);

  // Check parsing from wrong type
  typename TestFixture::WrongFob wrong_fob(CreateFob<typename TestFixture::WrongTagType>());
  typename TestFixture::WrongPublicFob wrong_public_fob(wrong_fob);
  serialised_public_fob = Serialise(wrong_public_fob);
  EXPECT_THROW(Parse<TestPublicFob>(serialised_public_fob), common_error);

  // Serialise/parse as base type
  const std::unique_ptr<Data> data_ptr(new TestPublicFob(fob));
  serialised_public_fob = Serialise(data_ptr);
  std::unique_ptr<Data> parsed_ptr(Parse<std::unique_ptr<Data>>(serialised_public_fob));
  ASSERT_NE(nullptr, parsed_ptr.get());
  ASSERT_NE(nullptr, dynamic_cast<TestPublicFob*>(parsed_ptr.get()));
  EXPECT_TRUE(Equal(public_fob, *dynamic_cast<TestPublicFob*>(parsed_ptr.get())));
}

TYPED_TEST(PublicFobTest, BEH_DefaultConstructed) {
  typename TestFixture::PublicFob public_fob;
  EXPECT_FALSE(public_fob.IsInitialised());
  EXPECT_THROW(public_fob.Name(), common_error);
  EXPECT_THROW(public_fob.public_key(), common_error);
  EXPECT_THROW(public_fob.validation_token(), common_error);
  EXPECT_THROW(Serialise(public_fob), common_error);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
