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

#include <string>

#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/serialisation/serialisation.h"

#include "maidsafe/passport/types.h"
#include "maidsafe/passport/tests/test_utils.h"

namespace maidsafe {

namespace passport {

namespace test {

template <typename TagType>
class FobTest : public testing::Test {
 protected:
  using Fob = detail::Fob<TagType>;
  using WrongTagType = typename InvalidType<TagType>::Tag;
  using WrongFob = detail::Fob<WrongTagType>;
};

TYPED_TEST_CASE(FobTest, FobTagTypes);

TYPED_TEST(FobTest, BEH_ConstructAssignAndSwap) {
  // Construct normally (self-signed are default constructed, non-self-signed are passed signer in
  // constructor)
  typename TestFixture::Fob fob1(CreateFob<TypeParam>());
  typename TestFixture::Fob fob2(CreateFob<TypeParam>());
  ASSERT_FALSE(Equal(fob1, fob2));

  // Check operator== and operator!= for the validation tokens while we've got two different keys
  EXPECT_FALSE(fob1.validation_token() == fob2.validation_token());
  EXPECT_FALSE(fob2.validation_token() == fob1.validation_token());
  EXPECT_TRUE(fob1.validation_token() != fob2.validation_token());
  EXPECT_TRUE(fob2.validation_token() != fob1.validation_token());
  EXPECT_TRUE(fob1.validation_token() == fob1.validation_token());
  EXPECT_FALSE(fob1.validation_token() != fob1.validation_token());
  auto copy_of_validation_token(fob1.validation_token());
  EXPECT_TRUE(fob1.validation_token() == copy_of_validation_token);
  EXPECT_FALSE(fob1.validation_token() != copy_of_validation_token);

  // Copy construct
  typename TestFixture::Fob copied_fob(fob1);
  EXPECT_TRUE(Equal(fob1, copied_fob));

  // Move construct
  typename TestFixture::Fob moved_fob(std::move(copied_fob));
  EXPECT_TRUE(Equal(fob1, moved_fob));

  // Copy assign
  copied_fob = fob2;
  EXPECT_TRUE(Equal(fob2, copied_fob));

  // Move assign
  moved_fob = std::move(copied_fob);
  EXPECT_TRUE(Equal(fob2, moved_fob));

  // Swap
  copied_fob = fob1;
  swap(copied_fob, moved_fob);
  EXPECT_TRUE(Equal(fob2, copied_fob));
  EXPECT_TRUE(Equal(fob1, moved_fob));
}

TYPED_TEST(FobTest, BEH_EncryptAndDecrypt) {
  typename TestFixture::Fob fob(CreateFob<TypeParam>());

  // Valid encryption and decryption
  crypto::AES256KeyAndIV symm_key_and_iv(
      RandomBytes(crypto::AES256_KeySize + crypto::AES256_IVSize));
  crypto::CipherText encrypted_fob(fob.Encrypt(symm_key_and_iv));
  typename TestFixture::Fob decrypted_fob(encrypted_fob, symm_key_and_iv);
  EXPECT_TRUE(Equal(fob, decrypted_fob));

  // Modfiy encrypted data and try to decrypt
  std::size_t index(RandomUint32() % encrypted_fob->string().size());
  auto invalid_encrypted_fob(encrypted_fob->string());
  invalid_encrypted_fob[index] = (invalid_encrypted_fob[index] == 'a' ? 'b' : 'a');
  EXPECT_THROW(typename TestFixture::Fob(crypto::CipherText(NonEmptyString(invalid_encrypted_fob)),
                                         symm_key_and_iv),
               common_error);

  // Check decrypting with wrong AES key/IV
  index = RandomUint32() % crypto::AES256_KeySize;
  auto invalid_symm_key(symm_key_and_iv.string());
  invalid_symm_key[index] = (invalid_symm_key[index] == 'a' ? 'b' : 'a');
  index = (RandomUint32() % crypto::AES256_IVSize) + crypto::AES256_KeySize;
  auto invalid_symm_iv(symm_key_and_iv.string());
  invalid_symm_iv[index] = (invalid_symm_iv[index] == 'a' ? 'b' : 'a');
  EXPECT_THROW(typename TestFixture::Fob(encrypted_fob, crypto::AES256KeyAndIV(invalid_symm_key)),
               common_error);
  EXPECT_THROW(typename TestFixture::Fob(encrypted_fob, crypto::AES256KeyAndIV(invalid_symm_iv)),
               common_error);

  // Check decrypting from wrong type
  typename TestFixture::WrongFob wrong_fob(CreateFob<typename TestFixture::WrongTagType>());
  encrypted_fob = wrong_fob.Encrypt(symm_key_and_iv);
  EXPECT_THROW(typename TestFixture::Fob(encrypted_fob, symm_key_and_iv), common_error);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
