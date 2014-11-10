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

#include "maidsafe/passport/passport.h"

#include <cstdint>
#include <future>
#include <memory>

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/authentication/user_credentials.h"

#include "maidsafe/passport/detail/fob.h"

namespace maidsafe {

namespace passport {

namespace test {

template <typename Fobtype>
bool AllFieldsMatch(const Fobtype& lhs, const Fobtype& rhs) {
  return lhs.validation_token() == rhs.validation_token() &&
         asymm::MatchingKeys(lhs.private_key(), rhs.private_key()) &&
         asymm::MatchingKeys(lhs.public_key(), rhs.public_key()) &&
         lhs.name() == rhs.name();
}

TEST(PassportTest, BEH_FreeFunctions) {
  MaidAndSigner maid_and_signer{ CreateMaidAndSigner() };
  CreateMpidAndSigner(NonEmptyString{ RandomString((RandomUint32() % 100) + 1) });
  PmidAndSigner pmid_and_signer{ CreatePmidAndSigner() };

  crypto::AES256Key symm_key{ RandomString(crypto::AES256_KeySize - 1) + "a" };
  crypto::AES256InitialisationVector symm_iv{ RandomString(crypto::AES256_IVSize) };

  crypto::CipherText encrypted_maid{ maidsafe::passport::EncryptMaid(maid_and_signer.first,
                                                                     symm_key, symm_iv) };
  crypto::CipherText encrypted_anpmid{ maidsafe::passport::EncryptAnpmid(pmid_and_signer.second,
                                                                         symm_key, symm_iv) };
  crypto::CipherText encrypted_pmid{ maidsafe::passport::EncryptPmid(pmid_and_signer.first,
                                                                     symm_key, symm_iv) };

  Maid maid{ maidsafe::passport::DecryptMaid(encrypted_maid, symm_key, symm_iv) };
  EXPECT_TRUE(AllFieldsMatch(maid_and_signer.first, maid));
  Anpmid anpmid{ maidsafe::passport::DecryptAnpmid(encrypted_anpmid, symm_key, symm_iv) };
  EXPECT_TRUE(AllFieldsMatch(pmid_and_signer.second, anpmid));
  Pmid pmid{ maidsafe::passport::DecryptPmid(encrypted_pmid, symm_key, symm_iv) };
  EXPECT_TRUE(AllFieldsMatch(pmid_and_signer.first, pmid));
  EXPECT_THROW(maidsafe::passport::DecryptMaid(encrypted_anpmid, symm_key, symm_iv),
                  maidsafe_error);
  EXPECT_THROW(maidsafe::passport::DecryptAnpmid(encrypted_pmid, symm_key, symm_iv),
                  maidsafe_error);
  EXPECT_THROW(maidsafe::passport::DecryptPmid(encrypted_maid, symm_key, symm_iv),
                  maidsafe_error);

  symm_key = crypto::AES256Key{ RandomString(crypto::AES256_KeySize - 1) + "b" };
  crypto::CipherText encrypted_maid1{ maidsafe::passport::EncryptMaid(maid_and_signer.first,
                                                                      symm_key, symm_iv) };
  crypto::CipherText encrypted_anpmid1{ maidsafe::passport::EncryptAnpmid(pmid_and_signer.second,
                                                                          symm_key, symm_iv) };
  crypto::CipherText encrypted_pmid1{ maidsafe::passport::EncryptPmid(pmid_and_signer.first,
                                                                      symm_key, symm_iv) };
  EXPECT_TRUE(encrypted_maid != encrypted_maid1);
  EXPECT_TRUE(encrypted_anpmid != encrypted_anpmid1);
  EXPECT_TRUE(encrypted_pmid != encrypted_pmid1);
  EXPECT_THROW(maidsafe::passport::DecryptMaid(encrypted_maid, symm_key, symm_iv),
                  maidsafe_error);
  EXPECT_THROW(maidsafe::passport::DecryptAnpmid(encrypted_anpmid, symm_key, symm_iv),
                  maidsafe_error);
  EXPECT_THROW(maidsafe::passport::DecryptPmid(encrypted_pmid, symm_key, symm_iv),
                  maidsafe_error);
}

authentication::UserCredentials CreateUserCredentials() {
  authentication::UserCredentials user_credentials;
  user_credentials.keyword = maidsafe::make_unique<authentication::UserCredentials::Keyword>(
      RandomAlphaNumericString((RandomUint32() % 100) + 1));
  user_credentials.pin = maidsafe::make_unique<authentication::UserCredentials::Pin>(
      std::to_string(RandomUint32()));
  user_credentials.password = maidsafe::make_unique<authentication::UserCredentials::Password>(
      RandomAlphaNumericString((RandomUint32() % 100) + 1));
  return user_credentials;
}

TEST(PassportTest, FUNC_ConstructorsSettersAndGetters) {
  MaidAndSigner maid_and_signer{ CreateMaidAndSigner() };
  Passport passport{ maid_and_signer };
  EXPECT_TRUE(AllFieldsMatch(passport.GetMaid(), maid_and_signer.first));
  EXPECT_TRUE(passport.GetPmids().empty());
  EXPECT_TRUE(passport.GetMpids().empty());

  // Encrypt/decrypt with just a Maid and Anmaid
  authentication::UserCredentials user_credentials{ CreateUserCredentials() };
  crypto::CipherText encrypted_passport{ passport.Encrypt(user_credentials) };
  EXPECT_TRUE(encrypted_passport->IsInitialised());
  Passport decrypted_passport{ encrypted_passport, user_credentials };
  EXPECT_TRUE(AllFieldsMatch(decrypted_passport.GetMaid(), maid_and_signer.first));
  EXPECT_TRUE(decrypted_passport.GetPmids().empty());
  EXPECT_TRUE(decrypted_passport.GetMpids().empty());

  // Add Pmids, check getters and encrypt/decrypt
  std::vector<PmidAndSigner> pmids_and_signers;
  for (size_t i(0); i < 3; ++i) {
    pmids_and_signers.emplace_back(CreatePmidAndSigner());
    if (i != 0) {
      PmidAndSigner duplicate_anpmid{ std::make_pair(pmids_and_signers.back().first,
                                                     pmids_and_signers.front().second) };
      EXPECT_THROW(passport.AddKeyAndSigner(duplicate_anpmid), maidsafe_error);
      PmidAndSigner duplicate_pmid{ std::make_pair(pmids_and_signers.front().first,
                                                   pmids_and_signers.back().second) };
      EXPECT_THROW(passport.AddKeyAndSigner(duplicate_pmid), maidsafe_error);
    }
    EXPECT_NO_THROW(passport.AddKeyAndSigner(pmids_and_signers.back()));
    ASSERT_TRUE(passport.GetPmids().size() == pmids_and_signers.size());
    EXPECT_TRUE(AllFieldsMatch(passport.GetPmids().back(), pmids_and_signers.back().first));
    EXPECT_THROW(passport.AddKeyAndSigner(pmids_and_signers.back()), maidsafe_error);
    encrypted_passport = passport.Encrypt(user_credentials);
    EXPECT_TRUE(encrypted_passport->IsInitialised());
    Passport decrypted{ encrypted_passport, user_credentials };
    EXPECT_TRUE(AllFieldsMatch(decrypted.GetMaid(), maid_and_signer.first));
    ASSERT_TRUE(decrypted.GetPmids().size() == pmids_and_signers.size());
    EXPECT_TRUE(AllFieldsMatch(decrypted.GetPmids().back(), pmids_and_signers.back().first));
    EXPECT_TRUE(decrypted.GetMpids().empty());
  }

  // Add Mpids, check getters and encrypt/decrypt
  std::vector<MpidAndSigner> mpids_and_signers;
  for (size_t i(0); i < 3; ++i) {
    mpids_and_signers.emplace_back(CreateMpidAndSigner(NonEmptyString{ std::to_string(i) }));
    if (i != 0) {
      MpidAndSigner duplicate_anmpid{ std::make_pair(mpids_and_signers.back().first,
                                                     mpids_and_signers.front().second) };
      EXPECT_THROW(passport.AddKeyAndSigner(duplicate_anmpid), maidsafe_error);
      MpidAndSigner duplicate_mpid{ std::make_pair(mpids_and_signers.front().first,
                                                   mpids_and_signers.back().second) };
      EXPECT_THROW(passport.AddKeyAndSigner(duplicate_mpid), maidsafe_error);
    }
    EXPECT_NO_THROW(passport.AddKeyAndSigner(mpids_and_signers.back()));
    ASSERT_TRUE(passport.GetMpids().size() == mpids_and_signers.size());
    EXPECT_TRUE(AllFieldsMatch(passport.GetMpids().back(), mpids_and_signers.back().first));
    EXPECT_THROW(passport.AddKeyAndSigner(mpids_and_signers.back()), maidsafe_error);
    encrypted_passport = passport.Encrypt(user_credentials);
    EXPECT_TRUE(encrypted_passport->IsInitialised());
    Passport decrypted{ encrypted_passport, user_credentials };
    EXPECT_TRUE(AllFieldsMatch(decrypted.GetMaid(), maid_and_signer.first));
    EXPECT_TRUE(decrypted.GetPmids().size() == pmids_and_signers.size());
    ASSERT_TRUE(decrypted.GetMpids().size() == mpids_and_signers.size());
    EXPECT_TRUE(AllFieldsMatch(decrypted.GetMpids().back(), mpids_and_signers.back().first));
  }
}

template <typename Fobtype>
bool NoFieldsMatch(const Fobtype& lhs, const Fobtype& rhs) {
  if (lhs.validation_token() == rhs.validation_token()) {
    LOG(kError) << "Validation tokens match.";
    return false;
  }
  if (asymm::MatchingKeys(lhs.private_key(), rhs.private_key())) {
    LOG(kError) << "Private keys match.";
    return false;
  }
  if (asymm::MatchingKeys(lhs.public_key(), rhs.public_key())) {
    LOG(kError) << "Public keys match.";
    return false;
  }
  if (lhs.name() == rhs.name()) {
    LOG(kError) << "Names match";
    return false;
  }
  return true;
}

TEST(PassportTest, FUNC_RemoveAndReplaceKeys) {
  MaidAndSigner maid_and_signer{ CreateMaidAndSigner() };
  Passport passport{ maid_and_signer };
  std::vector<PmidAndSigner> pmids_and_signers;
  for (size_t i(0); i < 3; ++i) {
    pmids_and_signers.emplace_back(CreatePmidAndSigner());
    passport.AddKeyAndSigner(pmids_and_signers.back());
  }
  std::vector<MpidAndSigner> mpids_and_signers;
  for (size_t i(0); i < 3; ++i) {
    mpids_and_signers.emplace_back(CreateMpidAndSigner(NonEmptyString{ std::to_string(i) }));
    passport.AddKeyAndSigner(mpids_and_signers.back());
  }

  // Replace Maid
  MaidAndSigner new_maid_and_signer{ CreateMaidAndSigner() };
  MaidAndSigner duplicate_new_maid{ std::make_pair(maid_and_signer.first,
                                                   new_maid_and_signer.second) };
  EXPECT_THROW(passport.ReplaceMaidAndSigner(maid_and_signer.first, duplicate_new_maid),
                  maidsafe_error);
  EXPECT_TRUE(AllFieldsMatch(passport.GetMaid(), maid_and_signer.first));

  MaidAndSigner duplicate_new_signer{ std::make_pair(new_maid_and_signer.first,
                                                     maid_and_signer.second) };
  EXPECT_THROW(passport.ReplaceMaidAndSigner(maid_and_signer.first, duplicate_new_signer),
                  maidsafe_error);
  EXPECT_TRUE(AllFieldsMatch(passport.GetMaid(), maid_and_signer.first));

  Anmaid anmaid{ passport.ReplaceMaidAndSigner(maid_and_signer.first, new_maid_and_signer) };
  EXPECT_TRUE(AllFieldsMatch(anmaid, maid_and_signer.second));
  EXPECT_THROW(passport.ReplaceMaidAndSigner(maid_and_signer.first, new_maid_and_signer),
                  maidsafe_error);
  EXPECT_TRUE(AllFieldsMatch(passport.GetMaid(), new_maid_and_signer.first));
  EXPECT_TRUE(NoFieldsMatch(passport.GetMaid(), maid_and_signer.first));

  // Remove Maid
  EXPECT_THROW(passport.RemoveKeyAndSigner(maid_and_signer.first), maidsafe_error);
  EXPECT_TRUE(AllFieldsMatch(passport.GetMaid(), new_maid_and_signer.first));
  anmaid = passport.RemoveKeyAndSigner(new_maid_and_signer.first);
  EXPECT_TRUE(AllFieldsMatch(anmaid, new_maid_and_signer.second));
  EXPECT_THROW(passport.GetMaid(), maidsafe_error);
  EXPECT_THROW(passport.RemoveKeyAndSigner(new_maid_and_signer.first), maidsafe_error);
  EXPECT_THROW(passport.ReplaceMaidAndSigner(maid_and_signer.first, new_maid_and_signer),
                  maidsafe_error);
  EXPECT_THROW(passport.Encrypt(CreateUserCredentials()), maidsafe_error);

  // Remove Pmids
  Anpmid anpmid{ passport.RemoveKeyAndSigner(pmids_and_signers[1].first) };
  EXPECT_TRUE(AllFieldsMatch(anpmid, pmids_and_signers[1].second));
  std::vector<Pmid> pmids{ passport.GetPmids() };
  ASSERT_TRUE(pmids.size() == 2U);
  EXPECT_TRUE(pmids[0].name() == pmids_and_signers[0].first.name());
  EXPECT_TRUE(pmids[1].name() == pmids_and_signers[2].first.name());
  EXPECT_THROW(passport.RemoveKeyAndSigner(pmids_and_signers[1].first), maidsafe_error);

  anpmid = passport.RemoveKeyAndSigner(pmids_and_signers[2].first);
  EXPECT_TRUE(AllFieldsMatch(anpmid, pmids_and_signers[2].second));
  EXPECT_TRUE(passport.GetPmids().size() == 1U);

  anpmid = passport.RemoveKeyAndSigner(pmids_and_signers[0].first);
  EXPECT_TRUE(AllFieldsMatch(anpmid, pmids_and_signers[0].second));
  EXPECT_TRUE(passport.GetPmids().empty());

  // Remove Mpids
  Anmpid anmpid{ passport.RemoveKeyAndSigner(mpids_and_signers[0].first) };
  EXPECT_TRUE(AllFieldsMatch(anmpid, mpids_and_signers[0].second));
  std::vector<Mpid> mpids{ passport.GetMpids() };
  ASSERT_TRUE(mpids.size() == 2U);
  EXPECT_TRUE(mpids[0].name() == mpids_and_signers[1].first.name());
  EXPECT_TRUE(mpids[1].name() == mpids_and_signers[2].first.name());
  EXPECT_THROW(passport.RemoveKeyAndSigner(mpids_and_signers[0].first), maidsafe_error);

  anmpid = passport.RemoveKeyAndSigner(mpids_and_signers[2].first);
  EXPECT_TRUE(AllFieldsMatch(anmpid, mpids_and_signers[2].second));
  EXPECT_TRUE(passport.GetMpids().size() == 1U);

  anmpid = passport.RemoveKeyAndSigner(mpids_and_signers[1].first);
  EXPECT_TRUE(AllFieldsMatch(anmpid, mpids_and_signers[1].second));
  EXPECT_TRUE(passport.GetMpids().empty());
}

TEST(PassportTest, FUNC_Encrypt) {
  MaidAndSigner maid_and_signer{ CreateMaidAndSigner() };
  Passport passport{ maid_and_signer };
  std::vector<PmidAndSigner> pmids_and_signers;
  for (size_t i(0); i < 3; ++i) {
    pmids_and_signers.emplace_back(CreatePmidAndSigner());
    passport.AddKeyAndSigner(pmids_and_signers.back());
  }
  std::vector<MpidAndSigner> mpids_and_signers;
  for (size_t i(0); i < 3; ++i) {
    mpids_and_signers.emplace_back(CreateMpidAndSigner(NonEmptyString{ std::to_string(i) }));
    passport.AddKeyAndSigner(mpids_and_signers.back());
  }

  const std::string kKeywordStr{ RandomAlphaNumericString((RandomUint32() % 100) + 1) };
  const uint32_t kPinValue{ RandomUint32() };
  const std::string kPasswordStr{ RandomAlphaNumericString((RandomUint32() % 100) + 1) };
  authentication::UserCredentials user_credentials;
  typedef authentication::UserCredentials::Keyword Keyword;
  typedef authentication::UserCredentials::Pin Pin;
  typedef authentication::UserCredentials::Password Password;
  user_credentials.pin = maidsafe::make_unique<Pin>(std::to_string(kPinValue));
  user_credentials.password = maidsafe::make_unique<Password>(kPasswordStr);

  // Check encrypting with null credential fields
  EXPECT_THROW(passport.Encrypt(user_credentials), maidsafe_error);
  user_credentials.keyword = maidsafe::make_unique<Keyword>(kKeywordStr);

  user_credentials.pin.reset();
  EXPECT_THROW(passport.Encrypt(user_credentials), maidsafe_error);
  user_credentials.pin = maidsafe::make_unique<Pin>(std::to_string(kPinValue));

  user_credentials.password.reset();
  EXPECT_THROW(passport.Encrypt(user_credentials), maidsafe_error);
  user_credentials.password = maidsafe::make_unique<Password>(kPasswordStr);

  // Check parsing with invalid encrypted_passport
  EXPECT_THROW(Passport(crypto::CipherText{ NonEmptyString{ RandomString(100) } },
                           user_credentials), maidsafe_error);

  // Check parsing with modified credential fields
  crypto::CipherText encrypted_passport{ passport.Encrypt(user_credentials) };
  user_credentials.keyword = maidsafe::make_unique<Keyword>(kKeywordStr + 'z');
  EXPECT_THROW(Passport(encrypted_passport, user_credentials), maidsafe_error);
  user_credentials.keyword = maidsafe::make_unique<Keyword>(kKeywordStr);

  user_credentials.pin = maidsafe::make_unique<Pin>(std::to_string(kPinValue + 9));
  EXPECT_THROW(Passport(encrypted_passport, user_credentials), maidsafe_error);
  user_credentials.pin = maidsafe::make_unique<Pin>(std::to_string(kPinValue));

  user_credentials.password = maidsafe::make_unique<Password>(kPasswordStr + 'z');
  EXPECT_THROW(Passport(encrypted_passport, user_credentials), maidsafe_error);
  user_credentials.password = maidsafe::make_unique<Password>(kPasswordStr);

  // Check parsing correctly
  Passport decrypted{ encrypted_passport, user_credentials };
  EXPECT_TRUE(AllFieldsMatch(decrypted.GetMaid(), maid_and_signer.first));

  std::vector<Pmid> pmids{ decrypted.GetPmids() };
  ASSERT_TRUE(pmids.size() == pmids_and_signers.size());
  std::vector<Pmid>::iterator pmids_itr{ std::begin(pmids) };
  std::vector<PmidAndSigner>::iterator pmids_and_signers_itr{ std::begin(pmids_and_signers) };
  while (pmids_itr != std::end(pmids))
    EXPECT_TRUE(AllFieldsMatch(*pmids_itr++, (*pmids_and_signers_itr++).first));

  std::vector<Mpid> mpids{ decrypted.GetMpids() };
  ASSERT_TRUE(mpids.size() == mpids_and_signers.size());
  std::vector<Mpid>::iterator mpids_itr{ std::begin(mpids) };
  std::vector<MpidAndSigner>::iterator mpids_and_signers_itr{ std::begin(mpids_and_signers) };
  while (mpids_itr != std::end(mpids))
    EXPECT_TRUE(AllFieldsMatch(*mpids_itr++, (*mpids_and_signers_itr++).first));
}

TEST(PassportTest, FUNC_ParallelAddsEncryptsAndRemoves) {
  MaidAndSigner maid_and_signer{ CreateMaidAndSigner() };
  Passport passport{ maid_and_signer };
  std::vector<std::future<void>> add_futures;
  std::vector<std::future<std::unique_ptr<Maid>>> get_maid_futures;
  std::vector<std::future<std::vector<Pmid>>> get_pmids_futures;
  std::vector<std::future<std::vector<Mpid>>> get_mpids_futures;

  // Add Pmids, Mpids and replace Maid while getting all
  std::vector<PmidAndSigner> pmids_and_signers;
  std::vector<MpidAndSigner> mpids_and_signers;
  for (size_t i(0); i < 3; ++i) {
    pmids_and_signers.emplace_back(CreatePmidAndSigner());
    mpids_and_signers.emplace_back(CreateMpidAndSigner(NonEmptyString{ std::to_string(i) }));
  }

  for (size_t i(0); i < 3; ++i) {
    add_futures.emplace_back(std::async(std::launch::async,
        [&, i] { passport.AddKeyAndSigner(pmids_and_signers[i]); }));
    add_futures.emplace_back(std::async(std::launch::async,
        [&, i] { passport.AddKeyAndSigner(mpids_and_signers[i]); }));
    get_maid_futures.emplace_back(std::async(std::launch::async,
        [&] { return maidsafe::make_unique<Maid>(passport.GetMaid()); }));
    get_pmids_futures.emplace_back(std::async(std::launch::async,
        [&] { return passport.GetPmids(); }));
    get_mpids_futures.emplace_back(std::async(std::launch::async,
        [&] { return passport.GetMpids(); }));
  }
  MaidAndSigner new_maid_and_signer{ CreateMaidAndSigner() };
  std::future<Anmaid> replace_maid_future{ std::async(std::launch::async,
      [&] { return passport.ReplaceMaidAndSigner(maid_and_signer.first, new_maid_and_signer); }) };

  for (auto& add_future : add_futures) {
    EXPECT_NO_THROW(add_future.get());
  }
  for (auto& get_maid_future : get_maid_futures) {
    EXPECT_NO_THROW(get_maid_future.get());
  }
  for (auto& get_pmids_future : get_pmids_futures) {
    EXPECT_NO_THROW(get_pmids_future.get());
  }
  for (auto& get_mpids_future : get_mpids_futures) {
    EXPECT_NO_THROW(get_mpids_future.get());
  }
  EXPECT_NO_THROW(replace_maid_future.get());

  // Remove Pmids, Mpids while encrypting and getting all
  get_maid_futures.clear();
  get_pmids_futures.clear();
  get_mpids_futures.clear();
  std::vector<std::future<Anpmid>> remove_pmids_futures;
  std::vector<std::future<Anmpid>> remove_mpids_futures;
  std::vector<std::future<crypto::CipherText>> encrypt_futures;
  authentication::UserCredentials user_credentials{ CreateUserCredentials() };

  for (size_t i(0); i < 3; ++i) {
    remove_pmids_futures.emplace_back(std::async(std::launch::async,
        [&, i] { return passport.RemoveKeyAndSigner(pmids_and_signers[i].first); }));
    remove_mpids_futures.emplace_back(std::async(std::launch::async,
        [&, i] { return passport.RemoveKeyAndSigner(mpids_and_signers[i].first); }));
    encrypt_futures.emplace_back(std::async(std::launch::async,
        [&] { return passport.Encrypt(user_credentials); }));
    get_maid_futures.emplace_back(std::async(std::launch::async,
        [&] { return maidsafe::make_unique<Maid>(passport.GetMaid()); }));
    get_pmids_futures.emplace_back(std::async(std::launch::async,
        [&] { return passport.GetPmids(); }));
    get_mpids_futures.emplace_back(std::async(std::launch::async,
        [&] { return passport.GetMpids(); }));
  }

  for (auto& remove_pmids_future : remove_pmids_futures) {
    EXPECT_NO_THROW(remove_pmids_future.get());
  }
  for (auto& remove_mpids_future : remove_mpids_futures) {
    EXPECT_NO_THROW(remove_mpids_future.get());
  }
  for (auto& encrypt_future : encrypt_futures) {
    EXPECT_NO_THROW(encrypt_future.get());
  }
  for (auto& get_maid_future : get_maid_futures) {
    EXPECT_NO_THROW(get_maid_future.get());
  }
  for (auto& get_pmids_future : get_pmids_futures) {
    EXPECT_NO_THROW(get_pmids_future.get());
  }
  for (auto& get_mpids_future : get_mpids_futures) {
    EXPECT_NO_THROW(get_mpids_future.get());
  }
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
