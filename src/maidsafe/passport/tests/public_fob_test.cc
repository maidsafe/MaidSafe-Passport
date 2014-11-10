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

#include "maidsafe/passport/types.h"

#include "maidsafe/common/serialisation.h"

namespace maidsafe {

namespace passport {

namespace test {

TEST(PublicFobTest, BEH_GenerateAndValidate) {
  Anmaid anmaid;
  Maid maid(anmaid);
  Anpmid anpmid;
  Pmid pmid(anpmid);
  Anmpid anmpid;
  Mpid mpid(NonEmptyString(RandomAlphaNumericString(1 + RandomUint32() % 100)), anmpid);

  PublicAnmaid public_anmaid(anmaid);
  PublicMaid public_maid(maid);
  PublicAnpmid public_anpmid(anpmid);
  PublicPmid public_pmid(pmid);
  PublicAnmpid public_anmpid(anmpid);
  PublicMpid public_mpid(mpid);

  PublicAnmaid public_anmaid1(public_anmaid);
  PublicMaid public_maid1(public_maid);
  PublicAnpmid public_anpmid1(public_anpmid);
  PublicPmid public_pmid1(public_pmid);
  PublicAnmpid public_anmpid1(public_anmpid);
  PublicMpid public_mpid1(public_mpid);

  PublicAnmaid public_anmaid2(std::move(public_anmaid1));
  PublicMaid public_maid2(std::move(public_maid1));
  PublicAnpmid public_anpmid2(std::move(public_anpmid1));
  PublicPmid public_pmid2(std::move(public_pmid1));
  PublicAnmpid public_anmpid2(std::move(public_anmpid1));
  PublicMpid public_mpid2(std::move(public_mpid1));

  public_anmaid1 = public_anmaid;
  public_maid1 = public_maid;
  public_anpmid1 = public_anpmid;
  public_pmid1 = public_pmid;
  public_anmpid1 = public_anmpid;
  public_mpid1 = public_mpid;

  public_anmaid2 = std::move(public_anmaid1);
  public_maid2 = std::move(public_maid1);
  public_anpmid2 = std::move(public_anpmid1);
  public_pmid2 = std::move(public_pmid1);
  public_anmpid2 = std::move(public_anmpid1);
  public_mpid2 = std::move(public_mpid1);

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

template <typename PublicFobType>
bool CheckSerialisationAndParsing(PublicFobType public_fob) {
  auto name(public_fob.name());
  auto serialised_public_fob(public_fob.Serialise());
  PublicFobType public_fob2(name, serialised_public_fob);
  if (public_fob.name() != public_fob2.name()) {
    LOG(kError) << "Names don't match.";
    return false;
  }
  if (public_fob.validation_token() != public_fob2.validation_token()) {
    LOG(kError) << "Validation tokens don't match.";
    return false;
  }
  if (!asymm::MatchingKeys(public_fob.public_key(), public_fob2.public_key())) {
    LOG(kError) << "Public keys don't match.";
    return false;
  }
  return true;
}

template <typename PublicFobType, typename SerialisedType>
void CheckParsingFromWrongType(PublicFobType& public_fob, SerialisedType serialised_public_fob) {
  static_assert(!std::is_same<typename PublicFobType::Tag,
    typename SerialisedType::tag_type>::value,
    "The test is designed to be passed different types.");
  Identity name{ public_fob.name().value };
  NonEmptyString serialised_string(serialised_public_fob.data);
  public_fob = PublicFobType{ typename PublicFobType::Name{ name },
    typename PublicFobType::serialised_type{ serialised_string } };
}

TEST(PublicFobTest, BEH_SerialisationAndParsing) {
  Anmaid anmaid;
  Maid maid{ anmaid };
  Anpmid anpmid;
  Pmid pmid{ anpmid };
  Anmpid anmpid;
  Mpid mpid{ NonEmptyString{ RandomAlphaNumericString(1 + RandomUint32() % 100) }, anmpid };

  PublicAnmaid public_anmaid{ anmaid };
  PublicMaid public_maid{ maid };
  PublicAnpmid public_anpmid{ anpmid };
  PublicPmid public_pmid{ pmid };
  PublicAnmpid public_anmpid{ anmpid };
  PublicMpid public_mpid{ mpid };

  EXPECT_TRUE(CheckSerialisationAndParsing(public_anmaid));
  EXPECT_TRUE(CheckSerialisationAndParsing(public_maid));
  EXPECT_TRUE(CheckSerialisationAndParsing(public_anpmid));
  EXPECT_TRUE(CheckSerialisationAndParsing(public_pmid));
  EXPECT_TRUE(CheckSerialisationAndParsing(public_anmpid));
  EXPECT_TRUE(CheckSerialisationAndParsing(public_mpid));

  PublicAnmaid::serialised_type serialised_anmaid{ public_anmaid.Serialise() };
  PublicMaid::serialised_type serialised_maid{ public_maid.Serialise() };
  PublicAnpmid::serialised_type serialised_anpmid{ public_anpmid.Serialise() };
  PublicPmid::serialised_type serialised_pmid{ public_pmid.Serialise() };
  PublicAnmpid::serialised_type serialised_anmpid{ public_anmpid.Serialise() };
  PublicMpid::serialised_type serialised_mpid{ public_mpid.Serialise() };

  EXPECT_THROW(CheckParsingFromWrongType(public_anmaid, serialised_maid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anmaid, serialised_anpmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anmaid, serialised_pmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anmaid, serialised_anmpid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anmaid, serialised_mpid), maidsafe_error);

  EXPECT_THROW(CheckParsingFromWrongType(public_maid, serialised_anmaid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_maid, serialised_anpmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_maid, serialised_pmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_maid, serialised_anmpid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_maid, serialised_mpid), maidsafe_error);

  EXPECT_THROW(CheckParsingFromWrongType(public_anpmid, serialised_anmaid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anpmid, serialised_maid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anpmid, serialised_pmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anpmid, serialised_anmpid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anpmid, serialised_mpid), maidsafe_error);

  EXPECT_THROW(CheckParsingFromWrongType(public_pmid, serialised_anmaid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_pmid, serialised_maid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_pmid, serialised_anpmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_pmid, serialised_anmpid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_pmid, serialised_mpid), maidsafe_error);

  EXPECT_THROW(CheckParsingFromWrongType(public_anmpid, serialised_anmaid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anmpid, serialised_maid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anmpid, serialised_anpmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anmpid, serialised_pmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_anmpid, serialised_mpid), maidsafe_error);

  EXPECT_THROW(CheckParsingFromWrongType(public_mpid, serialised_anmaid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_mpid, serialised_maid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_mpid, serialised_anpmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_mpid, serialised_pmid), maidsafe_error);
  EXPECT_THROW(CheckParsingFromWrongType(public_mpid, serialised_anmpid), maidsafe_error);
}

TEST(PublicFobTest, BEH_DoNotConstructPublicFobsFromInvalidStrings) {
  Identity name(RandomString(64));
  NonEmptyString string(RandomAlphaNumericString(1 + RandomUint32() % 100));
  EXPECT_THROW(PublicAnmaid(PublicAnmaid::Name(name), PublicAnmaid::serialised_type(string)),
                  std::exception);
  EXPECT_THROW(PublicMaid(PublicMaid::Name(name), PublicMaid::serialised_type(string)),
                  std::exception);
  EXPECT_THROW(PublicAnpmid(PublicAnpmid::Name(name), PublicAnpmid::serialised_type(string)),
                  std::exception);
  EXPECT_THROW(PublicPmid(PublicPmid::Name(name), PublicPmid::serialised_type(string)),
                  std::exception);
  EXPECT_THROW(PublicAnmpid(PublicAnmpid::Name(name), PublicAnmpid::serialised_type(string)),
                  std::exception);
  EXPECT_THROW(PublicMpid(PublicMpid::Name(name), PublicMpid::serialised_type(string)),
                  std::exception);
}

TEST(PublicFobTest, BEH_DoNotConstructPublicFobsFromUninitialisedStrings) {
  Identity uninitialised_name;
  Identity name(RandomString(64));
  NonEmptyString uninitialised_string;
  NonEmptyString string(RandomAlphaNumericString(1 + RandomUint32() % 100));
  EXPECT_THROW(
      PublicAnmaid(PublicAnmaid::Name(name), (PublicAnmaid::serialised_type(uninitialised_string))),
      std::exception);
  EXPECT_THROW(
      PublicMaid(PublicMaid::Name(name), (PublicMaid::serialised_type(uninitialised_string))),
      std::exception);
  EXPECT_THROW(
      PublicAnpmid(PublicAnpmid::Name(name), (PublicAnpmid::serialised_type(uninitialised_string))),
      std::exception);
  EXPECT_THROW(
      PublicPmid(PublicPmid::Name(name), (PublicPmid::serialised_type(uninitialised_string))),
      std::exception);
  EXPECT_THROW(
      PublicAnmpid(PublicAnmpid::Name(name), (PublicAnmpid::serialised_type(uninitialised_string))),
      std::exception);
  EXPECT_THROW(
      PublicMpid(PublicMpid::Name(name), (PublicMpid::serialised_type(uninitialised_string))),
      std::exception);

  EXPECT_THROW(
      PublicAnmaid(PublicAnmaid::Name(uninitialised_name), (PublicAnmaid::serialised_type(string))),
      std::exception);
  EXPECT_THROW(
      PublicMaid(PublicMaid::Name(uninitialised_name), (PublicMaid::serialised_type(string))),
      std::exception);
  EXPECT_THROW(
      PublicAnpmid(PublicAnpmid::Name(uninitialised_name), (PublicAnpmid::serialised_type(string))),
      std::exception);
  EXPECT_THROW(
      PublicPmid(PublicPmid::Name(uninitialised_name), (PublicPmid::serialised_type(string))),
      std::exception);
  EXPECT_THROW(
      PublicAnmpid(PublicAnmpid::Name(uninitialised_name), (PublicAnmpid::serialised_type(string))),
      std::exception);
  EXPECT_THROW(
      PublicMpid(PublicMpid::Name(uninitialised_name), (PublicMpid::serialised_type(string))),
      std::exception);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
