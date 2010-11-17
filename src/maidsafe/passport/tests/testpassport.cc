/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Unit tests for Passport class
* Version:      1.0
* Created:      2010-10-19-23.59.27
* Revision:     none
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include <boost/lexical_cast.hpp>
#include <gtest/gtest.h>
#include <maidsafe/base/utils.h>

#include "maidsafe/passport/passport.h"

namespace maidsafe {

namespace passport {

namespace test {

const boost::uint16_t kRsaKeySize(4096);
const boost::uint8_t kMaxThreadCount(5);

class PassportTest : public testing::Test {
 public:
  PassportTest()
      : passport_(kRsaKeySize, kMaxThreadCount),
        kUsername_(base::RandomAlphaNumericString(15)),
        kPin_(boost::lexical_cast<std::string>(base::RandomUint32())),
        kPassword_(base::RandomAlphaNumericString(20)),
        kPlainTextMasterData_(base::RandomString(10000)),
        mid_name_(),
        smid_name_() {}
 protected:
  typedef std::tr1::shared_ptr<pki::Packet> PacketPtr;
  typedef std::tr1::shared_ptr<MidPacket> MidPtr;
  typedef std::tr1::shared_ptr<TmidPacket> TmidPtr;
  typedef std::tr1::shared_ptr<SignaturePacket> SignaturePtr;
  void SetUp() {
    passport_.Init();
  }
  void TearDown() {}
  Passport passport_;
  const std::string kUsername_, kPin_, kPassword_, kPlainTextMasterData_;
  std::string mid_name_, smid_name_;
};

TEST_F(PassportTest, FUNC_PASSPORT_SignaturePacketFunctions) {
  EXPECT_EQ(kNullPointer,
            passport_.InitialiseSignaturePacket(ANMID, SignaturePtr()));

  SignaturePtr signature_packet(new SignaturePacket);
  EXPECT_EQ(kPassportError,
            passport_.InitialiseSignaturePacket(MID, signature_packet));
  EXPECT_TRUE(signature_packet->name().empty());
  EXPECT_FALSE(passport_.GetPacket(MID, false));
  EXPECT_FALSE(passport_.GetPacket(MID, true));

  EXPECT_EQ(kNoSigningPacket,
            passport_.InitialiseSignaturePacket(MAID, signature_packet));
  EXPECT_TRUE(signature_packet->name().empty());
  EXPECT_FALSE(passport_.GetPacket(MAID, false));
  EXPECT_FALSE(passport_.GetPacket(MAID, true));

  SignaturePtr anmaid1(new SignaturePacket);
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid1));
  EXPECT_FALSE(anmaid1->name().empty());
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false)->Equals(anmaid1.get()));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true));

  SignaturePtr anmaid2(new SignaturePacket);
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid2));
  EXPECT_FALSE(anmaid2->name().empty());
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false)->Equals(anmaid2.get()));
  EXPECT_FALSE(anmaid1->Equals(anmaid2.get()));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true));

  EXPECT_EQ(kNoSigningPacket,
            passport_.InitialiseSignaturePacket(MAID, signature_packet));
  EXPECT_TRUE(signature_packet->name().empty());
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true));
  EXPECT_FALSE(passport_.GetPacket(MAID, false));
  EXPECT_FALSE(passport_.GetPacket(MAID, true));

  EXPECT_EQ(kPassportError, passport_.ConfirmSignaturePacket(SignaturePtr()));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true));

  EXPECT_EQ(kPacketsNotEqual, passport_.ConfirmSignaturePacket(anmaid1));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true));

  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(anmaid2));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2.get()));

  SignaturePtr anmaid3(new SignaturePacket);
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid3));
  EXPECT_FALSE(anmaid3->name().empty());
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false)->Equals(anmaid3.get()));
  EXPECT_FALSE(anmaid2->Equals(anmaid3.get()));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2.get()));

  EXPECT_TRUE(passport_.SignaturePacketName(MAID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKey(MAID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketPrivateKey(MAID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKeySignature(MAID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketName(MAID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKey(MAID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketPrivateKey(MAID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKeySignature(MAID, true).empty());
  EXPECT_EQ(anmaid3->name(), passport_.SignaturePacketName(ANMAID, false));
  EXPECT_EQ(anmaid3->value(),
            passport_.SignaturePacketPublicKey(ANMAID, false));
  EXPECT_EQ(anmaid3->private_key(),
            passport_.SignaturePacketPrivateKey(ANMAID, false));
  EXPECT_EQ(anmaid3->public_key_signature(),
            passport_.SignaturePacketPublicKeySignature(ANMAID, false));
  EXPECT_EQ(anmaid2->name(), passport_.SignaturePacketName(ANMAID, true));
  EXPECT_EQ(anmaid2->value(), passport_.SignaturePacketPublicKey(ANMAID, true));
  EXPECT_EQ(anmaid2->private_key(),
            passport_.SignaturePacketPrivateKey(ANMAID, true));
  EXPECT_EQ(anmaid2->public_key_signature(),
            passport_.SignaturePacketPublicKeySignature(ANMAID, true));

  EXPECT_EQ(kPassportError, passport_.RevertSignaturePacket(MID));
  EXPECT_EQ(kPassportError, passport_.RevertSignaturePacket(MAID));
  EXPECT_EQ(kSuccess, passport_.RevertSignaturePacket(ANMAID));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2.get()));

  SignaturePtr maid(new SignaturePacket);
  EXPECT_EQ(kSuccess, passport_.InitialiseSignaturePacket(MAID, maid));
  std::string original_maid_name(maid->name());
  EXPECT_FALSE(original_maid_name.empty());
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2.get()));
  EXPECT_TRUE(passport_.GetPacket(MAID, false));
  EXPECT_TRUE(passport_.GetPacket(MAID, false)->Equals(maid.get()));
  EXPECT_FALSE(passport_.GetPacket(MAID, true));

  EXPECT_EQ(kSuccess, passport_.RevertSignaturePacket(MAID));
  EXPECT_FALSE(passport_.GetPacket(MAID, false));
  EXPECT_FALSE(passport_.GetPacket(MAID, true));

  EXPECT_EQ(kSuccess, passport_.InitialiseSignaturePacket(MAID, maid));
  EXPECT_FALSE(maid->name().empty());
  EXPECT_NE(original_maid_name, maid->name());
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2.get()));
  EXPECT_TRUE(passport_.GetPacket(MAID, false));
  EXPECT_TRUE(passport_.GetPacket(MAID, false)->Equals(maid.get()));
  EXPECT_FALSE(passport_.GetPacket(MAID, true));

  EXPECT_EQ(kNoPacket, passport_.DeletePacket(MID));
  EXPECT_EQ(kSuccess, passport_.DeletePacket(MAID));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true));
  EXPECT_FALSE(passport_.GetPacket(MAID, false));
  EXPECT_FALSE(passport_.GetPacket(MAID, true));

  EXPECT_EQ(kSuccess, passport_.InitialiseSignaturePacket(MAID, maid));
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid3));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true));
  EXPECT_TRUE(passport_.GetPacket(MAID, false));

  passport_.Clear();
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true));
  EXPECT_FALSE(passport_.GetPacket(MAID, false));

  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid3));
  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(anmaid3));
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid3));
  EXPECT_EQ(kSuccess, passport_.InitialiseSignaturePacket(MAID, maid));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true));
  EXPECT_TRUE(passport_.GetPacket(MAID, false));

  passport_.ClearKeyring();
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true));
  EXPECT_FALSE(passport_.GetPacket(MAID, false));
}

TEST_F(PassportTest, FUNC_PASSPORT_SetInitialDetails) {
  // Invalid data and null pointers
  std::string invalid_pin("Non-numerical");
  mid_name_ = smid_name_ = "a";
  EXPECT_EQ(kNullPointer, passport_.SetInitialDetails(kUsername_, kPin_, NULL,
                                                      &smid_name_));
  EXPECT_EQ(kNullPointer, passport_.SetInitialDetails(kUsername_, kPin_,
                                                      &mid_name_, NULL));

  EXPECT_EQ(kPassportError,
            passport_.SetInitialDetails(kUsername_, invalid_pin, &mid_name_,
                                        &smid_name_));
  EXPECT_TRUE(mid_name_.empty());
  EXPECT_TRUE(smid_name_.empty());

  mid_name_ = smid_name_ = "a";
  EXPECT_EQ(kPassportError, passport_.SetInitialDetails("", kPin_, &mid_name_,
                                                        &smid_name_));
  EXPECT_TRUE(mid_name_.empty());
  EXPECT_TRUE(smid_name_.empty());

  // Good initial data
  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_, &mid_name_,
                                                  &smid_name_));
  EXPECT_FALSE(mid_name_.empty());
  EXPECT_FALSE(smid_name_.empty());
  EXPECT_NE(mid_name_, smid_name_);
  PacketPtr pending_mid(passport_.GetPacket(MID, false));
  PacketPtr pending_smid(passport_.GetPacket(SMID, false));
  PacketPtr confirmed_mid(passport_.GetPacket(MID, true));
  PacketPtr confirmed_smid(passport_.GetPacket(SMID, true));
  EXPECT_TRUE(pending_mid);
  EXPECT_TRUE(pending_smid);
  EXPECT_FALSE(confirmed_mid);
  EXPECT_FALSE(confirmed_smid);
  EXPECT_EQ(mid_name_, pending_mid->name());
  EXPECT_EQ(smid_name_, pending_smid->name());

  // Different username should generate different mid and smid
  std::string different_username(kUsername_ + "a");
  std::string different_username_mid_name, different_username_smid_name;
  EXPECT_EQ(kSuccess,
            passport_.SetInitialDetails(different_username, kPin_,
                                        &different_username_mid_name,
                                        &different_username_smid_name));
  EXPECT_FALSE(different_username_mid_name.empty());
  EXPECT_FALSE(different_username_smid_name.empty());
  EXPECT_NE(different_username_mid_name, different_username_smid_name);
  EXPECT_NE(mid_name_, different_username_mid_name);
  EXPECT_NE(smid_name_, different_username_mid_name);
  EXPECT_NE(mid_name_, different_username_smid_name);
  EXPECT_NE(smid_name_, different_username_smid_name);
  pending_mid = passport_.GetPacket(MID, false);
  pending_smid = passport_.GetPacket(SMID, false);
  confirmed_mid = passport_.GetPacket(MID, true);
  confirmed_smid = passport_.GetPacket(SMID, true);
  EXPECT_TRUE(pending_mid);
  EXPECT_TRUE(pending_smid);
  EXPECT_FALSE(confirmed_mid);
  EXPECT_FALSE(confirmed_smid);
  EXPECT_EQ(different_username_mid_name, pending_mid->name());
  EXPECT_EQ(different_username_smid_name, pending_smid->name());

  // Different pin should generate different mid and smid
  std::string different_pin(boost::lexical_cast<std::string>(
                            boost::lexical_cast<boost::uint32_t>(kPin_) + 1));
  std::string different_pin_mid_name, different_pin_smid_name;
  EXPECT_EQ(kSuccess,
            passport_.SetInitialDetails(kUsername_, different_pin,
                                        &different_pin_mid_name,
                                        &different_pin_smid_name));
  EXPECT_FALSE(different_pin_mid_name.empty());
  EXPECT_FALSE(different_pin_smid_name.empty());
  EXPECT_NE(different_pin_mid_name, different_pin_smid_name);
  EXPECT_NE(mid_name_, different_pin_mid_name);
  EXPECT_NE(smid_name_, different_pin_mid_name);
  EXPECT_NE(mid_name_, different_pin_smid_name);
  EXPECT_NE(smid_name_, different_pin_smid_name);
  EXPECT_NE(different_username_mid_name, different_pin_mid_name);
  EXPECT_NE(different_username_smid_name, different_pin_mid_name);
  EXPECT_NE(different_username_mid_name, different_pin_smid_name);
  EXPECT_NE(different_username_smid_name, different_pin_smid_name);
  pending_mid = passport_.GetPacket(MID, false);
  pending_smid = passport_.GetPacket(SMID, false);
  confirmed_mid = passport_.GetPacket(MID, true);
  confirmed_smid = passport_.GetPacket(SMID, true);
  EXPECT_TRUE(pending_mid);
  EXPECT_TRUE(pending_smid);
  EXPECT_FALSE(confirmed_mid);
  EXPECT_FALSE(confirmed_smid);
  EXPECT_EQ(different_pin_mid_name, pending_mid->name());
  EXPECT_EQ(different_pin_smid_name, pending_smid->name());

  // Different username & pin should generate different mid and smid
  std::string different_both_mid_name, different_both_smid_name;
  EXPECT_EQ(kSuccess,
            passport_.SetInitialDetails(different_username, different_pin,
                                        &different_both_mid_name,
                                        &different_both_smid_name));
  EXPECT_FALSE(different_both_mid_name.empty());
  EXPECT_FALSE(different_both_smid_name.empty());
  EXPECT_NE(different_both_mid_name, different_both_smid_name);
  EXPECT_NE(mid_name_, different_both_mid_name);
  EXPECT_NE(smid_name_, different_both_mid_name);
  EXPECT_NE(mid_name_, different_both_smid_name);
  EXPECT_NE(smid_name_, different_both_smid_name);
  EXPECT_NE(different_username_mid_name, different_both_mid_name);
  EXPECT_NE(different_username_smid_name, different_both_mid_name);
  EXPECT_NE(different_username_mid_name, different_both_smid_name);
  EXPECT_NE(different_username_smid_name, different_both_smid_name);
  EXPECT_NE(different_pin_mid_name, different_both_mid_name);
  EXPECT_NE(different_pin_smid_name, different_both_mid_name);
  EXPECT_NE(different_pin_mid_name, different_both_smid_name);
  EXPECT_NE(different_pin_smid_name, different_both_smid_name);
  pending_mid = passport_.GetPacket(MID, false);
  pending_smid = passport_.GetPacket(SMID, false);
  confirmed_mid = passport_.GetPacket(MID, true);
  confirmed_smid = passport_.GetPacket(SMID, true);
  EXPECT_TRUE(pending_mid);
  EXPECT_TRUE(pending_smid);
  EXPECT_FALSE(confirmed_mid);
  EXPECT_FALSE(confirmed_smid);
  EXPECT_EQ(different_both_mid_name, pending_mid->name());
  EXPECT_EQ(different_both_smid_name, pending_smid->name());

  // Original username & pin should generate original mid and smid
  std::string original_mid_name, original_smid_name;
  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_,
                                                  &original_mid_name,
                                                  &original_smid_name));
  EXPECT_EQ(mid_name_, original_mid_name);
  EXPECT_EQ(smid_name_, original_smid_name);
  pending_mid = passport_.GetPacket(MID, false);
  pending_smid = passport_.GetPacket(SMID, false);
  confirmed_mid = passport_.GetPacket(MID, true);
  confirmed_smid = passport_.GetPacket(SMID, true);
  EXPECT_TRUE(pending_mid);
  EXPECT_TRUE(pending_smid);
  EXPECT_FALSE(confirmed_mid);
  EXPECT_FALSE(confirmed_smid);
  EXPECT_EQ(mid_name_, pending_mid->name());
  EXPECT_EQ(smid_name_, pending_smid->name());
}

TEST_F(PassportTest, FUNC_PASSPORT_SetNewUserData) {
  // Invalid data and null pointers
  MidPtr null_mid, mid(new MidPacket), null_smid, smid(new MidPacket);
  TmidPtr null_tmid, tmid(new TmidPacket);

  EXPECT_EQ(kNoMid,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_, mid,
                                     smid, tmid));
  EXPECT_TRUE(mid->name().empty());
  EXPECT_TRUE(smid->name().empty());
  EXPECT_TRUE(tmid->name().empty());

  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_, &mid_name_,
                                                  &smid_name_));
  EXPECT_EQ(kSuccess, passport_.packet_handler_.DeletePacket(SMID));
  EXPECT_EQ(kNoSmid,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_, mid,
                                     smid, tmid));
  EXPECT_TRUE(mid->name().empty());
  EXPECT_TRUE(smid->name().empty());
  EXPECT_TRUE(tmid->name().empty());

  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_, &mid_name_,
                                                  &smid_name_));
  EXPECT_EQ(kNullPointer,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_,
                                     null_mid, smid, tmid));
  EXPECT_TRUE(smid->name().empty());
  EXPECT_TRUE(tmid->name().empty());
  EXPECT_EQ(kNullPointer,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_,
                                     mid, null_smid, tmid));
  EXPECT_TRUE(mid->name().empty());
  EXPECT_TRUE(tmid->name().empty());
  EXPECT_EQ(kNullPointer,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_,
                                     mid, smid, null_tmid));
  EXPECT_TRUE(mid->name().empty());
  EXPECT_TRUE(smid->name().empty());

  // Good initial data
  EXPECT_EQ(kSuccess,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_, mid,
                                     smid, tmid));
  MidPtr pending_mid(std::tr1::static_pointer_cast<MidPacket>(
                     passport_.GetPacket(MID, false)));
  MidPtr pending_smid(std::tr1::static_pointer_cast<MidPacket>(
                      passport_.GetPacket(SMID, false)));
  TmidPtr pending_tmid(std::tr1::static_pointer_cast<TmidPacket>(
                       passport_.GetPacket(TMID, false)));
  MidPtr confirmed_mid(std::tr1::static_pointer_cast<MidPacket>(
                       passport_.GetPacket(MID, true)));
  MidPtr confirmed_smid(std::tr1::static_pointer_cast<MidPacket>(
                        passport_.GetPacket(SMID, true)));
  TmidPtr confirmed_tmid(std::tr1::static_pointer_cast<TmidPacket>(
                         passport_.GetPacket(TMID, true)));
  EXPECT_TRUE(pending_mid);
  EXPECT_TRUE(pending_smid);
  EXPECT_TRUE(pending_tmid);
  EXPECT_FALSE(confirmed_mid);
  EXPECT_FALSE(confirmed_smid);
  EXPECT_FALSE(confirmed_tmid);
  std::string mid_name(pending_mid->name()), smid_name(pending_smid->name());
  std::string tmid_name(pending_tmid->name());
  EXPECT_FALSE(mid_name.empty());
  EXPECT_FALSE(smid_name.empty());
  EXPECT_FALSE(tmid_name.empty());
  EXPECT_TRUE(pending_mid->Equals(mid.get()));
  EXPECT_TRUE(pending_smid->Equals(smid.get()));
  EXPECT_TRUE(pending_tmid->Equals(tmid.get()));
  EXPECT_EQ(kUsername_, pending_mid->username());
  EXPECT_EQ(kUsername_, pending_smid->username());
  EXPECT_EQ(kUsername_, pending_tmid->username());
  EXPECT_EQ(kPin_, pending_mid->pin());
  EXPECT_EQ(kPin_, pending_smid->pin());
  EXPECT_EQ(kPin_, pending_tmid->pin());
  boost::uint32_t rid(pending_mid->rid());
  EXPECT_NE(0U, rid);
  EXPECT_EQ(rid, pending_smid->rid());
  EXPECT_EQ(kPassword_, pending_tmid->password());
  // Check *copies* of pointers are returned
  EXPECT_EQ(1UL, mid.use_count());
  EXPECT_EQ(1UL, smid.use_count());
  EXPECT_EQ(1UL, tmid.use_count());

  // Check retry with same data generates new rid and hence new tmid name
  MidPtr retry_mid(new MidPacket), retry_smid(new MidPacket);
  TmidPtr retry_tmid(new TmidPacket);
  EXPECT_EQ(kSuccess,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_,
                                     retry_mid, retry_smid, retry_tmid));
  pending_mid = std::tr1::static_pointer_cast<MidPacket>(
                passport_.GetPacket(MID, false));
  pending_smid = std::tr1::static_pointer_cast<MidPacket>(
                 passport_.GetPacket(SMID, false));
  pending_tmid = std::tr1::static_pointer_cast<TmidPacket>(
                 passport_.GetPacket(TMID, false));
  confirmed_mid = std::tr1::static_pointer_cast<MidPacket>(
                  passport_.GetPacket(MID, true));
  confirmed_smid = std::tr1::static_pointer_cast<MidPacket>(
                   passport_.GetPacket(SMID, true));
  confirmed_tmid = std::tr1::static_pointer_cast<TmidPacket>(
                   passport_.GetPacket(TMID, true));
  EXPECT_TRUE(pending_mid);
  EXPECT_TRUE(pending_smid);
  EXPECT_TRUE(pending_tmid);
  EXPECT_FALSE(confirmed_mid);
  EXPECT_FALSE(confirmed_smid);
  EXPECT_FALSE(confirmed_tmid);
  EXPECT_EQ(mid_name, pending_mid->name());
  EXPECT_EQ(smid_name, pending_smid->name());
  EXPECT_NE(tmid_name, pending_tmid->name());
  EXPECT_FALSE(pending_tmid->name().empty());
  EXPECT_TRUE(pending_mid->Equals(retry_mid.get()));
  EXPECT_TRUE(pending_smid->Equals(retry_smid.get()));
  EXPECT_TRUE(pending_tmid->Equals(retry_tmid.get()));
  EXPECT_FALSE(pending_mid->Equals(mid.get()));
  EXPECT_FALSE(pending_smid->Equals(smid.get()));
  EXPECT_FALSE(pending_tmid->Equals(tmid.get()));
  EXPECT_EQ(kUsername_, pending_mid->username());
  EXPECT_EQ(kUsername_, pending_smid->username());
  EXPECT_EQ(kUsername_, pending_tmid->username());
  EXPECT_EQ(kPin_, pending_mid->pin());
  EXPECT_EQ(kPin_, pending_smid->pin());
  EXPECT_EQ(kPin_, pending_tmid->pin());
  EXPECT_NE(0U, pending_mid->rid());
  EXPECT_NE(rid, pending_mid->rid());
  EXPECT_EQ(pending_mid->rid(), pending_smid->rid());
  EXPECT_EQ(kPassword_, pending_tmid->password());
}

TEST_F(PassportTest, FUNC_PASSPORT_ConfirmNewUserData) {
  MidPtr null_mid, different_username_mid(new MidPacket);
  MidPtr null_smid, different_username_smid(new MidPacket);
  TmidPtr null_tmid, different_username_tmid(new TmidPacket);
  EXPECT_EQ(kSuccess, passport_.SetInitialDetails("Different", kPin_,
                                                  &mid_name_, &smid_name_));
  EXPECT_EQ(kSuccess, passport_.SetNewUserData(kPassword_,
                      kPlainTextMasterData_, different_username_mid,
                      different_username_smid, different_username_tmid));
  MidPtr mid(new MidPacket), smid(new MidPacket);
  TmidPtr tmid(new TmidPacket);
  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_, &mid_name_,
                                                  &smid_name_));
  EXPECT_EQ(kSuccess,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_, mid,
                                     smid, tmid));
  MidPtr pending_mid(std::tr1::static_pointer_cast<MidPacket>(
                     passport_.GetPacket(MID, false)));
  MidPtr pending_smid(std::tr1::static_pointer_cast<MidPacket>(
                      passport_.GetPacket(SMID, false)));
  TmidPtr pending_tmid(std::tr1::static_pointer_cast<TmidPacket>(
                       passport_.GetPacket(TMID, false)));
  EXPECT_TRUE(pending_mid);
  EXPECT_TRUE(pending_smid);
  EXPECT_TRUE(pending_tmid);
  EXPECT_FALSE(passport_.GetPacket(MID, true));
  EXPECT_FALSE(passport_.GetPacket(SMID, true));
  EXPECT_FALSE(passport_.GetPacket(TMID, true));

  EXPECT_EQ(kNullPointer, passport_.ConfirmNewUserData(null_mid, smid, tmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false));
  EXPECT_TRUE(passport_.GetPacket(SMID, false));
  EXPECT_TRUE(passport_.GetPacket(TMID, false));
  EXPECT_FALSE(passport_.GetPacket(MID, true));
  EXPECT_FALSE(passport_.GetPacket(SMID, true));
  EXPECT_FALSE(passport_.GetPacket(TMID, true));

  EXPECT_EQ(kNullPointer, passport_.ConfirmNewUserData(mid, null_smid, tmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false));
  EXPECT_TRUE(passport_.GetPacket(SMID, false));
  EXPECT_TRUE(passport_.GetPacket(TMID, false));
  EXPECT_FALSE(passport_.GetPacket(MID, true));
  EXPECT_FALSE(passport_.GetPacket(SMID, true));
  EXPECT_FALSE(passport_.GetPacket(TMID, true));

  EXPECT_EQ(kNullPointer, passport_.ConfirmNewUserData(mid, smid, null_tmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false));
  EXPECT_TRUE(passport_.GetPacket(SMID, false));
  EXPECT_TRUE(passport_.GetPacket(TMID, false));
  EXPECT_FALSE(passport_.GetPacket(MID, true));
  EXPECT_FALSE(passport_.GetPacket(SMID, true));
  EXPECT_FALSE(passport_.GetPacket(TMID, true));

  EXPECT_EQ(kMissingDependentPackets,
            passport_.ConfirmNewUserData(mid, smid, tmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false));
  EXPECT_TRUE(passport_.GetPacket(SMID, false));
  EXPECT_TRUE(passport_.GetPacket(TMID, false));
  EXPECT_FALSE(passport_.GetPacket(MID, true));
  EXPECT_FALSE(passport_.GetPacket(SMID, true));
  EXPECT_FALSE(passport_.GetPacket(TMID, true));

  SignaturePtr signature_packet(new SignaturePacket);
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMID, signature_packet));
  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(signature_packet));
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANSMID, signature_packet));
  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(signature_packet));
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANTMID, signature_packet));
  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(signature_packet));

  EXPECT_EQ(kPacketsNotEqual,
            passport_.ConfirmNewUserData(different_username_mid, smid, tmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false));
  EXPECT_TRUE(passport_.GetPacket(SMID, false));
  EXPECT_TRUE(passport_.GetPacket(TMID, false));
  EXPECT_FALSE(passport_.GetPacket(MID, true));
  EXPECT_FALSE(passport_.GetPacket(SMID, true));
  EXPECT_FALSE(passport_.GetPacket(TMID, true));

  EXPECT_EQ(kPacketsNotEqual,
            passport_.ConfirmNewUserData(mid, different_username_smid, tmid));
  EXPECT_FALSE(passport_.GetPacket(MID, false));
  EXPECT_TRUE(passport_.GetPacket(SMID, false));
  EXPECT_TRUE(passport_.GetPacket(TMID, false));
  EXPECT_TRUE(passport_.GetPacket(MID, true));
  EXPECT_FALSE(passport_.GetPacket(SMID, true));
  EXPECT_FALSE(passport_.GetPacket(TMID, true));

  EXPECT_EQ(kPacketsNotEqual,
            passport_.ConfirmNewUserData(mid, smid, different_username_tmid));
  EXPECT_FALSE(passport_.GetPacket(MID, false));
  EXPECT_FALSE(passport_.GetPacket(SMID, false));
  EXPECT_TRUE(passport_.GetPacket(TMID, false));
  EXPECT_TRUE(passport_.GetPacket(MID, true));
  EXPECT_TRUE(passport_.GetPacket(SMID, true));
  EXPECT_FALSE(passport_.GetPacket(TMID, true));

  EXPECT_EQ(kSuccess, passport_.ConfirmNewUserData(mid, smid, tmid));
  MidPtr confirmed_mid(std::tr1::static_pointer_cast<MidPacket>(
                       passport_.GetPacket(MID, true)));
  MidPtr confirmed_smid(std::tr1::static_pointer_cast<MidPacket>(
                        passport_.GetPacket(SMID, true)));
  TmidPtr confirmed_tmid(std::tr1::static_pointer_cast<TmidPacket>(
                         passport_.GetPacket(TMID, true)));
  EXPECT_FALSE(passport_.GetPacket(MID, false));
  EXPECT_FALSE(passport_.GetPacket(SMID, false));
  EXPECT_FALSE(passport_.GetPacket(TMID, false));
  EXPECT_TRUE(confirmed_mid);
  EXPECT_TRUE(confirmed_smid);
  EXPECT_TRUE(confirmed_tmid);

  EXPECT_TRUE(mid->Equals(pending_mid.get()));
  EXPECT_TRUE(smid->Equals(pending_smid.get()));
  EXPECT_TRUE(tmid->Equals(pending_tmid.get()));
  EXPECT_TRUE(mid->Equals(confirmed_mid.get()));
  EXPECT_TRUE(smid->Equals(confirmed_smid.get()));
  EXPECT_TRUE(tmid->Equals(confirmed_tmid.get()));

  EXPECT_EQ(kSuccess, passport_.ConfirmNewUserData(mid, smid, tmid));
}

TEST_F(PassportTest, FUNC_PASSPORT_ClearKeyring) {
  FAIL() << "ClearKeyring to be tested";
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
