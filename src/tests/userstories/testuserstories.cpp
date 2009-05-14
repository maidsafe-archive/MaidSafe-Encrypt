#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <stdio.h>
#include <gtest/gtest.h>
#include <sstream>
// #include "maidsafe/systempackets.h"
// #include "boost/timer.hpp"



//  ###Packet Handler User Stories###
TEST(UserStories, US1_CreateMPID_tests_4){
SUCCEED();
}

TEST(UserStories, US2_CreateTMID_tests_7) {
SUCCEED();
}

TEST(UserStories, US3_ShowFreeSpace_tests_17){
SUCCEED();
}

TEST(UserStories, US4_CreateSMID_tests_9) {
// The system should be able to create SMID to control MID saves etc (commit after read protection)
SUCCEED();
}

TEST(UserStories, US5_CreateMID_tests_1){
// The system should be able to  create an ID MID from hash of username + password
SUCCEED();
}

TEST(UserStories, US6_CreateMPID_tests_4){
// create Maidsafe Public ID
SUCCEED();
}

TEST(UserStories, US7_GenerateNewVaultPMID){
// User creates a new PMID for PD vault
EXPECT_FALSE("GenerateNewVaultPMID(string old_pmid,string new_pmid)") << "Failed to Generate New PMID for the Vault";
}

TEST(UserStories, US8_changeVaultPMID) {
// User alters the PMID for the PD Vault
EXPECT_FALSE("changeVaultPMID(string old_pmid,string new_pmid)") << "Failed to Change PMID for the Vault";
}

//  ###File System User Stories###

TEST(UserStories, US9_GetAvailableSpace_tests_16){
SUCCEED();
}


TEST(UserStories, US10_ListDirStruct_TBC) {
//  File System Iterator Test
// Ensure the system can write out a directory structure from any given point
EXPECT_FALSE("listDirStruct()") <<"Cannot list the directory structure";
}

//  ###Authentication User Stories###

TEST(UserStories, US11_Login_tests_41){
// The user can log in to the system using a username (richard.johnstone), PIN (1234) and password (subaru)
SUCCEED();
}

TEST(UserStories, US12_Logout_tests_TBC){
// richard.johnstone' can log out of the system
EXPECT_FALSE("login(U)") << "richard.johnstone failed to logout";
}

TEST(UserStories, US13_ChangePassword_tests_53) {
SUCCEED();
// Scenario: richard' can change the password from 'subaru' to 'Honda@2008'
// System Operations: Change Password
// Tests:  Authentication.Interface
}

TEST(UserStories, US14_ChangePasswordBack) {
// richard' can change his password back to 'subaru'
EXPECT_FALSE("ChangePassword(string old_passwd,string new_passwd)") << "Failed to Change Password back to origional";
}


TEST(UserStories, US15_ChangePIN_tests_52) {
// 'richard' can change his PIN from 1234 to 5432
SUCCEED();
}

TEST(UserStories, US16_LoginNewDetails){
// richard can login with the new 'Honda@2008' password
EXPECT_FALSE("login(U, P, new W)") << "Richard failed to login with new password 'Honda@2008'";
}



// #############################################

TEST(UserStories, US17_CreateKeypair_tests_77) {
// Ensure the system can create an RSA 4096 keypair
SUCCEED();
}

//  ###Vault User Stories###

TEST(UserStories, US18_InstallVault) {
// Scenario: The Vault should be installed without any errors
// System Operations:  Install Vault
// Tests:  Vault Interface
EXPECT_FALSE("successful_install_vault_software()") <<"Vault Software Installation Error";
}

TEST(UserStories, US19_UninstallVault) {
// Ensure the Vault can be uninstalled without any errors and removes all software and user data
EXPECT_FALSE("successful_uninstall_vault_software()") <<"Vault Software Un Install Error";
}

TEST(UserStories, US20_CancelVault) {
// User cancels their PD Vault
EXPECT_FALSE("cancelVault(vault)") << "Vault cancelation failed";
}

TEST(UserStories, US21_VaultSpaceQuery){
// The users client queries the vault for the amount of free space
EXPECT_FALSE("checkSpaceOfVault()") << "Failed to check space of vault";
}

TEST(UserStories, US22_CanVaultShutdown) {
// defined in Authentication.Interface
// Scenario: Ensure the vault can stop without generating any errors
// System Operations:  Exit Vault
// Tests:  Vault Interface
EXPECT_FALSE("successful_shutdown_vault_software()") <<"Vault Failed to shutdown cleanly";
}

//  ### Duplication User Stories ###

TEST(UserStories, US23_CheckDuplicatesForChunk){// user story added by josh
// Let me know how many copies of a chunk exist
EXPECT_FALSE("checkChunkDups()") << "Failed to get number of duplicate chunks";
}

TEST(UserStories, US24_CheckDuplicatesForFile){
// Let me know how many copies of a duplicate file exist (good for the Data Loss Prevention aspect for msSAN)
// In reality we will call the code from within checkDuplicatesForChunk (above) and get summary information
EXPECT_FALSE("checkDuplicatesForFile()") << "Failed to get minimum number of chunks for each file";
}

TEST(UserStories, US25_CheckMinDuplicatesForDirectory){// user story added by josh
// Let me know how the minimum duplicates that many copies of a duplicate file exist (good for the Data Loss Prevention aspect for msSAN)
// In reality we will call the code from within checkDuplicatesForChunk (above) and report summery information
EXPECT_FALSE("checkDuplicatesForDirectory()") << "Failed to get minimum number of chunks for each directory";
}

TEST(UserStories, US26_UploadDuplicate) {
// richard' can vault an mp3 file 'desperado', emma can download it, change the mp3 tag, and upload it again.
EXPECT_FALSE("login(U=richard,P,W)") << "Failed to login";
EXPECT_FALSE("uploadFile(~music/awsome_song.mp3)") << "Failed to upload file";
EXPECT_FALSE("login(U=emma,P,W)") << "Failed to login";
EXPECT_FALSE("downloadFile(~music/awsome_song.mp3)") << "Failed to download file";
EXPECT_FALSE("editTag(~music/awsome_song.mp3)") << "Failed to edit mp3 file tag";
EXPECT_FALSE("uploadFile(~music/awsome_song.mp3)") << "Failed to upload duplicate file with different Tag";
}

TEST(UserStories, US27_RecogniseDuplicate) {
// The file should still be recognised as a duplicate.
EXPECT_FALSE("login(U=emma,P,W)") << "Failed to login";
EXPECT_FALSE("isDuplicate(~music/awsome_song.mp3)") << "Failed to recognise mp3 file as duplicate";
}

// richard' can rename the shared folder 'House Details' to 'The House Plans'
TEST(UserStories, US28_RenameShare) {
EXPECT_FALSE("RenameShare(share_name)") << "Failed to rename share";
}

TEST(UserStories, US29_GgetUserRank){
// The users client queries the supernode for the users rank
EXPECT_FALSE("getUserRank()") << "Failed get Users Rank for Supernode";
}

TEST(UserStories, US30_GetGeoLocation){
// Let me know my geographical location
EXPECT_FALSE("getGeoLocation()") << "Failed to get Geographical Location";
}

TEST(UserStories, US31_SendIM){
// Send an instant message to a public name i've authorised
EXPECT_FALSE("sendIM(PMID)") << "Failed to send IM to public user name (PMID)";
}

TEST(UserStories, US32_SignFile) {
// Ensure the system can sign a file
EXPECT_FALSE("signFile()") <<"Cannot sign a file";
}

TEST(UserStories, US33_DelegateSharingRights) {
// The public username of 'richard' authorises 'emma' to have administrative access for sharing   richard.johnstone'
EXPECT_FALSE("DelegateSharingRights()") << "public username of 'richard' failed to authorise 'emma' to have administrative access for sharing 'richard.johnstone'";
}

TEST(UserStories, US34_DeleteFile) {
// can log in and delete a movie file from the 'House Details' shared area
EXPECT_FALSE("login()") << "Failed to login";
EXPECT_FALSE("delete(~house_details/movie.mpg)") << "Failed to delete file from shared area";
}

TEST(UserStories, US35_ShowActivityHistory){
// Show me what the history of my activity since I last logged in has been
EXPECT_FALSE("showActivityHistory()") << "Failed to show Activity History";
}

TEST(UserStories, US36_BackupToCacheDir) {
// The system should be able to save all files to a cache directory
EXPECT_FALSE("backup_dir(dir_to_backup)") << "Failed to backup dir to cache dir";
}

TEST(UserStories, US37_CleanCache) {
// The system should be able to clean up cache directory
EXPECT_FALSE("cleanCache(cache_dir)") << "Failed to clean up the Cache Directory";
}

//  ###Network Layer User Stories###

TEST(UserStories, US38_GetMyIP) {
// Let me know what my IP address is and port i'm using
EXPECT_FALSE("GetIP()") << "Failed to get IP and Port";
}

TEST(UserStories, US39_IsNAT) {
// Let me know how the software is getting out to the network (STUN/UPNP/etc)
EXPECT_FALSE("isNAT(return NAT type)") << "Failed to detect direct connect / NAT type";
}

TEST(UserStories, US40_DetectOS_tests_79) {
// Let me know how the software is getting out to the network (STUN/UPNP/etc)
SUCCEED();
}

TEST(UserStories, US41_RejectUnauthorisedMsgs_tests_83){
// Ensure messages sent to me from someone I havent authorised are automatically rejected
SUCCEED();
}

TEST(UserStories, US42_SignMsgs_tests_82){
// Ensure the system can sign a message
SUCCEED();
}

TEST(UserStories, US43_IdentifyFree_UsedSpace_tests_16_17_18){
// The system should be able to identify free / used disk space
SUCCEED();
}

TEST(UserStories, US44_RemoveUserFromSystem_tests_50){
// Remove me as a user from the system
SUCCEED();
}

TEST(UserStories, US45_EncryptMsg_tests_82){
// Ensure the system can encrypt a message with AES 256
SUCCEED();
}

TEST(UserStories, US46_LogInNewPIN_tests_52_F2){
// richard' can log in with the new 5432 PIN
// richard' can change the PIN to 1234
SUCCEED();
}

TEST(UserStories, US47_Sign_EncryptMessageRSA4096_tests_82){
// Ensure the system can encrypt a message with RSA4096
SUCCEED();
}

TEST(UserStories, US48_EncryptMIDRIDPBKDF_tests_1_2){
// The system should be able to  create a MID using pbkdf2 username and pin as itter to get passord to encrypt RID in mid
SUCCEED();
}

TEST(UserStories, US49_CreateUser_tests_41_42_43_44_45_F1){
// A new user called (emma.johnstone) created with a PIN (54321) and password (ford)
SUCCEED();
}

TEST(UserStories, US50_VerifySignature_tests_74){
// Ensure the system can verify a signature
SUCCEED();
}

// Ensure the client can tell me what operating system i'm using

// Ensure a user can buy additional space
// Ensure the Client be uninstalled without any errors and removes all software and user data
// Users starts the software with no vault linked
// The user can choose a music file from a random selection and vault it
// A music, movie and picture file are selected and then placed into a new share area called 'House Details'
// emma.johnstone' can login and delete a picture file from the 'House Details' shared area
// Ensure that a person set as an administrator in a share can delete the share
// Ensure a user can sell additional space
// Ensure the system deals with links
// The system should be able to  identify bandwidth
// The system should be able to encrypt cache directory with AES passwrd created from pbkdf2 user password and use pin as itter count
// The user  can choose a movie file from a random selection and vault it
// richard.johnstone can select and upload multiple (3) files into the vault
// user succesfully starts a PD Vault
// The users vault sends the PMID plus the private key to maidsafe
// Let me know what my node name is on the network
// Let me know how efficient my connection is (how many packets dropped, upstream connection, downstream connection)
// Ensure that a person not set as an administrator cannot delete a share
// The client should let me know what DEFCON level i'm using
// Ensure the system can deal with files which are not accessible
// The system should be able to  identify devices (network devices and IP addresses)
// The user can choose a picture from a random selection and vault it
// created   emma.johnstone' can select and upload multiple (3) files into her vault
// User changes the size of his PD Vault
// Accept the remote vault plus the PMID
// Let me know if i'm successfully connected to the network
// Let me know my current rank on the system
// Ensure the vault can start without generating any errors
// Ensure the system can deal with directories (traverse them)
// The system should be able to identify internet connected devices
// Scenario: The user can re-choose the same music, movie, and picture files, rename them and vault these file too (as a duplicate)
// System Operations:  Create a duplicate DM, try to upload - Fail because . different MDM
// Tests:  DA
// TEST_F(DataAtlasTest, Add_Get_DataMap)

// TODO


// Unclear stories:
// Ensure the system can create a list of files
// The client saves and recieves a chunk or provides an IOU for 'payment'
// Ensure that simulated network saves by moving files to another directory called cache/network/   ??

// Scenario: Clicking on the 'whats new' tab within the perpetual data software brings up the list of shared files
// System Operations:
// Tests:


// int main(int argc, char **argv){
//     testing::InitGoogleTest( &argc, argv);
//     return RUN_ALL_TESTS();
// }
