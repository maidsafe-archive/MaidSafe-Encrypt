/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Notification interface implemented by maidsafe gui
* Version:      1.0
* Created:      2009-05-06-00.00.00
* Revision:     none
* Compiler:     gcc
* Author:       William Cook (wdsc), info@maidsafe.net
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

#ifndef MAIDSAFE_CLIENT_CLIENTINTERFACE_H_
#define MAIDSAFE_CLIENT_CLIENTINTERFACE_H_

#include <string>

namespace maidsafe {

// ! Callback interface to be used for notifications from the ClientController
/*!
    Note: implementors of this interface should ensure they do not block whilst
    handling the notification.
*/
class ClientInterface {
 public:
  virtual ~ClientInterface() {}
  // ! A user has sent you a message
  virtual void messageReceived(const std::string& from,
                               const std::string& msg) = 0;

  // ! A contact's status has changed
  /*!
      TODO: emnumerate possible status
  */
  virtual void contactStatusChanged(const std::string& from,
                                    int status) = 0;

  // ! User requested add of contact
  /*!
      \param from contact who wants to add you
      \param msg introduction message

      In response, the request should be accepted or declined via client
      controller.
  */
  virtual void contactAdditionRequested(const std::string& from,
                                        const std::string& msg) = 0;

  // ! A user has shared something with you
  virtual void shareReceived(const std::string& from,
                             const std::string& share_name) = 0;

  // ! A share has been changed in some way e.g. permissions or removed
  virtual void shareChanged(const std::string& from,
                            const std::string& share_name) = 0;

  // ! A user has sent you a file
  /*!
      Currently saved directly into private file's section.
      Would be nice to prompt for new filename, whether to accept etc
  */
  virtual void fileReceived(const std::string& from,
                            const std::string& file_name) = 0;

  // ! System messages - to be decided
  virtual void systemMessage(const std::string& message) = 0;
};


}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_CLIENTINTERFACE_H_





