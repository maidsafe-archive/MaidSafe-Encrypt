/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#ifndef GUI_MESSAGE_PANEL_H_
#define GUI_MESSAGE_PANEL_H_
#include <wx/panel.h>
#include <list>
#include <vector>
#include "protobuf/packet.pb.h"

enum {
  id_scroll_messages = 1
};

class MessagePanel: public wxPanel {
 public:
  MessagePanel(wxWindow* parent, wxWindowID id = wxID_ANY,
    const wxPoint& pos = wxDefaultPosition,
    const wxSize& size = wxDefaultSize,
    std::vector<packethandler::InstantMessage> *msgs = NULL);
  virtual ~MessagePanel();
};

#endif  // GUI_MESSAGE_PANEL_H_
