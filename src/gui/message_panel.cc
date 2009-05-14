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
#include "gui/message_panel.h"
#include <wx/wx.h>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "base/utils.h"

MessagePanel::MessagePanel(wxWindow* parent, wxWindowID id,
  const wxPoint& pos, const wxSize& size,
  std::vector<packethandler::InstantMessage> *msgs)
  : wxPanel(parent, id, pos, size) {
  wxFlexGridSizer *fgs = new wxFlexGridSizer(0, 1, 0, 0);
  fgs->SetFlexibleDirection(wxHORIZONTAL);
  wxScrolledWindow *sw = new wxScrolledWindow(this,
    id_scroll_messages, wxDefaultPosition,
    wxDefaultSize, wxALL|wxEXPAND|wxHSCROLL,
    _T("id_scroll_messages"));
  sw->SetScrollbars(10, 10, 1000, 1000);
  wxString wx_header = wxString::FromAscii("Messages:\n------------");
  wxStaticText *st_header = new wxStaticText(sw, 9000,
    wx_header, wxDefaultPosition, wxSize(350, 30), 0, _T("static_text"));
  fgs->Add(st_header, 1, wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);

  if (msgs != NULL) {
    for (int n = msgs->size() - 1; n > -1 ; n--) {
      printf("En el mensaje %i\n", n);
      packethandler::InstantMessage im = msgs->at(n);
      // TODO(dan): Move the following crap to a function.
      time_t rawtime = im.date();
      boost::posix_time::ptime t = boost::posix_time::from_time_t(rawtime);
      std::string label("[");
      label += boost::posix_time::to_simple_string(t);
      label += "] ";
      label += im.sender();
      label += ":\n";
      label += im.message();
      wxString wx_s = wxString::FromAscii(label.c_str());
      wxStaticText *st = new wxStaticText(sw, n+9001,
        wx_s, wxDefaultPosition, wxSize(350, 50), 0, _T("static_text"));
      fgs->Add(st, 1, wxALL|wxEXPAND|wxALIGN_LEFT|wxALIGN_TOP, 5);
    }
  }

  sw->SetSizer(fgs);
  fgs->Fit(sw);
  fgs->SetSizeHints(this);
  fgs->Fit(this);
  Layout();
}

MessagePanel::~MessagePanel() {
}
