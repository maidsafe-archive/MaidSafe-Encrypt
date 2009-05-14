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
 *   Author: Team
 */

// #ifndef SHARE_PANEL_H
// #define SHARE_PANEL_H
//
// #include <wx/panel.h>
//
// class SharePanel: public wxPanel {
// public:
//  SharePanel(wxWindow* parent,wxWindowID id=wxID_ANY,
//    const wxPoint& pos=wxDefaultPosition,const wxSize& size=wxDefaultSize);
// };
//
// #endif
#ifndef GUI_SHARE_PANEL_H_
#define GUI_SHARE_PANEL_H_

#include <wx/wx.h>
#include <wx/sizer.h>
#include <wx/listctrl.h>
#include <wx/notebook.h>
#include <wx/panel.h>
#include <wx/listbook.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/radiobox.h>

class SharePanel: public wxPanel {
// private:
//  wxStaticBox* staticBox;
 public:
  SharePanel(wxWindow* parent, wxWindowID id = wxID_ANY,
    const wxPoint& pos = wxDefaultPosition,
    const wxSize& size = wxDefaultSize);
  SharePanel(const SharePanel&);
  SharePanel& operator=(const SharePanel&);
  virtual ~SharePanel();
  bool Create(wxWindow* parent, wxWindowID id = wxID_ANY,
    const wxPoint& pos = wxDefaultPosition,
    const wxSize& size = wxDefaultSize);
  void CreateControls();
  void CreateShareClick(wxCommandEvent& event);  // NOLINT

  DECLARE_EVENT_TABLE()
};

#endif  // GUI_SHARE_PANEL_H_
