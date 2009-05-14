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
#ifndef GUI_CREATESHAREDIALOG_H_
#define GUI_CREATESHAREDIALOG_H_

#include <wx/wx.h>
#include <wx/grid.h>
#include <wx/checklst.h>
#include <boost/shared_ptr.hpp>
#include <sstream>
#include <string>
#include <list>
#include <set>

class ShareDialog: public wxDialog {
  DECLARE_CLASS(ShareDialog)
  DECLARE_EVENT_TABLE()

 private:
  int messages;
  int contact_step;
  wxCheckListBox* clb;
  wxBoxSizer* topLevel;
  wxStaticBox* staticBox;
  wxStaticBoxSizer* staticSizer;
  wxTextCtrl* share_name;
  std::set<std::string> *contact_set;
  void RedrawForStep(std::string title);
  void PresentFinalStep();

 public:
  //  Constructors
  ShareDialog();
  ShareDialog(const ShareDialog&);
  ShareDialog& operator=(const ShareDialog&);
  ShareDialog(wxWindow* parent,
    wxWindowID id = wxID_ANY,
    const wxString& caption = wxT("Create Share Dialog"),
    const wxPoint& pos = wxDefaultPosition,
    const wxSize& size = wxDefaultSize,
    int32_t style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU,
    int phase = 0, std::set<std::string> *result_set = 0);
  //  Initialize our variables
  void Init();
  //  Creation
  bool Create(wxWindow* parent,
    wxWindowID id = wxID_ANY,
    const wxString& caption = wxT("Create Share Dialog"),
    const wxPoint& pos = wxDefaultPosition,
    const wxSize& size = wxDefaultSize,
    int32_t style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU);
  //  Creates the controls and sizers
  void CreateControls();
  void OnOk(wxCommandEvent& event);  // NOLINT
};

#endif  // GUI_CREATESHAREDIALOG_H_
