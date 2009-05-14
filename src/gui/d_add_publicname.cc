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
#include "gui/d_add_publicname.h"
#include <wx/statline.h>
#include <wx/textctrl.h>
#include "maidsafe/client/clientcontroller.h"

const int32_t PublicUsernameDialog::ID_NAME = wxNewId();
const int32_t PublicUsernameDialog::ID_RESET = wxNewId();
const int32_t PublicUsernameDialog::ID_OK = wxNewId();

IMPLEMENT_CLASS(PublicUsernameDialog, wxDialog)

BEGIN_EVENT_TABLE(PublicUsernameDialog, wxDialog)
  EVT_BUTTON(ID_OK, PublicUsernameDialog::OnOkClick)
  EVT_BUTTON(ID_RESET, PublicUsernameDialog::OnResetClick)
END_EVENT_TABLE()

//  Event handlers
void PublicUsernameDialog::OnResetClick(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  Init();
  //     TransferDataToWindow();
}

void PublicUsernameDialog::OnOkClick(wxCommandEvent& event) {  // NOLINT
  printf("Event id: %i\n", event.GetId());
  wxString wx_username_txt = nameCtrl->GetValue();
  std::string username_txt((const char*)wx_username_txt.mb_str());
  if (username_txt != "")
    if (maidsafe::ClientController::getInstance()->CreatePublicUsername(
      username_txt)) {
      EndModal(wxID_OK);
    }
}

//  Constructors
PublicUsernameDialog::PublicUsernameDialog() : nameCtrl(NULL) {
  Init();
}

PublicUsernameDialog::PublicUsernameDialog(wxWindow* parent,
  wxWindowID id, const wxString& caption,
  const wxPoint& pos, const wxSize& size, int32_t style)
  : nameCtrl(NULL) {
  Init();
  Create(parent, id, caption, pos, size, style);
}

//  Inits
void PublicUsernameDialog::Init() { }

bool PublicUsernameDialog::Create(wxWindow* parent,
  wxWindowID id, const wxString& caption,
  const wxPoint& pos, const wxSize& size, int32_t style) {
  //  We have to set extra styles before creating the
  //  dialog
  SetExtraStyle(wxWS_EX_BLOCK_EVENTS|wxDIALOG_EX_CONTEXTHELP);

  if (!wxDialog::Create(parent, id, caption, pos, size, style))
    return false;
  CreateControls();
  //   SetDialogHelp();
  //   SetDialogValidators();
  //  This fits the dialog to the minimum size dictated by
  //  the sizers
  GetSizer()->Fit(this);
  //  This ensures that the dialog cannot be sized smaller
  //  than the minimum size
  GetSizer()->SetSizeHints(this);
  //  Centre the dialog on the parent or (if none) screen
  Centre();

  return true;
}

void PublicUsernameDialog::CreateControls() {
  //  A top-level sizer
  wxBoxSizer* topSizer = new wxBoxSizer(wxVERTICAL);
  this->SetSizer(topSizer);
  //  A second box sizer to give more space around the controls
  wxBoxSizer* boxSizer = new wxBoxSizer(wxVERTICAL);
  topSizer->Add(boxSizer, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
  //  A friendly message
  wxStaticText* descr = new wxStaticText(this, wxID_STATIC,
    wxT("Please enter your desired public username. This is the name you \n")
    wxT("might share with other users so they can communicate with you. "),
    wxDefaultPosition, wxDefaultSize, 0);
  boxSizer->Add(descr, 0, wxALIGN_LEFT|wxALL, 5);

  //  Spacer
  boxSizer->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
  //  Label for the name text control
  wxStaticText* nameLabel = new wxStaticText(this, wxID_STATIC,
    wxT("&Public Username:"), wxDefaultPosition, wxDefaultSize, 0);
  boxSizer->Add(nameLabel, 0, wxALIGN_LEFT|wxALL, 5);
  //  A text control for the user’s name
  nameCtrl = new wxTextCtrl(this, ID_NAME, wxT(""),
    wxDefaultPosition, wxDefaultSize, 0);
  boxSizer->Add(nameCtrl, 0, wxGROW|wxALL, 5);

  //  A dividing line before the OK and Cancel buttons
  wxStaticLine* line = new wxStaticLine(this, wxID_STATIC,
    wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL);
  boxSizer->Add(line, 0, wxGROW|wxALL, 5);
  //  A horizontal box sizer to contain Reset, OK, Cancel and Help
  wxBoxSizer* okCancelBox = new wxBoxSizer(wxHORIZONTAL);
  boxSizer->Add(okCancelBox, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);
  //  The OK button
  wxButton* ok = new wxButton(this, ID_OK, wxT("&OK"),
    wxDefaultPosition, wxDefaultSize, 0);
  okCancelBox->Add(ok, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5);
  //  The Cancel button
  wxButton* cancel = new wxButton(this, wxID_CANCEL,
    wxT("&Cancel"), wxDefaultPosition, wxDefaultSize, 0);
  okCancelBox->Add(cancel, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5);

  nameCtrl->SetFocus();
}

