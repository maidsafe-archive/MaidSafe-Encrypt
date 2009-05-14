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

#include "gui/createsharedialog.h"

enum create_share_dialog_ids {
  ID_share_name = 1,
  ID_ListBox
};

IMPLEMENT_CLASS(ShareDialog, wxDialog)

BEGIN_EVENT_TABLE(ShareDialog, wxDialog)
  EVT_BUTTON(wxID_OK, ShareDialog::OnOk)
END_EVENT_TABLE()

// Constructors
ShareDialog::ShareDialog() : messages(-1), contact_step(-1), clb(NULL),
    topLevel(NULL), staticBox(NULL), staticSizer(NULL), share_name(NULL),
    contact_set(NULL) {
  Init();
}

ShareDialog::ShareDialog(wxWindow* parent,
    wxWindowID id, const wxString& caption,
    const wxPoint& pos, const wxSize& size,
    int32_t style, int phase, std::set<std::string> *result_set)
    : messages(0), contact_step(phase),
    clb(NULL), topLevel(NULL),
    staticBox(NULL), staticSizer(NULL),
    share_name(NULL), contact_set(result_set) {
  Init();
  Create(parent, id, caption, pos, size, style);
}

// Inits
void ShareDialog::Init() {
}

bool ShareDialog::Create(wxWindow* parent,
    wxWindowID id, const wxString& caption,
    const wxPoint& pos, const wxSize& size,
    int32_t style) {
  //  We have to set extra styles before creating the
  //  dialog
  SetExtraStyle(wxWS_EX_BLOCK_EVENTS|wxDIALOG_EX_CONTEXTHELP);

  if (!wxDialog::Create(parent, id, caption, pos, size, style))
    return false;
  if (contact_step == 0)
    return false;
  else if (contact_step == 1)
    CreateControls();
  else if (contact_step == 2)
    RedrawForStep("Admin Contacts");
  else if (contact_step == 3)
    RedrawForStep("Read Only Contacts");
  Centre();
  return true;
}

void ShareDialog::CreateControls() {
  share_name = new wxTextCtrl(this, ID_share_name, wxEmptyString,
    wxDefaultPosition, wxSize(200, 25), wxTE_LEFT);
  wxButton* b = new wxButton(this, wxID_OK,
    wxT("Next"), wxDefaultPosition, wxDefaultSize);
  wxButton* cb = new wxButton(this, wxID_CANCEL,
    wxT("Cancel"), wxDefaultPosition, wxDefaultSize);

  // Create top-level sizer
  wxBoxSizer* topLevel = new wxBoxSizer(wxVERTICAL);
  // Create static box and static box sizer
  wxStaticBox* staticBox = new wxStaticBox(this, wxID_ANY, wxT("Share Name"));
  staticSizer = new wxStaticBoxSizer(staticBox, wxVERTICAL);
  topLevel->Add(staticSizer, 0, wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

  staticSizer->Add(share_name, 0, wxALIGN_LEFT |wxALL, 5);
  staticSizer->Add(b, 0, wxALIGN_LEFT |wxALL, 5);
  staticSizer->Add(cb, 0, wxALIGN_LEFT |wxALL, 5);
  SetSizer(topLevel);
  topLevel->Fit(this);
  topLevel->SetSizeHints(this);
}

void ShareDialog::OnOk(wxCommandEvent& event) {  // NOLINT
#ifdef DEBUG
  printf("ShareDialog::OnOk: %i\n", event.GetId());
#endif
  event.GetId();
  switch (contact_step) {
    case 1: {
              std::string share((const char*)share_name->GetValue().mb_str());
              if (share != "") {
                contact_set->insert(share);
              }
            } break;
    case 2: {
              contact_set->clear();
              wxArrayInt ai;
              clb->GetSelections(ai);
              // std::cout << ai.size() << std::endl;
              for (unsigned int n = 0; n < clb->GetCount(); n++)
                if (clb->IsChecked(n)) {
                  std::string c((const char*)clb->GetString(n).mb_str());
                  // std::cout << c << std::endl;
                  contact_set->insert(c);
                }
            } break;
    case 3: {
              contact_set->clear();
              wxArrayInt ai;
              clb->GetSelections(ai);
              // std::cout << ai.size() << std::endl;
              for (unsigned int n = 0; n < clb->GetCount(); n++)
                if (clb->IsChecked(n)) {
                  std::string c((const char*)clb->GetString(n).mb_str());
                  // std::cout << c << std::endl;
                  contact_set->insert(c);
                }
            } break;
    default: break;
  }
  EndModal(wxID_OK);
}

void ShareDialog::RedrawForStep(std::string title) {
  // Create top-level sizer
  topLevel = new wxBoxSizer(wxVERTICAL);
  // Create static box and static box sizer
  staticBox = new wxStaticBox(this,
    55555, wxString::FromAscii(title.c_str()));
  staticSizer = new wxStaticBoxSizer(staticBox,
    wxVERTICAL);
  topLevel->Add(staticSizer, 0,
    wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

  wxArrayString contacts;
  std::set<std::string>::iterator it;
  for (it = contact_set->begin(); it != contact_set->end(); ++it) {
    std::string s(*it);
    contacts.Add(wxString::FromAscii(s.c_str()));
  }

  clb = new wxCheckListBox(this, ID_ListBox,
    wxDefaultPosition, wxSize(180, 180), contacts,
    wxLB_EXTENDED|wxLB_NEEDED_SB|wxLB_SORT);
  wxButton* b = new wxButton(this, wxID_OK,
    wxT("Next"), wxDefaultPosition, wxDefaultSize);
  wxButton* cb = new wxButton(this, wxID_CANCEL,
    wxT("Cancel"), wxDefaultPosition, wxDefaultSize);

  staticSizer->Add(clb, 0, wxALIGN_LEFT |wxALL, 5);
  staticSizer->Add(b, 0, wxALIGN_LEFT |wxALL, 5);
  staticSizer->Add(cb, 0, wxALIGN_LEFT |wxALL, 5);
  SetSizer(topLevel);
  topLevel->Fit(this);
  topLevel->SetSizeHints(this);
  Layout();
}

void ShareDialog::PresentFinalStep() {
  std::string title("Finished!");
  // Create top-level sizer
  topLevel = new wxBoxSizer(wxVERTICAL);
  // Create static box and static box sizer
  staticBox = new wxStaticBox(this,
    wxID_ANY, wxString::FromAscii(title.c_str()));
  staticSizer = new wxStaticBoxSizer(staticBox,
    wxVERTICAL);
  topLevel->Add(staticSizer, 0,
    wxALIGN_CENTER_HORIZONTAL|wxALL, 5);

  std::string message("You're all done, fella.");
  wxString wx_s = wxString::FromAscii(message.c_str());
  wxStaticText *st = new wxStaticText(this, 23232,
    wx_s, wxDefaultPosition, wxDefaultSize, 0, _T("id_stat_txt"));
  wxButton* b = new wxButton(this, wxID_OK,
    wxT("OK"), wxDefaultPosition, wxDefaultSize);

  staticSizer->Add(st, 0, wxALIGN_LEFT |wxALL, 5);
  staticSizer->Add(b, 0, wxALIGN_LEFT |wxALL, 5);
  SetSizer(topLevel);
  topLevel->Fit(this);
  topLevel->SetSizeHints(this);
  Refresh();
  Layout();
}
