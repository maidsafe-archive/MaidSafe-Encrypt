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
#ifndef GUI_D_ADD_PUBLICNAME_H_
#define GUI_D_ADD_PUBLICNAME_H_

#include <wx/dialog.h>
#include <wx/wx.h>
#include "base/utils.h"

// PublicUsernameDialog class declaration
class PublicUsernameDialog: public wxDialog {
  DECLARE_CLASS(PublicUsernameDialog)
  DECLARE_EVENT_TABLE()

  public:
    //  Constructors
    PublicUsernameDialog();
    PublicUsernameDialog(const PublicUsernameDialog&);
    PublicUsernameDialog& operator=(const PublicUsernameDialog&);
    PublicUsernameDialog(wxWindow* parent,
      wxWindowID id = wxID_ANY,
      const wxString& caption = wxT("Public Username Dialog"),
      const wxPoint& pos = wxDefaultPosition,
      const wxSize& size = wxDefaultSize,
      int32_t style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU);
    //  Initialize our variables
    void Init();
    //  Creation
    bool Create(wxWindow* parent,
      wxWindowID id = wxID_ANY,
      const wxString& caption = wxT("Public Username Dialog"),
      const wxPoint& pos = wxDefaultPosition,
      const wxSize& size = wxDefaultSize,
      int32_t style = wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU);
    //  Creates the controls and sizers
    void CreateControls();
    void OnOkClick(wxCommandEvent& event);  // NOLINT
    void OnResetClick(wxCommandEvent& event);  // NOLINT

    wxTextCtrl* nameCtrl;

    static const int32_t ID_NAME;
    static const int32_t ID_OK;
    static const int32_t ID_RESET;
};

#endif  // GUI_D_ADD_PUBLICNAME_H_
