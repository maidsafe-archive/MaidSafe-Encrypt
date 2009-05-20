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

#ifndef GUI_GENERAL_LOGIN_H_
#define GUI_GENERAL_LOGIN_H_

#include <wx/wx.h>
#include <wx/gauge.h>
#include <wx/checkbox.h>
#include <wx/sizer.h>
#include <wx/button.h>
#include <wx/panel.h>
#include <wx/textctrl.h>
#include <wx/statbmp.h>
#include <wx/wizard.h>
#include <wx/frame.h>
#include <wx/stattext.h>
#include <wx/log.h>
#include <wx/checklst.h>
#include <wx/msgdlg.h>
#include <wx/radiobox.h>
#include <wx/menu.h>
#include <wx/xrc/xmlres.h>

#include <boost/scoped_ptr.hpp>
#include <string>

#include "maidsafe/utils.h"
#include "fs/filesystem.h"
#include "maidsafe/config.h"
#include "maidsafe/client/clientcontroller.h"

#if defined(MAIDSAFE_WIN32)
  #include "fs/w_fuse/fswin.h"
#elif defined(MAIDSAFE_POSIX)
  #include "fs/l_fuse/fslinux.h"
#elif defined(MAIDSAFE_APPLE)
  #include "fs/m_fuse/fsmac.h"
#endif

class general_login: public wxPanel {
  public:
    general_login(wxWindow* parent, wxWindowID id = wxID_ANY,
      const wxPoint& pos = wxDefaultPosition,
      const wxSize& size = wxDefaultSize);
    general_login(const general_login&);
    general_login& operator=(const general_login&);
    ~general_login();

    std::string GetUsername();
    std::string GetPin();
    std::string GetPassword();
    wxStaticText* StaticTextCREATEUSER;

    void ClearData();
    void ShowProgress(std::string value);
    void HideProgress();
    void OnQuit(wxCommandEvent& event);  // NOLINT
    void OnAbout(wxCommandEvent& event);  // NOLINT
    void OnRunWizard(wxCommandEvent& event);  // NOLINT
    void OnRunWizardNoSizer(wxCommandEvent& event);  // NOLINT
    void OnRunWizardModeless(wxCommandEvent& event);  // NOLINT
    void OnWizardCancel(wxWizardEvent& event);  // NOLINT
    void OnWizardFinished(wxWizardEvent& event);  // NOLINT


    // Identifiers(general_login)
    static const int32_t ID_GAUGE_LOGIN;
    static const int32_t ID_STATICTEXT_LOGIN;
    static const int32_t ID_CHECKBOX_SAVE_USER_AND_PIN;
    static const int32_t ID_STATICTEXTUSERNAME;
    static const int32_t ID_TEXTCTRLUSERNAME;
    static const int32_t ID_STATICTEXTPIN;
    static const int32_t ID_TEXTCTRLPIN;
    static const int32_t ID_STATICTEXTPASSWORD;
    static const int32_t ID_TEXTCTRLPASSWORD;
    static const int32_t ID_STATICTEXT1;
    static const int32_t ID_NEWUSER;
    static const int32_t ID_LOGIN;
    static const int32_t ID_STATICBITMAPPD;
    static const int32_t ID_WIZARD;
    wxButton* button_create_user;
    wxFlexGridSizer* GridSizer1;
    wxBoxSizer* BoxSizer2;
    wxBoxSizer* BoxSizer4;

  private:
    file_system::FileSystem *fsys;
    #ifdef MAIDSAFE_WIN32

    #elif defined(MAIDSAFE_POSIX)
      fs_l_fuse::FSLinux fsl_;
    #elif defined(MAIDSAFE_APPLE)
      fs_m_fuse::FSMac fsm_;
    #endif

    wxBoxSizer* BoxSizer5;

    wxBoxSizer* BoxSizer3;

    wxBoxSizer* BoxSizer1;
    wxStaticText* static_username;
    wxButton* button_login;
    wxTextCtrl* txt_password;
    wxStaticBitmap *StaticBitmapPD;
    wxTextCtrl* txt_pin;
    wxButton* button_cancel_clear1;
    wxButton* button_cancel_clear;
    wxGauge* gauge_login;
    wxStaticText* static_password;
    wxTextCtrl* txt_username;

    wxStaticText* static_txt_progress;
    wxStaticText* static_pin;
    wxCheckBox* check_box_save_user_and_pin;
    wxWizard *wizard;
    wxWindow *m_parent;

    void Oncheck_box_save_user_and_pinClick(
      wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_username_enter(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_pin_enter(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_username_foc(wxFocusEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_pin_foc(wxFocusEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_password_enter(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_passwordText(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Onbutton_cancel_clearClick(
      wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Onbutton_createCLICK(wxCommandEvent& WXUNUSED(event));  // NOLINT
    void OnKey_username(wxKeyEvent& event);  // NOLINT
    void OnKey_pin(wxKeyEvent& event);  // NOLINT
  // DECLARE_EVENT_TABLE()
};

class PDWizard : public wxWizard {
  public:
    PDWizard(wxFrame *frame, bool useSizer = true);
    PDWizard(const PDWizard&);
    PDWizard& operator=(const PDWizard&);

    //   wxWizard * wi
    wxWizardPage *GetFirstPage() const { return m_page1; }

  private:
    wxWizardPageSimple *m_page1;
    DECLARE_EVENT_TABLE()
  };

//  It also shows how to use a different bitmap for one of the pages.
class wxValidationPage : public wxWizardPageSimple {
  public:
    explicit wxValidationPage(wxWizard *parent) : wxWizardPageSimple(parent) {
      m_bitmap = wxXmlResource::Get()->LoadBitmap(wxT("pd"));

      m_checkbox = new wxCheckBox(this, wxID_ANY, _T("&Check me"));

      wxBoxSizer *mainSizer = new wxBoxSizer(wxVERTICAL);
      mainSizer->Add(new wxStaticText(this, wxID_ANY,
        _T("You need to check the checkbox\n")
        _T("below before going to the next page\n")),
        0,
        wxALL,
        5);

      mainSizer->Add(
        m_checkbox,
        0,  //  No stretching
        wxALL,
        5);   //  Border
      SetSizer(mainSizer);
      mainSizer->Fit(this);
    }

    wxValidationPage(const wxValidationPage&);
    wxValidationPage& operator=(const wxValidationPage&);

    virtual bool TransferDataFromWindow() {
      if ( !m_checkbox->GetValue() ) {
        wxMessageBox(_T("Check the checkbox first!"), _T("No way"),
          wxICON_WARNING | wxOK, this);
        return false;
      }
      return true;
    }

  private:
    wxCheckBox *m_checkbox;
};

// This is a more complicated example of validity checking: using events we may
// allow to return to the previous page, but not to proceed. It also
// demonstrates how to intercept [Cancel] button press.
class wxRadioboxPage : public wxWizardPageSimple {
  public:
    // directions in which we allow the user to proceed from this page
    enum {
        Forward, Backward, Both, Neither
    };

    wxRadioboxPage(const wxRadioboxPage&);
    wxRadioboxPage& operator=(const wxRadioboxPage&);
    explicit wxRadioboxPage(wxWizard *parent)
    : wxWizardPageSimple(parent), m_radio(NULL) {
      //  should correspond to the enum above
      //  static wxString choices[] =
      //    { "forward", "backward", "both", "neither" };
      //  The above syntax can cause an internal compiler error with gcc.
      wxString choices[4];
      choices[0] = _T("forward");
      choices[1] = _T("backward");
      choices[2] = _T("both");
      choices[3] = _T("neither");

      m_radio = new wxRadioBox(this, wxID_ANY, _T("Allow to proceed:"),
         wxDefaultPosition, wxDefaultSize,
         WXSIZEOF(choices), choices,
         1, wxRA_SPECIFY_COLS);
      m_radio->SetSelection(Both);

      wxBoxSizer *mainSizer = new wxBoxSizer(wxVERTICAL);
      mainSizer->Add(m_radio,
        0,  //  No stretching
        wxALL,
        5);   //  Border

      SetSizer(mainSizer);
      mainSizer->Fit(this);
    }

    //  wizard event handlers
    void OnWizardCancel(wxWizardEvent& event) {  // NOLINT
      if ( wxMessageBox(_T("Do you really want to cancel?"), _T("Question"),
        wxICON_QUESTION | wxYES_NO, this) != wxYES ) {
          //  not confirmed
          event.Veto();
      }
    }

    void OnWizardPageChanging(wxWizardEvent& event) {  // NOLINT
      int sel = m_radio->GetSelection();
      if (sel == Both)
        return;
      if (event.GetDirection() && sel == Forward)
        return;
      if (!event.GetDirection() && sel == Backward)
        return;
      wxMessageBox(_T("You can't go there"), _T("Not allowed"),
        wxICON_WARNING | wxOK, this);
      event.Veto();
    }

  private:
    wxRadioBox *m_radio;

    DECLARE_EVENT_TABLE()
};

// This shows how to dynamically (i.e. during run-time) arrange the page order.
class wxCheckboxPage : public wxWizardPage {
  public:
    wxCheckboxPage(const wxCheckboxPage&);
    wxCheckboxPage& operator=(const wxCheckboxPage&);
    wxCheckboxPage(wxWizard *parent, wxWizardPage *prev,
      wxWizardPage *next) : wxWizardPage(parent), m_prev(prev),
      m_next(next), m_checkbox(NULL), m_checklistbox(NULL) {
        m_prev = prev;
        m_next = next;
        wxBoxSizer *mainSizer = new wxBoxSizer(wxVERTICAL);
        mainSizer->Add(
          new wxStaticText(this, wxID_ANY,
          _T("Try checking the box below and\n")
          _T("then going back and clearing it")),
          0,  //  No vertical stretching
          wxALL,
          5);   //  Border width

        m_checkbox = new wxCheckBox(this, wxID_ANY, _T("&Skip the next page"));
        mainSizer->Add(
          m_checkbox,
          0,  //  No vertical stretching
          wxALL,
          5);   //  Border width

        #if wxUSE_CHECKLISTBOX
        static const wxChar *aszChoices[] = {
            _T("Zeroth"),
            _T("First"),
            _T("Second"),
            _T("Third"),
            _T("Fourth"),
            _T("Fifth"),
            _T("Sixth"),
            _T("Seventh"),
            _T("Eighth"),
            _T("Nineth")
        };

        m_checklistbox = new wxCheckListBox(this, wxID_ANY, wxDefaultPosition,
          wxSize(100, 100), wxArrayString(WXSIZEOF(aszChoices), aszChoices));

        mainSizer->Add(m_checklistbox,
          0,    //  No vertical stretching
          wxALL,
          5);   //  Border width
        #endif  //  wxUSE_CHECKLISTBOX

        SetSizer(mainSizer);
        mainSizer->Fit(this);
    }

    //  implement wxWizardPage functions
    virtual wxWizardPage *GetPrev() const { return m_prev; }
    virtual wxWizardPage *GetNext() const {
        return m_checkbox->GetValue() ? m_next->GetNext() : m_next;
    }

  private:
    wxWizardPage *m_prev, *m_next;

    wxCheckBox *m_checkbox;
    #if wxUSE_CHECKLISTBOX
    wxCheckListBox *m_checklistbox;
    #endif
};

#endif  // GUI_GENERAL_LOGIN_H_
