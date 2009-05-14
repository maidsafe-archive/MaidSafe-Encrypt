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
#ifndef GUI_CONTACTS_H_
#define GUI_CONTACTS_H_

#ifdef WIN32
// #define WIN32_LEAN_AND_MEAN
// passed as a compiler flag now
// Edited by David Irvine <david.irvine@maidsafe.net> 2009-01-26
// #include <wx/msw/winundef.h>
#endif
#include <wx/wx.h>
#include <wx/artprov.h>
#include <wx/hyperlink.h>
#include "gui/contact_detail.h"

class contacts: public wxPanel {
  public:

    contacts(wxWindow* parent, wxWindowID id = wxID_ANY,
      const wxPoint& pos = wxDefaultPosition,
      const wxSize& size = wxDefaultSize);
    contacts(const contacts&);
    contacts& operator=(const contacts&);
    virtual ~contacts();

    wxBitmapButton* bitmap_button_add_contact;
    wxBitmapButton* bitmap_button_clear_search;
    wxHyperlinkCtrl* stat_url_pub_name;
    wxStaticText* stat_txt_pub_name;
    wxTextCtrl* txt_ctrl_search_contacts;
    wxTextCtrl* txt_ctrl_add_contact;
    wxListBox* list_box_contacts;
    wxStaticText *stat_txt_space_available;
    wxScrolledWindow *contact_scrolled_window;
    wxFlexGridSizer* flex_grid_my_details;
    wxFlexGridSizer* flex_grid_main;
    wxFlexGridSizer * grid_sizer_contact_list;
    wxBoxSizer *box_sizer_scrolled_window;
    wxFlexGridSizer * flex_sizer_main;
    wxButton* addPublicUsername;

  protected:

    static const int32_t id_txt_ctrl_search_contacts;
    static const int32_t id_stat_txt_pub_name;
    static const int32_t id_stat_url_pub_name;
    static const int32_t id_stat_txt_space_available;
    static const int32_t id_bitmap_button_add_contact;
    static const int32_t id_bitmap_button_clear_search;
    static const int32_t id_txt_ctrl_add_contact;
    static const int32_t id_list_box_contacts;
    static const int32_t id_contact_scrolled_window;
    static const int32_t id_add_public_username;

  private:

    void OnSearchEnter(wxFocusEvent& WXUNUSED(event));  // NOLINT
    void OnSearchLeave(wxFocusEvent& WXUNUSED(event));  // NOLINT
    void Onbitmap_button_add_contactClick(
      wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Onbitmap_button_clear_search(
      wxCommandEvent& WXUNUSED(event));  // NOLINT
    void OnCreatePublicUsernameClick(wxCommandEvent& event);  // NOLINT
    void On_focus_bitmap_button_clear_search(
      wxFocusEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_ctrl_search_contactsText(
      wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_ctrl_search_contactsTextUrl(
      wxTextUrlEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_ctrl_search_contactsTextMaxLen(
      wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_ctrl_add_contactText(
      wxCommandEvent& WXUNUSED(event));  // NOLINT
    void Ontxt_ctrl_add_contactTextEnter(
      wxCommandEvent& WXUNUSED(event));  // NOLINT

    DECLARE_EVENT_TABLE()
};

#endif  // GUI_CONTACTS_H_
