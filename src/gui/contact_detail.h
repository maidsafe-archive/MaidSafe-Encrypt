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
#ifndef GUI_CONTACT_DETAIL_H_
#define GUI_CONTACT_DETAIL_H_
// #ifdef WIN32
//  #include <wxprec_monolib.pch>
// #else
#include <wx/wx.h>
#include <wx/artprov.h>
#include <wx/hyperlink.h>
#include "maidsafe/utils.h"
// #endif


class ContactDetail: public wxPanel {
  public:

    ContactDetail(wxWindow* parent,
      wxWindowID id_win_contact_detail =  wxID_ANY,
      const wxPoint& pos = wxDefaultPosition,
      const wxSize& size = wxDefaultSize,
      const wxString& user_name_ = (_("")),
      const char &status = 'U');
    ContactDetail(const ContactDetail&);
    ContactDetail& operator=(const ContactDetail&);
    virtual ~ContactDetail();

    wxMenu user_action_menu;
    wxString user_name;
    wxFlexGridSizer* flex_grid_small;
    wxFlexGridSizer* flex_grid_detail;
    wxFlexGridSizer* flex_grid_main;
    wxFileDialog* FileDialog1;
    const wxString db_key;

    inline wxString GetUser() { return user_name; }

  protected:

    static const int32_t id_static_bitmap_user_status;
    static const int32_t id_static_text_contact_name;
    static const int32_t id_bitmap_button_user_actions;
    static const int32_t id_delete_user_button;
    static const int32_t id_static_bitmap_user_photo;
    static const int32_t id_text_ctrl_user_comment;
    static const int32_t id_bitmap_button_user_profile;
    static const int32_t id_button_send_message;
    static const int32_t id_bitmap_button_send_file;
    static const int32_t id_static_text_last_seen;
    static const int32_t id_menuitem_send_message1;
    static const int32_t id_menu_item_block_user;
    static const int32_t id_menu_item_delete_user;
    static const int32_t id_menu_item_add_to_share_ro;
    static const int32_t id_menu_item_add_to_share_rw;
    static const int32_t id_menu_item_add_to_share_admin;
    static const int32_t id_menu_item_remove_from_share;
    static const int32_t id_menuitem_share1;
    static const int32_t id_menu_shares;

  private:

    void Onview_profile_buttonClick(wxCommandEvent& event);  // NOLINT
    void Ondelete_user_buttonClick(wxCommandEvent& event);  // NOLINT
    void Onuser_actions_buttonClick(wxCommandEvent& event);  // NOLINT
    void Onbutton_send_messageClick(wxCommandEvent& event);  // NOLINT
    void Onfile_send_buttonClick(wxCommandEvent& event);  // NOLINT
    void Ontxt_ctrl_user_commentText(wxCommandEvent& event);  // NOLINT
    void OnMouseEnter(wxMouseEvent& event);  // NOLINT
    void OnMouseLeave(wxMouseEvent& event);  // NOLINT
    void UserActionMenu();

    DECLARE_EVENT_TABLE()
};
// WX_DECLARE_LIST(wxWindow*, MyList);

#endif  // GUI_CONTACT_DETAIL_H_
