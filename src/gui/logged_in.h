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
#ifndef GUI_LOGGED_IN_H_
#define GUI_LOGGED_IN_H_
// #ifdef __WXMSW__
//  #undef CreateDialog
//  #include "wx/msw/winundef.h"
// #endif

#include <wx/gauge.h>
#include <wx/sizer.h>
#include <wx/button.h>
#include <wx/panel.h>
#include <wx/slider.h>
#include <wx/stattext.h>
#include <wx/choice.h>
#include <wx/statbmp.h>

class logged_in: public wxPanel {
  public:

    logged_in(wxWindow* parent, wxWindowID id = wxID_ANY,
      const wxPoint& pos = wxDefaultPosition,
      const wxSize& size = wxDefaultSize);
    logged_in(const logged_in&);
    logged_in& operator=(const logged_in&);
    virtual ~logged_in();

    static const int32_t ID_STATICBITMAP_LOGGED_IN_LOGO;
    static const int32_t ID_STATICBITMAP_LOGGED_IN_IMAGE;
    static const int32_t ID_STATICTEXTLOGEDINASLABEL;
    static const int32_t ID_STATICTEXT_LOGED_IN_AS;
    static const int32_t ID_STATICTEXT_VERSION;
    static const int32_t ID_STATICTEXT4;
    static const int32_t ID_STATICTEXT_ONLINE_STATUS;
    static const int32_t ID_CHOICE_STATUS;
    static const int32_t ID_STATICTEXT_BANDWIDTH_SPEED;
    static const int32_t ID_GAUGE_BANDWIDTH;
    static const int32_t ID_STATICTEXT_SPACE_FREE;
    static const int32_t ID_GAUGE_SPACE;
    static const int32_t ID_STATICTEXT_SECURITY_LEVEL;
    static const int32_t ID_CHOICE_SECURITY;
    static const int32_t ID_STATICTEXT_SPACE_DONATED;
    static const int32_t ID_SLIDER_DONATE_SPACE;
    static const int32_t ID_STATICTEXT_BALANCE;
    static const int32_t ID_STATICTEXT_SHOW_BALANCE;
    static const int32_t ID_BUTTON_BUY_CREDIT;
    static const int32_t ID_BUTTON_DONATE;
    static const int32_t ID_BUTTON_UPGRADE;
    static const int32_t ID_BUTTON_LOGOUT;

  private:
    wxStaticText* StaticTextSayVersion;
    wxStaticText* static_txt_space_free;
    wxFlexGridSizer* FlexGridSizer1;
    wxGauge* GaugeSpace;
    wxStaticText* StaticTextShowBalance;
    wxStaticBitmap* StaticBitmapLogedInImage;
    wxStaticText* stat_version;
    wxStaticText* static_disk_space_donated;
    wxStaticText* static_security_level;
    wxButton* button_upgrade;
    wxButton* button_buy_credits;
    wxChoice* choice_security;
    wxSlider* slider_donate_space;
    wxStaticText* stat_txt_balance;
    wxStaticText* static_online_status;
    wxStaticText* StaticTextLogedInAsLabel;
    wxChoice* choice_status;
    wxButton* button_logout;
    wxStaticText* static_bandwidth_speed;
    wxButton* button_donate;
    wxGauge* GaugeBandwidth;
    wxStaticText* static_loged_in_as;
    wxStaticBitmap* StaticBitmapLogedInLogo;
};

#endif  // GUI_LOGGED_IN_H_
