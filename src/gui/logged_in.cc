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
#include "gui/logged_in.h"

#include <wx/string.h>
#include <wx/intl.h>
#include <wx/bitmap.h>
#include <wx/image.h>
// #include "gui/maidsafe_logo1.xpm"

const int32_t logged_in::ID_STATICBITMAP_LOGGED_IN_LOGO = wxNewId();
const int32_t logged_in::ID_STATICBITMAP_LOGGED_IN_IMAGE = wxNewId();
const int32_t logged_in::ID_STATICTEXTLOGEDINASLABEL = wxNewId();
const int32_t logged_in::ID_STATICTEXT_LOGED_IN_AS = wxNewId();
const int32_t logged_in::ID_STATICTEXT_VERSION = wxNewId();
const int32_t logged_in::ID_STATICTEXT4 = wxNewId();
const int32_t logged_in::ID_STATICTEXT_ONLINE_STATUS = wxNewId();
const int32_t logged_in::ID_CHOICE_STATUS = wxNewId();
const int32_t logged_in::ID_STATICTEXT_BANDWIDTH_SPEED = wxNewId();
const int32_t logged_in::ID_GAUGE_BANDWIDTH = wxNewId();
const int32_t logged_in::ID_STATICTEXT_SPACE_FREE = wxNewId();
const int32_t logged_in::ID_GAUGE_SPACE = wxNewId();
const int32_t logged_in::ID_STATICTEXT_SECURITY_LEVEL = wxNewId();
const int32_t logged_in::ID_CHOICE_SECURITY = wxNewId();
const int32_t logged_in::ID_STATICTEXT_SPACE_DONATED = wxNewId();
const int32_t logged_in::ID_SLIDER_DONATE_SPACE = wxNewId();
const int32_t logged_in::ID_STATICTEXT_BALANCE = wxNewId();
const int32_t logged_in::ID_STATICTEXT_SHOW_BALANCE = wxNewId();
const int32_t logged_in::ID_BUTTON_BUY_CREDIT = wxNewId();
const int32_t logged_in::ID_BUTTON_DONATE = wxNewId();
const int32_t logged_in::ID_BUTTON_UPGRADE = wxNewId();
const int32_t logged_in::ID_BUTTON_LOGOUT = wxNewId();

logged_in::logged_in(wxWindow* parent, wxWindowID id,
  const wxPoint& pos, const wxSize& size)
  : StaticTextSayVersion(NULL), static_txt_space_free(NULL),
  FlexGridSizer1(NULL), GaugeSpace(NULL), StaticTextShowBalance(NULL),
  StaticBitmapLogedInImage(NULL), stat_version(NULL),
  static_disk_space_donated(NULL), static_security_level(NULL),
  button_upgrade(NULL), button_buy_credits(NULL), choice_security(NULL),
  slider_donate_space(NULL), stat_txt_balance(NULL),
  static_online_status(NULL), StaticTextLogedInAsLabel(NULL),
  choice_status(NULL), button_logout(NULL),
  static_bandwidth_speed(NULL), button_donate(NULL), GaugeBandwidth(NULL),
  static_loged_in_as(NULL), StaticBitmapLogedInLogo(NULL) {
  Create(parent, id, pos, size,
    wxTAB_TRAVERSAL, _T("id"));
  SetMaxSize(wxSize(-1, -1));
  SetBackgroundColour(wxColour(255, 255, 255));

  //  FlexGridSizer1 = new wxFlexGridSizer(5, 2, 0, 0);
  //  FlexGridSizer1->AddGrowableCol(0);
  //  FlexGridSizer1->AddGrowableCol(1);
  //  FlexGridSizer1->AddGrowableCol(2);
  //  FlexGridSizer1->AddGrowableCol(3);
  //  FlexGridSizer1->AddGrowableRow(0);
  //  FlexGridSizer1->AddGrowableRow(1);
  //  FlexGridSizer1->AddGrowableRow(2);
  //  FlexGridSizer1->AddGrowableRow(3);
  //  FlexGridSizer1->AddGrowableRow(4);
  //  FlexGridSizer1->AddGrowableRow(5);
  //  FlexGridSizer1->AddGrowableRow(6);
  //  FlexGridSizer1->AddGrowableRow(7);
  //  FlexGridSizer1->AddGrowableRow(8);
  //  FlexGridSizer1->AddGrowableRow(9);
  //  StaticBitmapLogedInLogo = new wxStaticBitmap(this,
  //    ID_STATICBITMAP_LOGGED_IN_LOGO, wxBitmap(wxImage(maidsafe_logo1_xpm)),
  //    wxDefaultPosition, wxDefaultSize, 0,
  //    _T("ID_STATICBITMAP_LOGGED_IN_LOGO"));
  //  FlexGridSizer1->Add(StaticBitmapLogedInLogo, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  StaticBitmapLogedInImage = new wxStaticBitmap(this,
  //    ID_STATICBITMAP_LOGGED_IN_IMAGE,
  //    wxBitmap(wxImage(maidsafe_logo1_xpm).Rescale(wxSize(208, 56).GetWidth(),
  //    wxSize(208, 56).GetHeight())), wxDefaultPosition,
  //    wxSize(208, 56), 0, _T("ID_STATICBITMAP_LOGGED_IN_IMAGE"));
  //  FlexGridSizer1->Add(StaticBitmapLogedInImage, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  StaticTextLogedInAsLabel = new wxStaticText(this,
  //    ID_STATICTEXTLOGEDINASLABEL, _("Logged in as"),
  //    wxDefaultPosition, wxDefaultSize, 0,
  //    _T("ID_STATICTEXTLOGEDINASLABEL"));
  //  FlexGridSizer1->Add(StaticTextLogedInAsLabel, 1,
  //    wxALL|wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL, 5);
  //  static_loged_in_as = new wxStaticText(this, ID_STATICTEXT_LOGED_IN_AS,
  //    _("Label"), wxDefaultPosition, wxDefaultSize, 0,
  //    _T("ID_STATICTEXT_LOGED_IN_AS"));
  //  FlexGridSizer1->Add(static_loged_in_as, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  stat_version = new wxStaticText(this, ID_STATICTEXT_VERSION,
  //    _("Version"), wxDefaultPosition, wxDefaultSize,
  //    0, _T("ID_STATICTEXT_VERSION"));
  //  FlexGridSizer1->Add(stat_version,
  //    1, wxALL|wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL, 5);
  //  StaticTextSayVersion = new wxStaticText(this,
  //    ID_STATICTEXT4, _("Free Alpha Version"), wxDefaultPosition,
  //    wxDefaultSize, 0, _T("ID_STATICTEXT4"));
  //  FlexGridSizer1->Add(StaticTextSayVersion, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  static_online_status = new wxStaticText(this,
  //    ID_STATICTEXT_ONLINE_STATUS, _("On-line status"),
  //    wxDefaultPosition, wxDefaultSize,
  //    0, _T("ID_STATICTEXT_ONLINE_STATUS"));
  //  FlexGridSizer1->Add(static_online_status, 1,
  //    wxALL|wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL, 5);
  //  choice_status = new wxChoice(this, ID_CHOICE_STATUS,
  //    wxDefaultPosition, wxDefaultSize, 0, 0,
  //    0, wxDefaultValidator, _T("ID_CHOICE_STATUS"));
  //  choice_status->SetSelection(choice_status->Append(_("Online")));
  //  choice_status->Append(_("Busy"));
  //  choice_status->Append(_("Away"));
  //  choice_status->Append(_("Hide"));
  //  choice_status->SetToolTip(_("Select on line status"));
  //  FlexGridSizer1->Add(choice_status, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  static_bandwidth_speed = new wxStaticText(this,
  //    ID_STATICTEXT_BANDWIDTH_SPEED, _("Bandwidth speed"),
  //    wxDefaultPosition, wxDefaultSize, 0,
  //    _T("ID_STATICTEXT_BANDWIDTH_SPEED"));
  //  FlexGridSizer1->Add(static_bandwidth_speed, 1,
  //    wxALL|wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL, 5);
  //  GaugeBandwidth = new wxGauge(this, ID_GAUGE_BANDWIDTH,
  //    100, wxDefaultPosition, wxDefaultSize,
  //    wxGA_SMOOTH, wxDefaultValidator, _T("ID_GAUGE_BANDWIDTH"));
  //  GaugeBandwidth->SetShadowWidth(2);
  //  GaugeBandwidth->SetBezelFace(2);
  //  FlexGridSizer1->Add(GaugeBandwidth, 1,
  //    wxALL|wxEXPAND|wxSHAPED|wxALIGN_CENTER_HORIZONTAL|
  //    wxALIGN_CENTER_VERTICAL, 5);
  //  static_txt_space_free = new wxStaticText(this,
  //    ID_STATICTEXT_SPACE_FREE, _("Space free"), wxDefaultPosition,
  //    wxDefaultSize, 0, _T("ID_STATICTEXT_SPACE_FREE"));
  //  static_txt_space_free->SetToolTip(_("The lower the number the
  //    better the rank. Only Rank 1 or 0 can effectively
  //    work from any internet device."));
  //  FlexGridSizer1->Add(static_txt_space_free,
  //    1, wxALL|wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL, 5);
  //  GaugeSpace = new wxGauge(this, ID_GAUGE_SPACE,
  //    100, wxDefaultPosition, wxDefaultSize, wxGA_SMOOTH,
  //    wxDefaultValidator, _T("ID_GAUGE_SPACE"));
  //  GaugeSpace->SetShadowWidth(2);
  //  FlexGridSizer1->Add(GaugeSpace, 1,
  //    wxALL|wxEXPAND|wxSHAPED|wxALIGN_CENTER_HORIZONTAL|
  //    wxALIGN_CENTER_VERTICAL, 5);
  //  static_security_level = new wxStaticText(this,
  //    ID_STATICTEXT_SECURITY_LEVEL, _("Security Level"),
  //    wxDefaultPosition, wxDefaultSize, 0,
  //    _T("ID_STATICTEXT_SECURITY_LEVEL"));
  //  FlexGridSizer1->Add(static_security_level, 1,
  //    wxALL|wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL, 5);
  //  choice_security = new wxChoice(this, ID_CHOICE_SECURITY,
  //    wxDefaultPosition, wxDefaultSize, 0, 0, 0,
  //    wxDefaultValidator, _T("ID_CHOICE_SECURITY"));
  //  choice_security->SetSelection(choice_security->Append(_("Defcon 1")));
  //  choice_security->Append(_("Defcon 2"));
  //  choice_security->Append(_("Defcon 3"));
  //  choice_security->SetToolTip(_("Defcon 1 - all chunks stored
  //    on network only.\nDefcon 2 - A local copy of all data
  //    maintained (off-line secure mode)\nDefcon 3 - most secure
  //    - no trace of you left on machine."));
  //  FlexGridSizer1->Add(choice_security, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  static_disk_space_donated = new wxStaticText(this,
  //    ID_STATICTEXT_SPACE_DONATED, _("Donate Disk Space"), wxDefaultPosition,
  //    wxDefaultSize, 0, _T("ID_STATICTEXT_SPACE_DONATED"));
  //  FlexGridSizer1->Add(static_disk_space_donated, 1,
  //    wxALL|wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL, 5);
  //  slider_donate_space = new wxSlider(this, ID_SLIDER_DONATE_SPACE,
  //    20, 0, 100, wxDefaultPosition, wxSize(102,19),
  //    0, wxDefaultValidator, _T("ID_SLIDER_DONATE_SPACE"));
  //  slider_donate_space->SetTickFreq(1);
  //  slider_donate_space->SetLineSize(100);
  //  slider_donate_space->SetToolTip(_("This is the amount of disk
  //    space representing 50% of your free space. Increasing the slider
  //    increases donated space (up to 50% maximum of free space)."));
  //  slider_donate_space->SetHelpText(_("This is the amount of disk space
  //    representing 50% of your free space. Increasing the slider
  //    increases donated space (up to 50% maximum of free space)."));
  //  FlexGridSizer1->Add(slider_donate_space, 1,
  //    wxALL|wxEXPAND|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  stat_txt_balance = new wxStaticText(this, ID_STATICTEXT_BALANCE,
  //    _("Current balance"), wxDefaultPosition,
  //    wxDefaultSize, 0, _T("ID_STATICTEXT_BALANCE"));
  //  FlexGridSizer1->Add(stat_txt_balance, 1,
  //    wxALL|wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL, 5);
  //  StaticTextShowBalance = new wxStaticText(this,
  //    ID_STATICTEXT_SHOW_BALANCE, _("$4M"), wxDefaultPosition,
  //    wxDefaultSize, 0, _T("ID_STATICTEXT_SHOW_BALANCE"));
  //  FlexGridSizer1->Add(StaticTextShowBalance, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  button_buy_credits = new wxButton(this, ID_BUTTON_BUY_CREDIT,
  //    _("Buy Credits"), wxDefaultPosition, wxDefaultSize, 0,
  //    wxDefaultValidator, _T("ID_BUTTON_BUY_CREDIT"));
  //  FlexGridSizer1->Add(button_buy_credits, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  button_donate = new wxButton(this, ID_BUTTON_DONATE, _("Donate"),
  //    wxDefaultPosition, wxDefaultSize, 0,
  //    wxDefaultValidator, _T("ID_BUTTON_DONATE"));
  //  button_donate->SetDefault();
  //  button_donate->SetToolTip(_("Donate to the maidsafe
  //    perpetual data project"));
  //  FlexGridSizer1->Add(button_donate, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //  button_upgrade = new wxButton(this, ID_BUTTON_UPGRADE,
  //    _("Upgrade to Pro"), wxDefaultPosition, wxDefaultSize,
  //    0, wxDefaultValidator, _T("ID_BUTTON_UPGRADE"));
  //  button_upgrade->SetToolTip(_("Allows unlimited shares and
  //    space. Also allows you to  remove any advertising."));
  //  button_upgrade->SetHelpText(_("Allows unlimited shares
  //    and space. Also allows you to  remove any advertising."));
  //  FlexGridSizer1->Add(button_upgrade, 1,
  //    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  //
  //  button_logout = new wxButton(this, ID_BUTTON_LOGOUT,
  //    _("Logout"), wxDefaultPosition, wxDefaultSize, 0,
  //    wxDefaultValidator, _T("ID_BUTTON_LOGOUT"));

  FlexGridSizer1->Add(button_logout, 1,
    wxALL|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL, 5);
  SetSizer(FlexGridSizer1);
  FlexGridSizer1->Fit(this);
  FlexGridSizer1->SetSizeHints(this);
}

logged_in::~logged_in() {
}
