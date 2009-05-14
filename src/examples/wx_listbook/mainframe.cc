#ifdef WX_PRECOMP
#include "wx_pch.h"
#endif

#ifdef __BORLANDC__
#pragma hdrstop
#endif // __BORLANDC__

#include "mainframe.h"

// helper functions
enum wxbuildinfoformat {
    short_f, long_f };

wxString wxbuildinfo(wxbuildinfoformat format)
{
    wxString wxbuild(wxVERSION_STRING);

    if (format == long_f )
    {
#if defined(__WXMSW__)
        wxbuild << _T("-Windows");
#elif defined(__WXMAC__)
        wxbuild << _T("-Mac");
#elif defined(__UNIX__)
        wxbuild << _T("-Linux");
#endif

#if wxUSE_UNICODE
        wxbuild << _T("-Unicode build");
#else
        wxbuild << _T("-ANSI build");
#endif //  wxUSE_UNICODE
    }

    return wxbuild;
}

BEGIN_EVENT_TABLE(MainFrame, wxFrame)
  EVT_CLOSE(MainFrame::OnClose)
  EVT_MENU(idMenuQuit, MainFrame::OnQuit)
  EVT_MENU(idMenuAbout, MainFrame::OnAbout)
  EVT_BUTTON(Page1::idButton1, MainFrame::OnButton1Page1)
  EVT_BUTTON(Page2::idButton1, MainFrame::OnButton1Page2)
END_EVENT_TABLE()

MainFrame::MainFrame(wxFrame *frame, const wxString& title)
  : wxFrame(frame, -1, title) {
#if wxUSE_MENUS
  //  create a menu bar
  wxMenuBar* mbar = new wxMenuBar();
  wxMenu* fileMenu = new wxMenu(_T(""));
  fileMenu->Append(idMenuQuit, _("&Quit\tAlt-F4"), _("Quit the application"));
  mbar->Append(fileMenu, _("&File"));

  wxMenu* helpMenu = new wxMenu(_T(""));
  helpMenu->Append(idMenuAbout, _("&About\tF1"), _("Show info about this application"));
  mbar->Append(helpMenu, _("&Help"));

  SetMenuBar(mbar);
#endif //  wxUSE_MENUS

#if wxUSE_STATUSBAR
  //  create a status bar with some information about the used wxWidgets version
  CreateStatusBar(2);
  SetStatusText(_("Hello Code::Blocks user!"),0);
  SetStatusText(wxbuildinfo(short_f), 1);
#endif //  wxUSE_STATUSBAR

  m_panel_ = NULL;
  m_book_ctrl_ = NULL;
  page1_ = NULL;
  page2_ = NULL;
  m_sizerFrame_ = new wxBoxSizer(wxVERTICAL);


  m_panel_ = new wxPanel(this);
  m_panel_->SetSizer(m_sizerFrame_);

  CreateBook();

  m_sizerFrame_->Fit(this);
  m_sizerFrame_->SetSizeHints(this);

}


MainFrame::~MainFrame() {}

void MainFrame::CreateBook() {
  m_book_ctrl_ = new wxListbook(m_panel_, wxID_ANY,wxDefaultPosition, wxDefaultSize, wxBK_TOP);
  m_book_ctrl_->Hide();
  page1_ = new Page1(m_book_ctrl_);
  wxString title = wxT("PAGE 1");
  m_book_ctrl_->AddPage(page1_, title, false);

  page2_ = new Page2(m_book_ctrl_);
  title = wxT("PAGE 2");
  m_book_ctrl_->AddPage(page2_, title, false);
  m_sizerFrame_->Insert(0, m_book_ctrl_, wxSizerFlags(5).Expand().Border());
  m_sizerFrame_->Show(m_book_ctrl_);
  m_sizerFrame_->Layout();
}

void MainFrame::OnButton1Page1(wxCommandEvent& event) {
  std::cout << "Button 1 of Page 1 pressed" << std::endl;
  std::string val = page1_->GetTxtCtrlVal();
  std::cout << "Value: " << val << std::endl;
}

void MainFrame::OnButton1Page2(wxCommandEvent& event) {
  std::cout << "Button 1 of Page 2 pressed" << std::endl;
}

void MainFrame::OnClose(wxCloseEvent &event) {
    Destroy();
}

void MainFrame::OnQuit(wxCommandEvent &event) {
    Destroy();
}

void MainFrame::OnAbout(wxCommandEvent &event) {
    wxString msg = wxbuildinfo(long_f);
    wxMessageBox(msg, _("Welcome to..."));
}
