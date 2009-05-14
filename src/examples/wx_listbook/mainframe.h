#ifndef MAINFRAME_H
#define MAINFRAME_H

#include <wx/wx.h>
#include <wx/listbook.h>

#include "wxwidgetstestApp.h"
#include "page1.h"
#include "page2.h"

class MainFrame: public wxFrame {
public:
  MainFrame(wxFrame *frame, const wxString& title);
  ~MainFrame();
private:
  enum{
    idMenuQuit = 1000,
    idMenuAbout
  };
  wxPanel *m_panel_;
  wxListbook *m_book_ctrl_;
  wxBoxSizer *m_sizerFrame_;
  Page1 *page1_;
  Page2 *page2_;
  void OnClose(wxCloseEvent& event);
  void OnQuit(wxCommandEvent& event);
  void OnAbout(wxCommandEvent& event);

  void OnButton1Page1(wxCommandEvent& event);
  void OnButton1Page2(wxCommandEvent& event);

  void CreateBook();

  DECLARE_EVENT_TABLE()

};


#endif //  WXWIDGETSTESTMAIN_H
