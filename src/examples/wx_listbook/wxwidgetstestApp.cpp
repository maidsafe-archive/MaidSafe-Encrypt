#ifdef WX_PRECOMP
#include "wx_pch.h"
#endif

#ifdef __BORLANDC__
#pragma hdrstop
#endif // __BORLANDC__

#include "wxwidgetstestApp.h"
#include "mainframe.h"

IMPLEMENT_APP(wxwidgetstestApp);

bool wxwidgetstestApp::OnInit(){
    MainFrame* frame = new MainFrame(0L, _("wxWidgets Application Template"));

    frame->Show();

    return true;
}
