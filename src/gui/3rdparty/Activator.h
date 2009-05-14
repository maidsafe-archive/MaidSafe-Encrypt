

wxLogWindow *logW;

class MainApp : public wxApp
{
  public:
    virtual bool OnInit(void);
    virtual int OnExit(void);
};
DECLARE_APP(MainApp);


class Activator : public wxFrame
{
  public:
    Activator(wxWindow* parent=(wxWindow *)NULL);
    ~Activator();

  private:        
    void OnQuit(wxCommandEvent &event);
    void ButtonDown(wxCommandEvent &event);
    void SetColors(wxCommandEvent &event);
    void SetColors2(wxCommandEvent &event);
    wxButton *colButton1;
    wxButton *colButton2;
    ToasterBox tb;
    wxPanel *pn;
    int pSizeX, pSizeY, pLinger, pPosX, pPosY, pScrollSpeed;
    wxString pText, pBitmap;
    wxColor colBg, colFg;

    //  any class wishing to process wxWindows events must use this macro
    DECLARE_EVENT_TABLE()
};

enum
{
    //  menu items
    MainApp_Quit = 1,
    MainApp_About,
    ID_BTNEXIT,
    ID_BTNGO
};


BEGIN_EVENT_TABLE(Activator, wxFrame)
  EVT_BUTTON(ID_BTNEXIT, Activator::OnQuit)
  EVT_BUTTON(ID_BTNGO, Activator::ButtonDown)
END_EVENT_TABLE()

IMPLEMENT_APP(MainApp)
