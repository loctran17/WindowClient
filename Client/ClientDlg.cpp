#include "stdafx.h"
#include "Client.h"
#include "ClientDlg.h"
#include "afxdialogex.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#endif




// CClientDlg dialog



CClientDlg::CClientDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CClientDlg::IDD, pParent)
	, m_strUserName(_T(""))
	, m_strPassword(_T(""))
	, m_strDisplay(_T(""))
{
	//m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_USERNAME, m_strUserName);
	DDX_Text(pDX, IDC_PASSWORD, m_strPassword);
	//  DDX_Control(pDX, IDC_USERNAME, m_edtUserName);
	//  DDX_Control(pDX, IDC_PASSWORD, m_edtPassword);
	//  DDX_Control(pDX, IDC_USERNAME, m_edtUserName);
	//  DDX_Control(pDX, IDC_PASSWORD, m_edtPassword);
	//  DDX_Control(pDX, IDC_USERNAME, m_edtUserName);
	DDX_Control(pDX, IDC_EDIT4, m_edtDisplay);
	DDX_Control(pDX, IDC_USERNAME, m_edtUserName);
	DDX_Control(pDX, IDC_FILEPROGRESS, m_prgFileTransfer);
	DDX_Control(pDX, IDCLOGIN, m_btLogin);
	DDX_Control(pDX, IDC_PRODUCTLIST, m_lstProduct);
	DDX_Control(pDX, IDC_LOAD, m_btLoad);
	DDX_Control(pDX, IDC_PASSWORD, m_edtPassword);
	//  DDX_Control(pDX, IDC_PRODUCT_CONSOLE, m_edtProductConsole);
	//DDX_Control(pDX, IDC_PRODUCT_CONSOLE, m_lstProductConsole);
	//  DDX_Text(pDX, IDC_STATIC_VAC, m_stVac);
	DDX_Control(pDX, IDC_STATIC_BUILD_VERSION, m_stBuildVersion);
	DDX_Control(pDX, IDC_STATIC_ESEA, m_stEsea);
	DDX_Control(pDX, IDC_STATIC_ESL, m_stEsl);
	DDX_Control(pDX, IDC_STATIC_EXPIRE_DAY, m_stExpireDate);
	DDX_Control(pDX, IDC_STATIC_GAME_NAME, m_stGameName);
	//  DDX_Control(pDX, IDC_STATIC_VAC, m_stVac);
	DDX_Control(pDX, IDC_STATIC_VAC, m_stVac);
	DDX_Control(pDX, IDC_CONSOLE_PRODUCT, m_edtProductConsole);
}

BEGIN_MESSAGE_MAP(CClientDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDCLOGIN, &CClientDlg::OnBnClickedClogin)
	ON_WM_CTLCOLOR()
//	ON_EN_SETFOCUS(IDC_USERNAME, &CClientDlg::OnSetfocusUsername)
	ON_EN_SETFOCUS(IDC_PASSWORD, &CClientDlg::OnSetfocusPassword)
//	ON_EN_KILLFOCUS(IDC_USERNAME, &CClientDlg::OnKillfocusUsername)
ON_EN_KILLFOCUS(IDC_USERNAME, &CClientDlg::OnKillfocusUsername)
ON_EN_SETFOCUS(IDC_USERNAME, &CClientDlg::OnSetfocusUsername)
ON_EN_CHANGE(IDC_USERNAME, &CClientDlg::OnEnChangeUsername)
ON_EN_KILLFOCUS(IDC_PASSWORD, &CClientDlg::OnKillfocusPassword)
ON_EN_CHANGE(IDC_PASSWORD, &CClientDlg::OnChangePassword)
ON_WM_LBUTTONDOWN()
ON_WM_LBUTTONUP()
ON_WM_MOUSEMOVE()
ON_NOTIFY(NM_CUSTOMDRAW, IDC_FILEPROGRESS, &CClientDlg::OnNMCustomdrawFileprogress)
ON_WM_TIMER()
ON_BN_CLICKED(IDC_LOAD, &CClientDlg::OnBnClickedLoad)
ON_EN_CHANGE(IDC_EDIT4, &CClientDlg::OnEnChangeEdit4)
ON_EN_CHANGE(IDC_CONSOLE, &CClientDlg::OnEnChangeConsole)
ON_STN_CLICKED(IDC_STATIC_GAME_NAME, &CClientDlg::OnStnClickedStaticGameName)
ON_LBN_SELCHANGE(IDC_PRODUCTLIST, &CClientDlg::OnSelchangeProductlist)
ON_WM_CONTEXTMENU()
END_MESSAGE_MAP()


// CClientDlg message handlers

BOOL CClientDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
#if 0
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
#endif
		//pSysMenu->RemoveMenu(SC_MOVE, MF_BYCOMMAND);
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	m_strUserName.SetString(_T(""));
	m_strPassword.SetString(_T(""));
	m_bBanner = false;
	m_sslClient = new SSLClient(
		"81.4.106.108", /* Address */
		"1340", /* Port*/
		"client", /* PEM pass*/
		&m_prgFileTransfer, /* Progress bar*/
		&m_edtDisplay,
		&m_lstProduct, /* List product*/
		&m_stExpireDate,
		&m_edtProductConsole,
		&m_stGameName,
		&m_stBuildVersion,
		&m_stVac,
		&m_stEsl,
		&m_stEsea,
		&m_bBanner);

	m_prgFileTransfer.SetRange(0, 100);

	/* Set timer 1s */
	m_nTimerSteamID = SetTimer(IDC_LOGIN_ATTEMPT_TIMER, 1000, NULL);
	m_nTimerExitID = SetTimer(IDC_EXIT_TIMER, 5000, NULL);
	m_strDisplay.SetString(_T(""));

	/*	1. Hide list product,
		2. Hide list product console,
		3. Hide Load button,
		4. Hide progress file transfer,
		5. Hide Game static and Game name ... */
	m_lstProduct.ShowWindow(SW_HIDE);
	m_btLoad.ShowWindow(SW_HIDE);
	m_prgFileTransfer.ShowWindow(SW_HIDE);
	m_edtProductConsole.ShowWindow(SW_HIDE);
	CWnd* pWnd = GetDlgItem(IDC_STATIC_GAME);
	pWnd->ShowWindow(SW_HIDE);
	pWnd = GetDlgItem(IDC_STATIC_GAME_NAME);
	pWnd->ShowWindow(SW_HIDE);
	pWnd = GetDlgItem(IDC_STATIC_BUILD);
	pWnd->ShowWindow(SW_HIDE);
	pWnd = GetDlgItem(IDC_STATIC_BUILD_VERSION);
	pWnd->ShowWindow(SW_HIDE);
	pWnd = GetDlgItem(IDC_STATIC_STATUS);
	pWnd->ShowWindow(SW_HIDE);
	pWnd = GetDlgItem(IDC_STATIC_VAC);
	pWnd->ShowWindow(SW_HIDE);
	pWnd = GetDlgItem(IDC_STATIC_ESL);
	pWnd->ShowWindow(SW_HIDE);
	pWnd = GetDlgItem(IDC_STATIC_ESEA);
	pWnd->ShowWindow(SW_HIDE);
	pWnd = GetDlgItem(IDC_STATIC_SUB_EXPIRE);
	pWnd->ShowWindow(SW_HIDE);
	pWnd = GetDlgItem(IDC_STATIC_EXPIRE_DAY);
	pWnd->ShowWindow(SW_HIDE);

	EnableToolTips();
	m_iTitleHeight = ::GetSystemMetrics(SM_CYCAPTION);
	
	if (!m_ToolTip.Create(this))
	{
		MessageBox(_T("Unable to create the ToolTip!"));
	}
	else
	{
		
	}
	RECT mainWindowRect;
	GetWindowRect(&mainWindowRect);
	m_iWindowHeight = mainWindowRect.bottom - mainWindowRect.top;
	m_iWindowWidth = mainWindowRect.right - mainWindowRect.left;

	SetWindowPos(NULL, 0, 0, 315, 150, SWP_NOMOVE | SWP_NOZORDER);

	m_ToolTip.Activate(TRUE);

	UpdateData(FALSE);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CClientDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CClientDlg::OnPaint()
{
	
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
#if 0
		CDC MemDC;
		CBitmap bmp;
		CPaintDC dc(this);

		CRect rct;
		this->GetClientRect(&rct);

		MemDC.CreateCompatibleDC(&dc);
		bmp.LoadBitmap(IDB_BITMAP_BKG);
		MemDC.SelectObject(&bmp);

		dc.BitBlt(0, 0, rct.Width(), rct.Height(), &MemDC, 0, 0, SRCCOPY);
#endif			
		CDialog::OnPaint();

	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CClientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CClientDlg::OnBnClickedClogin()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);

	std::string response;
	std::wstring wUserName(m_strUserName);
	std::wstring wPassword(m_strPassword);
	std::string username;
	std::string password;
	std::string version((char*) VERSION);
	CString message;
	
	username.assign(wUserName.begin(), wUserName.end());
	password.assign(wPassword.begin(), wPassword.end());

	/* make version to 32 length */
	version.insert(version.end(), VERSION_LENGTH - version.length(), ' ');

	response.clear();
	m_edtDisplay.SetSel(0, -1);
	m_edtDisplay.Clear();

	//response = m_sslClient->MakeLoginRequest(username, password);
	if (m_sslClient->Start())
	{

		response = m_sslClient->MakeLoginRequest(username, password, version);
		message.Format(_T("%S"), response.c_str());
		m_edtDisplay.SetWindowText(message);
		if (response.compare((char*)USER_VERIFY) == 0)
		{
			SetWindowPos(NULL, 0, 0, 420, 385, SWP_NOMOVE | SWP_NOZORDER);
			
			m_btLogin.ShowWindow(SW_HIDE);
			m_edtDisplay.ShowWindow(SW_HIDE);
			m_edtUserName.ShowWindow(SW_HIDE);
			m_edtPassword.ShowWindow(SW_HIDE);
			CWnd* pWnd = GetDlgItem(IDC_STATIC_USER);
			pWnd->ShowWindow(SW_HIDE);
			pWnd = GetDlgItem(IDC_STATIC_PASS);
			pWnd->ShowWindow(SW_HIDE);
			m_lstProduct.ShowWindow(SW_SHOW);
			m_lstProduct.SetCurSel(0);
			m_btLoad.ShowWindow(SW_SHOW);
			m_prgFileTransfer.ShowWindow(SW_SHOW);


			/* */
			m_edtProductConsole.ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_GAME);
			pWnd->ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_GAME_NAME);
			pWnd->ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_BUILD);
			pWnd->ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_BUILD_VERSION);
			pWnd->ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_STATUS);
			pWnd->ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_VAC);
			pWnd->ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_ESL);
			pWnd->ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_ESEA);
			pWnd->ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_SUB_EXPIRE);
			pWnd->ShowWindow(SW_SHOW);
			pWnd = GetDlgItem(IDC_STATIC_EXPIRE_DAY);
			pWnd->ShowWindow(SW_SHOW);
			//m_sslClient->ReceiveFile();
		}
	}
	else
	{
		m_strDisplay = _T("");
		UpdateData(FALSE);
	}
		
}


void CClientDlg::OnFinalRelease()
{
	// TODO: Add your specialized code here and/or call the base class
	m_sslClient->Stop();

	CDialog::OnFinalRelease();
}


void CClientDlg::PostNcDestroy()
{
	// TODO: Add your specialized code here and/or call the base class
	delete m_sslClient;

	CDialog::PostNcDestroy();
}


HBRUSH CClientDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	CString status;

	switch (pWnd->GetDlgCtrlID())
	{
		case IDC_STATIC_VAC:
			
			m_stVac.GetWindowText(status);
			if (status.Compare(_T("BANS")) == 0)
			{
				m_stVac.SetWindowText(_T("VAC"));
				pDC->SetTextColor(RGB(190, 190, 190));
				m_ToolTip.AddTool(&m_stVac, _T("BANS"));
			}
			else if (status.Compare(_T("UNDETECTED")) == 0)
			{
				m_stVac.SetWindowText(_T("VAC"));
				pDC->SetTextColor(RGB(0, 255, 0));
				m_ToolTip.AddTool(&m_stVac, _T("UNDETECTED"));
			}
			else if (status.Compare(_T("DETECTED")) == 0)
			{
				m_stVac.SetWindowText(_T("VAC"));
				pDC->SetTextColor(RGB(255, 0, 0));
				m_ToolTip.AddTool(&m_stVac, _T("DETECTED"));
			}

			break;
		case IDC_STATIC_ESL:
			m_stEsl.GetWindowText(status);
			if (status.Compare(_T("BANS")) == 0)
			{
				m_stEsl.SetWindowText(_T("ESL"));
				pDC->SetTextColor(RGB(190, 190, 190));
				m_ToolTip.AddTool(&m_stEsl, _T("BANS"));
			}
			else if (status.Compare(_T("UNDETECTED")) == 0)
			{
				m_stEsl.SetWindowText(_T("ESL"));
				pDC->SetTextColor(RGB(0, 255, 0));
				m_ToolTip.AddTool(&m_stEsl, _T("UNDETECTED"));
			}
			else if (status.Compare(_T("DETECTED")) == 0)
			{
				m_stEsl.SetWindowText(_T("ESL"));
				pDC->SetTextColor(RGB(255, 0, 0));
				m_ToolTip.AddTool(&m_stEsl, _T("DETECTED"));
			}

			break;
		case IDC_STATIC_ESEA:
			m_stEsea.GetWindowText(status);
			if (status.Compare(_T("BANS")) == 0)
			{
				m_stEsea.SetWindowText(_T("ESEA"));
				pDC->SetTextColor(RGB(190, 190, 190));
				m_ToolTip.AddTool(&m_stEsea, _T("BANS"));
			}
			else if (status.Compare(_T("UNDETECTED")) == 0)
			{
				m_stEsea.SetWindowText(_T("ESEA"));
				pDC->SetTextColor(RGB(0, 255, 0));
				m_ToolTip.AddTool(&m_stEsea, _T("UNDETECTED"));
			}
			else if (status.Compare(_T("DETECTED")) == 0)
			{
				m_stEsea.SetWindowText(_T("ESEA"));
				pDC->SetTextColor(RGB(255, 0, 0));
				m_ToolTip.AddTool(&m_stEsea, _T("DETECTED"));
			}

			break;
		default:
			break;
	}
	m_ToolTip.Activate(TRUE);

	// TODO:  Return a different brush if the default is not desired
	return hbr;
}


void CClientDlg::SetMyFont()
{
	CRect	rRect;
	int		iHeight;

	/* Get dimesion of username edit control */

	/* Calculate the area height */
	iHeight = rRect.top - rRect.bottom;
	if (iHeight < 0) iHeight = 0 - iHeight;

	/* Realease current font */
	m_fMyFont.Detach();
	m_fMyFont.CreateFont(
		(iHeight - 5), 
		0, 
		0, 
		0, 
		FW_NORMAL, 
		TRUE, 
		FALSE, 
		FALSE, 
		ANSI_CHARSET, 
		OUT_DEFAULT_PRECIS, 
		CLIP_DEFAULT_PRECIS, 
		DEFAULT_QUALITY, 
		DEFAULT_PITCH | FF_SWISS, 
		_T("Arial"));
	//m_edtUserName.SetFont(&m_fMyFont);	
}

void CClientDlg::OnKillfocusUsername()
{
	
	
}


void CClientDlg::OnSetfocusUsername()
{
	
}


void CClientDlg::OnEnChangeUsername()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
	UpdateData(TRUE);
	if (m_strUserName.IsEmpty())
	{
		UpdateData(FALSE);
	}
}


void CClientDlg::OnSetfocusPassword()
{
	
}


void CClientDlg::OnKillfocusPassword()
{
	
}


void CClientDlg::OnChangePassword()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
	UpdateData(TRUE);
	if (m_strPassword.IsEmpty())
	{
		UpdateData(FALSE);
	}
}


void CClientDlg::OnLButtonDown(UINT nFlags, CPoint point)
{
	// TODO: Add your message handler code here and/or call default
	
	m_iPrevX = point.x;
	if (point.y < m_iTitleHeight)
	{
		m_iPrevY = point.y;
		dragWindow = true;
		SetCapture();
	}

	CDialog::OnLButtonDown(nFlags, point);

}


void CClientDlg::OnLButtonUp(UINT nFlags, CPoint point)
{
	// TODO: Add your message handler code here and/or call default
	dragWindow = false;
	ReleaseCapture();

	CDialog::OnLButtonUp(nFlags, point);
}


void CClientDlg::OnMouseMove(UINT nFlags, CPoint point)
{
	// TODO: Add your message handler code here and/or call default
	
	if (dragWindow == true)
	{
		RECT mainWindowRect;
		int windowWidth, windowHeight;

		GetWindowRect(&mainWindowRect);
		windowHeight = mainWindowRect.bottom - mainWindowRect.top;
		windowWidth = mainWindowRect.right - mainWindowRect.left;

		ClientToScreen(&point);
		MoveWindow(point.x - m_iPrevX, point.y - m_iPrevY, windowWidth, windowHeight, TRUE);

	}
	
	CDialog::OnMouseMove(nFlags, point);
}


void CClientDlg::OnNMCustomdrawFileprogress(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;
}



DWORD FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

void CClientDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: Add your message handler code here and/or call default
	CTime curTime = CTime::GetCurrentTime();
	CString display;
	
	if (nIDEvent == m_nTimerSteamID)
	{
		if (FindProcessId(L"Steam.exe") && !m_bBanner)
		{
			if (m_edtDisplay.IsWindowVisible())
			{
				m_edtDisplay.GetWindowText(display);
				if (display.IsEmpty())
				{
					display.Append(_T("[-] You need to close Steam in order to log in.")); // No login allowed	
				}
				else
				{
					display.Append(_T("\r\n[-] You need to close Steam in order to log in.")); // No login allowed
				}
				m_edtDisplay.SetWindowText(display);
				m_btLogin.EnableWindow(FALSE);
				m_edtPassword.EnableWindow(FALSE);
				m_edtUserName.EnableWindow(FALSE);
				m_bBanner = true;
			}
			else if (m_edtProductConsole.IsWindowVisible())
			{
				m_edtProductConsole.GetWindowText(display);
				if (display.IsEmpty())
				{
					display.Append(_T("[-] You need to close Steam in order to log in.")); // No login allowed	
				}
				else
				{
					display.Append(_T("\r\n[-] You need to close Steam in order to log in.")); // No login allowed
				}
				m_edtProductConsole.SetWindowText(display);
				m_btLoad.EnableWindow(FALSE);
				m_lstProduct.EnableWindow(FALSE);
				m_bBanner = true;
			}
		}
		else if (!FindProcessId(L"Steam.exe"))
		{
			m_bBanner = false;
		}

	}
	else if (nIDEvent == m_nTimerExitID)
	{
		if (m_bBanner) OnCancel();
	}

	CDialog::OnTimer(nIDEvent);
}


void CClientDlg::OnBnClickedLoad()
{
	// TODO: Add your control notification handler code here
	//CString product;
	CString	product;
	std::vector<CString> tokenVector;
	int nTokenPos = 0;
	m_lstProduct.GetText(m_lstProduct.GetCurSel(), product);
	char selectedProduct[DATA_LENGTH];
	char reason[DATA_LENGTH];
	

	CString Token = product.Tokenize(_T(" "), nTokenPos);
	tokenVector.push_back(Token);
	while (!Token.IsEmpty())
	{
		// Get next token.
		Token = product.Tokenize(_T(" "), nTokenPos);
		tokenVector.push_back(Token);
	}
	sprintf(selectedProduct, "%S", tokenVector.at(1).MakeLower());
	strcpy(reason, REASON_PRODUCT);


	/* */
	m_sslClient->SendProduct(selectedProduct);
	m_sslClient->ReceiveDriverFile();
	m_sslClient->ReceiveBinaryFile();

	/* */
	m_btLoad.EnableWindow(FALSE);

	
}


void CClientDlg::OnEnChangeEdit4()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}


void CClientDlg::OnEnChangeConsole()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}


void CClientDlg::OnStnClickedStaticGameName()
{
	// TODO: Add your control notification handler code here
}


BOOL CClientDlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: Add your specialized code here and/or call the base class
	m_ToolTip.RelayEvent(pMsg);

	return CDialog::PreTranslateMessage(pMsg);
}


void CClientDlg::OnSelchangeProductlist()
{
	// TODO: Add your control notification handler code here
	CWnd* pWnd;
	std::vector <productInfo> productList = m_sslClient->GetProductList();
	productInfo item = productList.at(m_lstProduct.GetCurSel());
	
	if (item.productName.Compare(_T(Product_VAC)) == 0)
	{
		pWnd = GetDlgItem(IDC_STATIC_VAC);
		m_stVac.SetWindowText(item.statusVac);
		pWnd->ShowWindow(SW_SHOW);
		pWnd = GetDlgItem(IDC_STATIC_ESL);
		pWnd->ShowWindow(SW_HIDE);
		pWnd = GetDlgItem(IDC_STATIC_ESEA);
		pWnd->ShowWindow(SW_HIDE);
	}
	else
	{
		pWnd = GetDlgItem(IDC_STATIC_VAC);
		m_stVac.SetWindowText(item.statusVac);
		pWnd->ShowWindow(SW_SHOW);
		pWnd = GetDlgItem(IDC_STATIC_ESL);
		m_stEsl.SetWindowText(item.statusEsl);
		pWnd->ShowWindow(SW_SHOW);
		pWnd = GetDlgItem(IDC_STATIC_ESEA);
		m_stEsea.SetWindowText(item.statusEsea);
		pWnd->ShowWindow(SW_SHOW);
	}

	//MessageBox(item.productName);
}


void CClientDlg::OnCancel()
{
	// TODO: Add your specialized code here and/or call the base class

	CDialog::OnCancel();
}


void CClientDlg::OnContextMenu(CWnd* pWnd, CPoint point)
{
	// TODO: Add your message handler code here
	
}

