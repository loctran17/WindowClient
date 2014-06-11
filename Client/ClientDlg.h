
// ClientDlg.h : header file
//

#pragma once

#include "SSLClient.h"
#include "afxwin.h"
#include "afxcmn.h"
#include "MenuEdit.h"

// CClientDlg dialog
class CClientDlg : public CDialog
{
// Construction
public:
	CClientDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_CLIENT_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;
	CFont	m_fMyFont;
	CToolTipCtrl m_ToolTip;
	

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

	/* Set my font */
	void SetMyFont();
public:
	afx_msg void OnBnClickedClogin();

	// Username for login
	CString m_strUserName;

	// Password for login
	CString m_strPassword;

	//SSL client
	SSLClient *m_sslClient;

	virtual void OnFinalRelease();
	virtual void PostNcDestroy();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);

	afx_msg void OnSetfocusPassword();
	afx_msg void OnKillfocusUsername();
	afx_msg void OnSetfocusUsername();
	CMenuEdit m_edtDisplay;
	afx_msg void OnEnChangeUsername();
	CEdit m_edtUserName;
	bool	dragWindow;
	int		m_iPrevX;
	int		m_iPrevY;
	afx_msg void OnKillfocusPassword();
	afx_msg void OnChangePassword();
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	// FileTransfer
	CProgressCtrl m_prgFileTransfer;
	afx_msg void OnNMCustomdrawFileprogress(NMHDR *pNMHDR, LRESULT *pResult);
	CString m_strDisplay;
	CListBox m_lstProduct;
private:
	CButton m_btLogin;
protected:
	afx_msg void OnTimer(UINT_PTR nIDEvent);

public:
	CButton m_btLoad;
	CEdit m_edtPassword;
	afx_msg void OnBnClickedLoad();
	afx_msg void OnEnChangeEdit4();
	afx_msg void OnEnChangeConsole();
//	CListBox m_edtProductConsole;
	CListBox m_lstProductConsole;
private:
//	CString m_stVac;
	CStatic m_stBuildVersion;
	CStatic m_stEsea;
	CStatic m_stEsl;
	CStatic m_stExpireDate;
	CStatic m_stGameName;
	CStatic m_stVac;

	CString m_strVac;
	CString m_strEsl;
	CString m_strEsea;
	
public:
	afx_msg void OnStnClickedStaticGameName();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg void OnSelchangeProductlist();
private:
	CMenuEdit m_edtProductConsole;
	UINT_PTR m_nTimerSteamID;
	UINT_PTR m_nTimerExitID;
	int m_iTitleHeight;
	bool m_bBanner;
	virtual void OnCancel();
	int m_iWindowWidth, m_iWindowHeight;
public:
	afx_msg void OnContextMenu(CWnd* /*pWnd*/, CPoint /*point*/);
};
