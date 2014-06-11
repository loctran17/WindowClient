#pragma once
#include "stdafx.h"
class CMenuEdit :
	public CEdit
{
public:
	CMenuEdit();
	~CMenuEdit();

protected:
	virtual BOOL OnCommand(WPARAM wParam, LPARAM lParam);
	afx_msg void OnContextMenu(CWnd* pWnd, CPoint point);

	DECLARE_MESSAGE_MAP()
};

