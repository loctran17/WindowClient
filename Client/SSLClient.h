#ifndef SSLCLIENT_H
#define SSLCLIENT_H

#include <vector>

#define DEFAULT_BUFFER_LENGTH	512

#define VERSION			"0.0.1"
#define VERSION_LENGTH	20		
#define LOG_ATTEMPT		3

/* Message will send to client */
#define USER_NOT_REG	"[-] You have to be a subscriber to use our products"
#define WRONG_PASS		"[-] Wrong password, please try again"
#define EXP_DAY			"[-] Your subscription expired"
#define OLD_VERSION		"[-] Please download an updated version of this software"
#define USER_VERIFY		"[+] Login successful"
#define OUTOF_LOGIN		"[-] Too many failed login attempts, try again in 1 minute"


/* Reasons */
#define REASON_PASSWORD			"Password"
#define REASON_USERNAME			"Username"
#define REASON_HWID				"HWID"
#define REASON_VERSION			"Version"
#define REASON_ERROR			"Error"
#define REASON_NOTIFY			"Notification"
#define REASON_PRODUCT_LIST		"ProductList"
#define REASON_PRODUCT			"Product"
#define REASON_PRODUCTNAME		"Productname"
#define REASON_PRODUCTGAME		"Game"
#define REASON_PRODUCTBUILD		"Build"

/* Product status */
#define REASON_PRODUCTSTATVAC	"VAC"
#define REASON_PRODUCTSTATESL	"ESL"
#define REASON_PRODUCTSTATESEA	"ESEA"

#define Product_VAC "pseudontech vac"
#define Product_League "pseudontech league"



/* Maximum number of login */
#define MAX_LOGIN		3

/* Reason length  */
#define REASON_LENGTH	64

/* Data lenght */
#define DATA_LENGTH		128

struct productInfo
{
	CString productName;
	CString GameName;
	CString BuildVersion;
	CString statusVac;
	CString statusEsl;
	CString statusEsea;
};

class SSLClient
{
public:
	SSLClient()
	{

	}
	SSLClient(
			char* szServerName, 
			char* szPort, 
			char* szPassword, 
			CProgressCtrl *pProgress, 
			CEdit			*edtDisplay,
			CListBox		*ListProduct,
			CStatic			*expiredDay,
			CEdit			*edtConsoleProduct,
			CStatic			*GameName,
			CStatic			*BuildVersion,
			CStatic			*StatusVAC,
			CStatic			*StatusESL,
			CStatic			*StatusESES,
			bool			*banner);

	~SSLClient();

	bool Start();
	void Stop();
	bool Send(char* reason, char* szMsg);
	bool Recv(char* reason, char* pBuf);

	// Make login request to server. Return Response message from server
	std::string MakeLoginRequest(std::string m_strUsername, std::string m_strPassword, std::string version);

	// ReceiveBinaryFile
	bool ReceiveBinaryFile();

	// ReceiveDriverFile
	bool ReceiveDriverFile();

	// Get number loggin attempt
	int GetLogAttempt();

	void ResetLogAttempt();

	/* Product list */
	void SendProduct(char* product);

	std::vector <productInfo> GetProductList();

private:
	char    *m_szServerName;
	char	*m_szPort;
	char	*m_szCaPassword;
	std::string m_strPassword;
	std::string m_strUsername;
	int		m_iNumLogAttempt = 0;
	char	*version;

	/* Progress */
	CProgressCtrl	*m_Progress;

	/* Edit control for console textbox */
	CEdit			*m_EditCtrl;

	/* All component of product form */
	CListBox		*m_ListProduct;
	CStatic			*m_expireDay;
	CEdit			*m_edtConsoleProduct;
	CStatic			*m_GameName;
	CStatic			*m_BuildVersion;
	CStatic			*m_StatusVAC;
	CStatic			*m_StatusESL;
	CStatic			*m_StatusESES;
	bool			*m_banner;

		
	BIO		*m_BIO_con;
	SSL_CTX	*m_ctx;
	SSL		*m_ssl;

	/* Binary stream */
	char	*binary_buffer;
	unsigned long *binary_length;

	/* Driver stream */
	char	*driver_buffer;
	unsigned long *driver_length;

#if 0
	void ForkProcess(char *pBuffer);
#endif

private:
	std::vector<productInfo> productList;

};

#endif
