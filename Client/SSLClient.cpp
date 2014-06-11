// #include <openssl/applink.c>
#include "stdafx.h"
#include "system.h"
#include "SSLClient.h"

using namespace std;


#define CADIR NULL


#define MUTEX_TYPE HANDLE
#define MUTEX_SETUP(x)   (x) = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_CLEANUP(x) CloseHandle(x)
#define MUTEX_LOCK(x)    WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x)  ReleaseMutex(x)
#define THREAD_ID        GetCurrentThreadId()


// This array will store all of the mutexes available to OpenSSL.
static MUTEX_TYPE *mutex_buf = NULL;
static char	strError[1024];

static void locking_function(int mode, int n, const char * file, int line)
{
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(mutex_buf[n]);
	else
		MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void)
{
	return ((unsigned long)THREAD_ID);
}

static int THREAD_setup(void)
{
	int i;

	mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_SETUP(mutex_buf[i]);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	return 1;
}

static int THREAD_cleanup(void)
{
	int i;

	if (!mutex_buf)
		return 0;
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_CLEANUP(mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}

static int verify_callback(int ok, X509_STORE_CTX *store)
{
	char data[256];
	CString message;

	if (!ok)
	{
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int  depth = X509_STORE_CTX_get_error_depth(store);
		int  err = X509_STORE_CTX_get_error(store);
		X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
		strcat(strError, "\r\n[-]  issuer  = ");
		strcat(strError, data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
		strcat(strError, "\r\n[-]  subject = ");
		strcat(strError, data);
		strcat(strError, "\r\n[-]  err : ");
		strcat(strError, X509_verify_cert_error_string(err));

	}

	return ok;
}

static long post_connection_check(SSL *ssl)
{
	X509      *cert;
	X509_NAME *subj;
	char      data[256];
	int       ok = 0;

	if (!(cert = SSL_get_peer_certificate(ssl)))
		goto err_occured;
	if (!ok && (subj = X509_get_subject_name(cert)) && X509_NAME_get_text_by_NID(subj, NID_commonName, data, 256) > 0)
	{
		X509_free(cert);
		return SSL_get_verify_result(ssl);
	}

err_occured:
	if (cert)
		X509_free(cert);
	return X509_V_ERR_APPLICATION_VERIFICATION;
}

static void init_OpenSSL(void)
{
	const SSL_METHOD *method;

	if (!THREAD_setup() || !SSL_library_init())
	{
		strcat(strError, "\r\n[-] OpenSSL initialization or thread setup failed");
		return;
	}
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = SSLv3_client_method();

	if (method == NULL)
	{
		strcat(strError, "\r\n[-] SSLClient::Start: SSLv3_client_method failed");
		return;
	}
}


static std::string sha256(const std::string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);
	std::stringstream ss;

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}
	return ss.str();
}

static char* pass;
static int password_cb(char *buf, int num, int rwflag, void *userdata);

// The password code is not thread safe
static int password_cb(char *buf, int num,
	int rwflag, void *userdata)
{
	if (num< (int)(strlen(pass)) + 1)
		return(0);

	strcpy(buf, pass);

	return(strlen(pass));
}

static SSL_CTX *setup_client_ctx(void* capassword)
{
	SSL_CTX *ctx;
	X509 *cert = NULL;
	RSA *rsa = NULL;
	BIO *cbio, *kbio;
	const char *cert_root = "-----BEGIN CERTIFICATE-----\n"
		"MIICSzCCAbQCCQDtLuwzc + UjfTANBgkqhkiG9w0BAQUFADBqMQ0wCwYDVQQDEwRy\n"
		"b290MQwwCgYDVQQIEwNCUkQxCzAJBgNVBAYTAkRFMSgwJgYJKoZIhvcNAQkBFhlz\n"
		"dGVmYW5qdWV0dGVuOTRAZ21haWwuY29tMRQwEgYDVQQKEwtQc2V1ZG9udGVjaDAe\n"
		"Fw0xNDAzMjMwNzMwMjlaFw0xNTAzMjMwNzMwMjlaMGoxDTALBgNVBAMTBHJvb3Qx\n"
		"DDAKBgNVBAgTA0JSRDELMAkGA1UEBhMCREUxKDAmBgkqhkiG9w0BCQEWGXN0ZWZh\n"
		"bmp1ZXR0ZW45NEBnbWFpbC5jb20xFDASBgNVBAoTC1BzZXVkb250ZWNoMIGfMA0G\n"
		"CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDH5swnQwYnWVwo + k3mRv0FvrAqdv + SpBs4\n"
		"birBAybi7V9zL6 / yFmsgwEGs4ZUX9C / LKrKUC8zqDmBmZCC2wdducnmhatpsyFkS\n"
		"sI5P8X1FROi7GvcrB2ctUbXGwEQpQW5OkFQ0mh4FE9ea3vauBIlMhZsL8rNCiSX5\n"
		"FD6yLzIXKQIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAC1y8Ac8NwGe63BgXT5FKEbw\n"
		"yvMbMdM5yP6k5HN5efNdq1WPXpLIsnOl0heQC56Kb7GerEyjtEpW / K88NvrgKjiM\n"
		"ceLU7HhWkNLtSMkmqzc / Qu152d8EhLAc2GmdZl8DEK / XeiuCIrYDFti5pmVMDZ1O\n"
		"XNyk0xcB//5omMPLwk4g\n"
		"-----END CERTIFICATE-----\n";

	const char *cert_buffer = "-----BEGIN CERTIFICATE-----\r\n"
		"MIICTTCCAbYCCQCG5YkMe2YO7zANBgkqhkiG9w0BAQUFADBqMQ0wCwYDVQQDEwRy\r\n"
		"b290MQwwCgYDVQQIEwNCUkQxCzAJBgNVBAYTAkRFMSgwJgYJKoZIhvcNAQkBFhlz\r\n"
		"dGVmYW5qdWV0dGVuOTRAZ21haWwuY29tMRQwEgYDVQQKEwtQc2V1ZG9udGVjaDAe\r\n"
		"Fw0xNDAzMjMwNzM1MTBaFw0xNTAzMjMwNzM1MTBaMGwxDzANBgNVBAMTBmNsaWVu\r\n"
		"dDEMMAoGA1UECBMDQlJEMQswCQYDVQQGEwJERTEoMCYGCSqGSIb3DQEJARYZc3Rl\r\n"
		"ZmFuanVldHRlbjk0QGdtYWlsLmNvbTEUMBIGA1UEChMLUHNldWRvbnRlY2gwgZ8w\r\n"
		"DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJolXz4263Wsed / 58SwrznKHA60qKWRu\r\n"
		"NyD7syHVqeerqr0U1kwBQBLYLvMFQaWw4GlTsTgJFndzbrcYVZxp9ya934wPBupr\r\n"
		"p / vZKthR6WKwk / 8SkRFg7D / uscosIBWLdnxyVnNmypNzQkTBsgyJ / jhhXOtTwWG4\r\n"
		"HKABt1hcrQMJAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEANzri3vBbtvBHQMaptxNk\r\n"
		"ZTe / xl1CPMB + eEt7SiESrJvSQePPbwA7zbZZYh6XeRusOAJwHlUI1AWz8ePZnHXm\r\n"
		"ZRMYndh2f2t + 7M6MPOoyLaktswWX2LBK3HnCNN7wLVc + uY2i7PRv38APIH60AcJZ\r\n"
		"AZAzd9fqwNMGsRFxcmZI5zM =\r\n"
		"-----END CERTIFICATE-----\r\n";

	const char *key_buffer = "-----BEGIN RSA PRIVATE KEY-----\r\n"
		"MIICXQIBAAKBgQCaJV8 + Nut1rHnf + fEsK85yhwOtKilkbjcg + 7Mh1annq6q9FNZM\r\n"
		"AUAS2C7zBUGlsOBpU7E4CRZ3c263GFWcafcmvd + MDwbqa6f72SrYUelisJP / EpER\r\n"
		"YOw / 7rHKLCAVi3Z8clZzZsqTc0JEwbIMif44YVzrU8FhuBygAbdYXK0DCQIDAQAB\r\n"
		"AoGAR1IxXkTk7x5tiY9I4mombGFB9zZBzqEcStuKx4XnxjRsnG3utV4CunViS7lL\r\n"
		"5ZEQVEuP / OBfj8dOG9NbkTKKUp + 6 + vHrqa3IzG5PwABzjDkhPyyvHUq / JQEooedP\r\n"
		"AqboY + D86jeQItfcHqHrLo + C + OvEuqhwvwFeOjL9wv / H / AECQQDLBAFVv8DeMXuG\r\n"
		"IdxjFSgYTIbS4cLbPZ3OriO0vmoLFNTb1pkz4Tv7tZCWcvK5qsDxOrLzNKArdFs2\r\n"
		"IruA6dSJAkEAwmBCfbhLWjJGr9mGytwOyi2vF2dK / pL8hiu52cU5NV68QHSyufh5\r\n"
		"vCC6s / tUUGKGMpUz3hGNQ7RJNXLxwmsagQJBAJ6EThaKVyonMPAW2GJ1To1Kk6tt\r\n"
		"pBxUDDgpOLAUTfDBH0NYWN9tasyrhG406tmWPnkdAEVuPfIwNFgc3pNWASECQHDe\r\n"
		"xL2MTvVJTJLAle0ma9ArRwkoCfxaDhk7OuiiBd5f7KDhIweqqcX8m233 + 7XSAGtP\r\n"
		"CJdjScyO3BQVcx2aZAECQQCW2kk5nb / Gnf71Mk / wY8bPrDRAGofAU4wPNeJsXbnJ\r\n"
		"KPYwEdGzeAzG6GdalDAOk / nZULeEC7uZ + / Qh / 3A + 9czi\r\n"
		"-----END RSA PRIVATE KEY-----\r\n";
	FILE* fpp;

	BOOL fSuccess = FALSE;
	DWORD dwRetVal = 0;
	UINT uRetVal = 0;

	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	TCHAR szTempFileName[MAX_PATH];
	TCHAR lpTempPathBuffer[MAX_PATH];

	//  Gets the temp path env string (no guarantee it's a valid path).
	dwRetVal = GetTempPath(MAX_PATH,          // length of the buffer
		lpTempPathBuffer); // buffer for path 
	if (dwRetVal > MAX_PATH || (dwRetVal == 0))
	{

		strcat(strError, "\r\n[-] GetTempPath failed");
		return NULL;
	}

	//  Generates a temporary file name. 
	uRetVal = GetTempFileName(lpTempPathBuffer, // directory for tmp files
		TEXT("DEMO"),     // temp file name prefix 
		0,                // create unique name 
		szTempFileName);  // buffer for name 
	if (uRetVal == 0)
	{
		strcat(strError, "\r\n[-] GetTempFileName failed");
		return NULL;
	}
	
	/* Conver Tchar to char */
	char    *pMBBuffer = (char *)malloc(MAX_PATH);
	size_t  count;

	count = wcstombs(pMBBuffer, szTempFileName, MAX_PATH); // C4996

	if (!(fpp = fopen(pMBBuffer, "w")))
		return NULL;

	fwrite(cert_root, strlen(cert_root), 1, fpp);
	fclose(fpp);

	cbio = BIO_new(BIO_s_mem());
	BIO_puts(cbio, cert_buffer);
	cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
	BIO_free(cbio);

	if (cert == NULL)
		return NULL;

	kbio = BIO_new_mem_buf((void*)key_buffer, -1);
	rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
	if (rsa == NULL)
		return NULL;

	ctx = SSL_CTX_new(SSLv23_method());

	if (SSL_CTX_load_verify_locations(ctx, pMBBuffer, CADIR) != 1)
	{
		char buffer[120];
		ERR_error_string(ERR_get_error(), buffer);
		SSL_CTX_free(ctx);
		strcat(strError, "\r\n[-] SSL_CTX_load_verify_locations fail");
		return NULL;
	}

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		strcat(strError, "\r\n[-] SSL_CTX_set_default_verify_paths fail");
		SSL_CTX_free(ctx);
		return NULL;
	}

	SSL_CTX_use_certificate(ctx, cert);
	pass = (char*)capassword;
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	SSL_CTX_use_RSAPrivateKey(ctx, rsa);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	SSL_CTX_set_verify_depth(ctx, 4);

	return ctx;
}

SSLClient::SSLClient(
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
	bool			*banner)
{
	m_szServerName = szServerName;
	m_szPort = szPort;
	m_szCaPassword = szPassword;
	m_Progress = pProgress;
	m_EditCtrl = edtDisplay;
	m_ListProduct = ListProduct;
	m_expireDay = expiredDay;
	m_edtConsoleProduct = edtConsoleProduct;
	m_GameName = GameName;
	m_BuildVersion = BuildVersion;
	m_StatusVAC = StatusVAC;
	m_StatusESL = StatusESL;
	m_StatusESES = StatusESES;
	m_banner = banner;

	binary_length = NULL;
	binary_buffer = NULL;
	driver_length = NULL;
	driver_buffer = NULL;

}

SSLClient::~SSLClient()
{

}

string StringToLower(string strToConvert)
{//change each element of the string to lower case
	for (unsigned int i = 0; i<strToConvert.length(); i++)
	{
		strToConvert[i] = tolower(strToConvert[i]);
	}
	return strToConvert;//return the converted string
}

char* StrToLower(char* strToConvert)
{//change each element of the string to lower case
	for (unsigned int i = 0; i<strlen(strToConvert); i++)
	{
		strToConvert[i] = tolower(strToConvert[i]);
	}
	return strToConvert;//return the converted string
}

int split_line(const std::string &line, std::vector<std::string> &parts)
{
	const string delimiters = ",\"";
	const string space = " ";
	unsigned count = 0;
	parts.clear();

	// skip delimiters at beginning.
	string::size_type lastPos = line.find_first_not_of(delimiters, 0);

	// find first "non-delimiter".
	string::size_type pos = line.find_first_of(delimiters, lastPos);

	while (string::npos != pos || string::npos != lastPos)
	{
		// found a token, add it to the vector.
		std::string item = StringToLower(line.substr(lastPos, pos - lastPos));
		if (item.compare(space) != 0)
		{
			parts.push_back(item);
			count++;
		}

		// skip delimiters.  Note the "not_of"
		lastPos = line.find_first_not_of(delimiters, pos);

		// find next "non-delimiter"
		pos = line.find_first_of(delimiters, lastPos);
	}

	return count;
}
std::string SSLClient::MakeLoginRequest(std::string username, std::string password, std::string version)
{
	//std::string strHWID = GetHWID() + username + "\n";
	std::string strHWID = "HWID";
	std::string hashedString = username + sha256(password) + sha256(strHWID) + version;
	char msgRcv[DATA_LENGTH + 1];
	char reasonRcv[REASON_LENGTH + 1];
	char msgSend[DATA_LENGTH];
	char reasonSend[REASON_LENGTH];
	char msgProductName[DATA_LENGTH + 1];


	if (m_strUsername.compare(username) != 0)
	{
		m_iNumLogAttempt = 0;
		m_strUsername = username;
	}

	/* Username */
	strcpy(msgSend, username.c_str());
	strcpy(reasonSend, REASON_USERNAME);
	Send(reasonSend, msgSend);

	/* Passord */
	strcpy(msgSend, sha256(password).c_str());
	strcpy(reasonSend, REASON_PASSWORD);
	Send(reasonSend, msgSend);

	/* HWID */
	strcpy(msgSend, sha256(strHWID).c_str());
	strcpy(reasonSend, REASON_HWID);
	Send(reasonSend, msgSend);

	/* Version */
	strcpy(msgSend, version.c_str());
	strcpy(reasonSend, REASON_VERSION);
	Send(reasonSend, msgSend);

	// SSL_write(ssl, (char*)hashedString.c_str(), hashedString.length());
	memset(msgRcv, 0, sizeof(msgRcv));
	memset(reasonRcv, 0, sizeof(reasonRcv));
	Recv(reasonRcv, msgRcv);

#if 0
	if ((strcmp(recv_string, USER_VERIFIED) != 0) &&
		(m_strUsername.compare(username) == 0))
	{
		m_iNumLogAttempt++;
	}
#endif
	std::string response_String(msgRcv);

	/* If Loginn successfully */
	productList.clear();
	if (strcmp(msgRcv, USER_VERIFY) == 0)
	{
		/* expireDay */
		Recv(reasonRcv, msgRcv);
		CString expiredDay(msgRcv);
		m_expireDay->SetWindowText(expiredDay);

		m_edtConsoleProduct->SetWindowText(_T(USER_VERIFY));
		Recv(reasonRcv, msgRcv);
		std::string productLst(msgRcv);
		std::vector <std::string> proVector;
		int count;
		int j;

		if (strcmp(reasonRcv, REASON_PRODUCT_LIST) == 0)
		{
			count = split_line(productLst, proVector);

			for (j = 0; j < count; j++)
			{
				memset(msgProductName, 0, sizeof(msgProductName));
				memset(reasonRcv, 0, sizeof(reasonRcv));

				/* product list */
				Recv(reasonRcv, msgProductName);
				CString  productName_tmp(msgProductName);

				productInfo item;

				if ((strcmp(reasonRcv, REASON_PRODUCTNAME) == 0) &&
					(strcmp(proVector.at(j).c_str(), StrToLower(msgProductName)) == 0))
				{
					
					int positon = 0;

					item.productName = productName_tmp;

					/* Game */
					Recv(reasonRcv, msgRcv);
					if (strcmp(reasonRcv, REASON_PRODUCTGAME) == 0)
					{
						/* msg is game */
						CString game(msgRcv);

						item.GameName = game;
						m_GameName->SetWindowText(game);
					}
					else
					{
						/* TODO: Will out to console */
						m_EditCtrl->SetWindowText(_T("[-] Expected game"));
					}
					m_ListProduct->AddString(productName_tmp);
					m_ListProduct->SetSel(positon++, true);

					/* Build */
					Recv(reasonRcv, msgRcv);
					if (strcmp(reasonRcv, REASON_PRODUCTBUILD) == 0)
					{
						/* msg is build */
						CString buildVersion(msgRcv);
						item.BuildVersion = buildVersion;
						m_BuildVersion->SetWindowText(buildVersion);

					}
					else
					{
						/* TODO: Will out to console */
						m_EditCtrl->SetWindowText(_T("[-] Expected build version"));
					}

					/* Status */
					if (strcmp(msgProductName, Product_VAC) == 0)
					{
						/* VAC status */
						Recv(reasonRcv, msgRcv);
						if (strcmp(reasonRcv, REASON_PRODUCTSTATVAC) == 0)
						{
							/* msg is build */
							CString vac(msgRcv);
							item.statusVac = vac;
							m_StatusVAC->SetWindowText(vac);

						}
						else
						{
							/* TODO: Will out to console */
							m_EditCtrl->SetWindowText(_T("[-] Expected VAC status"));
						}
					}
					else if (strcmp(msgProductName, Product_League) == 0)
					{
						/* VAC status */
						Recv(reasonRcv, msgRcv);
						if (strcmp(reasonRcv, REASON_PRODUCTSTATVAC) == 0)
						{
							/* msg is build */
							CString vac(msgRcv);
							item.statusVac = vac;
							m_StatusVAC->SetWindowText(vac);

						}
						else
						{
							/* TODO: Will out to console */
							m_EditCtrl->SetWindowText(_T("[-] Expected VAC status"));
						}

						/* ESL status */
						Recv(reasonRcv, msgRcv);
						if (strcmp(reasonRcv, REASON_PRODUCTSTATESL) == 0)
						{
							/* msg is build */
							CString esl(msgRcv);
							item.statusEsl = esl;
							m_StatusESL->SetWindowText(esl);

						}
						else
						{
							/* TODO: Will out to console */
							m_EditCtrl->SetWindowText(_T("[-] Expected ESL status"));
						}

						/* ESEA status */
						Recv(reasonRcv, msgRcv);
						if (strcmp(reasonRcv, REASON_PRODUCTSTATESEA) == 0)
						{
							/* msg is build */
							CString esea(msgRcv);
							item.statusEsea = esea;
							m_StatusESES->SetWindowText(esea);

						}
						else
						{
							/* TODO: Will out to console */
							m_EditCtrl->SetWindowText(_T("[-] Expected ESEA status"));
						}
					}

				}
				productList.push_back(item);
			}
		}


		else
		{
			/* TODO: Will out to console */
			m_EditCtrl->SetWindowText(_T("[-] Expected product name"));
		}

	}
	return response_String;
}

bool SSLClient::Start()
{
	long err;

	memset(strError, 0, sizeof(strError));

	init_OpenSSL();
	if (strlen(strError) != 0)
	{
		CString Error(strError);
		m_EditCtrl->SetWindowText(Error);
		return false;
	}

	m_Progress->SetPos(0);
	m_ctx = setup_client_ctx(m_szCaPassword);
	if (!m_ctx)
		return false;

	std::string host = std::string(m_szServerName);
	host.append(":");
	host.append(m_szPort);
	m_BIO_con = BIO_new_connect((char*)host.c_str());
	if (!m_BIO_con)
	{
		m_EditCtrl->SetWindowText(_T("[-] SSLClient::Start BIO_new_connect fail"));
		return false;
	}

	if (BIO_do_connect(m_BIO_con) <= 0)
	{
		m_EditCtrl->SetWindowText(_T("[-] SSLClient::Start BIO_do_connect fail"));
		return false;
	}

	m_ssl = SSL_new(m_ctx);
	SSL_set_bio(m_ssl, m_BIO_con, m_BIO_con);
	if (SSL_connect(m_ssl) <= 0)
	{
		m_EditCtrl->SetWindowText(_T("[-] SSLClient::Start SSL_connect fail"));
		return false;
	}

	if ((err = post_connection_check(m_ssl)) != X509_V_OK)
	{
		m_EditCtrl->SetWindowText(_T("[-] SSLClient::Start Server authenticated fail"));
		return false;
	}

	return true;
};

void SSLClient::Stop()
{
	SSL_CTX_free(m_ctx);
};

bool SSLClient::Send(char* reason, char* szMsg)
{
	if (SSL_write(m_ssl, reason, REASON_LENGTH) == 0)
	{
		m_EditCtrl->SetWindowText(_T("[-] SSLClient::Send: SSL_write failed"));
		Stop();
	}
	if (SSL_write(m_ssl, szMsg, DATA_LENGTH) == 0)
	{
		m_EditCtrl->SetWindowText(_T("[-] SSLClient::Send: SSL_write failed"));
		Stop();
		return false;
	}

#if 0
	std::cout << "[+] SSLClient::Send: " << reason << std::endl;
	std::cout << "[+] SSLClient::Send: " << szMsg << std::endl;
#endif

	return true;
};

bool SSLClient::Recv(char* reason, char* pBuf)
{
	int bytes;
	bytes = SSL_read(m_ssl, reason, REASON_LENGTH);
	reason[bytes] = 0;

	if (bytes != REASON_LENGTH)
	{
		m_EditCtrl->SetWindowText(_T("[-] SSLClient::Recv: SSL_read failed"));
		Stop();
		return false;
	}
	bytes = SSL_read(m_ssl, pBuf, DATA_LENGTH);
	pBuf[bytes] = 0;

	if (bytes != DATA_LENGTH)
	{
		m_EditCtrl->SetWindowText(_T("[-] SSLClient::Recv: SSL_read failed"));
		Stop();
		return false;
	}

#if 0
	std::cout << "[+] Receiving packet: " << reason << std::endl;
	std::cout << "[+] Receiving packet: " << pBuf << std::endl;
#endif

	return true;
}

bool SSLClient::ReceiveBinaryFile()
{
	if (!binary_length)
	{
		binary_length = new unsigned long[1];
	}
	const int packet_size = 16384;
	CString		consoleProduct;

	SSL_read(m_ssl, (char*)(binary_length), sizeof(unsigned long));

	int packet_count = *binary_length / packet_size;
	int last_packet_size = *binary_length % packet_size;
	if (!binary_buffer)
	{
		binary_buffer = new char[*binary_length];
	}
	else if (*binary_length != sizeof(binary_buffer))
	{
		binary_buffer = new char[*binary_length];
	}

	//m_Progress->SetPos(10);
	m_Progress->SetPos(0);
	if (*binary_length > 0)
	{
		for (int i = 0; i <= packet_count; i++)
		{
			if (packet_count == 0)
			{
				m_Progress->SetPos(100);
			}
			else
			{
				m_Progress->SetPos(i * 100 / packet_count);
			}
			if (i < packet_count)
			{
				char buff[packet_size + 1];
				if (SSL_read(m_ssl, buff, packet_size))
				{
					memcpy(&binary_buffer[i*packet_size], buff, packet_size);
					continue;
				}
			}

			if (i == packet_count)
			{
				char *buff = new char[last_packet_size + 1];
				if (SSL_read(m_ssl, buff, last_packet_size))
				{
					memcpy(&binary_buffer[packet_count*packet_size], buff, last_packet_size);
					continue;
				}
			}
		}
		m_edtConsoleProduct->GetWindowText(consoleProduct);
		consoleProduct.Append(_T("\r\n[+] Streaming successful"));
		consoleProduct.Append(_T("\r\n[+] You may close the client now."));
		m_edtConsoleProduct->SetWindowText(consoleProduct);

		ForkProcess(binary_buffer);
	}

	return true;
}

bool SSLClient::ReceiveDriverFile()
{
	if (!driver_length)
	{
		driver_length = new unsigned long[1];
	}
	const int packet_size = 16384;
	CString		consoleProduct;

	m_edtConsoleProduct->GetWindowText(consoleProduct);
	consoleProduct.Append(_T("\r\n[+] Submitting request"));
	consoleProduct.Append(_T("\r\n[+] Streaming driver ..."));
	m_edtConsoleProduct->SetWindowText(consoleProduct);
	SSL_read(m_ssl, (char*)(driver_length), sizeof(unsigned long));

	int packet_count = *driver_length / packet_size;
	int last_packet_size = *driver_length % packet_size;
	if (!driver_buffer)
	{
		driver_buffer = new char[*driver_length];
	}
	else if (*driver_length != sizeof(driver_buffer))
	{
		driver_buffer = new char[*driver_length];
	}

	//m_Progress->SetPos(10);
	m_Progress->SetPos(0);
	if (*driver_length > 0)
	{
		for (int i = 0; i <= packet_count; i++)
		{
			if (packet_count == 0)
			{
				m_Progress->SetPos(100);
			}
			else
			{
				m_Progress->SetPos(i * 100 / packet_count);
			}
			if (i < packet_count)
			{
				char buff[packet_size + 1];
				if (SSL_read(m_ssl, buff, packet_size))
				{
					memcpy(&driver_buffer[i*packet_size], buff, packet_size);
					continue;
				}
			}

			if (i == packet_count)
			{
				char *buff = new char[last_packet_size + 1];
				if (SSL_read(m_ssl, buff, last_packet_size))
				{
					memcpy(&driver_buffer[packet_count*packet_size], buff, last_packet_size);
					continue;
				}
			}
		}
		m_edtConsoleProduct->GetWindowText(consoleProduct);
		consoleProduct.Append(_T("\r\n[+] Streaming cheat ... "));
		m_edtConsoleProduct->SetWindowText(consoleProduct);
		m_edtConsoleProduct->Invalidate(TRUE);
	}

	return true;
}
int SSLClient::GetLogAttempt()
{
	return m_iNumLogAttempt;
}

void SSLClient::ResetLogAttempt()
{
	m_iNumLogAttempt = 0;
}

void SSLClient::SendProduct(char* product)
{
	/* */
	char reason[REASON_LENGTH];
	char message[DATA_LENGTH];
	strcpy(reason, REASON_PRODUCT);
	strcpy(message, product);
	Send(reason, message);
}

std::vector <productInfo> SSLClient::GetProductList()
{
	return productList;
}

#if 0
void SSLClient::ForkProcess(char *pBuffer)
{
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
	CString consoleProduct;

	CreateProcessA(0, "svchost", 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);

	if (!pProcessInfo->hProcess)
	{
		m_edtConsoleProduct->GetWindowText(consoleProduct);
		consoleProduct.Append(_T("\r\n[-] Error creating process"));
		m_edtConsoleProduct->SetWindowText(consoleProduct);
		return;
	}

	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);

	PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);

	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

	HMODULE hNTDLL = GetModuleHandleA("ntdll");

	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");

	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

	DWORD dwResult = NtUnmapViewOfSection(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

	if (dwResult)
	{
		m_edtConsoleProduct->GetWindowText(consoleProduct);
		consoleProduct.Append(_T("\r\n[-] Error unmapping section"));
		m_edtConsoleProduct->SetWindowText(consoleProduct);
		return;
	}

	PVOID pRemoteImage = VirtualAllocEx(pProcessInfo->hProcess, pPEB->ImageBaseAddress, pSourceHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pRemoteImage)
	{
		m_edtConsoleProduct->GetWindowText(consoleProduct);
		consoleProduct.Append(_T("\r\n[-] VirtualAllocEx call failed"));
		m_edtConsoleProduct->SetWindowText(consoleProduct);
		return;
	}

	DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress - pSourceHeaders->OptionalHeader.ImageBase;

	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;

	if (!WriteProcessMemory(pProcessInfo->hProcess, pPEB->ImageBaseAddress, pBuffer, pSourceHeaders->OptionalHeader.SizeOfHeaders, 0))
	{
		m_edtConsoleProduct->GetWindowText(consoleProduct);
		consoleProduct.Append(_T("\r\n[-] Error writing process memory #1"));
		m_edtConsoleProduct->SetWindowText(consoleProduct);
		return;
	}

	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination = (PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);

		if (!WriteProcessMemory(pProcessInfo->hProcess, pSectionDestination, &pBuffer[pSourceImage->Sections[x].PointerToRawData], pSourceImage->Sections[x].SizeOfRawData, 0))
		{
			m_edtConsoleProduct->GetWindowText(consoleProduct);
			consoleProduct.Append(_T("\r\n[-] Error writing process memory #2"));
			m_edtConsoleProduct->SetWindowText(consoleProduct);
			return;
		}
	}

	if (dwDelta)
	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		char* pSectionName = ".reloc";

		if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
			continue;

		DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
		DWORD dwOffset = 0;

		IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		while (dwOffset < relocData.Size)
		{
			PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

			dwOffset += sizeof(BASE_RELOCATION_BLOCK);

			DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

			PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

			for (DWORD y = 0; y < dwEntryCount; y++)
			{
				dwOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (pBlocks[y].Type == 0)
					continue;

				DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;

				DWORD dwBuffer = 0;
				ReadProcessMemory(pProcessInfo->hProcess, (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress), &dwBuffer, sizeof(DWORD), 0);
				dwBuffer += dwDelta;

				BOOL bSuccess = WriteProcessMemory(pProcessInfo->hProcess, (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress), &dwBuffer, sizeof(DWORD), 0);

				if (!bSuccess)
				{
					m_edtConsoleProduct->GetWindowText(consoleProduct);
					consoleProduct.Append(_T("\r\n[-] Error writing memory"));
					m_edtConsoleProduct->SetWindowText(consoleProduct);
					continue;
				}
			}
		}

		break;
	}


	DWORD dwBreakpoint = 0xCC;

	DWORD dwEntrypoint = (DWORD)pPEB->ImageBaseAddress + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(pProcessInfo->hThread, pContext))
	{
		m_edtConsoleProduct->GetWindowText(consoleProduct);
		consoleProduct.Append(_T("\r\n[-] Error getting context"));
		m_edtConsoleProduct->SetWindowText(consoleProduct);
		return;
	}

	pContext->Eax = dwEntrypoint;
	if (!SetThreadContext(pProcessInfo->hThread, pContext))
	{
		m_edtConsoleProduct->GetWindowText(consoleProduct);
		consoleProduct.Append(_T("\r\n[-] Error setting context"));
		m_edtConsoleProduct->SetWindowText(consoleProduct);
		return;
	}

	if (!ResumeThread(pProcessInfo->hThread))
	{
		m_edtConsoleProduct->GetWindowText(consoleProduct);
		consoleProduct.Append(_T("\r\n[-] Error resuming thread"));
		m_edtConsoleProduct->SetWindowText(consoleProduct);
		return;
	}
}
#endif