/*
* SmartCardRemoval
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
*/

#include "stdafx.h"
#include "SmartCardRemoval_i.h"

using namespace ATL;

class CSmartCardRemovalModule;
typedef CAtlServiceModuleT<CSmartCardRemovalModule, IDS_SERVICENAME> ServiceModule;

class CSmartCardRemovalModule : public ServiceModule
{
	std::ofstream log;
	std::string readers;
	bool seenCards = false;

public:
	DECLARE_LIBID(LIBID_SmartCardRemovalLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_SMARTCARDREMOVAL, "{DEAE87CA-A84D-4F75-BC47-721D7F0F7848}")
	HRESULT InitializeSecurity() throw()
	{
		return S_OK;
	}

	CSmartCardRemovalModule()
	{
		std::wstring path(MAX_PATH, 0);
		DWORD size = GetTempPath(DWORD(path.size()), &path[0]);
		path.resize(size);
		path += L"smartcardremoval.run.log";
		log.open(path, std::ofstream::app);
		log << "module started" << std::endl;
	}

	bool ParseCommandLine(_In_z_ LPCTSTR lpCmdLine, _Out_ HRESULT *pnRetCode) throw()
	{
		if (!ServiceModule::ParseCommandLine(lpCmdLine, pnRetCode))
			return false;
		TCHAR szTokens[] = _T("-/");
		for (LPCTSTR lpszToken = FindOneOf(lpCmdLine, szTokens); lpszToken; lpszToken = FindOneOf(lpszToken, szTokens)) {
			if (WordCmpI(lpszToken, _T("RemoveCerts")) == 0) {
				log << "<<--launched with /RemoveCerts" << std::endl;
				removeCerts();
				return false;
			}
		}
		return true;
	}

	void RunMessageLoop()
	{
		log << "starting monitor .." << std::endl;
		bool isRunning = true;
		std::thread thread([&]{
			while (isRunning) {
				std::this_thread::sleep_for(std::chrono::milliseconds(5000));
				executeCheck();
			}
		});
		log << "running .. " << std::endl;
		ServiceModule::RunMessageLoop();
		isRunning = false;
		thread.join();
		log << "stopped." << std::endl;
	}

private:
	void removeCerts()
	{
		log << "enuming certs" << std::endl;
		HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
			CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG, L"MY");
		PCCERT_CONTEXT ctx = nullptr;
		CHAR nameBuf[MAX_PATH];
		while (ctx = CertEnumCertificatesInStore(hStore, ctx))
		{
			CertGetNameStringA(ctx, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, nullptr, nameBuf, sizeof(nameBuf));
			log << "checking if Esteid cert [" << nameBuf << "]" << std::endl;
			DWORD sz = 0;
			if (!CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &sz))
				continue;
			std::vector<BYTE> buf(sz, 0);
			if (!CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, buf.data(), &sz))
				continue;
			PCRYPT_KEY_PROV_INFO info = PCRYPT_KEY_PROV_INFO(buf.data());
			if (info->pwszProvName && (
				wcscmp(L"Microsoft Base Smart Card Crypto Provider", info->pwszProvName) == 0 ||
				wcscmp(L"Microsoft Smart Card Key Storage Provider", info->pwszProvName) == 0)) {
				log << "Found BaseCSP certificate. Removing" << std::endl;
				if (!CertDeleteCertificateFromStore(CertDuplicateCertificateContext(ctx)))
					log << "we got an error on CertDeleteCertificateFromStore, " << GetLastError() << std::endl;
			}
		}
		CertCloseStore(hStore, 0);
		log << "..done enum" << std::endl;
	}

	void executeCheck()
	{
		SCARDCONTEXT hContext = 0;
		if (SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &hContext) != SCARD_S_SUCCESS)
			return;
		DWORD size = 0;
		if (SCardListReadersA(hContext, nullptr, nullptr, &size) != SCARD_S_SUCCESS || !size) {
			SCardReleaseContext(hContext);
			return;
		}
		readers.resize(size);
		if (SCardListReadersA(hContext, nullptr, &readers[0], &size) != SCARD_S_SUCCESS) {
			SCardReleaseContext(hContext);
			return;
		}
		std::vector<SCARD_READERSTATEA> list;
		for (const char *name = readers.c_str(); *name != 0; name += strlen(name) + 1)
			list.push_back({ name, 0, 0, 0, 0, {} });
		DWORD status = SCardGetStatusChangeA(hContext, 0, list.data(), DWORD(list.size()));
		SCardReleaseContext(hContext);
		if (status != SCARD_S_SUCCESS)
			return;

		static const std::vector<std::vector<byte>> atrs{
			{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30, 0xA8 }, /*ESTEID_V3_COLD_DEV1_ATR*/
			{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x56, 0x1B, 0x16, 0x83, 0x01, 0x90, 0x00, 0x86 }, /*ESTEID_V3_WARM_DEV1_ATR*/
			{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x01, 0x90, 0x00, 0xE1 }, /*ESTEID_V3_WARM_DEV2_ATR*/
			{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x0F, 0x90, 0x00, 0xEF }, /*ESTEID_V3_WARM_DEV3_ATR/ESTEID_V35_WARM_ATR*/
			{ 0x3B, 0xFA, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0xFE, 0x65, 0x49, 0x44, 0x20, 0x2F, 0x20, 0x50, 0x4B, 0x49, 0x03 }, /*ESTEID_V35_COLD_ATR*/
		};

		int cardsFound = 0;
		for (const SCARD_READERSTATEA &state : list)
		{
			if (any_of(atrs.cbegin(), atrs.cend(), [&](const std::vector<byte> &atr){
				return atr.size() == state.cbAtr && equal(atr.cbegin(), atr.cend(), state.rgbAtr);
			}))
				cardsFound++;
		}
		if (cardsFound > 0)
		{
			log << "found esteid cards" << std::endl;
			seenCards = true;
			return;
		}

		log << "no esteid cards" << std::endl;
		if (!seenCards)
			return;

		seenCards = false;
		log << "launching cleanup" << std::endl;
		std::string szFilePath(MAX_PATH, 0);
		size = ::GetModuleFileNameA(NULL, &szFilePath[0], MAX_PATH);
		szFilePath.resize(size);
		startProcess("\"" + szFilePath + "\" /RemoveCerts");
	}

	bool startProcess(const std::string &command)
	{
		PWTS_SESSION_INFOW sessionInfo = 0;
		DWORD dwCount = 0;
		WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessionInfo, &dwCount);

		DWORD sessionId = 0;
		for (DWORD i = 0; i < dwCount; ++i)
		{
			WTS_SESSION_INFO si = sessionInfo[i];
			if (WTSActive == si.State)
			{
				sessionId = si.SessionId;
				break;
			}
		}
		WTSFreeMemory(sessionInfo);

		HANDLE currentToken = 0;
		BOOL bRet = WTSQueryUserToken(sessionId, &currentToken);
		log << "WTSQueryUserToken" << GetLastError() << std::endl;
		if (!bRet)
			return false;

		HANDLE primaryToken = 0;
		bRet = DuplicateTokenEx(currentToken, TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS, 0, SecurityImpersonation, TokenPrimary, &primaryToken);
		CloseHandle(currentToken);
		log << "DuplicateTokenEx" << GetLastError() << std::endl;
		if (!bRet)
			return false;

		if (!primaryToken)
		{
			log << "primaryToken = 0" << std::endl;
			return false;
		}

		log << "command:" << command.c_str() << std::endl;
		STARTUPINFOA StartupInfo = { sizeof(StartupInfo) };
		PROCESS_INFORMATION processInfo;
		BOOL result = CreateProcessAsUserA(primaryToken, 0, LPSTR(command.c_str()), nullptr, nullptr, FALSE,
			CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &StartupInfo, &processInfo);
		CloseHandle(primaryToken);

		log << "CreateProcessAsUserA " << result << GetLastError() << std::endl;
		if (result)
			log << "launched" << std::endl;
		else
			log << "didnt launch" << std::endl;
		return result == TRUE;
	}
};

CSmartCardRemovalModule _AtlModule;

//
extern "C" int WINAPI _tWinMain(HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/, 
                                LPTSTR /*lpCmdLine*/, int nShowCmd)
{
    return _AtlModule.WinMain(nShowCmd);
}
