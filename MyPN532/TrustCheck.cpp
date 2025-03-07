﻿/*
TrustCheck.cpp - 用于检查程序的数字签名是否有效
Licensed under the MIT License (MIT)
* Notice: Some code is generated by AI.

The MIT License (MIT)
Copyright © 2025 shc0743<github.com/shc0743>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights 
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do 
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Fork this project to create your own MIT license that you can always link to.
*/
#include "TrustCheck.hpp"
using namespace std;

// 链接到 Wintrust.lib 库
#pragma comment(lib, "wintrust.lib")

// 提取可执行文件的
static std::wstring GetProgramFullName() {
	WCHAR exeFullPath[MAX_PATH];
	GetModuleFileNameW(NULL, exeFullPath, MAX_PATH);

	return std::wstring(exeFullPath);
}
// 提取可执行文件的文件名（xxx.exe 部分）
static std::wstring GetProgramExecutableName() {
	WCHAR exeFullPath[MAX_PATH];
	GetModuleFileNameW(NULL, exeFullPath, MAX_PATH);

	// 使用 PathFindFileName 提取文件名
	WCHAR* exeName = PathFindFileNameW(exeFullPath);
	return std::wstring(exeName);
}
static wstring ErrorCodeToStringW(DWORD ErrorCode)
{
	typedef LPWSTR str_t;
	str_t LocalAddress = NULL;
	if (NULL == ([&] {
		__try {
			if (!FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_IGNORE_INSERTS |
				FORMAT_MESSAGE_FROM_SYSTEM, NULL,
				ErrorCode, 0, (str_t)&LocalAddress, 0, NULL)) {
				return (str_t)NULL;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { return (str_t)NULL; }
		return LocalAddress;
		})()) {
		SetLastError(ErrorCode);
		return L"";
	}
	LocalAddress[wcslen((str_t)LocalAddress) - 1] = 0;
	wstring szText = LocalAddress;
	LocalFree((HLOCAL)LocalAddress);
	SetLastError(ErrorCode);
	return szText;
}

static LONG VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
	LONG lStatus;

	// 初始化 WINTRUST_FILE_INFO 结构
	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	// 初始化 WINTRUST_DATA 结构
	WINTRUST_DATA WinTrustData;
	memset(&WinTrustData, 0, sizeof(WinTrustData));
	WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
	WinTrustData.pPolicyCallbackData = NULL;
	WinTrustData.pSIPClientData = NULL;
	WinTrustData.dwUIChoice = WTD_UI_NONE;
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WinTrustData.hWVTStateData = NULL;
	WinTrustData.pwszURLReference = NULL;
	WinTrustData.dwProvFlags = WTD_SAFER_FLAG;
	WinTrustData.dwUIContext = 0;
	WinTrustData.pFile = &FileData;

	// 使用 WINTRUST_ACTION_GENERIC_VERIFY_V2 策略验证文件签名
	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_CHAIN_VERIFY;

	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	// 清理
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	return (lStatus == 0) ? 0 : lStatus;
}


bool TrustCheck(bool Security__VALIDATE_certificate_chain_ROOT_MUST_BE_TRUSTED) {
	wstring app = GetProgramFullName();
	auto verify_result = VerifyEmbeddedSignature(app.c_str());
	errno = verify_result;
	switch (verify_result)
	{
	case 0:
		return true;

	case CERT_E_UNTRUSTEDROOT:
		return Security__VALIDATE_certificate_chain_ROOT_MUST_BE_TRUSTED ? false : true;
		
	default:
		return false;
	}
}
static std::map<std::wstring, std::vector<std::wstring>> i18n;
int SafeCheck(bool Security__VALIDATE_certificate_chain_ROOT_MUST_BE_TRUSTED) {
	if (!i18n.size()) {
		// init i18n
		i18n.emplace(L"zh", std::vector<std::wstring>{
			L"错误来自%s",
			L"数字签名无效。文件已遭到篡改。请重新下载最新版本。\n错误代码: %d: %s",
		});
		i18n.emplace(L"en", std::vector<std::wstring>{
			L"Error from %s",
			L"Digital signature is invalid. The file has been damaged. Please download the latest version again.\nError code: %d: %s",
		});
	}
	// 获取当前语言
	WCHAR lang[8]{ L"##" };
	static auto langID = PRIMARYLANGID(GetUserDefaultUILanguage());
	if (langID == LANG_CHINESE) {
		wcscpy_s(lang, L"zh");
	}
	else if (langID == LANG_ENGLISH) {
		wcscpy_s(lang, L"en");
	}
	// 如果程序的语言列表中没有用户所使用的语言，则使用英语
	if (i18n.count(lang) == 0) {
		wcscpy_s(lang, L"en");
	}

	if (!TrustCheck(Security__VALIDATE_certificate_chain_ROOT_MUST_BE_TRUSTED)) {
		// 弹出错误提示框
		WCHAR
			szTitle[MAX_PATH + 4]{},
			szText[1024]{};
		wsprintfW(szTitle, i18n[lang][0].c_str(), GetProgramExecutableName().c_str());
		wsprintfW(szText, i18n[lang][1].c_str(), errno, ErrorCodeToStringW(errno).c_str());
		DWORD response = 0;
		WTSSendMessageW(WTS_CURRENT_SERVER, WTS_CURRENT_SESSION, szTitle, MAX_PATH + 4, szText, 1024, MB_ICONERROR, 0, &response, TRUE);
		return ERROR_FILE_CORRUPT;
	}
	return 0;
}


