// 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <drogon/drogon.h>
#include <Windows.h>
#include <VersionHelpers.h>
#include <cstdio>
#include "../../resource/tool.h"

#include "wizard.user.h"
#pragma comment(lib, "MyProgressWizardLib64.lib")

#include "server.h"
#include "updater.hpp"

HINSTANCE hInst;
using namespace std;
using namespace drogon;

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")


extern string app_token;
extern size_t appConnectedTimes;

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "检测端口是否被占用.hpp"
#include "TrustCheck.hpp"

std::string base64_encode(const std::string& data) {
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO* mem = BIO_new(BIO_s_mem());
	BIO_push(b64, mem);

	BIO_write(b64, data.data(), (int)data.size());
	BIO_flush(b64);

	char* bptr{};
	long len = BIO_get_mem_data(mem, &bptr);

	if (len < 0) {
		// Handle error
		// ...
		return std::string();
	}

	// Ensure we null-terminate the string
	char* base64_data = new char[len + 1];
	std::copy(bptr, bptr + len, base64_data);
	base64_data[len] = '\0';

	std::string result(base64_data);
	delete[] base64_data; // Don't forget to delete the allocated memory

	BIO_free_all(b64);
	return result;
}
std::string base64_decode(const std::string& encoded_data) {
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Don't use newlines to flush buffer  

	BIO* mem = BIO_new(BIO_s_mem());
	BIO_push(b64, mem);

	// Write the encoded data to the BIO  
	BIO_write(b64, encoded_data.data(), (int)encoded_data.size());

	// Create a buffer to hold the decoded data  
	BUF_MEM* bufferPtr;
	BIO_get_mem_ptr(mem, &bufferPtr);

	// BIO_read is not suitable here because the base64 filter BIO  
	// does not automatically remove padding. We use the buffer directly.  
	std::vector<char> decoded_bytes(bufferPtr->length, 0);
	std::copy(bufferPtr->data, bufferPtr->data + bufferPtr->length, decoded_bytes.begin());

	// Free the BIOs  
	BIO_free_all(b64);

	// Remove padding '=' characters if any  
	// Note: This is a simple approach, assuming '=' can only appear at the end  
	// and that the encoded data is valid.  
	size_t padding = 0;
	if (encoded_data.back() == '=') {
		++padding;
		if (encoded_data.size() > 1 && encoded_data[encoded_data.size() - 2] == '=') {
			++padding;
		}
	}

	// Adjust the size of the decoded data based on padding  
	decoded_bytes.resize(decoded_bytes.size() - padding);

	// Convert vector to string  
	std::string result(decoded_bytes.begin(), decoded_bytes.end());

	return result;
}

std::string ossl_sha256(const std::string str) {
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

	if (!mdctx) {
		// 处理错误  
		return "";
	}

	// 初始化消息摘要上下文  
	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
		// 处理错误  
		EVP_MD_CTX_free(mdctx);
		return "";
	}

	// 提供数据  
	if (1 != EVP_DigestUpdate(mdctx, str.data(), str.size())) {
		// 处理错误  
		EVP_MD_CTX_free(mdctx);
		return "";
	}

	// 计算哈希值  
	if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
		// 处理错误  
		EVP_MD_CTX_free(mdctx);
		return "";
	}

	// 释放消息摘要上下文  
	EVP_MD_CTX_free(mdctx);

	// 将哈希值转换为十六进制字符串  
	std::stringstream ss;
	for (unsigned int i = 0; i < hash_len; i++) {
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}

	return ss.str();
}




#if 1
static void sWebRootHandler(const HttpRequestPtr& req,
	std::function<void(const HttpResponsePtr&)>&& callback) 
{
#if 0
	string sess = [&]() -> string {
		try {
			return req->getParameter("token");
		}
		catch (...) { return ""; }
	}();
	string cookie = [&]() -> string {
		try {
			return req->getCookie("MyPN532_web_token");
		}
		catch (...) { return ""; }
	}();
	if (sess != app_token && cookie != app_token) {
		HttpResponsePtr resp = HttpResponse::newHttpResponse();
		resp->setStatusCode(k401Unauthorized);
		//resp->addHeader("WWW-Authenticate", "Basic");
		resp->setBody("<h1 style=color:red>Access denied");
		callback(resp);
		return;
	}
#endif
	HttpResponsePtr resp = HttpResponse::newFileResponse("./webroot/" + req->getPath());
#if 0
	if (cookie != app_token) {
		resp->addCookie("MyPN532_web_token", app_token);
	}
#endif
	CORSadd(req, resp);
	callback(resp);
}
#endif



// wWinMain function: The application will start from here.
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);

	// TODO: Place code here.
	UNREFERENCED_PARAMETER(0);
	using namespace std;

	{ auto r = SafeCheck(false); if (r != 0)return r; }

	if (!IsWindowsVistaOrGreater()) {
		fprintf(stderr, "[FATAL] Your OS is TOO LOW!\nIf you want to run this "
			"program, please update your OS.\nAt least Windows Vista is required.\n"
			"Exiting...\n");
		return ERROR_NOT_SUPPORTED; // Exit
	}


	::hInst = hInstance;


	CmdLineW cl(GetCommandLineW());
	wstring type;
	cl.getopt(L"type", type);


	InitMprgComponent();



	if (type == L"server") {
		bool allow_global_access = (cl.getopt(L"allow-global-access") != 0);
		wstring sPort; unsigned short port = 0;
		cl.getopt(L"port", sPort);
		port = (unsigned short)atoi(ws2c(sPort));
		if (!port) return ERROR_INVALID_PARAMETER;

		std::wstring root = GetProgramDirW() + L".data";
		(cl.getopt(L"root-path", root));
		if (-1 != IsFileOrDirectory(root)) {
			if (!CreateDirectoryW(root.c_str(), NULL)) {
				return GetLastError();
			}
		}
		SetCurrentDirectoryW(root.c_str());
		std::wstring webroot = L"./webroot";
		//(cl.getopt(L"webroot", webroot));
		if (-1 != IsFileOrDirectory(webroot)) {
			if (!CreateDirectoryW(webroot.c_str(), NULL)) {
				return GetLastError();
			}
		}
		std::wstring uploadPath = L"./uploads";

		wstring mybeaar;
		//cl.getopt(L"bearer", mybeaar);
		//::bearer = "Basic " + base64_encode(ws2s(mybeaar));
		cl.getopt(L"token", mybeaar);
		::app_token = ws2s(mybeaar);

		string s_webroot, s_upload, s_sslCrt, s_sslKey;
		ConvertUTF16ToUTF8(webroot, s_webroot);
		ConvertUTF16ToUTF8(uploadPath, s_upload);


#if 0
		if (!file_exists(L"pn532_data")) CreateDirectoryW(L"pn532_data", 0);
		if (!file_exists(L"pn532_data/keys")) CreateDirectoryW(L"pn532_data/keys", 0);
		if (!file_exists(L"pn532_data/dumps")) CreateDirectoryW(L"pn532_data/dumps", 0);
		if (!file_exists(L"pn532_data/temp")) CreateDirectoryW(L"pn532_data/temp", 0);
		if (!file_exists(L"pn532_data/cache")) CreateDirectoryW(L"pn532_data/cache", 0);
		if (!file_exists(L"pn532_data/logs")) CreateDirectoryW(L"pn532_data/logs", 0);
#else
		const auto runCreateProgramDir = [] (const vector<wstring> & dirsWillUse) {
			for (auto& i : dirsWillUse) {
				auto fileType = IsFileOrDirectory(L"./" + i);
				if (fileType == 1) {
					DeleteFileW(i.c_str());
				}
				fileType = IsFileOrDirectory(L"./" + i);
				if (fileType != -1) {
					CreateDirectoryW(i.c_str(), NULL);
				}
			}
		};
		runCreateProgramDir(vector<wstring>({
			L"keys", L"dumps", L"autodump",
			L"temp", L"cache", L"logs",
			L"config",
			L"redist",
		}));
		SetCurrentDirectoryW(L"logs");
		runCreateProgramDir(vector<wstring>({
			L"Server", L"Batch", L"Update"
		}));
		SetCurrentDirectoryW(L"..");
#endif


		std::shared_ptr<server::MainServer> srv(new server::MainServer);
		auto& app = drogon::app();
		app.setLogPath("./logs/Server")
			.setLogLevel(trantor::Logger::kWarn)
			.setUploadPath(s_upload)
			.setDocumentRoot(s_webroot)
			.setDefaultHandler(sWebRootHandler)
			//.addALocation("/")
#define signlethread
#undef signlethread
#ifdef signlethread
#pragma warning signle thrad server is only fo tesring! do not use in profuction
			.setThreadNum(1)
#else
			.setThreadNum(0)
#endif
			.setClientMaxBodySize(2147483648)
			.setClientMaxMemoryBodySize(67108864)
			.registerController(srv);
		bool useSSL = false;
		app.addListener(allow_global_access ? "0.0.0.0" : "127.0.0.1", port, useSSL);

		int CODE = ERROR_SUCCESS;

		CloseHandleIfOk(CreateThread(0, 0, [](PVOID pode)->DWORD {
			int* code = (int*)pode;
			Sleep(30000);
			if (!::appConnectedTimes) {
				*code = ERROR_TIMEOUT;
				drogon::app().quit();
			}
			return 0;
		}, &CODE, 0, 0));

		std::wstring s_signal; cl.getopt(L"signal-start", s_signal);
		if (!s_signal.empty()) {
			HANDLE signal = (HANDLE)(LONG_PTR)atoll(ws2s(s_signal).c_str());
			if (signal) {
				SetEvent(signal);
			}
		}

		if (检测端口是否被占用(port)) {
			return ERROR_SERVICE_ALREADY_RUNNING;
		}

		app.run();

		return CODE;
	}

	if (type == L"ui") {
		SetCurrentDirectoryW(GetProgramPathW().c_str());

		unsigned short port = 37532;
		HMPRGOBJ hObj = CreateMprgObject();
		HMPRGWIZ hWiz = CreateMprgWizard(hObj, MPRG_CREATE_PARAMS{
			.cb = sizeof(MPRG_CREATE_PARAMS),
			.szTitle = L"请稍候...",
			.max = 100,
			.value = 0,
		});
		OpenMprgWizard(hWiz);

		SetMprgWizardText(hWiz, L"正在检测系统环境...");
		SetMprgWizardValue(hWiz, 10);
		if (1 != IsFileOrDirectory(L"./pn532_data/bin/self/service.exe")) {
			MessageBoxTimeoutW(GetMprgHwnd(hWiz), L"文件损坏！请重新下载程序。\n"
				L"损坏的文件是: ./pn532_data/bin/self/service.exe", 0,
				MB_ICONERROR, 0, 30000);
			DeleteMprgObject(hObj);
			return ERROR_FILE_CORRUPT;
		}
	checkRuntime:
		if (Process.StartAndWait(L"./pn532_data/bin/self/service.exe"
			" --type=test-app") != 0x12345678) {
			if (IDOK == MessageBoxTimeoutW(GetMprgHwnd(hWiz),
				L"需要安装运行库才能启动应用程序！是否前往下载安装？",
				L"应用程序无法启动", MB_ICONERROR | MB_OKCANCEL, 0, 30000)) {
				DWORD c = 1;
				if (!file_exists(L"./pn532_data/redist/VC_redist.x64.exe")) {
					if (!file_exists(L"./pn532_data/redist"))
						CreateDirectoryW(L"./pn532_data/redist", NULL);
					if (c = Process.StartAndWait(
						L"./pn532_data/bin/self/download --url="
						"https://aka.ms/vs/17/release/vc_redist.x64.exe"
						" --file=./pn532_data/redist/VC_redist.x64.exe"
					)) {
						MessageBoxTimeoutW(GetMprgHwnd(hWiz),
							(L"运行库下载失败！\n" + ErrorCodeToString(c) +
								L"\n\ndwExitCode= " + to_wstring(c))
							.c_str(), L"下载失败", MB_ICONERROR, 0, 30000);
						DeleteMprgObject(hObj);
						return c;
					}
				}
				Process.StartAndWait(L"./pn532_data/redist/VC_redist.x64");
				goto checkRuntime;
			}
			DeleteMprgObject(hObj);
			return ERROR_NOT_SUPPORTED;
		}

		SetMprgWizardText(hWiz, L"正在创建HTTP服务器进程...");
		SetMprgWizardValue(hWiz, 20);

		wstring token = GenerateUUIDW();

		SECURITY_ATTRIBUTES sa{};
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = TRUE;
		HANDLE hEvent = CreateEventW(&sa, TRUE, FALSE, 0);
		if (!hEvent) {
			return MessageBoxW(GetMprgHwnd(hWiz),
				LastErrorStrW().c_str(),
				L"无法创建事件！", MB_ICONERROR);
		}
		wstring cmd = L"\""s + GetProgramDirW() + L"\" --type=server --port=" +
			to_wstring(port) + L" --root-path=./pn532_data --signal-start=" +
			to_wstring((ULONG_PTR)(PVOID)hEvent) + L" --token=\"" + token + L"\" ";
#pragma warning(push)
#pragma warning(disable: 6335)
		auto pi = [] (const wstring& paras) {
			STARTUPINFOW si{.cb = sizeof(si)};
			PROCESS_INFORMATION pi;
			ZeroMemory(&pi, sizeof(pi));
			LPTSTR cl = (LPTSTR)calloc(paras.length() + 1, sizeof(TCHAR));
			if (!cl) return PROCESS_INFORMATION{ 0,0,0,0 };
			wcscpy_s(cl, paras.length() + 1, paras.c_str());
			BOOL r = ::CreateProcess(NULL, cl,
				NULL, NULL, TRUE, 0, NULL, NULL,
				&si, &pi);
			free(cl);
			if (!r) return PROCESS_INFORMATION{};
			return pi;
		}(cmd);
#pragma warning(pop)
		if (!pi.hProcess) return MessageBoxW(GetMprgHwnd(hWiz), (LastErrorStrW() +
			L"\n\ncmd= " + cmd)
			.c_str(), L"无法创建HTTP服务器", MB_ICONERROR);
		CloseHandle(pi.hThread);

		SetMprgWizardText(hWiz, L"正在创建HTTP服务器...");
		SetMprgWizardValue(hWiz, 50);
		HANDLE hEvents[2]{hEvent, pi.hProcess};
		if (WAIT_TIMEOUT == WaitForMultipleObjects(2, hEvents, FALSE, 60000)) {
			TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
			CloseHandle(pi.hProcess);
			return MessageBoxW(GetMprgHwnd(hWiz),
				ErrorCodeToStringW(ERROR_TIMEOUT).c_str(),
				L"无法创建HTTP服务器", MB_ICONERROR);
		}
		{
			DWORD dwExitCode = 0;
			GetExitCodeProcess(pi.hProcess, &dwExitCode);
			if (dwExitCode != STILL_ACTIVE) {
				CloseHandle(pi.hProcess);
				CloseHandle(hEvent);
				MessageBoxTimeoutW(GetMprgHwnd(hWiz),
					(ErrorCodeToString(dwExitCode) +
					L"\n\ndwExitCode= " + to_wstring(dwExitCode))
					.c_str(), L"应用程序启动失败", MB_ICONERROR, 0, 30000);
				DeleteMprgObject(hObj);
				return dwExitCode;
			}
		}

		SetMprgWizardText(hWiz, L"正在打开应用程序...");
		SetMprgWizardValue(hWiz, 90);
		ShellExecuteW(0, L"open", (L"http://127.0.0.1:" + to_wstring(port) +
			L"/api/v2/auth/sso?token=" + token).c_str(), L"", NULL, SW_NORMAL);

		SetMprgWizardText(hWiz, L"完成！");
		SetMprgWizardValue(hWiz, 100);

		DWORD dwExitCode = 0;
		DestroyMprgWizard(hObj, hWiz);
		WaitForSingleObject(pi.hProcess, INFINITE);
		GetExitCodeProcess(pi.hProcess, &dwExitCode);
		CloseHandle(pi.hProcess);

		if (dwExitCode) {
			MessageBoxTimeoutW(0, (ErrorCodeToString(dwExitCode) +
				L"\n\ndwExitCode= " + to_wstring(dwExitCode))
				.c_str(), L"应用程序异常退出", MB_ICONERROR, 0, 30000);
		}

		DeleteMprgObject(hObj);
		return 0;
	}

	if (type == L"standard-updater") {
		return UpdaterEntry(cl);
	}


	if (cl.argc() < 2) {
		return Process.StartAndWait(L"\"" + GetProgramDirW() + L"\" --type=ui ");
	}

	return ERROR_INVALID_PARAMETER;
	return 0;
}




