#pragma once
#include <drogon/drogon.h>
#include <drogon/WebSocketController.h>
#include <Windows.h>
#include <string>
#include <vector>


#define CORSadd(req, resp) {\
	resp->addHeader("access-control-allow-origin", req->getHeader("origin"));\
	resp->addHeader("access-control-allow-methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS");\
	resp->addHeader("access-control-allow-headers", req->getHeader("access-control-request-headers"));\
	resp->addHeader("access-control-allow-credentials", "true");\
	resp->addHeader("access-control-max-age", "300");\
}




namespace server {
	using namespace drogon;
	using namespace std;


	class AuthFilter :public drogon::HttpFilter<AuthFilter>
	{
	public:
		virtual void doFilter(const HttpRequestPtr& req,
			FilterCallback&& fcb,
			FilterChainCallback&& fccb) override;
	};

	class MainServer : public drogon::HttpController<MainServer>
	{
	public:
		METHOD_LIST_BEGIN
			ADD_METHOD_TO(server::MainServer::meinfo, "/api/me", Get, Options, "server::AuthFilter");

			ADD_METHOD_TO(server::MainServer::ssov2, "/api/v2/auth/sso", Get, "server::AuthFilter");

			ADD_METHOD_TO(server::MainServer::exitimmediate, "/api/v4.8/app/exit", Post, Options, "server::AuthFilter");

			ADD_METHOD_TO(server::MainServer::webconfig, "/api/v4.8/user/web/config", Get, Post, Put, Patch, Delete, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::keyfile, "/api/v4.8/api/keyfile", Head, Get, Post, Put, Patch, Options, Delete, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::dumpfile, "/api/v4.8/api/dumpfile", Head, Get, Post, Put, Patch, Options, Delete, "server::AuthFilter");

			ADD_METHOD_TO(server::MainServer::launchcmd, "/api/v4.8/native/launchcmd", Post, "server::AuthFilter");

			ADD_METHOD_TO(server::MainServer::detectnfcdevice, "/api/v4.8/nfc/devicedetection", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::scandevice, "/api/v4.8/nfc/devscan", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::taginfo, "/api/v4.8/nfc/taginfo", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::taginfojson, "/api/v4.8/nfc/taginfojson", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::defaultdevice, "/api/v4.8/nfc/defaultdevice", Get, Put, Delete, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::testdevice, "/api/v5.0/nfc/testdevice", Post, Options, "server::AuthFilter");
			
			ADD_METHOD_TO(server::MainServer::readultralight, "/api/v4.8/nfc/ultralight/read", Post, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::writeultralight, "/api/v4.8/nfc/ultralight/write", Post, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::lockufuid, "/api/v4.8/nfc/uid/lock", Post, Options, "server::AuthFilter");

			ADD_METHOD_TO(server::MainServer::appversion, "/api/v5.0/app/version", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::appversion, "/api/v5.0/app/version/internal", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::appversioncommon, "/api/v5.0/app/version/common", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::updateurl, "/api/v5.0/app/update/url", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::updaterel, "/api/v5.0/app/update/release", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::updateserviceprovider, "/api/v5.0/app/update/service_provider", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::updateurlconstruct, "/api/v5.0/app/update/construct", Post, Options, "server::AuthFilter");
			
			ADD_METHOD_TO(server::MainServer::getgenshinurl, "/api/v5.0/api/genshin/url", Get, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::getgenshinversion, "/api/v5.0/api/genshin/version", Get, Options, "server::AuthFilter");
			
			ADD_METHOD_TO(server::MainServer::getlogfilelist, "/api/v5.1/app/log/list", Get, Post, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::getlogfile, "/api/v5.1/app/log/data", Post, Options, "server::AuthFilter");
			
			ADD_METHOD_TO(server::MainServer::updateorigin, "/api/v5.3/app/update/provider", Get, Put, Options, "server::AuthFilter");
			ADD_METHOD_TO(server::MainServer::updatelistprovider, "/api/v5.3/app/update/providers", Get, Options, "server::AuthFilter");
		METHOD_LIST_END


		void meinfo(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;


		void ssov2(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;


		void exitimmediate(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;

		void webconfig(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void keyfile(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void dumpfile(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;

		void launchcmd(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;

		void detectnfcdevice(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void taginfo(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void taginfojson(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void scandevice(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void defaultdevice(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void testdevice(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		
		void readultralight(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void writeultralight(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void lockufuid(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;

		void appversion(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void appversioncommon(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void updateurl(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void updaterel(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void updateserviceprovider(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void updateurlconstruct(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void updateorigin(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void updatelistprovider(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		
		void getgenshinurl(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void getgenshinversion(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		
		void getlogfilelist(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;
		void getlogfile(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const;


	public:


		MainServer() {

		}

		static const bool isAutoCreation = false;
	};

	class WebSocketService : public drogon::WebSocketController<WebSocketService>
	{
	  public:
		void handleNewMessage(const WebSocketConnectionPtr&,
							  std::string &&,
							  const WebSocketMessageType &) override;
		void handleNewConnection(const HttpRequestPtr &,
								 const WebSocketConnectionPtr&) override;
		void handleConnectionClosed(const WebSocketConnectionPtr&) override;
		WS_PATH_LIST_BEGIN
		//list path definitions here;
			WS_PATH_ADD("/api/v4.8/web", "server::AuthFilter");
		WS_PATH_LIST_END
	};


}



