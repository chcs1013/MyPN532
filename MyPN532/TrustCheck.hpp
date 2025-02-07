#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <tchar.h>
#include <iostream>
#include <softpub.h>
#include <WtsApi32.h>
#include <Shlwapi.h>
#include <vector>
#include <map>
bool TrustCheck(bool Security__VALIDATE_certificate_chain_ROOT_MUST_BE_TRUSTED = true);
int SafeCheck(bool Security__VALIDATE_certificate_chain_ROOT_MUST_BE_TRUSTED = true);
