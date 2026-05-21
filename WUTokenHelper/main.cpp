#include "pch.h"
#include <combaseapi.h>
#include <winerror.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Security::Authentication::Web;
using namespace winrt::Windows::Security::Authentication::Web::Core;
using namespace winrt::Windows::Security::Cryptography;

#define WU_NO_ACCOUNT MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x200)
#define WU_TOKEN_FETCH_ERROR_BASE MAKE_HRESULT(SEVERITY_ERROR, FACILITY_ITF, 0x300)

extern "C" __declspec(dllexport) HRESULT __stdcall GetWUToken(wchar_t** retToken) {
	if (!retToken) {
		return E_POINTER;
	}

	*retToken = nullptr;

	try {
		const auto accountProvider = WebAuthenticationCoreManager::FindAccountProviderAsync(L"https://login.microsoft.com", L"consumers").get();
		const auto findAccountsResult = WebAuthenticationCoreManager::FindAllAccountsAsync(accountProvider).get();
		const auto accounts = findAccountsResult.Accounts();

		std::wprintf(L"Account count = %u\n", accounts.Size());

		if (accounts.Size() == 0) {
			return WU_NO_ACCOUNT;
		}

		const auto accountInfo = accounts.GetAt(0);

		std::wprintf(L"ID = %ls\n", accountInfo.Id().c_str());
		std::wprintf(L"Name = %ls\n", accountInfo.UserName().c_str());

		const WebTokenRequest request(accountProvider, L"service::dcat.update.microsoft.com::MBI_SSL", L"{28520974-CE92-4F36-A219-3F255AF7E61E}");
		const auto result = WebAuthenticationCoreManager::GetTokenSilentlyAsync(request, accountInfo).get();

		if (result.ResponseStatus() != WebTokenRequestStatus::Success) {
			return WU_TOKEN_FETCH_ERROR_BASE | static_cast<int32_t>(result.ResponseStatus());
		}

		const auto responseData = result.ResponseData();
		const auto token = responseData.GetAt(0).Token();

		std::wprintf(L"Token = %ls\n", token.c_str());

		const auto tokenBinary = CryptographicBuffer::ConvertStringToBinary(token, BinaryStringEncoding::Utf16LE);
		const auto tokenBase64 = CryptographicBuffer::EncodeToBase64String(tokenBinary);

		std::wprintf(L"Encoded token = %ls\n", tokenBase64.c_str());

		const auto byteCount = (tokenBase64.size() + 1) * sizeof(wchar_t);
		auto* buffer = static_cast<wchar_t*>(::CoTaskMemAlloc(byteCount));
		
		if (!buffer) {
			return E_OUTOFMEMORY;
		}

		std::memcpy(buffer, tokenBase64.c_str(), byteCount);

		*retToken = buffer;
		return S_OK;
	}
	catch (const winrt::hresult_error& e) {
		return e.code();
	}
	catch (...) {
		return E_FAIL;
	}
}