//                                                  How the dll mod works (Warning: Poor english grammar!):
//
// How it works is that it modifies the instruction on address 0x407B38. This is a instruction used to go to the next switch statement if the value isn't 0x12
// The next switch-case value is 8 which so-happens to be the one that gives you the erorr message of being a invalid checksum.
//
// Heres how the instructions looks like
//		.text:0000000140407B35 41 3A DE				cmp     bl, r14b		- Comparasion check to see if the checksum was 0x12
//		.text:0000000140407B38 0F 84 13 13 00 00	jz      loc_140408E51	- Does a relative jump towards 0x408E51 (What we care about)
//
// loc_140408E51 is the one that gives you that checksum error message. This DLL modifies it so case 8 would literally do case 0x12. Completely bypassing the checksum.

//                                How to update this dll mod if it doesn't work in the game version your currently in:
//                                            NOTE: We expect for you to use IDA Pro in this section!
//
// Go into strings, Search for "invalidChecksumIndex < (int)m_serverGameInfo.m_vecFileChecksums.size()" and go to the address where that is used. Open up the Pseudocode view
// and also make sure they are synced with the IDA-View. Now find ANY "jz" instruction that jumps to the case where the string is and make it not jump there but to the case.
// which is when the checksum is correct. At the time of writing this (SM 0.7.3 build 776), case 0x12 would jump to 9. Case 0x12 is actually the one that would get ranned if
// the checksum was correct. So basicly dont jump to case to 0x19 by modifing the jz instruction in case 0x12 to not go there!

#include <cstdint>
#include <Windows.h>
#include <array>

// Address of where the client disconnects if the server sends a "checksums denied" packet
constexpr uint32_t addressClient = 0x0407B3A;

// Address of where the server sends the "checksums denied" packet
constexpr uint32_t addressServer = 0x08cf395;

// Make sure the sizes for oldBytes and newBytes match!
constexpr std::array<unsigned char, 4> oldBytesClient = { 0x13, 0x13, 0x00, 0x00 };
constexpr std::array<unsigned char, 4> newBytesClient = { 0x5F, 0x09, 0x00, 0x00 };

// Packet ID 0x8 = denied, 0x7 = accepted
constexpr unsigned char oldByteServer = 0x8;
constexpr unsigned char newByteServer = 0x7;

static void Attach(const HMODULE hModule) {
	uint64_t baseAddress = (uint64_t)GetModuleHandle(NULL);
	LPVOID addressPtrClient = reinterpret_cast<LPVOID>(baseAddress + addressClient);
	LPVOID addressPtrServer = reinterpret_cast<LPVOID>(baseAddress + addressServer);

	DWORD oldProtectClient = 0;
	DWORD oldProtectServer = 0;
	if (
		!VirtualProtect(addressPtrClient, newBytesClient.size(), PAGE_EXECUTE_READWRITE, &oldProtectClient) ||
		!VirtualProtect(addressPtrServer, sizeof(newByteServer), PAGE_EXECUTE_READWRITE, &oldProtectServer)
		) {
		MessageBox(NULL, L"NetworkChecksumDisabler couldn't update protections with the game's memory!", L"NetworkChecksumDisabler - Error", MB_OK | MB_ICONERROR);
		
		FreeLibraryAndExitThread(hModule, 1); // If it fails here, then we can just uninject since the memory didnt even change from this dll.
		return;
	}

	if (
		(memcmp(addressPtrClient, oldBytesClient.data(), oldBytesClient.size()) != 0) ||
		(memcmp(addressPtrServer, &oldByteServer, sizeof(oldByteServer)) != 0)
		)
		MessageBox(NULL, L"NetworkChecksumDisabler isn't compatible with this game version!", L"NetworkChecksumDisabler - Error", MB_OK | MB_ICONERROR);
	else {
		memcpy(addressPtrClient, newBytesClient.data(), newBytesClient.size());
		memcpy(addressPtrServer, &newByteServer, sizeof(newByteServer));
	}

	VirtualProtect(addressPtrClient, newBytesClient.size(), oldProtectClient, &oldProtectClient); // Wouldn't make sense for this to error if the protection change above this worked.
	VirtualProtect(addressPtrServer, sizeof(newByteServer), oldProtectServer, &oldProtectServer);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
	switch (reason) {
		case DLL_PROCESS_ATTACH:
			CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Attach, hModule, NULL, NULL);
			break;
	}
	return TRUE;
}

