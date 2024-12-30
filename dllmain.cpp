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
#include <vector>

static const uint32_t address = 0x407B38;

static const std::vector<unsigned char> oldAddress = { 0x13, 0x13, 0x00, 0x00 };
static const std::vector<unsigned char> newAddress = { 0x5F, 0x09, 0x00, 0x00 };

static void Attach(const HMODULE hModule){
	const uint64_t& base = (uint64_t)GetModuleHandle(NULL);
	LPVOID pAddress = reinterpret_cast<LPVOID>(base + address + 0x2);

	DWORD oldProtect = 0;
	DWORD exitCode = 0;

	if (!VirtualProtect(pAddress, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		MessageBox(NULL, L"NetworkChecksumDisabler couldn't update protections with the game's memory!", L"NetworkChecksumDisabler - Error", MB_OK | MB_ICONERROR);
		
		FreeLibraryAndExitThread(hModule, 1);
		return;
	}

	if (memcmp(pAddress, oldAddress.data(), sizeof(uint32_t)) != 0) {
		MessageBox(NULL, L"NetworkChecksumDisabler isn't compatible with this game version!", L"NetworkChecksumDisabler - Error", MB_OK | MB_ICONERROR);
		exitCode = 1;
	} else {
		memcpy(pAddress, newAddress.data(), sizeof(uint32_t));
	}
	
	if (!VirtualProtect(pAddress, sizeof(uint32_t), oldProtect, &oldProtect)) {
		MessageBox(NULL, L"NetworkChecksumDisabler couldn't revert protections with the game's memory!", L"NetworkChecksumDisabler - Error", MB_OK | MB_ICONERROR);
		exitCode = 1;
	}
	
	FreeLibraryAndExitThread(hModule, exitCode);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
	switch (reason) {
		case DLL_PROCESS_ATTACH:
			CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Attach, hModule, NULL, NULL);
			break;
	}
	return TRUE;
}

