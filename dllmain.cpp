
#include <cstdint>
#include <windows.h>

static void Attach() {
	uint64_t base = uint64_t(GetModuleHandle(0));
	uint32_t* pAddr = (uint32_t*)(base + 0x407B38 + 0x2);

	DWORD oldProtect;
	VirtualProtect(pAddr, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect);

	if (*pAddr == uint32_t(0x00001313))
		*pAddr = uint32_t(0x0000095F);

	VirtualProtect(pAddr, sizeof(uint32_t), oldProtect, &oldProtect);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH: {
			Attach();
			break;
		}
		case DLL_PROCESS_DETACH:
			FreeLibrary(hModule);
	}
	return TRUE;
}

