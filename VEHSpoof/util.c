#include "util.h"

//https://hulkops.gitbook.io/blog/red-team/x64-call-stack-spoofing
PVOID RetExceptionAddress(PEXCEPTION_INFO pExceptionInfo) {
	UINT64 pImageNtHeader, hModule;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader;

	hModule = pExceptionInfo->hModule;

	pImageNtHeader = hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew;
	pOptionalHeader = &((PIMAGE_NT_HEADERS64)pImageNtHeader)->OptionalHeader;

	pExceptionInfo->pExceptionDirectory = hModule + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	pExceptionInfo->dwRuntimeFunctionCount = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION);
}

UINT64 RetStackSize(UINT64 hModule, UINT64 pFuncAddr) {

	EXCEPTION_INFO sExceptionInfo = { 0 };
	sExceptionInfo.hModule = hModule;

	RetExceptionAddress(&sExceptionInfo);

	PRUNTIME_FUNCTION pRuntimeFunction = (PRUNTIME_FUNCTION)sExceptionInfo.pExceptionDirectory;
	DWORD dwFuncOffset = pFuncAddr - hModule;
	PUNWIND_INFO pUnwindInfo;
	PUNWIND_CODE pUnwindCode;
	UINT64 dwStackSize = 0;


	// Loop Through RunTimeFunction structures until we find the structure for our target function
	for (int i = 0; i < sExceptionInfo.dwRuntimeFunctionCount; i++) {
		if (dwFuncOffset >= pRuntimeFunction->BeginAddress && dwFuncOffset <= pRuntimeFunction->EndAddress) {
			break;
		}

		pRuntimeFunction++;
	}

	// From the RunTimeFunction structure we need the offset to UnwindInfo structure

	pUnwindInfo = ((PUNWIND_INFO)(hModule + pRuntimeFunction->UnwindInfoAddress));

	// Loop Through the UnwindCodes 
	pUnwindCode = pUnwindInfo->UnwindCode; // UnwindCode Array

	for (int i = 0; i < pUnwindInfo->CountOfUnwindCodes; i++) {

		UBYTE bUnwindCode = pUnwindCode[i].UnwindOp;

		switch (bUnwindCode)
		{
		case UWOP_ALLOC_SMALL:
			dwStackSize += (pUnwindCode[i].OpInfo + 1) * 8;
			break;
		case UWOP_PUSH_NONVOL:
			if (pUnwindCode[i].OpInfo == 4)
				return 0;
			dwStackSize += 8;
			break;
		case UWOP_ALLOC_LARGE:
			if (pUnwindCode[i].OpInfo == 0) {
				dwStackSize += pUnwindCode[i + 1].FrameOffset * 8;
				i++;
			}
			else {

				dwStackSize += *(ULONG*)(&pUnwindCode[i + 1]);
				i += 2;

			}
			break;
		case UWOP_PUSH_MACHFRAME:
			if (pUnwindCode[i].OpInfo == 0)
				dwStackSize += 40;
			else
				dwStackSize += 48;
		case UWOP_SAVE_NONVOL:
			i++;
			break;
		case UWOP_SAVE_NONVOL_FAR:
			i += 2;
			break;
		default:
			break;
		}


	}

	return dwStackSize;

}

void PushToStack(PCONTEXT Context, const ULONG64 value)
{
	Context->Rsp -= 0x8;
	PULONG64 AddressToWrite = (PULONG64)(Context->Rsp);
	*AddressToWrite = value;
}