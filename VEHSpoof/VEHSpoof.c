#include <Windows.h>
#include <stdio.h>
#include "structs.h"
#include "util.h"

#define STACKSPOOF 0x57

uintptr_t pOriginalRip = NULL;
uintptr_t pOriginalRsp = NULL;


PVECTORED_EXCEPTION_HANDLER Handler(EXCEPTION_POINTERS* info) {
	UINT64 pGadget, pRtlUserThreadStart, pBaseThreadInitThunk;
	UINT64 pNtdll, pKernel32;

	pNtdll = GetModuleHandleA("ntdll");
	pKernel32 = GetModuleHandleA("kernel32.dll");
	//pGadget = RetGadget(pKernel32);
	pRtlUserThreadStart = GetProcAddress(pNtdll, "RtlUserThreadStart");
	pBaseThreadInitThunk = GetProcAddress(pKernel32, "BaseThreadInitThunk");


	if (info->ExceptionRecord->ExceptionCode == STACKSPOOF) {
		pOriginalRip = info->ContextRecord->Rip;// could also slap this into a non-vol instead of a global but whatever.
		pOriginalRsp = *(UINT64*)(info->ContextRecord->Rsp);

		ULONG_PTR* Args = info->ExceptionRecord->ExceptionInformation;

		info->ContextRecord->Rip = Args[0];
		info->ContextRecord->Rcx = (void*)Args[2];
		info->ContextRecord->Rdx = Args[3];
		info->ContextRecord->R8  = Args[4];
		info->ContextRecord->R9  = Args[5];

		PushToStack(info->ContextRecord, 0);
		info->ContextRecord->Rsp -= RetStackSize(pNtdll, pRtlUserThreadStart);
		PushToStack(info->ContextRecord, pRtlUserThreadStart + 0x21);

		info->ContextRecord->Rsp -= RetStackSize(pKernel32, pBaseThreadInitThunk);
		PushToStack(info->ContextRecord, pBaseThreadInitThunk + 0x14);

		// Push additional fake frames
		// 
		// add additional args to stack.


		return EXCEPTION_CONTINUE_EXECUTION;
	}
	

	// This is just a quick and dirty example.
	// Ideally, we want to make sure the illegal instruction address is the correct address IE baseThreadInitThunk function but I cba to do that right now.
	// or actually just do something better to get back to our exception handler like a call <register> and set the register to a unique value, catch that.. whatever.
	if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {// handle the ACCESS_VIOLATION ON THE RET 
		info->ContextRecord->Rsp += RetStackSize(pKernel32, pBaseThreadInitThunk);
		info->ContextRecord->Rsp += 8;
		info->ContextRecord->Rsp += RetStackSize(pNtdll, pRtlUserThreadStart);
		info->ContextRecord->Rsp += 8;
		info->ContextRecord->Rsp += 8;// I think this is correct.

		PushToStack(info->ContextRecord, pOriginalRsp);
		info->ContextRecord->Rip = pOriginalRip;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
	AddVectoredExceptionHandler(0, Handler);

	ULONG_PTR args[6];  // Array to store all the function parameters

	args[0] = (ULONG_PTR)&MessageBoxA;  // Function pointer
	args[1] = (ULONG_PTR)4;             // ArgCount
	args[2] = (ULONG_PTR)NULL;          // Arg1
	args[3] = (ULONG_PTR)"Hello World"; // Arg2
	args[4] = (ULONG_PTR)"Hello World"; // Arg3
	args[5] = (ULONG_PTR)MB_OK;         // Arg4

	printf("Outside VEH: %p \n", args);

	RaiseException(STACKSPOOF, 0, 6, args);

	printf("Finished \n");

	getchar();
}

