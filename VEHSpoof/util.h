#pragma once
#include <stdio.h>
#include <Windows.h>
#include <time.h>
#include <stdlib.h>

#include "structs.h"

extern PVOID Spoof(PSTACK_INFO);
UINT64 RetStackSize(UINT64 hModule, UINT64 pFuncAddr);
PVOID RetGadget(UINT64 hModule);
PVOID RetExceptionAddress(PEXCEPTION_INFO pExceptionInfo);
void PushToStack(PCONTEXT Context, const ULONG64 value);
// pvoid because I cannot be fucked dealing with alignment issues.
typedef struct _SPOOF_ARGS {
	PVOID pAddress;
	DWORD ArgCount;
	PVOID pArgs1;
	PVOID pArgs2;
	PVOID pArgs3;
	PVOID pArgs4;
	PVOID pArgs5;
	PVOID pArgs6;
	PVOID pArgs7;
	PVOID pArgs8;
	PVOID pArgs9;
	PVOID pArgs10;
} SPOOFARGS, * PSPOOFARGS;