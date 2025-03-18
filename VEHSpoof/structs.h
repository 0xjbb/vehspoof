#pragma once
typedef UCHAR UBYTE;

typedef struct _STACK_INFO {
	UINT64 pRltUserThreadStart_RetAddr;
	UINT64 dwRtlUserThreadStart_Size;

	UINT64 pBaseThreadInitThunk_RetAddr;
	UINT64 dwBaseThreadInitThunk_Size;

	UINT64 pGadgetAddr;
	UINT64 dwGadgetSize;

	UINT64 pTargetFunction;
	UINT64 pRBX;
	UINT64 dwNumberOfParams;
	PVOID pArgs;
}STACK_INFO, * PSTACK_INFO;

typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	UWOP_PUSH_MACHFRAME = 10
};

typedef union _UNWIND_CODE
{
	struct
	{
		UBYTE CodeOffset;
		UBYTE UnwindOp : 4;
		UBYTE OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
	UCHAR Version : 3;
	UCHAR Flags : 5;
	UCHAR SizeOfPrologue;
	UCHAR CountOfUnwindCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameRegisterOffset : 4;
	UNWIND_CODE UnwindCode[1];

	union {
		OPTIONAL ULONG ExceptionHandler;
		OPTIONAL ULONG FunctionEntry;
	};
	OPTIONAL ULONG ExceptionData[];

} UNWIND_INFO, * PUNWIND_INFO;

typedef struct _EXCEPTION_INFO {
	UINT64 hModule;
	UINT64 pExceptionDirectory;
	DWORD dwRuntimeFunctionCount;
}EXCEPTION_INFO, * PEXCEPTION_INFO;
