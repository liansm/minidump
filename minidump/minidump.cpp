// minidump.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <windows.h>
#include "DbgHelp.h"
#include "dbgeng.h"
#include "minidump.h"


CrashInfo crash_info;

int main(int argc, char ** argv)
{
	if (argc != 3) {
		Usage();
		return -1;
	}

	const char* minidump_file = argv[1];
	const char* symbol_path = argv[2];

	//Analyze the minidump file
	AnalyzeDumpFile(minidump_file, symbol_path);

	//Dump the crash info
	DumpCrashInfo();
    return 0;
}



void Usage()
{
	printf("Usage: ./minidump minidump_file  symbol_path\n");
}

void InitSymbol(IDebugSymbols3* Symbol, const char* symbol_path)
{
	ULONG SymOpts = 0;

	// Load line information
	SymOpts |= SYMOPT_LOAD_LINES;
	SymOpts |= SYMOPT_OMAP_FIND_NEAREST;
	// Fail if a critical error is encountered
	SymOpts |= SYMOPT_FAIL_CRITICAL_ERRORS;
	// Always load immediately; no deferred loading
	SymOpts |= SYMOPT_DEFERRED_LOADS;
	// Require an exact symbol match
	SymOpts |= SYMOPT_EXACT_SYMBOLS;
	// This option allows for undecorated names to be handled by the symbol engine.
	SymOpts |= SYMOPT_UNDNAME;

	Symbol->SetSymbolOptions(SymOpts);
	Symbol->SetImagePath(symbol_path);
	Symbol->SetSymbolPath(symbol_path);
}

void LoadModule(IDebugSymbols3* Symbol)
{
	// The the number of loaded modules
	ULONG LoadedModuleCount = 0;
	ULONG UnloadedModuleCount = 0;

	Symbol->GetNumberModules(&LoadedModuleCount, &UnloadedModuleCount);

	// Find the relative names of all the modules so we know which files to sync
	int ExecutableIndex = -1;
	for (ULONG ModuleIndex = 0; ModuleIndex < LoadedModuleCount; ModuleIndex++)
	{
		ModuleInfo module_info;

		ULONG64 ModuleBase = 0;	
		Symbol->GetModuleByIndex(ModuleIndex, &ModuleBase);

		// Get the full path of the module name
		char ModuleName[MAX_PATH] = { 0 };
		Symbol->GetModuleNameString(DEBUG_MODNAME_IMAGE, ModuleIndex, ModuleBase, ModuleName, MAX_PATH, NULL);
		module_info.Name = ModuleName;
		module_info.BaseOfImage = ModuleBase;

		VS_FIXEDFILEINFO VersionInfo = { 0 };
		Symbol->GetModuleVersionInformationWide(ModuleIndex, ModuleBase, TEXT("\\"), &VersionInfo, sizeof(VS_FIXEDFILEINFO), NULL);
		module_info.Major = HIWORD(VersionInfo.dwProductVersionMS);
		module_info.Minor = LOWORD(VersionInfo.dwProductVersionMS);
		module_info.Patch = HIWORD(VersionInfo.dwProductVersionLS);
		module_info.Revision = LOWORD(VersionInfo.dwProductVersionLS);

		DEBUG_MODULE_PARAMETERS ModuleParameters = { 0 };
		Symbol->GetModuleParameters(1, NULL, ModuleIndex, &ModuleParameters);
		module_info.SizeOfImage = ModuleParameters.Size;

		Symbol->Reload(ModuleName);
		crash_info.module_info_list.push_back(module_info);

		HRESULT hr = Symbol->Reload(ModuleName);

		/*
		if (FAILED(hr)) {
			printf("Fail to load the module: %s\n", ModuleName);
		}
		else {
			printf("success to load the module: %s\n", ModuleName);
		}
		*/
	}
}



void GetSystemInfo(IDebugControl4* Control, SystemInfo & info)
{
	ULONG PlatformId = 0;
	ULONG Major = 0;
	ULONG Minor = 0;
	ULONG Build = 0;
	ULONG Revision = 0;
	Control->GetSystemVersionValues(&PlatformId, &Major, &Minor, &Build, &Revision);

	info.OSMajor = Major;
	info.OSMinor = Minor;
	info.OSBuild = Build;
	info.OSRevision = Revision;

	ULONG ProcessorType = 0;
	Control->GetActualProcessorType(&ProcessorType);

	switch (ProcessorType)
	{
	case IMAGE_FILE_MACHINE_I386:
		// x86
		info.ProcessorArchitecture = "PA_X86";
		break;

	case IMAGE_FILE_MACHINE_ARM:
		// ARM
		info.ProcessorArchitecture = "PA_ARM";
		break;

	case IMAGE_FILE_MACHINE_AMD64:
		// x64
		info.ProcessorArchitecture = "PA_X64";
		break;

	default:
		break;
	};

	ULONG ProcessorCount = 0;
	Control->GetNumberProcessors(&ProcessorCount);
	info.ProcessorCount = ProcessorCount;
}

void GetThreadInfo(IDebugControl4* Control)
{

}

void GetExceptionInfo(IDebugControl4* Control, ExceptionInfo & info)
{
	ULONG ExceptionType = 0;
	ULONG ProcessID = 0;
	ULONG ThreadId = 0;
	char Description[MAX_PATH] = { 0 };
	Control->GetLastEventInformation(&ExceptionType, &ProcessID, &ThreadId, NULL, 0, NULL, Description, MAX_PATH, NULL);

	info.Code = ExceptionType;
	info.ProcessId = ProcessID;
	info.ThreadId = ThreadId;
	info.ExceptionString = Description;
}


bool IsOffsetWithinModules(ULONG64 Offset)
{
	for (size_t module_index = 0; module_index < crash_info.module_info_list.size(); module_index++)
	{
		ModuleInfo& module_info = crash_info.module_info_list[module_index];
		if (Offset >= module_info.BaseOfImage && Offset < module_info.BaseOfImage + module_info.SizeOfImage)
		{
			return true;
		}
	}

	return false;
}

int GetCallstackInfo(IDebugControl4* Control, IDebugSymbols3* Symbol)
{
	int NumValidFunctionNames = 0;

	//const float int int32 FString
	const int ContextSize = 4096;
	byte* Context = new byte[ContextSize];
	ULONG DebugEvent = 0;
	ULONG ProcessID = 0;
	ULONG ThreadID = 0;
	ULONG ContextUsed = 0;

	// Get the context of the crashed thread
	HRESULT hr = Control->GetStoredEventInformation(&DebugEvent, &ProcessID, &ThreadID, Context, ContextSize, &ContextUsed, NULL, 0, 0);
	if (FAILED(hr))
	{
		return NumValidFunctionNames;
	}

	// Some magic number checks
	if (ContextUsed == 716)
	{
		printf("Context size matches x86 sizeof( CONTEXT )\n");
	}
	else if (ContextUsed == 1232)
	{
		printf("Context size matches x64 sizeof( CONTEXT )\n");
	}

	// Get the entire stack trace
	const int MaxFrames = 8192;
	const int MaxFramesSize = MaxFrames * ContextUsed;

	DEBUG_STACK_FRAME* StackFrames = new DEBUG_STACK_FRAME[MaxFrames];
	ULONG Count = 0;
	bool bFoundSourceFile = false;
	byte* ContextData = new byte[MaxFramesSize];
	memset(ContextData, 0, MaxFramesSize);

	HRESULT HR = Control->GetContextStackTrace(Context, ContextUsed, StackFrames, MaxFrames, ContextData, MaxFramesSize, ContextUsed, &Count);
	printf("GetContextStackTrace() got %d frames\n", Count);


	int AssertOrEnsureIndex = -1;
	for (ULONG StackIndex = 0; StackIndex < Count; StackIndex++)
	{
		const ULONG64 Offset = StackFrames[StackIndex].InstructionOffset;

		if (IsOffsetWithinModules(Offset))
		{
			// Get the module, function, and offset
			ULONG64 Displacement = 0;
			char NameByOffset[MAX_PATH] = { 0 };
			Symbol->GetNameByOffset(Offset, NameByOffset, ARRAYSIZE(NameByOffset) - 1, NULL, &Displacement);
			std::string ModuleAndFunction = NameByOffset;

			if (ModuleAndFunction.find('!') != std::string::npos)
			{
				NumValidFunctionNames++;
			}

			// Look for source file name and line number
			char SourceName[MAX_PATH] = { 0 };
			ULONG LineNumber = 0;
			Symbol->GetLineByOffset(Offset, &LineNumber, SourceName, ARRAYSIZE(SourceName) - 1, NULL, NULL);

			char crash_string[2048];
			memset(crash_string, 0, sizeof(crash_string));
			if (strlen(SourceName) > 0) {
				sprintf_s(crash_string, "%s [%s:%d]", NameByOffset, SourceName, LineNumber);
			}
			else {
				strcpy_s(crash_string, NameByOffset);
			}
			crash_info.crash_stack_info.push_back(crash_string);
		}
	}

	return NumValidFunctionNames;
}


bool AnalyzeDumpFile(const char* minidump_file, const char * symbol_path)
{
	IDebugClient5* Client = NULL;
	IDebugControl4* Control = NULL;
	IDebugSymbols3* Symbol = NULL;
	IDebugAdvanced3* Advanced = NULL;

	HRESULT hr = ::CoInitialize(NULL);
	if (hr != S_OK) {
		printf("Coinitialize fail to init");
		return false;
	}

	if (DebugCreate(__uuidof(IDebugClient5), (void**)&Client) != S_OK) {
		printf("fail to create the Client");
		return false;
	}

	if (Client->QueryInterface(__uuidof(IDebugControl4), (void**)&Control) != S_OK) {
		printf("fail to query the Control\n");
		return false;
	}

	if (Client->QueryInterface(__uuidof(IDebugSymbols3), (void**)&Symbol) != S_OK) {
		printf("fail to query the symbol\n");
		return false;
	}
	
	if(Client->QueryInterface(__uuidof(IDebugAdvanced3), (void**)&Advanced) != S_OK) {
		printf("fail to query the advanced\n");
		return false;
	}

	hr = Client->OpenDumpFile(minidump_file);
	if (FAILED(hr))
	{
		printf("Failed to open minidump file: %s", minidump_file);
		return false;
	}

	if (Control->WaitForEvent(0, INFINITE) != S_OK)
	{
		printf("Failed while waiting for minidump to load: %s", minidump_file);
		return false;
	}

	//Init the symbol option and path
	InitSymbol(Symbol, symbol_path);

	//Load the moudle symbol
	LoadModule(Symbol);

	//Get System info
	GetSystemInfo(Control, crash_info.sys_info);
	
	//Get Thread info
	GetThreadInfo(Control);

	//Get Exception info
	GetExceptionInfo(Control, crash_info.excep_info);

	//Get the Callstack info
	GetCallstackInfo(Control, Symbol);

	//release
	Advanced->Release();
	Symbol->Release();
	Control->Release();

	Client->Release();

	::CoUninitialize();
	return true;

}

void DumpCrashInfo()
{
	printf("CALLSTACK BEGIN\n");
	for (size_t i = 0; i < crash_info.crash_stack_info.size(); ++i) {
		printf("%s\n", crash_info.crash_stack_info[i].c_str());
	}
	printf("CALLSTACK END\n");
}

