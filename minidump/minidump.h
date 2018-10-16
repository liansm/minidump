#pragma once

#include <string>
#include <vector>

//ModuleInfo
struct ModuleInfo
{
public:
	std::string Name;
//	std::string Extension;
	unsigned long long BaseOfImage;
	unsigned long SizeOfImage;
	int Major;
	int Minor;
	int Patch;
	int Revision;

	ModuleInfo()
		: BaseOfImage(0)
		, SizeOfImage(0)
		, Major(0)
		, Minor(0)
		, Patch(0)
		, Revision(0)
	{
	}
};

//System info
struct SystemInfo
{
public:
	int OSMajor;
	int OSMinor;
	int OSBuild;
	int OSRevision;
	int ProcessorCount;
	std::string ProcessorArchitecture;

	SystemInfo()
		: OSMajor(0)
		, OSMinor(0)
		, OSBuild(0)
		, OSRevision(0)
		, ProcessorCount(0)

	{
	}
};

//Thread info
struct ThreadInfo
{
public:
	int ThreadID;
	int SuspendCount;

	ThreadInfo() : ThreadID(0), SuspendCount(0)
	{

	}
};


//Exception info
struct ExceptionInfo
{
public:
	int ProcessId;
	int ThreadId;
	int Code;
	std::string ExceptionString;

	std::vector<std::string> CallStackString;

	ExceptionInfo()
		: ProcessId(0)
		, ThreadId(0)
		, Code(0)
	{
	}
};


//Crash info
struct CrashInfo
{
public:
	std::vector<ModuleInfo> module_info_list;
	SystemInfo sys_info;
	ExceptionInfo excep_info;
	std::vector<std::string> crash_stack_info;
};

void Usage();

bool AnalyzeDumpFile(const char* minidump_file, const char * symbol_path);

void DumpCrashInfo();



