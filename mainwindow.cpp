#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#pragma comment(lib,"Dbghelp.lib")
#define ASLR "[ASLR]"
#define DEP "[DEP]"
#include <psapi.h>
#include<sddl.h>
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib,"Advapi32.lib")
namespace IntegrityLevel
{
    extern "C" { __declspec(dllexport) int GetFileIntegrityLevel(LPCWSTR FileName); }
    extern "C" { __declspec(dllexport) bool SetFileIntegrityLevel(int level, LPCWSTR FileName); }
}
using namespace std;


struct process
{
    unsigned long pid;
    char process_name[MAX_PATH]={0};
    unsigned long PARENT_PID;
    char parent[MAX_PATH]={0};
    char path[MAX_PATH]={0};
    char dll_list[MAX_PATH][MAX_PATH];
    int type;
    int privelegies_counter=0;
    int integrity=0;
    int dll_counter;
    QString priveleg[MAX_PATH]={0};
    char privelegies[MAX_PATH]={0};
    QString defend ;
    char username[MAX_PATH];
};

struct LANGANDCODEPAGE
{
    WORD wLanguage;
    WORD wCodePage;
};
process proc_info[MAX_PATH];

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}
int strcmp_parent(CHAR* s1, WCHAR* s2)
{
    while (*s1 && (*s1 == *s2))
        s1++, s2++;
    return *(char*)s1 - *(char*)s2;
}
int strcmp(char* s1,char* s2)
{
    while (*s1 && (*s1 == *s2))
        s1++, s2++;
    return *(char*)s1 - *(char*)s2;
}
void strcpy(char* first,TCHAR*second)
{
    for(int i=0;i<MAX_PATH;i++)
    {
      first[i]=second[i];
    }
}
void strcpy2(WCHAR* first,char*second)
{
    for(int i=0;i<MAX_PATH;i++)
    {
      first[i]=second[i];
    }
}

VOID PrintModuleList(HANDLE CONST hStdOut, DWORD CONST dwProcessId, int proc_number)
{
    MODULEENTRY32 meModuleEntry;
    TCHAR szBuff[1024];
    DWORD dwTemp;
    HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return;
    }
    int i=0;
    int counter=0;
    meModuleEntry.dwSize = sizeof(MODULEENTRY32);
    Module32First(hSnapshot, &meModuleEntry);
    do
    {
    //	wsprintf(szBuff, L"  ba: %08X, bs: %08X, %s\r\n",meModuleEntry.modBaseAddr, meModuleEntry.modBaseSize,meModuleEntry.szModule);
       for (int i=0; i < MAX_PATH; i++)
       {
           proc_info[proc_number].dll_list[counter][i] = meModuleEntry.szModule[i];
       }
       counter++;
       //WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);
    }
    while (Module32Next(hSnapshot, &meModuleEntry));
    proc_info[proc_number].dll_counter=counter;
    CloseHandle(hSnapshot);
}

VOID PrintProcessList(HANDLE CONST hStdOut)
{
    PROCESSENTRY32 peProcessEntry;
    TCHAR szBuff[1024];
    DWORD dwTemp;
    int proc_number=0;
    HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return;
    }
    peProcessEntry.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnapshot, &peProcessEntry);
do{
     //wsprintf(szBuff, L"=== %08X %s ===\r\n",peProcessEntry.th32ProcessID, peProcessEntry.szExeFile);
     WriteConsole(hStdOut, szBuff, lstrlen(szBuff), &dwTemp, NULL);
     PrintModuleList(hStdOut, peProcessEntry.th32ProcessID,proc_number);
     proc_number++;
} while (Process32Next(hSnapshot, &peProcessEntry));
    CloseHandle(hSnapshot);
}


char* getProcessUsername(HANDLE hSnapshot, PROCESSENTRY32 processList,char*buf)
{
    DWORD dwSize = 256;
    HANDLE hProcess;
    TOKEN_USER *pUserInfo;
    static char staticName[MAX_PATH];
    char name[MAX_PATH];
    char domain[MAX_PATH];
    char *result;
    int iUse;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processList.th32ProcessID);
    OpenProcessToken(hProcess, TOKEN_QUERY, &hSnapshot);
    pUserInfo = (PTOKEN_USER)GlobalAlloc(GPTR, dwSize);
    GetTokenInformation(hSnapshot, TokenUser, pUserInfo, dwSize, &dwSize);
    LookupAccountSidA(0, pUserInfo->User.Sid, name, &dwSize, domain, &dwSize, (PSID_NAME_USE)&iUse);
    strncpy_s(staticName, name, _TRUNCATE);
    result = staticName;
    strcpy(buf,staticName);
    return result;
}

BOOL IsWow64(unsigned long pid)
{
    BOOL Isx64 = FALSE;
    HANDLE Handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (Handle != NULL)
        {
          typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
          LPFN_ISWOW64PROCESS fnIsWow64Process = reinterpret_cast <LPFN_ISWOW64PROCESS>(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process"));
            if (fnIsWow64Process != NULL)
            {
                if (!fnIsWow64Process(Handle, &Isx64))
                {
                    CloseHandle(Handle);
                    return false;
                }
                else
                {
                    CloseHandle(Handle);
                    return true;
                }
            }
            else
            {
                CloseHandle(Handle);
                return false;
            }
        }
      else { return false; }
  }

bool get_path(unsigned long pid,char*path)
{
    HANDLE Handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (Handle != NULL)

    {
        TCHAR buf[MAX_PATH] = { 0 };
        if (GetModuleFileNameEx(Handle, 0, buf, MAX_PATH))
        {
            strcpy(path,buf);
            CloseHandle(Handle);
            return true;
        }
        else
        {
            CloseHandle(Handle);
            return false;
        }
    }
    else { return false; }
}
bool check_dep(unsigned int pid)

{
    HANDLE Handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (Handle != NULL)
    {
        PROCESS_MITIGATION_DEP_POLICY depPolicy = PROCESS_MITIGATION_DEP_POLICY();
        BOOL success = GetProcessMitigationPolicy(Handle, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy));
        if (success)
        {
            CloseHandle(Handle);
            return true;
        }
        else
        {
            CloseHandle(Handle);
            return false;
        }
    }
    else
    {
        CloseHandle(Handle);
        return false;
    }
}

bool check_aslr(unsigned long pid)
{
    HANDLE Handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (Handle != NULL)
    {
        PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = PROCESS_MITIGATION_ASLR_POLICY();
        BOOL success = GetProcessMitigationPolicy(Handle, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy));
        if (success)
        {
            CloseHandle(Handle);
            return true;
        }
        else
        {
            CloseHandle(Handle);
            return false;
        }
    }
   else
    {
       CloseHandle(Handle);
       return false;
    }
}

 int call_parent(int value, char *text)
{
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = value;
    CHAR szExeFile[MAX_PATH];
    strcpy(szExeFile, text);
    Process32First(hProcessSnap, &pe32);
    if (!strcmp_parent(szExeFile, pe32.szExeFile))
    {
       goto end;
    }
    while (Process32Next(hProcessSnap, &pe32))
    {
        if (!strcmp_parent(szExeFile, pe32.szExeFile))
        {
            goto end;
        }
    }
    end:
    return  pe32.th32ParentProcessID;
    CloseHandle(hProcessSnap);

}
void NameByPid( int pid,TCHAR*buf)
{
    HANDLE Handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,pid);
    GetModuleFileNameEx(Handle, 0, buf, MAX_PATH);
    CloseHandle(Handle);
}
unsigned long PIDByName(char* proc_name)
{
  HANDLE pHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 ProcessEntry;
  unsigned long pid;
  ProcessEntry.dwSize = sizeof(ProcessEntry);
  bool Loop = Process32First(pHandle, &ProcessEntry);
  while (Loop)

  {
      char name[MAX_PATH]={0};
      for(int i=0;i<15;i++)
      {
       name[i]=ProcessEntry.szExeFile[i];
      }
     if (strcmp(name,proc_name) == 0)
      {
          pid = ProcessEntry.th32ProcessID;
          CloseHandle(pHandle);
          return pid;
      }
      Loop = Process32Next(pHandle, &ProcessEntry);
    }
    return 0;
}


MainWindow::~MainWindow()
{
    delete ui;
}
bool GenerateProcessIntegrityLevel(int proc_number,int pid)

{
    DWORD dwLengthNeeded;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel;
    bool intlvl = false;
    HANDLE hToken;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess != NULL)
    {
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        {
            if (GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded) || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
                if (pTIL != NULL)
                {
                    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
                    {
                        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
                        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) { intlvl = true; proc_info[proc_number].integrity = 1; }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
                        {
                            intlvl = true; proc_info[proc_number].integrity = 2;
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) { intlvl = true; proc_info[proc_number].integrity = 3; }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) { intlvl = true; proc_info[proc_number].integrity = 4; }
                        CloseHandle(hProcess);
                        LocalFree(pTIL);
                        return true;
                    }
                    else
                    {
                        CloseHandle(hProcess);
                        LocalFree(pTIL);
                        return false;
                    }
                }
                else
                {
                    CloseHandle(hProcess);
                    return false;
                }
            }
            else
            {
                CloseHandle(hProcess);
                return false;
            }
        }
        else
        {
            proc_info[proc_number].integrity = 4;
            CloseHandle(hProcess);
            return true;
        }
    }
    else { return false; }
}
bool AdjustTokenIntegrityLevel(HANDLE token, const char * sid)
{

    BOOL ret;
    PSID psd = NULL;
    if (ConvertStringSidToSidA(sid, &psd))
    {
        TOKEN_MANDATORY_LABEL tml;
        ZeroMemory(&tml, sizeof(tml));
        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = psd;
        ret = SetTokenInformation(token, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(psd));
        LocalFree(psd);
    }
    else
    {
        ret = false;
    }
    return ret;
}
wchar_t *convertCharArrayToLPCWSTR(const char* charArray)
{
    wchar_t* wString=new wchar_t[4096];
    MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
    return wString;
}
void setProcessIntegrityLevel(const QString &putProcessIntegrityLevel,int proc_number)
{
    QString index_process_qml=putProcessIntegrityLevel;
    std::string level_str_key=index_process_qml.toStdString();
    std::string level_str;

    if(level_str_key=="Low")
    {
        level_str = "S-1-16-4096";
        std::cout<<level_str<<endl;
    }
    else if(level_str_key=="Medium")
    {
        level_str = "S-1-16-8192";
        std::cout<<level_str<<endl;

    }
    else if(level_str_key=="High")
    {
        level_str = "S-1-16-12288";
        std::cout<<level_str<<endl;
    }

    else
    {
        return;
    }

    int process_index=proc_number;
    HANDLE killProcess = OpenProcess(PROCESS_TERMINATE, FALSE, proc_info[process_index].pid);
        if (killProcess != NULL)
        {
            HANDLE token_cur, token_dup;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &token_cur))
            {
                if (DuplicateTokenEx(token_cur, 0, NULL, SecurityImpersonation, TokenPrimary, &token_dup))
                {
                    if (AdjustTokenIntegrityLevel(token_dup, level_str.c_str()))
                    {
                        PROCESS_INFORMATION pi;
                        STARTUPINFOW si;
                        LPCWSTR path=convertCharArrayToLPCWSTR(proc_info[process_index].path);
                        ZeroMemory(&si, sizeof(si));
                        si.cb = sizeof(si);
                        if (CreateProcessAsUserW(token_dup,path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
                        {
                            std::cout<<level_str<<std::endl;
                            TerminateProcess(killProcess, 9);
                            CloseHandle(killProcess);
                            CloseHandle(token_cur);
                            CloseHandle(token_dup);
                            return ;
                        }
                        else
                        {
                            std::cout <<"last error is"<< GetLastError() << std::endl;
                            return ;
                        }
                    }
                   else
                    {
                        TerminateProcess(killProcess, 9);
                        CloseHandle(killProcess);
                        CloseHandle(token_cur);
                        CloseHandle(token_dup);
                        return ;
                    }
                }
                else
                {
                    TerminateProcess(killProcess, 9);
                    CloseHandle(killProcess);
                    CloseHandle(token_cur);
                    CloseHandle(token_dup);
                    return ;
                }
            }
            else
            {
                TerminateProcess(killProcess, 9);
                CloseHandle(killProcess);
                CloseHandle(token_cur);
                CloseHandle(token_dup);
                return ;
            }
        }
}
void IsPrivilege(HANDLE curr,int proc_counter)
{
    bool flag = true;
    std::wstring AllPrivileges = L"";
    HANDLE hToken;
    DWORD cbNeeded;
    WCHAR szName[256];
    ULONG cbName;
    ULONG dwLangId;
    char array[MAX_PATH]={0};
    PTOKEN_PRIVILEGES pPriv;
    curr = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc_info[proc_counter].pid);
    if (!OpenProcessToken(curr, TOKEN_QUERY, &hToken))
    {
        proc_info[proc_counter].priveleg[0] = "no privelegies";
        return;
    }
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &cbNeeded))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            DWORD dwError = GetLastError();
            CloseHandle(hToken);
            proc_info[proc_counter].priveleg[0] = "no privelegies";
            return;
        }
    }
    pPriv = (PTOKEN_PRIVILEGES)_alloca(cbNeeded);
    _ASSERTE(pPriv != NULL);
    if (!GetTokenInformation(hToken, TokenPrivileges, pPriv, cbNeeded,&cbNeeded))
    {
        DWORD dwError = GetLastError();
        CloseHandle(hToken);
        proc_info[proc_counter].priveleg[0] = "no privelegies";
        return;
    }

    cbName = sizeof(szName) / sizeof(szName[0]);
    int kek = 0;
    for (UINT i = 0; i < pPriv->PrivilegeCount; i++)
    {

        if (LookupPrivilegeNameW(NULL, &pPriv->Privileges[i].Luid, szName, &cbName))
        {
            AllPrivileges += szName;
            AllPrivileges += L" ";
            strcpy(array,szName);
            proc_info[proc_counter].priveleg[kek] = array;
            kek++;
            flag = false;
        }


    }
    proc_info[proc_counter].privelegies_counter=kek;
    if (flag)
    {
        proc_info[proc_counter].priveleg[0]="no privelegies";
    }
}

void setProcessPrivileges(const QString &putProcessPrivileges,int proc_counter)
{
    QString change_parametr = putProcessPrivileges;
    std::wstring param = change_parametr.toStdWString().c_str();
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc_info[proc_counter].pid);
    int space_pos = param.find(L" ");
    std::wstring mode = param.substr(0, space_pos);
    param.erase(0, space_pos + 1);
    TOKEN_PRIVILEGES tp;
    LUID luid;
    bool bEnablePrivilege;
    if (param == L"on")
    {
        bEnablePrivilege = true;
    }
    else if (param == L"off")
    {
        bEnablePrivilege = false;
    }
    else
    {
        return;
    }
    HANDLE hToken(NULL);
    OpenProcessToken(processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    if (!LookupPrivilegeValueW(NULL,mode.c_str(),&luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %un", GetLastError());
        return;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    if (!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES),(PTOKEN_PRIVILEGES)NULL,(PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %x", GetLastError());
        return;
    }
    CloseHandle(processHandle);
    CloseHandle(hToken);
}

BOOL SetPrivilege(HANDLE hToken,LPCWSTR lpszPrivilege,BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL,lpszPrivilege,&luid))
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES),(PTOKEN_PRIVILEGES)NULL,(PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }
    return TRUE;
}
QString GetFileIntegrityLevel(LPCWSTR FileName,QString file_integrity)
{

    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL acl = 0;
    //printf("filename is %s\n",FileName);
    HANDLE hFile = CreateFileW(FileName, READ_CONTROL,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (ERROR_SUCCESS == GetSecurityInfo(hFile, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION|PROTECTED_SACL_SECURITY_INFORMATION| OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,NULL, NULL, 0, &acl, &pSD))
    {
        if (0 != acl && 0 < acl->AceCount)
        {
            SYSTEM_MANDATORY_LABEL_ACE* ace = 0;
            if (::GetAce(acl, 0, reinterpret_cast<void**>(&ace)))
            {
                SID* sid = reinterpret_cast<SID*>(&ace->SidStart);
                integrityLevel = sid->SubAuthority[0];
            }
        }
        PWSTR stringSD;
        ULONG stringSDLen = 0;
        ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &stringSD, &stringSDLen);
        if (pSD)
        {
            LocalFree(pSD);
        }
    }
    std::cout<<integrityLevel<<std::endl;
    if (integrityLevel == 0x0000)
        file_integrity= "none";
    else if (integrityLevel == 0x1000)
        file_integrity= "Low";
    else if (integrityLevel == 0x2000)
        file_integrity= "Medium";
    else if (integrityLevel == 0x3000)
        file_integrity= "High";
    else if (integrityLevel == 0x4000)
        file_integrity= "System";
    else
        file_integrity= "error";
    return file_integrity;
}

LPWSTR ConvertToLPWSTR( const std::wstring& s )
{
  LPWSTR ws = new wchar_t[s.size()+1];
  copy( s.begin(), s.end(), ws );
  ws[s.size()] = 0;
  return ws;
}


QString setFileInfo(wstring fileInfo,string paths)
{
    QString Info;
    ACCESS_ALLOWED_ACE* ace;
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    LPWSTR AcctName = NULL;
    LPWSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;
    hFile = CreateFileW(fileInfo.c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    std::cout<<"file info 3"<<std::endl;
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD dwErrorCode = 0;
        return 0;
    }
    std::cout<<"file info1"<<std::endl;
    PACL pDACL = NULL;
    PSID sidowner = NULL;
    PSID sidgroup = NULL;
    LPSTR oname=NULL;
    DWORD namelen;
    LPSTR doname = NULL;
    DWORD domainnamelen=0;
    SID_NAME_USE peUse;
    EXPLICIT_ACCESS ea;
    LPTSTR pszObjName=NULL;         // name of object
    SE_OBJECT_TYPE ObjectType; // type of object
    LPTSTR pszTrustee=NULL;     // trustee for new ACE
    TRUSTEE_FORM TrusteeForm;  // format of trustee structure
    DWORD dwAccessRights=0;    // access mask for new AC
    ACCESS_MODE AccessMode;   // type of ACE
    DWORD dwInheritance=0;
    dwRtnCode = GetSecurityInfo(hFile,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,&pSidOwner,NULL,NULL, NULL,&pSD);
    if (dwRtnCode != ERROR_SUCCESS)
    {
        DWORD dwErrorCode = 0;
        return 0;
    }
    SetLastError(0);
    if (!IsValidSid(pSidOwner))
    {
         std::cout << "SID supplied is invalid\n";
    }
    bRtnBool = LookupAccountSid(NULL,(PSID)pSidOwner,AcctName,(LPDWORD)&dwAcctName,DomainName,(LPDWORD)&dwDomainName,&eUse);
    AcctName = (LPWSTR)GlobalAlloc(GMEM_FIXED,dwAcctName);
    if (AcctName == NULL)
    {
        printf("33\n3");
        DWORD dwErrorCode = 0;
        return 0;
    }
    DomainName = (LPWSTR)GlobalAlloc(GMEM_FIXED,dwDomainName);
    if (DomainName == NULL)
    {
        printf("11111");
        DWORD dwErrorCode = 0;
        return 0;
    }
    bRtnBool = LookupAccountSid(NULL,pSidOwner,AcctName,(LPDWORD)&dwAcctName,DomainName,(LPDWORD)&dwDomainName,&eUse);                 // SID type
    if (bRtnBool == FALSE) {
        printf("1");
        DWORD dwErrorCode = 0;
        dwErrorCode = GetLastError();
        return 0;
    }
    else if (bRtnBool == TRUE)
        // Print the account name AcctName
     {
        Info+=" Account owner =";
        Info+=QString::fromStdWString(AcctName);
}
    DWORD dresult = GetNamedSecurityInfoA(paths.c_str(), SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL, NULL, &pDACL, NULL, &pSD);
    std::cout<< pDACL<<std::endl;
    if (dresult != ERROR_SUCCESS)
    {
         printf("2\n");
         return 0;
    }
    std::cout<<"file info 2"<<std::endl;
    std::cout<< pDACL<<std::endl;
    if (GetAce(pDACL,0,(LPVOID*)&ace) == FALSE)
          {
            wprintf(L"GetAce failed. GetLastError returned: %d\n", GetLastError());
            printf("3");
            return 0;
          }
      //  BOOL b = GetAce(pDACL, 1, (PVOID*)&ace);
      Info+="\n ACL:";
      std::cout<<"file info 2.1"<<std::endl;
      std::wcout << "ACE: mask:" << ace->Mask << " sidStart:" << ace->SidStart << "\n";

            if (DELETE & ace->Mask)
            {
                Info+="\nDELETE \n";
            }
            if (FILE_GENERIC_READ & ace->Mask)
            {
                Info+=" FILE_GENERIC_READ \n";
            }
            if (FILE_GENERIC_WRITE & ace->Mask)
            {
                Info+=" FILE_GENERIC_WRITE \n";
            }
            if (FILE_GENERIC_EXECUTE & ace->Mask)
            {
                Info+=" FILE_GENERIC_EXECUTE \n";
            }
            if (GENERIC_READ & ace->Mask)
            {
                Info+=" GENERIC_READ \n";
            }
            if (GENERIC_WRITE & ace->Mask)
            {
                Info+=" GENERIC_WRITE \n";
            }
            if (GENERIC_EXECUTE & ace->Mask)
            {
                Info+=" GENERIC_EXECUTE \n";
            }
            if (GENERIC_ALL & ace->Mask) {
                Info+=" GENERIC_ALL \n";
            }
            if (READ_CONTROL & ace->Mask) {
                Info+=" READ_CONTROL \n";
            }
            if (WRITE_DAC & ace->Mask) {
                Info+=" WRITE_DAC \n";
            }
            if (WRITE_OWNER & ace->Mask) {
                Info+=" WRITE_OWNER \n";
            }
            if (SYNCHRONIZE & ace->Mask)
            {
                Info+=" SYNCHRONIZE \n";
            }
      return Info;
}

void MainWindow::on_pushButton_clicked()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {return;}
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {CloseHandle(snap); return;}
    QStandardItemModel *model = new QStandardItemModel;
    QStandardItem *item;
    DWORD aProcesses[1024];
    DWORD cbNeeded;
    DWORD cProcesses;
    int proc_counter=0;
    PrintProcessList(snap);
do
    {
      if (pe.th32ProcessID != 0)
         {
           char total_parent[MAX_PATH]={0};
           char username[MAX_PATH]={0};
           char proc_name[MAX_PATH]={0};
           char path[MAX_PATH]={0};
           TCHAR parent[MAX_PATH]={0};
           for(int i=0;i<MAX_PATH;i++)
           {
              proc_info[proc_counter].process_name[i]=pe.szExeFile[i];
           }
           proc_info[proc_counter].pid=pe.th32ProcessID;//PIDByName(proc_info[proc_counter].process_name);
           int proc_type=0;
           if(IsWow64(PIDByName(proc_info[proc_counter].process_name))){proc_type=32;}
           else {proc_type=64;}
           proc_info[proc_counter].type=proc_type;
           get_path(proc_info[proc_counter].pid,path);
           strcpy( proc_info[proc_counter].path,path);
           QString defend;
           proc_info[proc_counter].PARENT_PID=call_parent(proc_info[proc_counter].pid,proc_info[proc_counter].process_name);
           if(check_dep(proc_info[proc_counter].pid)) { defend = DEP;  }
           if(check_aslr(proc_info[proc_counter].pid)){ defend = ASLR; }
           proc_info[proc_counter].defend=defend;
           NameByPid(proc_info[proc_counter].PARENT_PID,parent);
           strcpy(proc_info[proc_counter].parent,parent);
           getProcessUsername(snap, pe,username);
           GenerateProcessIntegrityLevel(proc_counter,proc_info[proc_counter].pid);
           IsPrivilege(snap,proc_counter);
           strcpy( proc_info[proc_counter].username,username);
           QString empty="   ";
           QString all= QString::number(proc_counter)+empty+ proc_info[proc_counter].process_name;
           item = new QStandardItem(all);
           model->appendRow(item);
           ui->listView->setModel(model);
           proc_counter++;
          }
   }
    while (Process32Next(snap, &pe));
    CloseHandle(snap);
}
void MainWindow::on_listView_indexesMoved(const QModelIndexList &indexes)
{


}
void MainWindow::on_listView_2_indexesMoved(const QModelIndexList &indexes)
{

}

void MainWindow::on_pushButton_2_clicked()
{
    QString str1 = ui->lineEdit->text();
    int proc_counter=str1.toInt();
    QStandardItemModel *model = new QStandardItemModel;
    QStandardItem *item;
    QString empty="\n";
    QString name="PROCESS NAME : ";
    QString PID="PID : ";
    QString TYPE ="TYPE(32/64 bit) : ";
    QString PATH ="PATH : ";
    QString defend="ASLR/DEP : ";
    QString PARENT_ID="PARENT ID : ";
    QString parent="PARENT : ";
    QString username="SID : ";
    QString ENVIROMENT="ENVIROMENT : ";
    QString DLL_LIST="DLL_LIST : ";
    QString enviroment;
    QString kek;
    QString INTEGRITY="INTEGRITY : ";
    QString integrity;
    QString privelegies= "PRIVELEGIES : ";
    switch(proc_info[proc_counter].integrity)
    {
       case 1 : {integrity="Low";break;}
       case 2 : {integrity="Medium";break;}
       case 3 : {integrity="High";break;}
       case 4 : {integrity="System";break;}
       case 0: {integrity="Unknown";break;}
    }
    int using_NET=0;

    for(int i=0;i<proc_info[proc_counter].dll_counter;i++)
     {
       kek= proc_info[proc_counter].dll_list[i];
       if(kek=="mscoree.dll" || kek=="MSCOREE.dll"|| kek=="mscoreei.dll")
       {
         using_NET=1;
       }
     }
    if(using_NET)
    {
       enviroment=".NET";
    }
    else { enviroment="Native code";}

    QString all=

            name + proc_info[proc_counter].process_name+ empty+ PID+
            QString::number(proc_info[proc_counter].pid) +empty+ TYPE+
            QString::number(proc_info[proc_counter].type)+empty+ PATH+
            proc_info[proc_counter].path+empty+ defend+
            proc_info[proc_counter].defend+ empty+ PARENT_ID+
            QString::number(proc_info[proc_counter].PARENT_PID)+empty+parent+
            proc_info[proc_counter].parent+empty + username+
            proc_info[proc_counter].username + empty+ENVIROMENT+enviroment+empty+
            INTEGRITY+ integrity+empty+privelegies;

    item = new QStandardItem(all);
    model->appendRow(item);

    for(int i=0;i<=proc_info[proc_counter].privelegies_counter;i++)
    {
        QString priv=proc_info[proc_counter].priveleg[i];
        item = new QStandardItem(priv);
        model->appendRow(item);
    }

    QString DLL= "DLL LIST : ";
    item = new QStandardItem(DLL);
    model->appendRow(item);

    for(int i=1;i<proc_info[proc_counter].dll_counter;i++)
     {
        QString kek= proc_info[proc_counter].dll_list[i];
        item = new QStandardItem(kek);
         model->appendRow(item);
     }

     ui->listView_2->setModel(model);
}
bool SetFileIntegrityLevel(QString level, LPCWSTR FileName)
    {
        QMessageBox msgBox;
        msgBox.setText(level);
        msgBox.exec();
        LPCWSTR INTEGRITY_SDDL_SACL_W;
        if (level == "Low")
        {
            INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;LW)";
            printf("Low\n");
        }
        else if (level == "Medium")
        {
            INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;ME)";
        }
        else if (level == "High")
        {
            INTEGRITY_SDDL_SACL_W = L"S:(ML;;NR;;;HI)";
        }
        DWORD dwErr = ERROR_SUCCESS;
        PSECURITY_DESCRIPTOR pSD = NULL;
        PACL pSacl = NULL;
        BOOL fSaclPresent = FALSE;
        BOOL fSaclDefaulted = FALSE;
        printf("\n0\n");
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, NULL))
        {
            printf("\n1\n");
            if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl,&fSaclDefaulted))
            {
                printf("\n2\n");
                dwErr = SetNamedSecurityInfoW((LPWSTR)FileName,SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,NULL, NULL, NULL, pSacl);
                if (dwErr == ERROR_SUCCESS)
                {
                    printf("\nOKAAAAy 3 \n");
                    return true;
                }
            }
            LocalFree(pSD);
            return false;
        }
        return false;
    }

void setchangeACL(QString changeACL,QString path)//DENY/GRANT PERM
{
    QString file_name = path;
    QString acl_changes=changeACL;
    std::wstring changes=acl_changes.toStdWString().c_str();
    std::wcout<<changes<<std::endl;
    /*realisation*/
    int mode;
    long permission;
    std::wstring permissionValue;
    PSID pEveryoneSID = NULL;
    PACL pACL = NULL;
    EXPLICIT_ACCESS ea[1];
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    int space_pos = changes.find(L" ");
    std::wstring accessMode = changes.substr(0,space_pos);
    changes.erase(0,space_pos+1);
    if(accessMode==L"on")//+
    {
        mode = 1;
    }
    else if(accessMode==L"off")//-
    {
        mode = 3;
    }
    else if(accessMode == L"")
    {
        return;
    }
    if(changes==L"GR")//GR
    {
        permission = FILE_GENERIC_READ;
    }
    else if(changes==L"GW")//GW
    {
        permission = FILE_GENERIC_WRITE;
    }
    else if(changes==L"GE")//GE
    {
        permission = GENERIC_EXECUTE;
    }
    else if(changes==L"GA")//GA
    {
        permission = ~0x10000000;
    }
    else if(changes==L"")
    {

    }
    PSECURITY_DESCRIPTOR pSD = NULL;
    AllocateAndInitializeSid(&SIDAuthWorld, 1,SECURITY_WORLD_RID,0, 0, 0, 0, 0, 0, 0,&pEveryoneSID);
    DWORD dwRes = GetNamedSecurityInfo(file_name.toStdWString().c_str(), SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL, NULL, &pACL, NULL, &pSD);
       if (ERROR_SUCCESS != dwRes)
       {
           printf( "GetNamedSecurityInfo Error %u\n", dwRes );
       }
    ZeroMemory(&ea, 1 * sizeof(EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = permission;
    ea[0].grfAccessMode = (ACCESS_MODE)mode;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    SetEntriesInAclW(1, ea, pACL, &pNewDACL);
        if (ERROR_SUCCESS != dwRes)  {
            printf( "SetEntriesInAcl Error %u\n", dwRes );
        }
    LPWSTR buf = ConvertToLPWSTR(file_name.toStdWString());
    dwRes = SetNamedSecurityInfoW(buf, SE_FILE_OBJECT,
              DACL_SECURITY_INFORMATION,
              NULL, NULL, pNewDACL, NULL);
    if (pEveryoneSID)
        FreeSid(pEveryoneSID);
    if (pACL)
        LocalFree(pACL);
    if (pSD)
        LocalFree(pSD);
}

void setChangeHost(const QString &changeHost,QString path)
{
    QString file_name = path;
    QString host_changes=changeHost;
    std::string host_Val=host_changes.toStdString();
    std::wstring changes=host_changes.toStdWString().c_str();
    HANDLE token;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    std::wstring filename =path.toStdWString();
    std::wstring newuser =host_changes.toStdWString();
    DWORD len;
    PSECURITY_DESCRIPTOR security = NULL;
    PSID sidPtr = NULL;
    int retValue = 1;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
        {
            SetPrivilege(token, L"SeTakeOwnershipPrivilege", 1);
            SetPrivilege(token, L"SeSecurityPrivilege", 1);
            SetPrivilege(token, L"SeBackupPrivilege", 1);
            SetPrivilege(token, L"SeRestorePrivilege", 1);
        }
     else retValue = 0;
     if (retValue)
       {
            GetFileSecurityW((LPCWSTR)filename.c_str(), OWNER_SECURITY_INFORMATION, security, 0, &len);
            security = (PSECURITY_DESCRIPTOR)malloc(len);
            if (!InitializeSecurityDescriptor(security, SECURITY_DESCRIPTOR_REVISION))
                retValue = 0;
        }

        // Get the sid for the username
        if (retValue) {
            wchar_t domainbuf[4096];
            DWORD sidSize = 0;
            DWORD bufSize = 4096;
            SID_NAME_USE sidUse;

            LookupAccountNameW(NULL, newuser.c_str(), sidPtr, &sidSize, domainbuf, &bufSize, &sidUse);
            PSID sid = (PSID)malloc(sidSize);
            if (!LookupAccountNameW(NULL, newuser.c_str(), (PSID)sid, &sidSize, domainbuf, &bufSize, &sidUse))
            {
                retValue = 0;
                return;
            }

        }
    if (retValue && !SetSecurityDescriptorOwner(security, sidPtr, 0))
    retValue = 0;
    if (retValue)
    retValue = SetFileSecurity(filename.c_str(), OWNER_SECURITY_INFORMATION, security);
    if (security) free(security);
    //if (sid) free(sid);
    return;
}



void MainWindow::on_pushButton_3_clicked()
{
    QString level = ui->lineEdit_2->text();
    QString str1 = ui->lineEdit->text();
    int proc_counter=str1.toInt();
    setProcessIntegrityLevel(level,proc_counter);
}
void MainWindow::on_pushButton_4_clicked()
{
  QString name_on_off = ui->lineEdit_3->text();
  QString str1 = ui->lineEdit->text();
  int proc_counter=str1.toInt();
  setProcessPrivileges(name_on_off,proc_counter);
}
void MainWindow::on_pushButton_5_clicked()
{
    QStandardItemModel *model = new QStandardItemModel;
    QStandardItem *item;
    char path[MAX_PATH]={0};
    QString file_integrity;
    QString username;
    QString str1 = ui->lineEdit_4->text();
    std::wstring fileName=str1.toStdWString().c_str();
    std::string fff = str1.toStdString().c_str();
    std::wcout<<fileName<<std::endl;
    QByteArray ba = str1.toLocal8Bit();
    const char *c_str2 = ba.data();
    LPCWSTR paths=convertCharArrayToLPCWSTR(c_str2);
    char info[100]={0};
    username=( setFileInfo(fileName,fff));
    file_integrity=("INTEGRITY LEVEL : " + GetFileIntegrityLevel(paths,file_integrity));
    item = new QStandardItem(str1);
    model->appendRow(item);
    item = new QStandardItem(file_integrity);
    model->appendRow(item);
    item = new QStandardItem(username);
    model->appendRow(item);
    ui->listView_3->setModel(model);
}
void MainWindow::on_pushButton_6_clicked()
{
    QString integrity = ui->lineEdit_5->text();
    QString filename = ui->lineEdit_4->text();
    QByteArray ba = filename.toLocal8Bit();
    const char *c_str2 = ba.data();
    LPCWSTR paths=convertCharArrayToLPCWSTR(c_str2);
    SetFileIntegrityLevel(integrity,paths);

}
void MainWindow::on_pushButton_7_clicked()
{
    QString acl = ui->lineEdit_6->text();
    QString path = ui->lineEdit_4->text();
    std::wstring fileName=acl.toStdWString().c_str();
    setchangeACL(acl,path);
}
void MainWindow::on_pushButton_8_clicked()
{
    QString host = ui->lineEdit_7->text();
    QString path = ui->lineEdit_4->text();
    setChangeHost(host,path);
}

void MainWindow::on_lineEdit_2_cursorPositionChanged(int arg1, int arg2)
{

}

void MainWindow::on_lineEdit_cursorPositionChanged(int arg1, int arg2)
{

}


void MainWindow::on_lineEdit_3_cursorPositionChanged(int arg1, int arg2)
{

}


void MainWindow::on_lineEdit_4_cursorPositionChanged(int arg1, int arg2)
{

}

void MainWindow::on_listView_3_indexesMoved(const QModelIndexList &indexes)
{

}


void MainWindow::on_lineEdit_5_cursorPositionChanged(int arg1, int arg2)
{

}

void MainWindow::on_lineEdit_6_cursorPositionChanged(int arg1, int arg2)
{

}

void MainWindow::on_lineEdit_7_cursorPositionChanged(int arg1, int arg2)
{

}



