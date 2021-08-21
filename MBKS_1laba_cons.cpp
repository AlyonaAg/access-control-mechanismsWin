#pragma comment(lib,"Version.lib")
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <winver.h>
#include <tlhelp32.h>
#include <conio.h>
#include <string>
#include <Sddl.h>
#include <io.h>
#include <fcntl.h>
#include <fstream>
#include <AclAPI.h>
#include <strsafe.h>


#define MAX_NAME 256

using namespace std;

FILE* file;
FILE* file_lib;
FILE* file_priv;
DWORD cProcesses;
int count_proc = 0;
PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;

int GetProcessList();
int GetInfoObject(char* Path);
int SetOwnerInternal(char* Path, char* Owner);
int ChangeIntegrityLevel(char* Path, long lLevel);
int AddAce(char* Path, bool typeACL, char* Owner, ACCESS_MODE aclType, ACCESS_MASK Mask);
int ChangeACL(char* Path, int Num, bool aclType, ACCESS_MASK Mask);
int DeleteACL(char* Path, int DelNum, bool aclType);
int SetProcessIntegrityLevel(DWORD processID, DWORD dwIntegrityLevel);
void SetPrivilegeChoose(HANDLE hProcess, int privileges, BOOL mode);

bool OpenSecurityDescriptor(char* wchDirName)
{
    // Определяем файл это или директория 
    bool ItIsAFile;
    DWORD fAttr = GetFileAttributesA(wchDirName);
    if (fAttr & FILE_ATTRIBUTE_DIRECTORY)
        ItIsAFile = false;
    else
        ItIsAFile = true;

    // Открываем дескриптор безопасности 
    DWORD SdLength = 0;
    DWORD dwRetCode;

    // Получаем длину дескриптора безопасности
    if (!GetFileSecurityA(wchDirName, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
        SecurityDescriptor, 0, &SdLength))
    {
        dwRetCode = GetLastError();
        if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
            // распределяем память для буфера
            SecurityDescriptor = (SECURITY_DESCRIPTOR*) new char[SdLength];
        else
        {
            printf("GetFileSecurity");
            return false;
        }
    }

    // Читаем дескриптор безопасности
    if (!GetFileSecurityA(wchDirName, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
        SecurityDescriptor, SdLength, &SdLength))
    {
        printf("GetFileSecurity");
        return false;
    }

    return true;
}

ACCESS_MASK GetMask(int mas[17])
{
    ACCESS_MASK aMask = 0;
    if (mas[0])
        aMask |= GENERIC_ALL;
    if (mas[1])
        aMask |= GENERIC_READ;
    if (mas[2])
        aMask |= GENERIC_WRITE;
    if (mas[3])
        aMask |= GENERIC_EXECUTE;
    if (mas[4])
        aMask |= DELETE;
    if (mas[5])
        aMask |= READ_CONTROL;
    if (mas[6])
        aMask |= WRITE_DAC;
    if (mas[7])
        aMask |= FILE_READ_DATA | FILE_LIST_DIRECTORY;
    if (mas[8])
        aMask |= FILE_WRITE_DATA | FILE_ADD_FILE;
    if (mas[9])
        aMask |= FILE_APPEND_DATA | FILE_ADD_SUBDIRECTORY;
    if (mas[10])
        aMask |= FILE_EXECUTE | FILE_TRAVERSE;
    if (mas[11])
        aMask |= WRITE_OWNER;
    if (mas[12])
        aMask |= FILE_READ_ATTRIBUTES;
    if (mas[13])
        aMask |= FILE_WRITE_ATTRIBUTES;
    if (mas[14])
        aMask |= FILE_READ_EA;
    if (mas[15])
        aMask |= FILE_WRITE_EA;

    return aMask;
}


int main(int argc, char *argv[])
{
    system("chcp 1251 > nul");
    setlocale(LC_ALL, "Russian");
    DWORD aProcesses[1024], cbNeeded;
    unsigned int i, result = 0;

    for (int i = 0; i < 36; i++)
        SetPrivilegeChoose(GetCurrentProcess(), i, true);

    if (!strncmp(argv[1], "procinf", strlen("procinf")) && strlen(argv[1]) == strlen("procinf"))
    {
        //SetProcessPrivilege(1);
        file = fopen("process_info.json", "w");
        file_lib = fopen("lib.json", "w");
        file_priv = fopen("privileges.json", "w");
        printf("receiving the information:\n");
        // Получение списка индентификаторов процессов
        if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
            return GetLastError();

        cProcesses = cbNeeded / sizeof(DWORD);
        //Вывод процессов и библиотек в файл
        result = GetProcessList();
        fclose(file);
        fclose(file_lib);
        fclose(file_priv);
        if (result)
            return result;
    }
    if ((!strncmp(argv[1], "objinf", strlen("objinf"))))
    {
        file = fopen("obj_info.json", "w");
        result = GetInfoObject(argv[2]);
        if (result)
            return result;
        fclose(file);
    }
    if ((!strncmp(argv[1], "objchng_o", strlen("objchng_o"))))
    {
        result=SetOwnerInternal(argv[2], argv[3]);
        if (result)
            return result;
    }
    if ((!strncmp(argv[1], "objchng_l", strlen("objchng_l"))))
    {
        long long int level;
        level = atoi(argv[3]);
        if (level == 0)
            level = SECURITY_MANDATORY_UNTRUSTED_RID;
        else if (level == 1)
            level = SECURITY_MANDATORY_LOW_RID;
        else if (level == 2)
            level = SECURITY_MANDATORY_MEDIUM_RID;
        else if (level == 3)
            level = SECURITY_MANDATORY_HIGH_RID;
        result=ChangeIntegrityLevel(argv[2], level);
        if (result)
            return result;
    }
    if ((!strncmp(argv[1], "objchng_ad", strlen("objchng_ad"))))
    {
        OpenSecurityDescriptor(argv[2]);
        result=DeleteACL(argv[2], atoi(argv[3]), atoi(argv[4]));
        if (result)
            return result;
    }
    if ((!strncmp(argv[1], "objchng_ac", strlen("objchng_ac"))))
    {
        ACCESS_MASK Mask = 0;
        OpenSecurityDescriptor(argv[2]);
        int mas_mask[17] = { 0 };
        for (int i = 5; i < argc; i++)
            mas_mask[atoi(argv[i])] = 1;
        Mask = GetMask(mas_mask);

        result = ChangeACL(argv[2], atoi(argv[3]), atoi(argv[4]), Mask);
        if (result)
            return result;
    }
    if ((!strncmp(argv[1], "procchng_l", strlen("procchng_l"))))
    {
        long long int level;
        level = atoi(argv[3]);
        if (level == 0)
            level = SECURITY_MANDATORY_UNTRUSTED_RID;
        else if (level == 1)
            level = SECURITY_MANDATORY_LOW_RID;
        else if (level == 2)
            level = SECURITY_MANDATORY_MEDIUM_RID;
        else if (level == 3)
            level = SECURITY_MANDATORY_HIGH_RID;
        result = SetProcessIntegrityLevel(atoi(argv[2]), level);
        if (result)
            return result;
    }
    if ((!strncmp(argv[1], "procchng_p", strlen("procchng_p"))))
    {
        int mas_priv[36] = { 0 };
        for (int i = 3; i < argc; i++)
            mas_priv[atoi(argv[i])] = 1;

        HANDLE hProcess;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[2]));

        for (int i = 0; i < 36; i++)
        {
            if (mas_priv[i])
                SetPrivilegeChoose(hProcess, i, true);
            else
                SetPrivilegeChoose(hProcess, i, false);
        }
    }
    if ((!strncmp(argv[1], "objchng_aa", strlen("objchng_aa"))))
    {
        ACCESS_MODE mode = SET_ACCESS;
        ACCESS_MASK Mask = 0;

        if (atoi(argv[5]) && atoi(argv[3]))
            mode = SET_ACCESS;
        else if (atoi(argv[5]) && !atoi(argv[3]))
            mode = SET_AUDIT_SUCCESS;
        else if (!atoi(argv[5]) && atoi(argv[3]))
            mode = DENY_ACCESS;
        else if (!atoi(argv[5]) && !atoi(argv[3]))
            mode = SET_AUDIT_FAILURE;

        int mas_mask[17] = { 0 };
        for (int i = 6; i < argc; i++)
            mas_mask[atoi(argv[i])] = 1;
        Mask = GetMask(mas_mask);

        result=AddAce(argv[2], atoi(argv[3]), argv[4], mode, Mask);
        if (result)
            return result;
    }
    return 0;
}


//--------------------------------------------- ИЗМЕНЕНИЕ ИНФОРМАЦИИ О БЕЗОПАСНОСТИ ПРОЦЕССА -------------------------------------------//

// Изменение уровня целостности у процесса
int SetProcessIntegrityLevel(DWORD processID, DWORD dwIntegrityLevel)
{
    HANDLE hToken;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);
    if (!hToken)
        return GetLastError();

    BOOL                  fRet = FALSE;
    PSID                  pIntegritySid = NULL;
    TOKEN_MANDATORY_LABEL TIL = { 0 };

    // Low integrity SID
    WCHAR wszIntegritySid[32];

    if (FAILED(StringCbPrintf(wszIntegritySid, sizeof(wszIntegritySid), L"S-1-16-%d", dwIntegrityLevel)))
        return GetLastError();

    fRet = ConvertStringSidToSid(wszIntegritySid, &pIntegritySid);

    if (!fRet)
        return GetLastError();

    TIL.Label.Attributes = SE_GROUP_INTEGRITY;
    TIL.Label.Sid = pIntegritySid;

    fRet = SetTokenInformation(hToken, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid));

    if (!fRet)
        return GetLastError();
    return 0;
}

//------------------------------------------------- ИНФОРМАЦИЯ О БЕЗОПАСНОСТИ ПРОЦЕССА -------------------------------------------------//

// Получение уровня целостности процесса
void GetProcessIntegrityLevel(DWORD processID)
{
    HANDLE hToken;
    HANDLE hProcess;

    DWORD dwLengthNeeded;
    DWORD dwError = ERROR_SUCCESS;

    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel;
    
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken))
    {
        // Get the Integrity level.
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded))
        {
            dwError = GetLastError();
            if (dwError == ERROR_INSUFFICIENT_BUFFER)
            {
                pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
                if (pTIL != NULL)
                {
                    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
                    {
                        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
                        if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
                            fprintf(file, "\t\t\"integrity\": \"untrusted\"\n");
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_LOW_RID && dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
                            fprintf(file, "\t\t\"integrity\": \"low\"\n");
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
                            fprintf(file, "\t\t\"integrity\": \"medium\"\n");
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
                            fprintf(file, "\t\t\"integrity\": \"high\"\n");
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID && dwIntegrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
                            fprintf(file, "\t\t\"integrity\": \"system\"\n");
                        else if (dwIntegrityLevel == SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
                            fprintf(file, "\t\t\"integrity\": \"protected process\"\n");
                    }
                    else
                        fprintf(file, "\t\t\"integrity\": \"untrusted\"\n");
                    LocalFree(pTIL);
                }
                else
                    fprintf(file, "\t\t\"integrity\": \"untrusted\"\n");
            }
            else fprintf(file, "\t\t\"integrity\": \"untrusted\"\n");
        }
        else fprintf(file, "\t\t\"integrity\": \"untrusted\"\n");
        CloseHandle(hToken);
    }
    else
        fprintf(file, "\t\t\"integrity\": \"untrusted\"\n");
}

// Получение привилегий
void GetPrivileges(DWORD processID)
{
    HANDLE curr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    fprintf(file_priv, "\t\t\"privileges\": [\n");
    bool flag = true;

    DWORD cbNeeded;
    WCHAR szName[8192];
    HANDLE hToken;
    ULONG cbName;
    ULONG dwLangId;
    PTOKEN_PRIVILEGES pPriv;
    if (!OpenProcessToken(curr, TOKEN_QUERY, &hToken))
    {
        fprintf(file_priv, "\t\t\t\" \"\n\t\t]\n");
        return;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &cbNeeded))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            CloseHandle(hToken);
            fprintf(file_priv, "\t\t\t\" \"\n\t\t]\n");
            return;
        }
    }

    pPriv = (PTOKEN_PRIVILEGES)_alloca(cbNeeded);
    _ASSERTE(pPriv != NULL);
    if (!GetTokenInformation(hToken, TokenPrivileges, pPriv, cbNeeded, &cbNeeded))
    {
        DWORD dwError = GetLastError();
        CloseHandle(hToken);
        fprintf(file_priv, "\t\t\t\" \"\n\t\t]\n");
        return;
    }
    cbName = sizeof(szName) / sizeof(szName[0]);
    for (UINT i = 0; i < pPriv->PrivilegeCount; i++)
    {
        if (LookupPrivilegeNameW(NULL, &pPriv->Privileges[i].Luid, szName, &cbName))
        {
            if (!flag)
                fwprintf(file_priv, L",\n", szName);
            fprintf(file_priv, "\t\t\t{\n");
            fwprintf(file_priv, L"\t\t\t\t\"privilege\": \"%ls\",\n", szName);
            if (pPriv->Privileges[i].Attributes== SE_PRIVILEGE_ENABLED)
                fprintf(file_priv, "\t\t\t\t\"mode\": \"enabled\"\n");
            else if (pPriv->Privileges[i].Attributes == 0)
                fprintf(file_priv, "\t\t\t\t\"mode\": \"disabled\"\n");
            else
                fprintf(file_priv, "\t\t\t\t\"mode\": \"default enabled\"\n");
            flag = false;
            fprintf(file_priv, "\t\t\t}");
        }
        else
        {
            if (LookupPrivilegeNameW(NULL, &pPriv->Privileges[i].Luid, szName, &cbName))
            {
                if (!flag)
                    fwprintf(file_priv, L",\n", szName);
                fprintf(file_priv, "\t\t\t{\n");
                fwprintf(file_priv, L"\t\t\t\t\"privilege\": \"%ls\",\n", szName);
                if (pPriv->Privileges[i].Attributes == SE_PRIVILEGE_ENABLED)
                    fprintf(file_priv, "\t\t\t\t\"mode\": \"enabled\"\n");
                else if (pPriv->Privileges[i].Attributes == 0)
                    fprintf(file_priv, "\t\t\t\t\"mode\": \"disabled\"\n");
                else
                    fprintf(file_priv, "\t\t\t\t\"mode\": \"default enabled\"\n");
                flag = false;
                fprintf(file_priv, "\t\t\t}");
            }
        }
    }
    if (flag)
    {
        fprintf(file_priv, "\t\t\t\" \"\n\t\t]\n");
        return;
    }
    fprintf(file_priv, "\n\t\t]\n");
    CloseHandle(hToken);
}

//------------------------------------------------- ИЗМЕНЕНИЕ ИНФОРМАЦИИ ОБ ОБЪЕКТАХ ОС ------------------------------------------------//

// Изменение владельца
int SetOwnerInternal(char* Path, char* Owner)
{
    PSID Sid = nullptr;
    if (!ConvertStringSidToSidA(Owner, &Sid))
    {
        SID_NAME_USE Use;
        DWORD cSid = 0, ReferencedDomain = 0;
        int res = LookupAccountNameA(nullptr, Owner, nullptr, &cSid, nullptr, &ReferencedDomain, &Use);
        if (cSid)
        {
            Sid = LocalAlloc(LMEM_FIXED, cSid);
            if (Sid)
            {
                char* ReferencedDomainName = new char[ReferencedDomain];
                if (ReferencedDomainName)
                {
                    if (!LookupAccountNameA(nullptr, Owner, Sid, &cSid, ReferencedDomainName, &ReferencedDomain, &Use))
                    {
                    }
                }
            }
        }
    }
    if (Sid)
    {
        DWORD dwResult = SetNamedSecurityInfoA(Path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, Sid, nullptr, nullptr, nullptr);
        if (dwResult != ERROR_SUCCESS)
            return GetLastError();
    }
    else
        return GetLastError();
    return 0;
}

// Изменяет уровень целостности файла
int ChangeIntegrityLevel(char* Path, long lLevel)
{
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL acl = 0;
    int res;
    if (ERROR_SUCCESS == (res = GetNamedSecurityInfoA(Path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, 0, 0, 0, &acl, &SecurityDescriptor)))
    {
        SID sid = { SID_REVISION, 1, {SECURITY_MANDATORY_LABEL_AUTHORITY}, lLevel };
        PACL Sacl;
        BOOL RtnBool, SaclPresent;
        if (!GetSecurityDescriptorSacl(SecurityDescriptor, (LPBOOL)&SaclPresent, &Sacl, (LPBOOL)&RtnBool))
            return GetLastError();

        DWORD sznSacl = sizeof(SYSTEM_MANDATORY_LABEL_ACE); // размер нового sacl 
        if (SaclPresent && Sacl != NULL)
            sznSacl += Sacl->AclSize + 50;
        else
            sznSacl += sizeof(ACL) + 50;

        // буфер может быть больше требуемого размера 
        PACL newSacl = (PACL)LocalAlloc(LPTR, sznSacl);
        if (!InitializeAcl(newSacl, sznSacl, ACL_REVISION))
            return GetLastError();

        // Пройдемся посмотрим есть ли уже эта метка
        // Если есть то пропустим этот ACE, остальные просто копируем 
        LPVOID lpAce;
        ACE_HEADER* phAce;
        if (SaclPresent && Sacl != NULL)
        {
            for (int i = 0; i < Sacl->AceCount; i++)
            {
                if (!GetAce(Sacl, i, &lpAce))
                    continue;
                phAce = (ACE_HEADER*)lpAce;
                if (phAce->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
                    if (!AddAce(newSacl, ACL_REVISION, MAXDWORD, lpAce, phAce->AceSize))
                        return GetLastError();
            }
        }
        DWORD AceFlags = 0;
        DWORD MandatoryPolicy = SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP;
        if (!AddMandatoryAce(newSacl, ACL_REVISION, AceFlags, MandatoryPolicy, &sid))
            return GetLastError();

        if (SetNamedSecurityInfoA(Path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, newSacl) != ERROR_SUCCESS)
            return GetLastError();
        return 0;
    }
    else
        return GetLastError();

    return 0;
}

// Добавляем новую запись в ACL
int AddAce(char* Path, bool typeACL, char* Owner, ACCESS_MODE ACLmode, ACCESS_MASK Mask)
{
    PSID Sid = nullptr;
    if (!ConvertStringSidToSidA(Owner, &Sid))
    {
        SID_NAME_USE Use;
        DWORD cSid = 0, ReferencedDomain = 0;
        int res = LookupAccountNameA(nullptr, Owner, nullptr, &cSid, nullptr, &ReferencedDomain, &Use);
        if (cSid)
        {
            Sid = LocalAlloc(LMEM_FIXED, cSid);
            if (Sid)
            {
                char* ReferencedDomainName = new char[ReferencedDomain];
                if (ReferencedDomainName)
                {
                    if (!LookupAccountNameA(nullptr, Owner, Sid, &cSid, ReferencedDomainName, &ReferencedDomain, &Use))
                    {
                    }
                }
            }
        }
    }
    if (Sid)
    {
        DWORD dwRes = 0;
        PACL pOldACL = NULL, pNewACL = NULL;
        PSECURITY_DESCRIPTOR pSD = NULL;
        EXPLICIT_ACCESS ea;

        if (typeACL)
            dwRes = GetNamedSecurityInfoA(Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldACL, NULL, &pSD);
        else
            dwRes = GetNamedSecurityInfoA(Path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &pOldACL, &pSD);
        if (ERROR_SUCCESS != dwRes) 
            return GetLastError();

        ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
        ea.grfAccessPermissions = Mask;
        ea.grfAccessMode = ACLmode;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.ptstrName = (LPWSTR)Sid;

        dwRes = SetEntriesInAcl(1, &ea, pOldACL, &pNewACL);
        if (ERROR_SUCCESS != dwRes) 
            return GetLastError();

        if (typeACL)
            dwRes = SetNamedSecurityInfoA(Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewACL, NULL);
        else
            dwRes = SetNamedSecurityInfoA(Path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, pNewACL);
        if (ERROR_SUCCESS != dwRes) 
            return GetLastError();
        return 0;
    }
    else
        return GetLastError();
    return 0;
}

// Удаление записи ACE
int DeleteACL(char* Path, int DelNum, bool aclType)
{
    if (SecurityDescriptor == NULL)
        return GetLastError();

    PACL Acl = NULL;
    BOOL RtnBool, AclPresent;
    if (aclType)
    {
        if (!GetSecurityDescriptorDacl(SecurityDescriptor, (LPBOOL)&AclPresent, &Acl, (LPBOOL)&RtnBool))
            return GetLastError();
    }
    else
    {
        if (!GetSecurityDescriptorSacl(SecurityDescriptor, (LPBOOL)&AclPresent, &Acl, (LPBOOL)&RtnBool))
            return GetLastError();
    }
    if (!AclPresent)
        return GetLastError();
    DeleteAce(Acl, DelNum);

    if (aclType)
    {
        if (SetNamedSecurityInfoA(Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Acl, NULL) != ERROR_SUCCESS)
            return GetLastError();
    }
    else
    {
        if (SetNamedSecurityInfoA(Path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, Acl) != ERROR_SUCCESS)
            return GetLastError();
    }
    return 0;
}

// Изменить запись ACE
int ChangeACL(char* Path, int Num, bool aclType, ACCESS_MASK Mask)
{
    if (SecurityDescriptor == NULL)
        return GetLastError();

    PACL Acl = NULL;
    BOOL RtnBool, AclPresent;
    if (aclType)
    {
        if (!GetSecurityDescriptorDacl(SecurityDescriptor, (LPBOOL)&AclPresent, &Acl, (LPBOOL)&RtnBool))
            return GetLastError();
    }
    else
    {
        if (!GetSecurityDescriptorSacl(SecurityDescriptor, (LPBOOL)&AclPresent, &Acl, (LPBOOL)&RtnBool))
            return GetLastError();
    }

    if (!AclPresent)
        return GetLastError();

    LPVOID lpAce;
    GetAce(Acl, Num, &lpAce);			// получаем необходимый указатель 
    ACE_HEADER* phAce = (ACE_HEADER*)lpAce;
    ACCESS_ALLOWED_ACE* alAce = NULL;
    ACCESS_DENIED_ACE* deAce = NULL;
    SYSTEM_AUDIT_ACE* auAce = NULL;

  /*  switch (phAce->AceType)
    {
    case ACCESS_ALLOWED_ACE_TYPE:
        alAce = (ACCESS_ALLOWED_ACE*)lpAce;
        alAce->Mask = Mask;
        break;
    case ACCESS_DENIED_ACE_TYPE:
        deAce = (ACCESS_DENIED_ACE*)lpAce;
        deAce->Mask = Mask;
        break;
    case SYSTEM_AUDIT_ACE_TYPE:
        auAce = (SYSTEM_AUDIT_ACE*)lpAce;
        auAce->Mask = Mask;
        break;
    default:
        printf("Unknown type of ACE");
    }*/
    alAce = (ACCESS_ALLOWED_ACE*)lpAce;
    alAce->Mask = Mask;
   // break;
    if (aclType)
    {
        if (SetNamedSecurityInfoA(Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Acl, NULL) != ERROR_SUCCESS)
            return GetLastError();
    }
    else
    {
        if (SetNamedSecurityInfoA(Path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, Acl) != ERROR_SUCCESS)
            return GetLastError();
    }
    return 0;
}


//------------------------------------------------------ ИНФОРМАЦИЯ ОБ ОБЪЕКТАХ ОС -----------------------------------------------------//

// Получение владельца
void GetOwner(char *Path)
{
    PSID pOwnerSid;
    PSECURITY_DESCRIPTOR pSD;

    if (GetNamedSecurityInfoA(Path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD) != ERROR_SUCCESS)
    {
        fprintf(file, "\t\"SID\": \" \",\n");
        fprintf(file, "\t\"owner\": \" \",\n");
        return;
    }

    DWORD SID;
    memcpy(&SID, pOwnerSid, sizeof(PSID));
    fprintf(file, "\t\"SID\": \"%d\",\n", SID);

    DWORD dwSize = MAX_NAME;
    DWORD dwLength = 0;
    SID_NAME_USE SidType;
    char lpName[MAX_NAME];
    char lpDomain[MAX_NAME];
    LookupAccountSidA(NULL, pOwnerSid, lpName, &dwSize, lpDomain, &dwSize, &SidType);
    fprintf(file, "\t\"owner\": \"%s\",\n", lpName);
}

// Получение уровня целостности файла
void GetFileIntegrityLevel(char* Path)
{
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL acl = 0;
    if (ERROR_SUCCESS == GetNamedSecurityInfoA(Path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, &acl, &pSD))
    {
        PACL Sacl; BOOL SaclPresent; // признак присутствия списка SACL
        BOOL RtnBool;

        if (!GetSecurityDescriptorSacl(pSD, (LPBOOL)&SaclPresent, &Sacl, (LPBOOL)&RtnBool))
        {
            fprintf(file, "\t\"integrity level\": \"MEDIUM\",\n");
            return;
        }

        if (!SaclPresent || (SaclPresent && (Sacl == NULL)) || Sacl->AceCount == 0)
        {
            // По умолчанию установлен средний уровень 
            fprintf(file, "\t\"integrity level\": \"MEDIUM\",\n");
            return;
        }

        LPVOID lpAce; // указатель на элемент ACE

        if (!GetAce(Sacl, Sacl->AceCount - 1, &lpAce))
        {
            fprintf(file, "\t\"integrity level\": \"MEDIUM\",\n");
            return;
        }

        ACE_HEADER* AceHeader = (ACE_HEADER*)lpAce;
        SYSTEM_MANDATORY_LABEL_ACE* maAce = NULL;
        if (AceHeader->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
        {
            fprintf(file, "\t\"integrity level\": \"MEDIUM\",\n");
            return;
        }

        maAce = (SYSTEM_MANDATORY_LABEL_ACE*)lpAce;
        SID* sid = (SID*)&(maAce->SidStart);

        if (sid->SubAuthority[0] == SECURITY_MANDATORY_UNTRUSTED_RID)
            fprintf(file, "\t\"integrity level\": \"UNTRUSTED\",\n");
        else if (sid->SubAuthority[0] >= SECURITY_MANDATORY_LOW_RID && sid->SubAuthority[0] < SECURITY_MANDATORY_MEDIUM_RID)
            fprintf(file, "\t\"integrity level\": \"LOW\",\n");
        else if (sid->SubAuthority[0] >= SECURITY_MANDATORY_MEDIUM_RID && sid->SubAuthority[0] < SECURITY_MANDATORY_HIGH_RID)
            fprintf(file, "\t\"integrity level\": \"MEDIUM\",\n");
        else if (sid->SubAuthority[0] >= SECURITY_MANDATORY_HIGH_RID && sid->SubAuthority[0] < SECURITY_MANDATORY_SYSTEM_RID)
            fprintf(file, "\t\"integrity level\": \"HIGH\",\n");
        else if (sid->SubAuthority[0] >= SECURITY_MANDATORY_SYSTEM_RID && sid->SubAuthority[0] < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
            fprintf(file, "\t\"integrity level\": \"SYSTEM\",\n");
        else if (sid->SubAuthority[0] == SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
            fprintf(file, "\t\"integrity level\": \"PROTECTED PROCESS\",\n");
    }
   
}

// Получение списков DACL
void GetDACL(char* Path)
{
    PACL a;
    PSECURITY_DESCRIPTOR pSD;
    int flag = 0;
    if (GetNamedSecurityInfoA(Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &a, NULL, &pSD) != ERROR_SUCCESS)
    {
        fprintf(file, "\t\"DACL\": [\n");
        fprintf(file, "\t]\n");
        return;
    }
 
    if (a == NULL)
    {
        fprintf(file, "\t\"DACL\": [\n");
        fprintf(file, "\t]\n");
        return;
    }

    ACL_REVISION_INFORMATION* buf = (ACL_REVISION_INFORMATION*)malloc(sizeof(ACL_REVISION_INFORMATION));
    GetAclInformation(a, buf, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation);
    LPVOID AceInfo;

    short Type_ACE = 0;
    fprintf(file, "\t\"DACL\": [\n");
    if (!a->AceCount)
    {
        fprintf(file, "\t]\n");
        return;
    }
    for (int i = 0; i < a->AceCount; i++)
    {
        GetAce(a, i, &AceInfo);

        ACCESS_ALLOWED_ACE* pACE = (ACCESS_ALLOWED_ACE*)AceInfo;
        PSID pSID;
        pSID = (PSID)(&(pACE->SidStart));
        DWORD dwSize = MAX_NAME;
        DWORD dwLength = 0;
        SID_NAME_USE SidType;
        char lpName[MAX_NAME];
        char lpDomain[MAX_NAME];
        if (LookupAccountSidA(NULL, pSID, lpName, &dwSize, lpDomain, &dwSize, &SidType))//меняются имя и домен владельцев
        {
            if (flag)
                fprintf(file, ",\n\t\t{\n");
            else
            {
                flag = 1;
                fprintf(file, "\t\t{\n");
            }
            fprintf(file, "\t\t\t\"name\": \"%s\",\n", lpName);
            switch (((ACE_HEADER*)AceInfo)->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
                fprintf(file, "\t\t\t\"access\": \"allow\",\n"); break;
            case ACCESS_DENIED_ACE_TYPE:
                fprintf(file, "\t\t\t\"access\": \"deny\",\n"); break;
            default:
                fprintf(file, "\t\t\t\"access\": \"undefined type\",\n"); break;
            }
            fprintf(file, "\t\t\t\"mask\": [\n");    

            int flag_dop = 0;

            // Generic rights
            if (pACE->Mask & GENERIC_ALL)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"GENERIC_ALL\"");
                flag_dop = 1;
            }
            if (pACE->Mask & GENERIC_READ)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"GENERIC_READ\"");
                flag_dop = 1;
            }
            if (pACE->Mask & GENERIC_WRITE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"GENERIC_WRITE\"");
                flag_dop = 1;
            }
            if (pACE->Mask & GENERIC_EXECUTE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"GENERIC_EXECUTE\"");
                flag_dop = 1;
            }

            // Standart rights
            if (pACE->Mask & DELETE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"DELETE\"");
                flag_dop = 1;
            }
            if (pACE->Mask & READ_CONTROL)	
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"READ_CONTROL\"");
                flag_dop = 1;
            }
            if (pACE->Mask & WRITE_DAC)	
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"WRITE_DAC\"");
                flag_dop = 1;
            }
            if (pACE->Mask & FILE_READ_DATA || pACE->Mask & FILE_LIST_DIRECTORY)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_READ_DATA/FILE_LIST_DIRECTORY\"");
                flag_dop = 1;
            }
            if (pACE->Mask & FILE_WRITE_DATA || pACE->Mask & FILE_ADD_FILE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_WRITE_DATA/FILE_ADD_FILE\"");
                flag_dop = 1;
            }
            if (pACE->Mask & FILE_APPEND_DATA || pACE->Mask & FILE_ADD_SUBDIRECTORY)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY\"");
                flag_dop = 1;
            }
            if (pACE->Mask & FILE_EXECUTE || pACE->Mask & FILE_TRAVERSE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_EXECUTE/FILE_TRAVERSE\"");
                flag_dop = 1;
            }
            if (pACE->Mask & WRITE_OWNER)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"WRITE_OWNER\"");
                flag_dop = 1;
            }
            if (pACE->Mask & FILE_READ_ATTRIBUTES)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_READ_ATTRIBUTES\"");
                flag_dop = 1;
            }
            if (pACE->Mask & FILE_WRITE_ATTRIBUTES)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_WRITE_ATTRIBUTES\"");
                flag_dop = 1;
            }
            if (pACE->Mask & FILE_READ_EA)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_READ_EA\"");
                flag_dop = 1;
            }
            if (pACE->Mask & FILE_WRITE_EA)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_WRITE_EA\"");
                flag_dop = 1;
            }
            fprintf(file, "\n\t\t\t]\n");
            fprintf(file, "\t\t}");
        }
    }
    fprintf(file, "\n\t],\n");
}

// Получение списков SACL
void GetSACL(char* Path)
{
    PACL a;
    PSECURITY_DESCRIPTOR pSD;
    int flag = 0;
    if (GetNamedSecurityInfoA(Path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &a, &pSD) != ERROR_SUCCESS)
    {
        fprintf(file, "\t\"SACL\": [\n");
        fprintf(file, "\t]\n");
        return;
    }

    if (a == NULL)
    {
        fprintf(file, "\t\"SACL\": [\n");
        fprintf(file, "\t]\n");
        return;
    }

    ACL_REVISION_INFORMATION* buf = (ACL_REVISION_INFORMATION*)malloc(sizeof(ACL_REVISION_INFORMATION));
    GetAclInformation(a, buf, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation);
    LPVOID AceInfo;

    short Type_ACE = 0;
    fprintf(file, "\t\"SACL\": [\n");
    if (!a->AceCount)
    {
        fprintf(file, "\t]\n");
        return ;
    }
    for (int i = 0; i < a->AceCount; i++)
    {
        GetAce(a, i, &AceInfo);
        ACE_HEADER* AceHeader = (ACE_HEADER*)AceInfo;
        SYSTEM_AUDIT_ACE* auAce = NULL;

        PSID AceSid = NULL;
        LPWSTR Acct, Domain;

        bool success = AceHeader->AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG;
        //  SACL's ACEs:
        auAce = (SYSTEM_AUDIT_ACE*)AceInfo;
        AceSid = (PSID) & (auAce->SidStart);
        DWORD dwSize = MAX_NAME;
        DWORD dwLength = 0;
        SID_NAME_USE SidType;
        char lpName[MAX_NAME];
        char lpDomain[MAX_NAME];
        if (LookupAccountSidA(NULL, AceSid, lpName, &dwSize, lpDomain, &dwSize, &SidType))//меняются имя и домен владельцев
        {
            if (flag)
                fprintf(file, ",\n\t\t{\n");
            else
            {
                flag = 1;
                fprintf(file, "\t\t{\n");
            }
            fprintf(file, "\t\t\t\"name\": \"%s\",\n", lpName);
            if (success)
                fprintf(file, "\t\t\t\"access\": \"success\",\n");
            else
                fprintf(file, "\t\t\t\"access\": \"fail\",\n");
            fprintf(file, "\t\t\t\"mask\": [\n");
            int flag_dop = 0;


            // Generic rights
            if (auAce->Mask & GENERIC_ALL)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"GENERIC_ALL\"");
                flag_dop = 1;
            }
            if (auAce->Mask & GENERIC_READ)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"GENERIC_READ\"");
                flag_dop = 1;
            }
            if (auAce->Mask & GENERIC_WRITE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"GENERIC_WRITE\"");
                flag_dop = 1;
            }
            if (auAce->Mask & GENERIC_EXECUTE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"GENERIC_EXECUTE\"");
                flag_dop = 1;
            }

            // Standart rights
            if (auAce->Mask & DELETE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"DELETE\"");
                flag_dop = 1;
            }
            if (auAce->Mask & READ_CONTROL)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"READ_CONTROL\"");
                flag_dop = 1;
            }
            if (auAce->Mask & WRITE_DAC)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"WRITE_DAC\"");
                flag_dop = 1;
            }
            if (auAce->Mask & FILE_READ_DATA || auAce->Mask & FILE_LIST_DIRECTORY)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_READ_DATA/FILE_LIST_DIRECTORY\"");
                flag_dop = 1;
            }
            if (auAce->Mask & FILE_WRITE_DATA || auAce->Mask & FILE_ADD_FILE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_WRITE_DATA/FILE_ADD_FILE\"");
                flag_dop = 1;
            }
            if (auAce->Mask & FILE_APPEND_DATA || auAce->Mask & FILE_ADD_SUBDIRECTORY)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY\"");
                flag_dop = 1;
            }
            if (auAce->Mask & FILE_EXECUTE || auAce->Mask & FILE_TRAVERSE)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_EXECUTE/FILE_TRAVERSE\"");
                flag_dop = 1;
            }
            if (auAce->Mask & WRITE_OWNER)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"WRITE_OWNER\"");
                flag_dop = 1;
            }
            if (auAce->Mask & FILE_READ_ATTRIBUTES)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_READ_ATTRIBUTES\"");
                flag_dop = 1;
            }
            if (auAce->Mask & FILE_WRITE_ATTRIBUTES)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_WRITE_ATTRIBUTES\"");
                flag_dop = 1;
            }
            if (auAce->Mask & FILE_READ_EA)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_READ_EA\"");
                flag_dop = 1;
            }
            if (auAce->Mask & FILE_WRITE_EA)
            {
                if (flag_dop)
                    fprintf(file, ",\n");
                fprintf(file, "\t\t\t\t\"FILE_WRITE_EA\"");
                flag_dop = 1;
            }
            fprintf(file, "\n\t\t\t]\n");
            fprintf(file, "\t\t}");
        }
    }
    fprintf(file, "\n\t]\n");
}

// Получение информации об объекте
int GetInfoObject(char* Path)
{
    fprintf(file, "{\n");
    GetOwner(Path);
    GetFileIntegrityLevel(Path);
    GetDACL(Path);
    GetSACL(Path);
    fprintf(file, "}\n");
    return 0;
}


//-------------------------------------------------- ОСНОВНАЯ ИНФОРМАЦИЯ ПРО ПРОЦЕССЫ --------------------------------------------------//

// Получение списка библиотек
bool ListProcessModules(DWORD dwPID)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    bool ret = false;
    MODULEENTRY32 me32;
    fwprintf(file_lib, TEXT("\t\t\"DLL\": [\n"));

    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        fwprintf(file_lib, TEXT("\t\t\t\" \"\n\t\t]\n"));
        return false;
    }

    me32.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModuleSnap, &me32))
    {
        fwprintf(file_lib, TEXT("\t\t\t\" \"\n\t\t]\n"));
        CloseHandle(hModuleSnap);    
        return false;
    }
 
    WCHAR str1[12] = { 'M', 'S','C','O','R','E','E','.','D','L','L', '\0' };
    WCHAR str2[12] = { 'm', 's','c','o','r','e','e','.','d','l','l', '\0' };

   // Module32Next(hModuleSnap, &me32);
    fwprintf(file_lib, TEXT("\t\t\t\"%s\""), me32.szModule);
    if (!memcmp(me32.szModule, str1, strlen("MSCOREE.DLL")))
        ret = true;
    if (!memcmp(me32.szModule, str2, strlen("MSCOREE.DLL")))
        ret = true;
    while (Module32Next(hModuleSnap, &me32))
    {
        fwprintf(file_lib, TEXT(",\n\t\t\t\"%s\""), me32.szModule);
        if (!memcmp(me32.szModule, str1, strlen("MSCOREE.DLL")))
            ret = true;
        if (!memcmp(me32.szModule, str2, strlen("MSCOREE.DLL")))
            ret = true;
    }

    fwprintf(file_lib, TEXT("\n\t\t]\n"));
    CloseHandle(hModuleSnap);
    return ret;
}

// Использование DEP/ASLR
void DEPandASLR(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    PROCESS_MITIGATION_DEP_POLICY DEPStruct;
    PROCESS_MITIGATION_ASLR_POLICY ASLRStruct;

    if (!GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, (PVOID)&DEPStruct, sizeof(_PROCESS_MITIGATION_DEP_POLICY)))
    {
        fprintf(file, "\t\t\"DEP\": \" \",\n");
        fprintf(file, "\t\t\"ASLR\": \" \",\n");
        CloseHandle(hProcess);
        return;
    }
    if (!DEPStruct.Enable)
        fprintf(file, "\t\t\"DEP\": \"no\",\n");
    else
        fprintf(file, "\t\t\"DEP\": \"yes\",\n");
ASLR:
    if (!GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, (PVOID)&ASLRStruct, sizeof(_PROCESS_MITIGATION_ASLR_POLICY)))
    {
        fprintf(file, "\t\t\"ASLR\": \" \",\n");
        CloseHandle(hProcess);
        return;
    }
    if (!ASLRStruct.EnableBottomUpRandomization)
        fprintf(file, "\t\t\"ASLR\": \"no\"\n");
    else
        fprintf(file, "\t\t\"ASLR\": \"yes\",\n");
    CloseHandle(hProcess);
}

// Получение описания процесса
void GetDescription(const wchar_t* filename)
{
    int dwLen = GetFileVersionInfoSize(filename, NULL);
    if (!dwLen)
    {
        fwprintf(file, TEXT("\t\t\"description\": \" \",\n"));
        return;
    }

    auto* sKey = new BYTE[dwLen];
    std::unique_ptr<BYTE[]> skey_automatic_cleanup(sKey);
    if (!GetFileVersionInfo(filename, NULL, dwLen, sKey))
    {
        fwprintf(file, TEXT("\t\t\"description\": \" \",\n"));
        return;
    }

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;

    UINT cbTranslate = 0;
    if (!VerQueryValueA(sKey, "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate))
    {
        fwprintf(file, TEXT("\t\t\"description\": \" \",\n"));
        return;
    }

    for (unsigned int i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++)
    {
        char subblock[256];
        sprintf_s(subblock, "\\StringFileInfo\\%04x%04x\\FileDescription", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
        char* description = NULL;
        UINT dwBytes;
        if (VerQueryValueA(sKey, subblock, (LPVOID*)&description, &dwBytes))
            fprintf(file, "\t\t\"description\": \"%s\",\n", description);
        else
            fwprintf(file, TEXT("\t\t\"description\": \" \",\n"));
    }
}

// Получение имени владельца и SID
void GetOwner(DWORD processID)
{
    DWORD dwSize = MAX_NAME;
    DWORD dwLength = 0;
    PTOKEN_USER ptu = NULL;
    HANDLE hToken;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);

    if (hToken == NULL)
    {
        fprintf(file, "\t\t\"SID\": \" \",\n");
        fprintf(file, "\t\t\"owner\": \" \",\n");
        return;
    }

    if (!GetTokenInformation(hToken, TokenUser, (LPVOID)ptu, 0, &dwLength))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            fprintf(file, "\t\t\"SID\": \" \",\n");
            fprintf(file, "\t\t\"owner\": \" \",\n");
            return;
        }

        ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);

        if (ptu == NULL)
        {
            fprintf(file, "\t\t\"SID\": \" \",\n");
            fprintf(file, "\t\t\"owner\": \" \",\n");
            return;
        }
    }

    if (!GetTokenInformation(hToken, TokenUser, (LPVOID)ptu, dwLength, &dwLength))
    {
        fprintf(file, "\t\t\"SID\": \" \",\n");
        fprintf(file, "\t\t\"owner\": \" \",\n");
    }

    LPSTR string;
    ConvertSidToStringSidA(ptu->User.Sid, &string);
    fprintf(file, "\t\t\"SID\": \"%s\",\n", string);

    SID_NAME_USE SidType;
    char lpName[MAX_NAME];
    char lpDomain[MAX_NAME];
    LookupAccountSidA(NULL, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType);
    fprintf(file, "\t\t\"owner\": \"%s\",\n", lpName);
    CloseHandle(hProcess);
}

//Получение разрядности процесса
void GetProcessType(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    BOOL bIsWow64 = FALSE;

    typedef BOOL(APIENTRY* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

    LPFN_ISWOW64PROCESS fnIsWow64Process;

    HMODULE module = GetModuleHandle(_T("kernel32"));
    const char funcName[] = "IsWow64Process";
    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(module, funcName);

    if (NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(hProcess, &bIsWow64))
        {
            fprintf(file, "\t\t\"type\": \" \",\n");
            return;
        }
    }
    if (bIsWow64)
        fwprintf(file, TEXT("\t\t\"type\": \"32-bit\",\n"));
    else
        fwprintf(file, TEXT("\t\t\"type\": \"64-bit\",\n"));
    CloseHandle(hProcess);
}

// Вывод пути процесса
void PrintProcessPath(DWORD processID)
{
    TCHAR szProcessNamePath[MAX_PATH] = TEXT(" ");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);       // Открытие процесса
    DWORD PATH_LENGTH = 1024;
    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))                               // Извлечение дескриптора
            GetModuleFileNameEx(hProcess, hMod, szProcessNamePath, sizeof(szProcessNamePath) / sizeof(TCHAR)); //тут путь
    }

    fwprintf(file, TEXT("\t\t\"path\": \"%s\",\n"), szProcessNamePath);
    auto path = szProcessNamePath;
    GetDescription(path);
    CloseHandle(hProcess);
}

// Поиск имени родителя
void FindParentName(DWORD parentPID)
{
    HANDLE SnapCopy = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pee32;
    pee32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(SnapCopy, &pee32))
    {
        do {
            if (parentPID == pee32.th32ProcessID)
            {
                fwprintf(file, TEXT("\t\t\"parent name\": \"%s\",\n"), pee32.szExeFile);
                return;
            }
        } while (Process32Next(SnapCopy, &pee32));
    }
    fwprintf(file, TEXT("\t\t\"parent name\": \" \",\n"), pee32.szExeFile);
}

// Просмотр списка процессов
BOOL GetProcessList()
{
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;
    int res;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return GetLastError();

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);    
        return GetLastError();
    }

    int flag = 0;
    printf("\r%d/%d    processes checked.", count_proc, cProcesses);
    fprintf(file, "[\n");
    fprintf(file_lib, "[\n");
    fprintf(file_priv, "[\n");
    do
    {
        if (flag)
        {
            fprintf(file, ",\n\t{\n");
            fprintf(file_lib, ",\n\t{\n");
            fprintf(file_priv, ",\n\t{\n");
        }
        else
        {
            fprintf(file, "\t{\n");
            fprintf(file_lib, "\t{\n");
            fprintf(file_priv, "\t{\n");
        }

        fwprintf(file, TEXT("\t\t\"name\": \"%s\",\n"), pe32.szExeFile);
        fwprintf(file_lib, TEXT("\t\t\"name\": \"%s\",\n"), pe32.szExeFile);
        fwprintf(file_priv, TEXT("\t\t\"name\": \"%s\",\n"), pe32.szExeFile);

        // Retrieve the priority class.
        dwPriorityClass = 0;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        
        fwprintf(file, TEXT("\t\t\"PID\": %u,\n"), pe32.th32ProcessID);
        fwprintf(file_priv, TEXT("\t\t\"PID\": %u,\n"), pe32.th32ProcessID);
        PrintProcessPath(pe32.th32ProcessID);
        fwprintf(file, TEXT("\t\t\"PPID\": %u,\n"), pe32.th32ParentProcessID);  
        FindParentName(pe32.th32ParentProcessID);
        GetOwner(pe32.th32ProcessID);
        GetProcessType(pe32.th32ProcessID);
        DEPandASLR(pe32.th32ProcessID);

        res = ListProcessModules(pe32.th32ProcessID);
        if (res == true)
            fprintf(file, "\t\t\"environment\": \".NET\",\n");
        else
            fprintf(file, "\t\t\"environment\": \"native code\",\n");
        GetProcessIntegrityLevel(pe32.th32ProcessID);
        GetPrivileges(pe32.th32ProcessID);
        fprintf(file, "\t}");
        fprintf(file_lib, "\t}");
        fprintf(file_priv, "\t}");
        flag = 1;
        count_proc++;
        printf("\r%d/%d", count_proc, cProcesses);       
    } while (Process32Next(hProcessSnap, &pe32));
    fprintf(file, "\n]\n");
    fprintf(file_lib, "\n]\n");
    fprintf(file_priv, "\n]\n");
    printf("\n");
    CloseHandle(hProcessSnap);
    return 0;
}


//---------------------------------------------------------- УСТАНОВКА ПРИВИЛЕГИЙ ----------------------------------------------------------//

// Установка привилегий
BOOL EnablePrivilege(HANDLE hToken, LPCWSTR SePrivilege, BOOL bEnablePrivilege)
{
    PTOKEN_PRIVILEGES   NewPrivileges;
    BYTE                OldPriv[1024];
    PBYTE               pbOldPriv;
    ULONG               cbNeeded;
    BOOL                b = TRUE;
    BOOL                fRc;
    LUID                LuidPrivilege;

    cbNeeded = 0;

    LookupPrivilegeValue(NULL, SePrivilege, &LuidPrivilege);

    NewPrivileges = (PTOKEN_PRIVILEGES)
        calloc(1, sizeof(TOKEN_PRIVILEGES) +
            (1 - ANYSIZE_ARRAY) * sizeof(LUID_AND_ATTRIBUTES));
    if (NewPrivileges == NULL)
    {
        CloseHandle(hToken);
        return FALSE;
    }

    NewPrivileges->PrivilegeCount = 1;
    NewPrivileges->Privileges[0].Luid = LuidPrivilege;
    if (bEnablePrivilege)
        NewPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        NewPrivileges->Privileges[0].Attributes = 0;

    pbOldPriv = OldPriv;
    fRc = AdjustTokenPrivileges(hToken, FALSE, NewPrivileges, 1024, (PTOKEN_PRIVILEGES)pbOldPriv, &cbNeeded);
    if (!fRc)
        return FALSE;

    fRc = AdjustTokenPrivileges(hToken, FALSE, NewPrivileges, 1024, (PTOKEN_PRIVILEGES)pbOldPriv, &cbNeeded);
    if (!fRc)
        return FALSE;

    if (!fRc)
    {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            pbOldPriv = (PBYTE)calloc(1, cbNeeded);
            if (pbOldPriv == NULL)
            {
                CloseHandle(hToken);
                return(FALSE);
            }

            fRc = AdjustTokenPrivileges(hToken, FALSE, NewPrivileges, cbNeeded,  (PTOKEN_PRIVILEGES)pbOldPriv, &cbNeeded);
            if (!fRc)
                return FALSE;
        }
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        return FALSE;
    CloseHandle(hToken);

    return(b);
}

// Установка привилегий
void SetPrivilegeChoose(HANDLE hProcess, int privileges, BOOL mode)
{
    HANDLE pToken;
    OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &pToken);
    if (!pToken)
    {
        printf("Error open %d\n", GetLastError());
        return;
    }
    switch (privileges)
    {
    case 0:
        EnablePrivilege(pToken, SE_ASSIGNPRIMARYTOKEN_NAME, mode);
        break;
    case 1:
        EnablePrivilege(pToken, SE_AUDIT_NAME, mode);
        break;
    case 2:
        EnablePrivilege(pToken, SE_BACKUP_NAME, mode);
        break;
    case 3:
        EnablePrivilege(pToken, SE_CHANGE_NOTIFY_NAME, mode);
        break;
    case 4:
        EnablePrivilege(pToken, SE_CREATE_GLOBAL_NAME, mode);
        break;
    case 5:
        EnablePrivilege(pToken, SE_CREATE_PAGEFILE_NAME, mode);
        break;
    case 6:
        EnablePrivilege(pToken, SE_CREATE_PERMANENT_NAME, mode);
        break;
    case 7:
        EnablePrivilege(pToken, SE_CREATE_SYMBOLIC_LINK_NAME, mode);
        break;
    case 8:
        EnablePrivilege(pToken, SE_CREATE_TOKEN_NAME, mode);
        break;
    case 9:
        EnablePrivilege(pToken, SE_DEBUG_NAME, mode);
        break;
    case 10:
        EnablePrivilege(pToken, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, mode);
        break;
    case 11:
        EnablePrivilege(pToken, SE_ENABLE_DELEGATION_NAME, mode);
        break;
    case 12:
        EnablePrivilege(pToken, SE_IMPERSONATE_NAME, mode);
        break;
    case 13:
        EnablePrivilege(pToken, SE_INC_BASE_PRIORITY_NAME, mode);
        break;
    case 14:
        EnablePrivilege(pToken, SE_INCREASE_QUOTA_NAME, mode);
        break;
    case 15:
        EnablePrivilege(pToken, SE_INC_WORKING_SET_NAME, mode);
        break;
    case 16:
        EnablePrivilege(pToken, SE_LOAD_DRIVER_NAME, mode);
        break;
    case 17:
        EnablePrivilege(pToken, SE_LOCK_MEMORY_NAME, mode);
        break;
    case 18:
        EnablePrivilege(pToken, SE_MACHINE_ACCOUNT_NAME, mode);
        break;
    case 19:
        EnablePrivilege(pToken, SE_MANAGE_VOLUME_NAME, mode);
        break;
    case 20:
        EnablePrivilege(pToken, SE_PROF_SINGLE_PROCESS_NAME, mode);
        break;
    case 21:
        EnablePrivilege(pToken, SE_RELABEL_NAME, mode);
        break;
    case 22:
        EnablePrivilege(pToken, SE_REMOTE_SHUTDOWN_NAME, mode);
        break;
    case 23:
        EnablePrivilege(pToken, SE_RESTORE_NAME, mode);
        break;
    case 24:
        EnablePrivilege(pToken, SE_SECURITY_NAME, mode);
        break;
    case 25:
        EnablePrivilege(pToken, SE_SHUTDOWN_NAME, mode);
        break;
    case 26:
        EnablePrivilege(pToken, SE_SYNC_AGENT_NAME, mode);
        break;
    case 27:
        EnablePrivilege(pToken, SE_SYSTEM_ENVIRONMENT_NAME, mode);
        break;
    case 28:
        EnablePrivilege(pToken, SE_SYSTEM_PROFILE_NAME, mode);
        break;
    case 29:
        EnablePrivilege(pToken, SE_SYSTEMTIME_NAME, mode);
        break;
    case 30:
        EnablePrivilege(pToken, SE_TAKE_OWNERSHIP_NAME, mode);
        break;
    case 31:
        EnablePrivilege(pToken, SE_TCB_NAME, mode);
        break;
    case 32:
        EnablePrivilege(pToken, SE_TIME_ZONE_NAME, mode);
        break;
    case 33:
        EnablePrivilege(pToken, SE_TRUSTED_CREDMAN_ACCESS_NAME, mode);
        break;
    case 34:
        EnablePrivilege(pToken, SE_UNDOCK_NAME, mode);
        break;
    case 35:
        EnablePrivilege(pToken, SE_UNSOLICITED_INPUT_NAME, mode);
        break;
    }
}