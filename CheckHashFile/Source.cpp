#include <iostream>
#include <windows.h>
#include <string>
using namespace std;

#define BUFSIZE 1024
#define MD5LEN  16
#define SHA1LEN  20
#define SHA256LEN  32
#define SHA384LEN  48
#define SHA512LEN  64

typedef FARPROC (WINAPI* _PGPA)(HMODULE ,LPCSTR);
typedef HANDLE (WINAPI* _PCF)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD (WINAPI* _PGLE)();
typedef BOOL (WINAPI* _PCAC)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL (WINAPI* _PCH)(HANDLE);
typedef BOOL (WINAPI* _PCCH)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
typedef BOOL (WINAPI* _PCRC)(HCRYPTPROV, DWORD);
typedef BOOL (WINAPI* _PRF)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI* _PCHD)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
typedef BOOL (WINAPI* _PCDH)(HCRYPTHASH);
typedef BOOL (WINAPI* _PCGHP)(HCRYPTHASH, DWORD, BYTE* ,DWORD* ,DWORD);


string CreatHash(LPCWSTR file_name, ALG_ID hash_algorithm, int LEN, void* fnList[])
{
    _PCF fnCreateFile = (_PCF)fnList[0];
    _PGLE fnGetLastError = (_PGLE)fnList[1];
    _PCAC fnCryptAcquireContext = (_PCAC)fnList[2];
    _PCH fnCloseHandle = (_PCH)fnList[3];
    _PCCH fnCryptCreateHash = (_PCCH)fnList[4];
    _PCRC fnCryptReleaseContext = (_PCRC)fnList[5];
    _PRF fnReadFile = (_PRF)fnList[6];
    _PCHD fnCryptHashData = (_PCHD)fnList[7];
    _PCDH fnCryptDestroyHash = (_PCDH)fnList[8];
    _PCGHP fnCryptGetHashParam = (_PCGHP)fnList[9];

    string strResult;
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE* rgbHash = new BYTE[LEN];

    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
    // Logic to check usage goes here.

    hFile = fnCreateFile(file_name,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = fnGetLastError();
        throw dwStatus;
    }

    // Get handle to the crypto provider
    if (!fnCryptAcquireContext(&hProv,

        NULL,
        NULL,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = fnGetLastError();
        fnCloseHandle(hFile);
        throw dwStatus;
    }

    if (!fnCryptCreateHash(hProv, hash_algorithm, 0, 0, &hHash))
    {
        dwStatus = fnGetLastError();
        fnCloseHandle(hFile);
        fnCryptReleaseContext(hProv, 0);
        throw dwStatus;

    }

    while (bResult = fnReadFile(hFile, rgbFile, BUFSIZE,
        &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!fnCryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = fnGetLastError();
            fnCryptReleaseContext(hProv, 0);
            fnCryptDestroyHash(hHash);
            fnCloseHandle(hFile);
            throw dwStatus;
        }
    }

    if (!bResult)
    {
        dwStatus = fnGetLastError();
        fnCryptReleaseContext(hProv, 0);
        fnCryptDestroyHash(hHash);
        fnCloseHandle(hFile);
        throw dwStatus;
    }

    cbHash = LEN;
    if (fnCryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        for (DWORD i = 0; i < cbHash; i++)
        {
            strResult.push_back(rgbDigits[rgbHash[i] >> 4]);
            strResult.push_back(rgbDigits[rgbHash[i] & 0xf]);
        }
    }
    else
    {
        dwStatus = fnGetLastError();
        fnCryptDestroyHash(hHash);
        fnCryptReleaseContext(hProv, 0);
        fnCloseHandle(hFile);
        throw dwStatus;
    }

    fnCryptDestroyHash(hHash);
    fnCryptReleaseContext(hProv, 0);
    fnCloseHandle(hFile);

    return strResult;
}

void SecondStage(void* funcList[])
{

    _PGPA pGPA = (_PGPA)funcList[1];

    auto hmod = GetModuleHandleW(L"Advapi32.dll");
    auto fnCreateFile = (void*)(pGPA)((HMODULE)funcList[0], "CreateFileW");
    auto fnGetLastError = (void*)(pGPA)((HMODULE)funcList[0], "GetLastError");
    auto fnCryptAcquireContext = (void*)(pGPA)(hmod, "CryptAcquireContextA");
    auto fnCloseHandle = (void*)(pGPA)((HMODULE)funcList[0], "CloseHandle");
    auto fnCryptCreateHash = (void*)(pGPA)(hmod, "CryptCreateHash");
    auto fnCryptReleaseContext = (void*)(pGPA)(hmod, "CryptReleaseContext");
    auto fnReadFile = (void*)(pGPA)((HMODULE)funcList[0], "ReadFile");
    auto fnCryptHashData = (void*)(pGPA)(hmod, "CryptHashData");
    auto fnCryptDestroyHash = (void*)(pGPA)(hmod, "CryptDestroyHash");
    auto fnCryptGetHashParam = (void*)(pGPA)(hmod, "CryptGetHashParam");

    void* fnList[] = { fnCreateFile, fnGetLastError, fnCryptAcquireContext ,fnCloseHandle ,fnCryptCreateHash 
        ,fnCryptReleaseContext, fnReadFile, fnCryptHashData ,fnCryptDestroyHash, fnCryptGetHashParam };

    int inChoose;
    LPCWSTR filename = L"Win10.iso";

    do {

        system("cls");
        wcout << "------ File: " << filename << " ------" << endl;
        cout << "(1)---- MD5" << endl;
        cout << "(2)---- SHA1" << endl;
        cout << "(3)---- SHA256" << endl;
        cout << "(4)---- SHA384" << endl;
        cout << "(5)---- SHA512" << endl;
        cout << "(0)---- All Hash Algorithm" << endl;
        cout << "------------" << endl;
        cout << "Choose: ";
        cin >> inChoose;

    } while (inChoose < 0 || inChoose > 5);

    system("cls");
    string strMD5;
    string strSHA1;
    string strSHA256;
    string strSHA384;
    string strSHA512;
    try {
        switch (inChoose)
        {
        case 1:

            strMD5 = CreatHash(filename, CALG_MD5, MD5LEN, fnList);
            cout << "- MD5    :" << strMD5;
            break;

        case 2:

            strSHA1 = CreatHash(filename, CALG_SHA1, SHA1LEN, fnList);
            cout << "- SHA1    :" << strSHA1;
            break;

        case 3:

            strSHA256 = CreatHash(filename, CALG_SHA_256, SHA256LEN, fnList);
            cout << "- SHA256    :" << strSHA256;
            break;

        case 4:

            strSHA384 = CreatHash(filename, CALG_SHA_384, SHA384LEN, fnList);
            cout << "- SHA384    :" << strSHA384;
            break;

        case 5:

            strSHA512 = CreatHash(filename, CALG_SHA_512, SHA512LEN, fnList);
            cout << "- SHA512    :" << strSHA512;
            break;

        case 0:

            strMD5 = CreatHash(filename, CALG_MD5, MD5LEN, fnList);

            strSHA1 = CreatHash(filename, CALG_SHA1, SHA1LEN, fnList);

            strSHA256 = CreatHash(filename, CALG_SHA_256, SHA256LEN, fnList);

            strSHA384 = CreatHash(filename, CALG_SHA_384, SHA384LEN, fnList);

            strSHA512 = CreatHash(filename, CALG_SHA_512, SHA512LEN, fnList);

            cout << "- MD5    :" << strMD5 << endl;
            cout << "- SHA1    :" << strSHA1 << endl;
            cout << "- SHA256    :" << strSHA256 << endl;
            cout << "- SHA384    :" << strSHA384 << endl;
            cout << "- SHA512    :" << strSHA512 << endl;
            break;

        }
    }
    catch (DWORD ex)
    {
        cout << "Error :" << ex;
    }

}

void FirstStage()
{
    auto hmod = GetModuleHandleW(L"Kernel32.dll");
    auto fnGetProcAddr = (void*)GetProcAddress(hmod, "GetProcAddress");

    void* funcList[] = { hmod, fnGetProcAddr };
    SecondStage(funcList);
}

int main()
{
    
    FirstStage();

    return 0;
}