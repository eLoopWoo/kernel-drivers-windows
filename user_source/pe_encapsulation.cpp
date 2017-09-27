#include <iostream>
#include <windows.h>


int main()
{
    LPCTSTR main_file = "C:\\sys_load_scm.exe";
    LPCTSTR resource_file_in = "C:\\DCOM.sys";
    LPCTSTR resource_file_out = "C:\\DCOM_OUTPUT.sys";

    HANDLE hFile;
    DWORD dwFileSize,
      dwBytesRead, dwBytesWrite;
    LPBYTE lpBuffer;
    hFile = CreateFile(resource_file_in, GENERIC_READ,
                   0,
                   NULL,
                   OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL,
                   NULL);

    if (INVALID_HANDLE_VALUE != hFile)
    {
        dwFileSize = GetFileSize(hFile, NULL);
        lpBuffer = new BYTE[dwFileSize];

        if (ReadFile(hFile, lpBuffer, dwFileSize, &dwBytesRead, NULL) != FALSE)
        {
        }

        CloseHandle(hFile);
    }


    HANDLE hResource1;

    hResource1 = BeginUpdateResource(main_file, FALSE);
    if (NULL != hResource1)
    {

        if (UpdateResource(hResource1,
            MAKEINTRESOURCE(10),
            MAKEINTRESOURCE(10),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPVOID) lpBuffer,
            dwFileSize) != FALSE)
        {
            EndUpdateResource(hResource1, FALSE);
        }
    }


    HMODULE hLibrary;
    HRSRC hResource;
    HGLOBAL hResourceLoaded;

    hLibrary = LoadLibrary(main_file);
    if (NULL != hLibrary)
    {
        hResource = FindResource(hLibrary, MAKEINTRESOURCE(10), MAKEINTRESOURCE(10));


        if (NULL != hResource)
        {

            hResourceLoaded = LoadResource(hLibrary, hResource);
            if (NULL != hResourceLoaded)
            {

                lpBuffer = (LPBYTE) LockResource(hResourceLoaded);
                if (NULL != lpBuffer)
                {
                }
            }
        }


    }


    DWORD dwBytesWritten;
    std::cout << lpBuffer << std::endl;

    dwFileSize = SizeofResource(hLibrary, hResource);
    hFile = CreateFile(resource_file_out,
                       GENERIC_WRITE,
                       0,
                       NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

    if (INVALID_HANDLE_VALUE != hFile)
    {
        WriteFile(hFile, lpBuffer, dwFileSize, &dwBytesWritten, NULL);
        CloseHandle(hFile);
    }

    return 0;
}
