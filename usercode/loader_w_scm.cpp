#include "windows.h"
#include "stdio.h"

bool _util_scm_load_sysfile(char *theDriverName)
{
    char aPath[1024];
    char aCurrentDirectory[515];

    SC_HANDLE sh = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(!sh)
    {
        return false;
    }

    GetCurrentDirectory( 512, aCurrentDirectory);

    _snprintf(aPath,1022,"%s\\%s.sys",aCurrentDirectory,theDriverName);
    printf("loading %s\n", aPath);

    SC_HANDLE rh = CreateService(sh,
            theDriverName,
            theDriverName,
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
            // service exists
            rh = OpenService(sh,theDriverName,SERVICE_ALL_ACCESS);
            if(!rh)
            {
                CloseServiceHandle(sh);
                return false;
            }
        }
        else
        {
            CloseServiceHandle(sh);
            return false;
        }
    }

    // start the drivers
    if(rh)
    {
        if(0 == StartService(rh, 0, NULL))
        {
            if(ERROR_SERVICE_ALREADY_RUNNING == GetLastError())
            {
                // no real problem
            }
            else
            {
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

int main()
{
    _util_scm_load_sysfile("DCOM");
    return 0;
}
