#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#define DLL_EXPORT __declspec(dllexport)

const char* ListDirectoryContents(const char* sDir)
{
    WIN32_FIND_DATA fdFile;
    HANDLE hFind = NULL;

    char sPath[2048];
    char res[2048] = "\n[+] Accessing c:\\ from native DLL!\n";

    //Specify a file mask. *.* = We want everything!
    sprintf(sPath, "%s*.*", sDir);

    if ((hFind = FindFirstFileA(sPath, &fdFile)) == INVALID_HANDLE_VALUE)
    {
        int err = GetLastError();
        if (err == 5)
        {
            sprintf(res, "%sAccess to the path '%s' is denied.\n", res, sDir);
        }
        else
        {
            sprintf(res, "%sInvalid file handle. Error is %u for the path %s.\n", res, err, sDir);
        }
        return res;
    }

    do
    {
        //Find first file will always return "."
        //    and ".." as the first two directories.
        if (strcmp(fdFile.cFileName, ".") != 0
            && strcmp(fdFile.cFileName, "..") != 0)
        {
            //Build up our file path using the passed in
            //  [sDir] and the file/foldername we just found:
            sprintf(sPath, "%s%s\n", sDir, fdFile.cFileName);

            // Add file/dir to result
            const char* aux1 = res;
            const char* aux2 = sPath;
            const char* concat;
            concat = malloc(strlen(aux1) + 1 + strlen(aux2));

            strcpy(concat, aux1);
            strcat(concat, aux2);
            sprintf(res, "%s", concat);
            free(concat);
        }
    } while (FindNextFileA(hFind, &fdFile)); //Find the next file.

    FindClose(hFind); //Always, Always, clean things up!

    return res;
}

DLL_EXPORT const char* Run()
{
    return ListDirectoryContents("c:\\");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return 1;
}