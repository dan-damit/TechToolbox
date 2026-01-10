using System;
using System.Runtime.InteropServices;

public static class CredImpersonator
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        string username,
        string domain,
        string password,
        int logonType,
        int logonProvider,
        out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}