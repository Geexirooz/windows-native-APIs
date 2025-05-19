[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_ATTRIBUTES
{
    public int Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName; // pointer to UNICODE_STRING (not used here)
    public uint Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}

[StructLayout(LayoutKind.Sequential)]
public struct CLIENT_ID
{
    public IntPtr UniqueProcess;
    public IntPtr UniqueThread;
}

public static class ProcessHandleHelper
{
    [DllImport("ntdll.dll")]
    private static extern int NtOpenProcess(
        out IntPtr ProcessHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref CLIENT_ID ClientId);

    public static IntPtr GetProcessHandle(int targetPID, uint desiredAccess = 0x001F0FFF) // PROCESS_ALL_ACCESS
    {
        var objAttr = new OBJECT_ATTRIBUTES
        {
            Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
            RootDirectory = IntPtr.Zero,
            ObjectName = IntPtr.Zero,
            Attributes = 0,
            SecurityDescriptor = IntPtr.Zero,
            SecurityQualityOfService = IntPtr.Zero
        };

        var clientId = new CLIENT_ID
        {
            UniqueProcess = (IntPtr)targetPID,
            UniqueThread = IntPtr.Zero
        };

        int status = NtOpenProcess(out IntPtr processHandle, desiredAccess, ref objAttr, ref clientId);

        if (status == 0) // STATUS_SUCCESS
            return processHandle;

        throw new Exception($"NtOpenProcess failed for PID {targetPID} with status 0x{status:X8}");
    }
}

//Usage
int pid = 1234; // or from GetPidByName("explorer.exe")
IntPtr handle = ProcessHandleHelper.GetProcessHandle(pid);
// Remember to close the handle when done (using CloseHandle from kernel32.dll)
