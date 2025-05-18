public enum SYSTEM_INFORMATION_CLASS
{
    SystemProcessInformation = 5
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_PROCESS_INFORMATION
{
    public uint NextEntryOffset;
    public uint NumberOfThreads;
    private long Reserved1;
    private long Reserved2;
    private long Reserved3;
    public long CreateTime;
    public IntPtr UserTime;
    public IntPtr KernelTime;
    public UNICODE_STRING ImageName;
    public IntPtr BasePriority;
    public IntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
}

public static class ProcessUtilities
{
    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        ref uint ReturnLength
    );

    public static int GetPidByName(string targetProcess)
    {
        const SYSTEM_INFORMATION_CLASS sysClass = SYSTEM_INFORMATION_CLASS.SystemProcessInformation;
        int bufferSize = 0x10000;
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        uint retLen = 0;

        try
        {
            uint status;
            do
            {
                status = NtQuerySystemInformation(sysClass, buffer, (uint)bufferSize, ref retLen);
                if (status == 0xC0000004) // STATUS_INFO_LENGTH_MISMATCH
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferSize *= 2;
                    buffer = Marshal.AllocHGlobal(bufferSize);
                }
            } while (status == 0xC0000004);

            if (status != 0)
                throw new Exception($"NtQuerySystemInformation failed with status 0x{status:X}");

            int offset = 0;
            while (true)
            {
                IntPtr entryPtr = IntPtr.Add(buffer, offset);
                SYSTEM_PROCESS_INFORMATION spi = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(entryPtr);

                string name = spi.ImageName.Buffer != IntPtr.Zero
                    ? Marshal.PtrToStringUni(spi.ImageName.Buffer, spi.ImageName.Length / 2)
                    : "";

                if (string.Equals(name, targetProcess, StringComparison.OrdinalIgnoreCase))
                {
                    return spi.UniqueProcessId.ToInt32();
                }

                if (spi.NextEntryOffset == 0)
                    break;

                offset += (int)spi.NextEntryOffset;
            }

            throw new Exception($"Process '{targetProcess}' not found.");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}

//Usage:
int pid = ProcessUtilities.GetPidByName("explorer.exe");
Console.WriteLine($"PID: {pid}");
