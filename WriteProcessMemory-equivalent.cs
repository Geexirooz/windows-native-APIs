[DllImport("ntdll.dll")]
public static extern int NtWriteVirtualMemory(
    IntPtr ProcessHandle,
    IntPtr BaseAddress,
    byte[] Buffer,
    uint NumberOfBytesToWrite,
    out IntPtr NumberOfBytesWritten
    );

public static void WriteRemoteMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer)
{
    IntPtr bytesWritten;
    int status = NtWriteVirtualMemory(
        processHandle,
        baseAddress,
        buffer,
        (uint)buffer.Length,
        out bytesWritten
    );

    if (status != 0) // STATUS_SUCCESS is 0
        throw new Exception($"NtWriteVirtualMemory failed: 0x{status:X}");

    if (bytesWritten.ToInt64() != buffer.Length)
        throw new Exception($"Incomplete write: wrote {bytesWritten} bytes out of {buffer.Length}");
    }
