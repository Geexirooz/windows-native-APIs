[DllImport("ntdll.dll")]
public static extern int NtWriteVirtualMemory(
    IntPtr ProcessHandle,
    IntPtr BaseAddress,
    byte[] Buffer,
    uint NumberOfBytesToWrite,
    out IntPtr NumberOfBytesWritten
);

/// <summary>
/// Writes a byte array into the memory of a remote process.
/// </summary>
/// <param name="processHandle">Handle to the remote process with write access.</param>
/// <param name="baseAddress">Base address in remote memory where data will be written.</param>
/// <param name="buffer">The data to write.</param>
public static void WriteRemoteMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer)
{
    if (processHandle == IntPtr.Zero)
        throw new ArgumentException("Invalid process handle.", nameof(processHandle));

    if (baseAddress == IntPtr.Zero)
        throw new ArgumentException("Invalid base address.", nameof(baseAddress));

    if (buffer == null || buffer.Length == 0)
        throw new ArgumentException("Buffer must not be null or empty.", nameof(buffer));

    int status = NtWriteVirtualMemory(
        processHandle,
        baseAddress,
        buffer,
        (uint)buffer.Length,
        out IntPtr bytesWritten
    );

    if (status != 0)
        throw new InvalidOperationException(
            $"NtWriteVirtualMemory failed with status 0x{status:X8}.");

    if ((long)bytesWritten != buffer.Length)
        throw new InvalidOperationException(
            $"Partial write: expected {buffer.Length} bytes, but wrote {bytesWritten} bytes.");
}

//Usage:
byte[] shellcode = new byte[] { 0x90, 0x90, 0x90, 0xC3 }; // NOP NOP NOP RET
IntPtr targetBase = allocAddr; // must be pre-allocated with enough memory and writable
WriteRemoteMemory(processHandle, targetBase, shellcode);
