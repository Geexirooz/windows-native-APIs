[DllImport("ntdll.dll")]
private static extern int NtCreateThreadEx(
    out IntPtr threadHandle,
    uint desiredAccess,
    IntPtr objectAttributes,
    IntPtr processHandle,
    IntPtr startAddress,
    IntPtr parameter,
    bool createSuspended,
    int stackZeroBits,
    int sizeOfStack,
    int maximumStackSize,
    IntPtr attributeList
);

private const uint THREAD_ALL_ACCESS = 0x1FFFFF;

/// <summary>
/// Creates a remote thread in the specified process using NtCreateThreadEx.
/// </summary>
/// <param name="processHandle">Handle to the target process.</param>
/// <param name="startAddress">Start address of the thread (usually address of shellcode).</param>
/// <param name="parameter">Parameter passed to the thread function.</param>
/// <param name="createSuspended">Whether to create the thread in a suspended state.</param>
/// <returns>Handle to the created thread.</returns>
/// <exception cref="Exception">Thrown if NtCreateThreadEx fails.</exception>
public static IntPtr CreateRemoteThreadNative(
    IntPtr processHandle,
    IntPtr startAddress,
    IntPtr parameter,
    bool createSuspended = false)
{
    int status = NtCreateThreadEx(
        out IntPtr threadHandle,
        THREAD_ALL_ACCESS,
        IntPtr.Zero,
        processHandle,
        startAddress,
        parameter,
        createSuspended,
        0,
        0,
        0,
        IntPtr.Zero);

    if (status != 0)
        throw new Exception($"NtCreateThreadEx failed with status 0x{status:X}");

    return threadHandle;
}

//Usage
CreateRemoteThreadNative(processHandle, remoteAddress, IntPtr.Zero);
