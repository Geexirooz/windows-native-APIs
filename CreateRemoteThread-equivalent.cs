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

public static IntPtr CreateRemoteThreadNative(IntPtr processHandle, IntPtr startAddress, IntPtr parameter)
{
    IntPtr threadHandle;
    int status = NtCreateThreadEx(
        out threadHandle,
        0x1FFFFF,  // All access
        IntPtr.Zero,
        processHandle,
        startAddress,
        parameter,
        false,   // Run immediately (not suspended)
        0,
        0,
        0,
        IntPtr.Zero);

    if (status != 0)
        throw new Exception($"NtCreateThreadEx failed: 0x{status:X}");

    return threadHandle;
}
