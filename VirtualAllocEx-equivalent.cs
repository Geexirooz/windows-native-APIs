// Constants for the memory allocations attributes
public static class NativeConstants
{
    public const int SECTION_ALL_ACCESS = 0x10000000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint SEC_COMMIT = 0x08000000;
    public const uint SECTION_MAP_READ = 0x0004;
    public const uint SECTION_MAP_WRITE = 0x0002;
    public const uint SECTION_MAP_EXECUTE = 0x0008;
}

// NtCreateSection Signature
[DllImport("ntdll.dll")]
public static extern int NtCreateSection(
    out IntPtr SectionHandle,
    int DesiredAccess,
    IntPtr ObjectAttributes,
    IntPtr MaximumSize, // pointer to LARGE_INTEGER (optional, can be null)
    uint SectionPageProtection,
    uint AllocationAttributes,
    IntPtr FileHandle
    );

// CreateSection function
public static IntPtr CreateSection(ulong size)
{
    IntPtr sectionHandle;

        // Allocate memory for LARGE_INTEGER
    long largeSize = (long)size;
    IntPtr maxSizePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(long)));
    Marshal.WriteInt64(maxSizePtr, largeSize);

    int status = NtCreateSection(
        out sectionHandle,
        NativeConstants.SECTION_ALL_ACCESS,
        IntPtr.Zero,
        maxSizePtr,
        NativeConstants.PAGE_EXECUTE_READWRITE,
        NativeConstants.SEC_COMMIT,
        IntPtr.Zero // Not backed by a file
    );

    Marshal.FreeHGlobal(maxSizePtr);

    if (status != 0) // STATUS_SUCCESS == 0
    {
        throw new Exception($"NtCreateSection failed: 0x{status:X}");
    }

    return sectionHandle;
}

// NtMapViewOfSection signature
[DllImport("ntdll.dll")]
public static extern int NtMapViewOfSection(
    IntPtr SectionHandle,
    IntPtr ProcessHandle,
    out IntPtr BaseAddress,
    UIntPtr ZeroBits,
    UIntPtr CommitSize,
    IntPtr SectionOffset,
    ref ulong ViewSize,
    uint InheritDisposition,
    uint AllocationType,
    uint Win32Protect
);

// Map section function
public static IntPtr MapSectionToRemoteProcess(IntPtr sectionHandle, IntPtr remoteProcessHandle, ulong size)
{
    IntPtr baseAddress = IntPtr.Zero;
    ulong viewSize = size;

    int status = NtMapViewOfSection(
        sectionHandle,
        remoteProcessHandle,
        out baseAddress,
        UIntPtr.Zero,
        UIntPtr.Zero,
        IntPtr.Zero,
        ref viewSize,
        1, // ViewShare
        0,
        NativeConstants.PAGE_EXECUTE_READWRITE);

    if (status != 0) // STATUS_SUCCESS == 0
    {
        throw new Exception($"NtMapViewOfSection failed: 0x{status:X}");
    }

    return baseAddress;
}

//Usage:
ulong sizeToMap = 4096;
IntPtr secHandle = CreateSection(sizeToMap);
// Assume phandle (OpenProcess-equivalent.cs)
IntPtr remoteMappedAddress = MapSectionToRemoteProcess(secHandle, phandle, sizeToMap);
