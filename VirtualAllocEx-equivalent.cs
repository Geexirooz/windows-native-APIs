public static class NativeConstants
{
    public const int SECTION_ALL_ACCESS = 0x10000000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint SEC_COMMIT = 0x08000000;

    public const uint SECTION_MAP_READ = 0x0004;
    public const uint SECTION_MAP_WRITE = 0x0002;
    public const uint SECTION_MAP_EXECUTE = 0x0008;

    public const uint ViewShare = 1;
}

public static class SectionManager
{
    [DllImport("ntdll.dll")]
    public static extern int NtCreateSection(
        out IntPtr SectionHandle,
        int DesiredAccess,
        IntPtr ObjectAttributes,
        ref long MaximumSize,
        uint SectionPageProtection,
        uint AllocationAttributes,
        IntPtr FileHandle
    );

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

    public static IntPtr CreateSection(ulong size)
    {
        if (size == 0)
            throw new ArgumentOutOfRangeException(nameof(size), "Section size must be greater than zero.");

        long maxSize = (long)size;
        int status = NtCreateSection(
            out IntPtr sectionHandle,
            NativeConstants.SECTION_ALL_ACCESS,
            IntPtr.Zero,
            ref maxSize,
            NativeConstants.PAGE_EXECUTE_READWRITE,
            NativeConstants.SEC_COMMIT,
            IntPtr.Zero
        );

        if (status != 0)
            throw new InvalidOperationException($"NtCreateSection failed with status 0x{status:X8}");

        return sectionHandle;
    }

    public static IntPtr MapSectionToRemoteProcess(IntPtr sectionHandle, IntPtr remoteProcessHandle, ulong size)
    {
        if (sectionHandle == IntPtr.Zero)
            throw new ArgumentException("Invalid section handle.", nameof(sectionHandle));

        if (remoteProcessHandle == IntPtr.Zero)
            throw new ArgumentException("Invalid remote process handle.", nameof(remoteProcessHandle));

        ulong viewSize = size;
        IntPtr baseAddress;

        int status = NtMapViewOfSection(
            sectionHandle,
            remoteProcessHandle,
            out baseAddress,
            UIntPtr.Zero,
            UIntPtr.Zero,
            IntPtr.Zero,
            ref viewSize,
            NativeConstants.ViewShare,
            0,
            NativeConstants.PAGE_EXECUTE_READWRITE
        );

        if (status != 0)
            throw new InvalidOperationException($"NtMapViewOfSection failed with status 0x{status:X8}");

        return baseAddress;
    }
}

//Usage:
// Example size to map (1 page)
ulong sizeToMap = 4096;
// Create a section
IntPtr sectionHandle = SectionManager.CreateSection(sizeToMap);
// Map to remote process (you must define `remoteProcessHandle` elsewhere)
IntPtr remoteAddress = SectionManager.MapSectionToRemoteProcess(sectionHandle, remoteProcessHandle, sizeToMap);
