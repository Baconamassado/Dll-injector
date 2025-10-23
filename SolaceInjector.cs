using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System;
using System.Security.Principal;

public class Injector
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    private const int ProcessCreateThread = 0x0002;
    private const int ProcessQueryInformation = 0x0400;
    private const int ProcessVmOperation = 0x0008;
    private const int ProcessVmWrite = 0x0020;
    private const int ProcessVmRead = 0x0010;
    private const int ProcessAllAccess = ProcessCreateThread | ProcessQueryInformation | ProcessVmOperation | ProcessVmWrite | ProcessVmRead;

    private const uint MemoryCommit = 0x00001000;
    private const uint MemoryReserve = 0x00002000;
    private const uint PageReadWrite = 4;

    public void Inject(string processName, string dllPath)
    {
        var procs = Process.GetProcessesByName(processName);
        if (procs.Length == 0)
        {
            Console.WriteLine($"Processo '{processName}' não encontrado.");
            return;
        }

        var processId = procs[0].Id;
        var loadLibraryA = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

        if (loadLibraryA == IntPtr.Zero)
        {
            Console.WriteLine("Failed to get LoadLibraryA address.");
            return;
        }
        else
        {
            Console.WriteLine("Loaded kernel32.dll");
        }

        var processHandle = OpenProcess(ProcessAllAccess, false, processId);
        if (processHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to get process handle.");
            return;
        }
        else
        {
            Console.WriteLine("Loaded process handle");
        }

        var bytes = Encoding.Default.GetBytes(dllPath);
        var memory = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)(bytes.Length + 1), MemoryCommit | MemoryReserve, PageReadWrite);
        if (memory == IntPtr.Zero)
        {
            Console.WriteLine("Failed allocating memory");
            return;
        }
        else
        {
            Console.WriteLine("Allocated memory");
        }

        if (WriteProcessMemory(processHandle, memory, bytes, (uint)(bytes.Length + 1), 0) == 0)
        {
            Console.WriteLine("Failed to write memory");
            return;
        }
        else
        {
            Console.WriteLine("Success writing memory");
        }

        Console.WriteLine("Creating remote thread...");

        if (CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryA, memory, 0, IntPtr.Zero) == IntPtr.Zero)
        {
            Console.WriteLine("Error creating remote thread");
        }
        else
        {
            Console.WriteLine("Successfully created remote thread");
        }
    }
}

class Program
{
    static bool Iraa()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            if (identity == null) return false;
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    static void Main()
    {
        bool runningAsDM = Iraa();
        Injector starter = new Injector();
        Console.WriteLine("Welcome to solace DLL injector");
        Console.WriteLine($"Status\nRunning as adm: {runningAsDM}");
        Console.WriteLine();

        Console.Write("Please input DLL path: ");
        string PathInp = Console.ReadLine();
        Console.Write("Now please insert process name: ");
        string processInp = Console.ReadLine();
        Console.WriteLine($"{processInp}");
        Console.WriteLine("Injecting...");
        Console.WriteLine();

        starter.Inject(processInp, PathInp);
    }
}
