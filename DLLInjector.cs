using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace DLLInjectorCS
{
    internal class DLLInjector
    {
        [Flags]
        private enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }
        //inner struct used only internally
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            const int MAX_PATH = 260;
            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal UInt32 th32ModuleID;
            internal UInt32 cntThreads;
            internal UInt32 th32ParentProcessID;
            internal Int32 pcPriClassBase;
            internal UInt32 dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }

        [DllImport("kernel32.dll")]
        public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] buffer, int size, int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(int hProcess, int lpBaseAddress, byte[] buffer, int size, int lpNumberOfBytesWritten);

        static uint DELETE = 0x00010000;
        static uint READ_CONTROL = 0x00020000;
        static uint WRITE_DAC = 0x00040000;
        static uint WRITE_OWNER = 0x00080000;
        static uint SYNCHRONIZE = 0x00100000;
        static uint END = 0xFFF; //if you have Windows XP or Windows Server 2003 you must change this to 0xFFFF
        static uint PROCESS_ALL_ACCESS = (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE | END);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle([In] IntPtr hObject);


        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr? lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

        static uint PAGE_EXECUTE_READWRITE = 0x40;
        static uint MEM_COMMIT = 0x00001000;

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
           IntPtr? lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
           IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll")]
        public static extern bool FreeLibrary(IntPtr hModule);

        public const UInt32 INVALID_HANDLE_VALUE = 0xffffffff;

        //Get ProcID by its name
        static int getProcID(string p_name)
        {
            Process[] procs = Process.GetProcessesByName(p_name);
            //Get first one and return its pid
            if (procs.Length > 0)
            {
                Process proc = procs[0];
                return proc.Id;
            } else
            {
                Console.Write("[!]Unable to find Process ID\n");
                return 0;
            }
            
        }
        static byte[] ReadDLLBytes(string DLL_Path)
        {
            if (File.Exists(DLL_Path))
            {
                byte[] fileBytes = File.ReadAllBytes(DLL_Path);
                return fileBytes;
            } else
            {
                return null;
            }
        }
        //Inject DLL to target process
        static bool InjectDLL(int pid, string DLL_Path)
        {
            long dll_size = DLL_Path.Length + 1;
            int? hlProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

            byte[] dll = ReadDLLBytes(DLL_Path);
            if (hlProc == null)
            {
                Console.Write("[!]Fail to open target process!\n");
                return false;
            }
            IntPtr hProc = new IntPtr(hlProc.Value);
            Console.Write("[+]Opening Target Process...\n");

            IntPtr MyAlloc = VirtualAllocEx(hProc, null, Convert.ToUInt32(dll.Length), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            
            if (MyAlloc == null)
            {
                Console.Write("[!]Fail to allocate memory in Target Process.\n");
                return false;
            }

            Console.Write("[+]Allocating memory in Target Process.\n");

            bool IsWriteOk = WriteProcessMemory((int)hProc, (int)MyAlloc, dll, dll.Length, 0);

            IntPtr dWord;
            IntPtr addrLoadLibrary = GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA");
            IntPtr? ThreadReturn = CreateRemoteThread(hProc, null, 0, addrLoadLibrary, MyAlloc, 0, out dWord);
            if (ThreadReturn == null)
            {
                Console.Write("[!]Fail to create Remote Thread\n");
                return false;
            }
            if ((hProc != null) && (MyAlloc != null) && (IsWriteOk != false) && (ThreadReturn != null))
            {
                Console.Write("[+]DLL Successfully Injected :)\n");
                return true;
            }
            return false;
        }

        static void usage()
        {
            Console.Write("Usage: DLLInjectorCS.exe <Process name | Process ID> <DLL Path to Inject>\n");
        }

        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                usage();
                Environment.Exit(1);
                return;
            }
            if (File.Exists(args[2]) == false)
            {
                Console.Write("[!]DLL file does NOT exist!\n");
                Environment.Exit(1);
                return;
            }
            int pid;
            if (int.TryParse(args[1], out pid) == true)
            {
                Console.Write("[+]Input Process ID: " + args[1] + "\n");
                InjectDLL(pid, args[2]);
            }
            else
            {
                InjectDLL(getProcID(args[1]), args[2]);
            }

            return;
        }
    }
}
