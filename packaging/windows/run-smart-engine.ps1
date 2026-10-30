param([Parameter(Mandatory=$true)][string]$Engine, [Parameter(Mandatory=$true)][string]$Config)
$ErrorActionPreference = 'Stop'
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
# A private hidden console allows Go's signal handler to close Wintun cleanly.
# CREATE_NO_WINDOW on sing-box would make CTRL_BREAK impossible.
Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class RtunEngineProcess {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct StartupInfo {
        public uint cb;
        public string reserved, desktop, title;
        public uint x, y, xSize, ySize, xChars, yChars, fill, flags;
        public ushort show, reservedSize;
        public IntPtr reservedData, input, output, error;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInfo { public IntPtr process, thread; public uint pid, tid; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcess(string application, System.Text.StringBuilder command,
        IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags,
        IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo info);
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll")] static extern bool FreeConsole();
    delegate bool ControlHandler(uint control);
    static readonly ControlHandler IgnoreControl = control => true;
    [DllImport("kernel32.dll")] static extern bool SetConsoleCtrlHandler(ControlHandler handler, bool add);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GenerateConsoleCtrlEvent(uint control, uint group);
    public static System.Threading.Tasks.Task<string> ReadStop() {
        return System.Threading.Tasks.Task.Run(() =>
            new System.IO.StreamReader(Console.OpenStandardInput()).ReadLine());
    }
    public static Process Start(string engine, string config) {
        IntPtr output = GetStdHandle(-11);
        if (!SetHandleInformation(output, 1, 1)) throw new Win32Exception();
        var startup = new StartupInfo();
        startup.cb = (uint)Marshal.SizeOf(typeof(StartupInfo));
        startup.flags = 0x101; // STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES
        startup.show = 0; // SW_HIDE
        startup.input = GetStdHandle(-10);
        startup.output = startup.error = output;
        var args = new System.Text.StringBuilder("\"" + engine + "\" --disable-color run -c \"" + config + "\"");
        ProcessInfo info;
        if (!CreateProcess(engine, args, IntPtr.Zero, IntPtr.Zero, true, 0x10,
            IntPtr.Zero, System.IO.Path.GetDirectoryName(engine), ref startup, out info))
            throw new Win32Exception();
        try { return Process.GetProcessById((int)info.pid); }
        finally { CloseHandle(info.thread); CloseHandle(info.process); }
    }
    public static bool Stop(Process process) {
        if (process.HasExited) return true;
        FreeConsole(); // PowerShell may have attached its own hidden host console.
        if (!AttachConsole((uint)process.Id)) throw new Win32Exception();
        try {
            SetConsoleCtrlHandler(IgnoreControl, true);
            if (!GenerateConsoleCtrlEvent(1, 0)) throw new Win32Exception();
            System.Threading.Thread.Sleep(200);
            return true; // CTRL_BREAK to this private console only
        } finally {
            FreeConsole();
            SetConsoleCtrlHandler(IgnoreControl, false);
        }
    }
}
"@
$process = $null
try {
    $process = [RtunEngineProcess]::Start($Engine, $Config)
    $stop = [RtunEngineProcess]::ReadStop()
    while (-not $process.WaitForExit(50)) {
        if ($stop.IsCompleted) {
            [void][RtunEngineProcess]::Stop($process)
            if (-not $process.WaitForExit(8000)) {
                [Console]::Out.WriteLine('Engine launcher: graceful shutdown timed out')
                $process.Kill()
                $process.WaitForExit()
            }
            break
        }
    }
    exit $process.ExitCode
} catch {
    [Console]::Out.WriteLine('Engine launcher: ' + $_.Exception.Message)
    exit 1
} finally {
    if ($null -ne $process) {
        if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $process.Dispose()
    }
}
