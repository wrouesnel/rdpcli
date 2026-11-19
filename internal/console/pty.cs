// RdpcliPty runs a program in a pseudo console (ConPTY) and carries its
// terminal over the console window it runs in, for rdpcli's interactive
// mode. See pty.go for the protocol. rdpcli renames the class with a hash
// of this source, so a console kept open from another build never runs an
// older copy. Windows PowerShell compiles it with the .NET Framework's C#
// 5 compiler, so it sticks to C# 5.

using System;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public class RdpcliPty
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, IntPtr attrs, int size);
    [DllImport("kernel32.dll")]
    static extern int CreatePseudoConsole(int size, SafeFileHandle input, SafeFileHandle output, uint flags, out IntPtr pc);
    [DllImport("kernel32.dll")]
    static extern int ResizePseudoConsole(IntPtr pc, int size);
    [DllImport("kernel32.dll")]
    static extern void ClosePseudoConsole(IntPtr pc);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr value, IntPtr size, IntPtr prev, IntPtr retSize);
    [DllImport("kernel32.dll")]
    static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pattrs, IntPtr tattrs, bool inherit, uint flags,
        IntPtr env, string dir, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")]
    static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll")]
    static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    const int ProcThreadAttributePseudoConsole = 0x20016;
    const uint ExtendedStartupInfoPresent = 0x80000;

    // rdpcli types at least every 15 seconds; after this long without a
    // key it is gone, and the program and this console are closed rather
    // than left waiting forever.
    static readonly TimeSpan IdleLimit = TimeSpan.FromSeconds(60);

    // Output read from the pseudo console and not yet shown.
    readonly object sync = new object();
    byte[] pbuf = new byte[65536];
    int plen;
    bool eof;
    DateTime lastOut = DateTime.UtcNow;

    IntPtr pc;
    FileStream ins;
    int cw, rh;

    // Run runs cmd (a UTF-8 command line, base64-encoded) in a pseudo
    // console of cols x rows cells until it exits or rdpcli sends "q".
    public static void Run(string cmd, int id, int cols, int rows)
    {
        new RdpcliPty().Session(Encoding.UTF8.GetString(Convert.FromBase64String(cmd)), id, cols, rows);
    }

    static int Size(int cols, int rows)
    {
        return (rows << 16) | (cols & 0xFFFF);
    }

    void Session(string cmd, int id, int cols, int rows)
    {
        SafeFileHandle inRead, inWrite, outRead, outWrite;
        if (!CreatePipe(out inRead, out inWrite, IntPtr.Zero, 0) || !CreatePipe(out outRead, out outWrite, IntPtr.Zero, 0))
            throw new Win32Exception();
        int hr = CreatePseudoConsole(Size(cols, rows), inRead, outWrite, 0, out pc);
        if (hr != 0)
            throw new COMException("CreatePseudoConsole failed", hr);

        PROCESS_INFORMATION pi;
        IntPtr size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
        IntPtr attrs = Marshal.AllocHGlobal(size);
        try
        {
            if (!InitializeProcThreadAttributeList(attrs, 1, 0, ref size))
                throw new Win32Exception();
            if (!UpdateProcThreadAttribute(attrs, 0, (IntPtr)ProcThreadAttributePseudoConsole, pc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception();
            STARTUPINFOEX si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            si.lpAttributeList = attrs;
            if (!CreateProcessW(null, new StringBuilder(cmd), IntPtr.Zero, IntPtr.Zero, false, ExtendedStartupInfoPresent,
                    IntPtr.Zero, null, ref si, out pi))
            {
                Win32Exception e = new Win32Exception();
                ClosePseudoConsole(pc);
                throw e;
            }
        }
        finally
        {
            DeleteProcThreadAttributeList(attrs);
            Marshal.FreeHGlobal(attrs);
        }
        // The pseudo console holds its own copies of its ends of the pipes.
        inRead.Dispose();
        outWrite.Dispose();

        ins = new FileStream(inWrite, FileAccess.Write, 1, false);
        FileStream outs = new FileStream(outRead, FileAccess.Read, 1, false);
        Thread reader = new Thread(delegate()
        {
            byte[] b = new byte[16384];
            try
            {
                int n;
                while ((n = outs.Read(b, 0, b.Length)) > 0)
                    Append(b, n);
            }
            catch (IOException) { }
            lock (sync) eof = true;
        });
        reader.IsBackground = true;
        reader.Start();

        bool pcClosed = false, idle = false;
        try
        {
            Console.TreatControlCAsInput = true;
            Console.CursorVisible = false;
            Console.Clear();
            idle = Loop(id, pi.hProcess, ref pcClosed);
        }
        finally
        {
            if (!pcClosed)
            {
                IntPtr p = pc;
                ThreadPool.QueueUserWorkItem(delegate { ClosePseudoConsole(p); });
            }
            if (WaitForSingleObject(pi.hProcess, 2000) != 0)
                TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            try { ins.Dispose(); } catch (IOException) { }
            Console.Clear();
            Console.CursorVisible = true;
            Console.TreatControlCAsInput = false;
        }
        if (idle)
            Environment.Exit(1);
    }

    // Loop runs the session until "q", returning false, or until rdpcli has
    // been silent too long, returning true.
    bool Loop(int id, IntPtr proc, ref bool pcClosed)
    {
        cw = Console.WindowWidth - 1;
        rh = Console.WindowHeight - 2;
        int cap = cw * rh;
        long seq = 0, inseq = 0;
        string data = "", st = "r";
        char enc = 'b';
        bool dirty = true, exited = false;
        DateTime exitAt = DateTime.MinValue, closedAt = DateTime.MinValue;
        StringBuilder frame = null;
        DateTime lastKey = DateTime.UtcNow;
        while (true)
        {
            while (Console.KeyAvailable)
            {
                char k = Console.ReadKey(true).KeyChar;
                lastKey = DateTime.UtcNow;
                if (frame != null)
                {
                    if (k == '.')
                    {
                        if (Frame(frame.ToString(), inseq))
                            inseq++;
                        frame = null;
                        dirty = true;
                    }
                    else if (frame.Length > 65536)
                        frame = null;
                    else
                        frame.Append(k);
                }
                else if (k >= '0' && k <= '9')
                {
                    // Acknowledges the page shown; a repeat is ignored.
                    if (data.Length > 0 && k - '0' == (seq + 1) % 10)
                    {
                        seq++;
                        data = "";
                        dirty = true;
                    }
                }
                else if (k == 'i' || k == 'w')
                {
                    frame = new StringBuilder();
                    frame.Append(k);
                }
                else if (k == 'q')
                    return false;
                else if (k != '.')
                    dirty = true;
            }

            DateTime now = DateTime.UtcNow;
            if (now - lastKey > IdleLimit)
                return true;
            if (!exited && WaitForSingleObject(proc, 0) == 0)
            {
                exited = true;
                exitAt = now;
            }
            if (exited && !pcClosed)
            {
                // Closing the pseudo console ends its output; let it finish
                // drawing the program's last output first.
                DateTime last;
                lock (sync) last = lastOut;
                if (now - last > TimeSpan.FromMilliseconds(300) || now - exitAt > TimeSpan.FromSeconds(3))
                {
                    pcClosed = true;
                    closedAt = now;
                    IntPtr p = pc;
                    ThreadPool.QueueUserWorkItem(delegate { ClosePseudoConsole(p); });
                }
            }
            if (data.Length == 0)
            {
                bool done;
                lock (sync) done = eof;
                data = Take(cap, out enc);
                if (data.Length > 0)
                    dirty = true;
                else if (pcClosed && st == "r" && (done || now - closedAt > TimeSpan.FromSeconds(2)))
                {
                    uint code;
                    GetExitCodeProcess(proc, out code);
                    st = code.ToString();
                    dirty = true;
                }
            }
            if (dirty)
            {
                Draw(id, seq, enc, data, inseq, st);
                dirty = false;
            }
            Thread.Sleep(10);
        }
    }

    // Frame applies an input frame: type, sequence digit, payload, then a
    // colon and a checksum of what precedes it. It returns false for a
    // damaged frame or a repeat of one already applied.
    bool Frame(string f, long inseq)
    {
        int c = f.LastIndexOf(':');
        if (c < 2 || f.Length != c + 5)
            return false;
        string body = f.Substring(0, c);
        if (Hex(Sha(body), 2) != f.Substring(c + 1) || body[1] - '0' != inseq % 10)
            return false;
        string p = body.Substring(2);
        try
        {
            if (body[0] == 'i')
            {
                byte[] b = Convert.FromBase64String(p);
                ins.Write(b, 0, b.Length);
                ins.Flush();
            }
            else
            {
                string[] s = p.Split(',');
                ResizePseudoConsole(pc, Size(int.Parse(s[0]), int.Parse(s[1])));
            }
        }
        catch (FormatException) { return false; }
        catch (IndexOutOfRangeException) { return false; }
        catch (IOException) { }
        return true;
    }

    // Draw shows a page: the data rows first and the header last, so a
    // header on screen means its rows are (almost always) there too.
    void Draw(int id, long seq, char enc, string data, long inseq, string st)
    {
        string head = "RDPCLI2 " + id + " " + seq + " " + enc + " " + data.Length + " " + inseq + " " + st;
        string sum = Hex(Sha(head + "\n" + data), 4);
        int row = 1;
        for (int q = 0; q < data.Length; q += cw)
        {
            Console.SetCursorPosition(0, row++);
            Console.Write(data.Substring(q, Math.Min(cw, data.Length - q)).PadRight(cw));
        }
        Console.SetCursorPosition(0, 0);
        Console.Write((head + " " + sum).PadRight(cw));
    }

    void Append(byte[] b, int n)
    {
        lock (sync)
        {
            if (plen + n > pbuf.Length)
            {
                byte[] nb = new byte[Math.Max(pbuf.Length * 2, plen + n)];
                Buffer.BlockCopy(pbuf, 0, nb, 0, plen);
                pbuf = nb;
            }
            Buffer.BlockCopy(b, 0, pbuf, plen, n);
            plen += n;
            lastOut = DateTime.UtcNow;
        }
    }

    // Take removes the next page's worth of output and returns it as
    // base64: deflated (enc 'z') when that carries more, else raw ('b').
    string Take(int cap, out char enc)
    {
        enc = 'b';
        lock (sync)
        {
            if (plen == 0)
                return "";
            int rawMax = cap / 4 * 3;
            if (plen > 256)
            {
                int k = Math.Min(plen, rawMax * 4);
                while (true)
                {
                    string z = Convert.ToBase64String(Deflate(pbuf, k));
                    if (z.Length <= cap && (k > rawMax || z.Length < (k + 2) / 3 * 4))
                    {
                        Consume(k);
                        enc = 'z';
                        return z;
                    }
                    if (k <= rawMax)
                        break;
                    k = Math.Max(rawMax, k * 2 / 3);
                }
            }
            int n = Math.Min(plen, rawMax);
            string s = Convert.ToBase64String(pbuf, 0, n);
            Consume(n);
            return s;
        }
    }

    void Consume(int n)
    {
        Buffer.BlockCopy(pbuf, n, pbuf, 0, plen - n);
        plen -= n;
    }

    static byte[] Deflate(byte[] b, int n)
    {
        MemoryStream m = new MemoryStream();
        using (DeflateStream z = new DeflateStream(m, CompressionMode.Compress))
            z.Write(b, 0, n);
        return m.ToArray();
    }

    static byte[] Sha(string s)
    {
        using (SHA256 h = SHA256.Create())
            return h.ComputeHash(Encoding.ASCII.GetBytes(s));
    }

    static string Hex(byte[] b, int n)
    {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < n; i++)
            s.Append(b[i].ToString("x2"));
        return s.ToString();
    }
}
