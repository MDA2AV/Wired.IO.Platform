// See https://aka.ms/new-console-template for more information

/*
using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Net;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Text;

namespace Wired.IO.Platform;

internal class Program
{
    private static Socket? _socket;
    
    private enum State
    {
        StartLine,
        Headers,
        Body
    }
    
    public static async Task Main(string[] args)
    {
        CreateListeningSocket();
        
        var acceptTasks = new Task[1];
        for (var i = 0; i < acceptTasks.Length; i++)
        {
            acceptTasks[i] = AcceptLoopAsync();
        }

        await Task.WhenAll(acceptTasks);
        
        //while (true) {
        //    var client = await _socket!.AcceptAsync();
        //    _ = HandleClientAsync2(client);
        //}
    }

    private static async Task AcceptLoopAsync()
    {
        while (true){
            var client = await _socket!.AcceptAsync(); 
            _ = HandleClientAsync(client);
        }
    }

    private static void HandleClient(Socket client)
    {
        try
        {
            while (client.Connected)
            {
                var arr = ArrayPool<byte>.Shared.Rent(512);
                var nbytes = client.Receive(arr, SocketFlags.None);

                if (nbytes == 0)
                    continue;
                
                client.Send(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 28\r\n\r\n {\"message\":\"Hello, World!\"}\r\n"u8);
            }
        }
        finally
        {
            client.Dispose();
        }
    }
    
    private static async Task HandleClientAsync2(Socket client)
    {
        try
        {
            while (client.Connected)
            {
                var arr = ArrayPool<byte>.Shared.Rent(512);
                var nbytes = await client.ReceiveAsync(arr, SocketFlags.None);
                client.Send(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 28\r\n\r\n {\"message\":\"Hello, World!\"}\r\n"u8);
            }
        }
        finally
        {
            client.Dispose();
        }
    }
    
    private static async ValueTask HandleClientAsync(Socket client)
    {
        await using var stream = new NetworkStream(client);
        
        var reader = PipeReader.Create(stream,
            new StreamPipeReaderOptions(
                MemoryPool<byte>.Shared, 
                leaveOpen: false,
                bufferSize: 4096*4, 
                minimumReadSize: 1024));
        
        var writer = PipeWriter.Create(stream,
            new StreamPipeWriterOptions(
                MemoryPool<byte>.Shared, 
                leaveOpen: false,
                minimumBufferSize: 512));

        try
        {
            var state = State.StartLine;

            while (true)
            {
                var readResult = await reader.ReadAsync();
                var buffer = readResult.Buffer;

                var isCompleted = readResult.IsCompleted;

                if (buffer.IsEmpty && isCompleted)
                    break;

                if (ProcessRequest(reader, writer, ref buffer, ref state, ref isCompleted))
                    await writer.FlushAsync();
            }
        }
        catch
        {
            // Do Nothing
        }
        finally
        {
            await reader.CompleteAsync();
            await writer.CompleteAsync();

            client.Dispose();
        }
    }

    private static bool ProcessRequest(
        PipeReader reader, 
        PipeWriter writer, 
        ref ReadOnlySequence<byte> buffer, 
        ref State state, 
        ref bool isCompleted)
    {
        var flush = false;

        // Hot path: A new request is starting, and the buffer is a single segment
        // If some of the request is already read, always fall back to multi-segment path
        // This avoids complex state management in the single-segment path
        // This optimizes for the common case of small requests that fit in one segment (vast majority of cases)
        if (buffer.IsSingleSegment && state == State.StartLine)
        {
            var currentPosition = 0;

            while (true)
            {
                if (buffer.Length == 0 || isCompleted)
                    break;

                var requestReceived = ExtractHeaderFromSingleSegment(ref buffer, ref currentPosition);
                if (!requestReceived)
                {
                    reader.AdvanceTo(buffer.GetPosition(0), buffer.GetPosition(buffer.FirstSpan.Length));
                    break;
                }
                
                reader.AdvanceTo(buffer.GetPosition(currentPosition));
                
                
                state = State.Body;
                
                
                //var bodyReceived = TryExtractBodyFromSingleSegment(context, ref buffer, ref currentPosition, out var bodyEmpty);
                //if (!bodyReceived)
                //    break;
                //if(!bodyEmpty)
                //    reader.AdvanceTo(buffer.GetPosition(currentPosition));
                

                // Respond
                writer.Write("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 28\r\n\r\n {\"message\":\"Hello, World!\"}\r\n"u8);
                
                // Signal that there is something to flush
                flush = true;

                state = State.StartLine;

                if (currentPosition == buffer.Length) // There is no more data, need to ReadAsync()
                    break;
            }
        }
        
        return flush;
    }
    
    [SkipLocalsInit]
    private static bool ExtractHeaderFromSingleSegment(
        ref ReadOnlySequence<byte> buffer, 
        ref int position)
    {
        // Hot path, single segment buffer
        var bufferSpan = buffer.FirstSpan[position..];
        var fullHeaderIndex = bufferSpan.IndexOf("\r\n\r\n"u8);

        if (fullHeaderIndex == -1)
            return false;

        // Whole headers are present for the request
        // Parse first header

        var lineEnd = bufferSpan.IndexOf("\r\n"u8);
        var firstHeader = bufferSpan[..lineEnd];

        var firstSpace = firstHeader.IndexOf(Space);
        if (firstSpace == -1)
            throw new InvalidOperationException("Invalid request line");

        //context.Request.HttpMethod = CachedData.PreCachedHttpMethods.GetOrAdd(firstHeader[..firstSpace]);
        
        var secondSpaceRelative = firstHeader[(firstSpace + 1)..].IndexOf(Space);
        if (secondSpaceRelative == -1)
            throw new InvalidOperationException("Invalid request line");

        var secondSpace = firstSpace + secondSpaceRelative + 1;
        var url = firstHeader[(firstSpace + 1)..secondSpace];
        var queryStart = url.IndexOf(Question); // (byte)'?'

        if (queryStart != -1)
        {
            // Route has params
            //context.Request.Route = CachedData.CachedRoutes.GetOrAdd(url[..queryStart]);
            var querySpan = url[(queryStart + 1)..];
            var current = 0;
            while (current < querySpan.Length)
            {
                var separator = querySpan[current..].IndexOf(QuerySeparator); // (byte)'&'
                ReadOnlySpan<byte> pair;

                if (separator == -1)
                {
                    pair = querySpan[current..];
                    current = querySpan.Length;
                }
                else
                {
                    pair = querySpan.Slice(current, separator);
                    current += separator + 1;
                }

                var equalsIndex = pair.IndexOf(Equal); // (byte)'='
                if (equalsIndex == -1)
                    break;
                
                //context.Request.QueryParameters?
                //    .TryAdd(CachedData.CachedQueryKeys.GetOrAdd(pair[..equalsIndex]),
                //         Encoders.Utf8Encoder.GetString(pair[(equalsIndex + 1)..]));
            }
        }
        else
        {
            // Url is same as route
            //context.Request.Route = CachedData.CachedRoutes.GetOrAdd(url);
        }

        // Parse remaining headers
        var lineStart = 0;
        while (true)
        {
            lineStart += lineEnd + 2;

            lineEnd = bufferSpan[lineStart..].IndexOf("\r\n"u8);
            if (lineEnd == 0)
            {
                // All Headers read
                break;
            }

            var header = bufferSpan.Slice(lineStart, lineEnd);
            var colonIndex = header.IndexOf(Colon);

            if (colonIndex == -1)
            {
                // Malformed header
                continue;
            }

            var headerKey = header[..colonIndex];
            var headerValue = header[(colonIndex + 2)..];

            //context.Request.Headers
            //    .TryAdd(CachedData.PreCachedHeaderKeys.GetOrAdd(headerKey), CachedData.PreCachedHeaderValues.GetOrAdd(headerValue));
        }

        position += fullHeaderIndex + 4;
        //context.Reader.AdvanceTo(buffer.GetPosition(position));

        return true;
    }
    
    // ---- Constants & literals ----

    /// <summary>CRLF delimiter used for line termination.</summary>
    private static ReadOnlySpan<byte> Crlf => "\r\n"u8;
    private static ReadOnlySpan<byte> CrlfCrlf => "\r\n\r\n"u8;

    private const string ContentLength = "Content-Length";
    private const string TransferEncoding = "Transfer-Encoding";
            
    private const byte Space = 0x20; // ' '
    private const byte Question = 0x3F; // '?'
    private const byte QuerySeparator = 0x26; // '&'
    private const byte Equal = 0x3D; // '='
    private const byte Colon = 0x3A; // ':'
    private const byte SemiColon = 0x3B; // ';'
    
    private static void CreateListeningSocket()
    {
        ////IPv6
        _socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        _socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
        _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        _socket.NoDelay = true;

        _socket.Bind(new IPEndPoint(IPAddress.Any, 8080));
        _socket.Listen(16384);
    }
}
*/

/*

using System;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Text;

internal static class Native
{
    public const int AF_INET = 2;
    public const int SOCK_STREAM = 1;
    public const int IPPROTO_TCP = 6;

    public const int SOL_SOCKET = 1;
    public const int SO_REUSEADDR = 2;

    public const int MSG_NOSIGNAL = 0x4000;

    [StructLayout(LayoutKind.Sequential)]
    public struct in_addr
    {
        public uint s_addr; // network byte order
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_in
    {
        public ushort sin_family;
        public ushort sin_port;   // network byte order
        public in_addr sin_addr;  // network byte order
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] sin_zero;
    }

    [DllImport("libc", SetLastError = true)]
    public static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    public static extern int setsockopt(int sockfd, int level, int optname, ref int optval, uint optlen);

    [DllImport("libc", SetLastError = true)]
    public static extern int bind(int sockfd, ref sockaddr_in addr, uint addrlen);

    [DllImport("libc", SetLastError = true)]
    public static extern int listen(int sockfd, int backlog);

    [DllImport("libc", SetLastError = true)]
    public static extern int accept(int sockfd, IntPtr addr, IntPtr addrlen);

    [DllImport("libc", SetLastError = true)]
    public static extern long recv(int sockfd, IntPtr buf, ulong len, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern long send(int sockfd, IntPtr buf, ulong len, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int close(int fd);

    public static ushort HostToNetwork16(ushort v) => (ushort)((v << 8) | (v >> 8));

    public static uint HostToNetwork32(uint v) =>
        (uint)(((v & 0x000000FF) << 24) |
               ((v & 0x0000FF00) << 8)  |
               ((v & 0x00FF0000) >> 8)  |
               ((v & 0xFF000000) >> 24));
}

public class Program
{
    // Add these constants
    public const int IPPROTO_TCP = 6;
    public const int TCP_NODELAY = 1;      // Linux
    public const int EAGAIN = 11;
    public const int EINTR  = 4;
    public const int EPIPE  = 32;
    public const int ECONNRESET = 104;
    
    public static void Main()
    {
        // 1) socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        int listenFd = Native.socket(Native.AF_INET, Native.SOCK_STREAM, Native.IPPROTO_TCP);
        ThrowIfError(listenFd, "socket");

        // 2) setsockopt(SO_REUSEADDR, 1)
        int yes = 1;
        var r = Native.setsockopt(listenFd, Native.SOL_SOCKET, Native.SO_REUSEADDR, ref yes, sizeof(int));
        ThrowIfError(r, "setsockopt(SO_REUSEADDR)");

        // 3) bind(0.0.0.0:8080)
        var addr = new Native.sockaddr_in
        {
            sin_family = (ushort)Native.AF_INET,
            sin_port = Native.HostToNetwork16(8080),
            sin_addr = new Native.in_addr { s_addr = 0 }, // INADDR_ANY
            sin_zero = new byte[8]
        };
        r = Native.bind(listenFd, ref addr, (uint)Marshal.SizeOf<Native.sockaddr_in>());
        ThrowIfError(r, "bind");

        // 4) listen(backlog)
        r = Native.listen(listenFd, 1024);
        ThrowIfError(r, "listen");

        Console.WriteLine("Listening on http://0.0.0.0:8080");

        // Prebuild response
        //byte[] headerBytes = Encoding.UTF8.GetBytes(headerStr);

        // Main accept loop
        while (true)
        {
            int clientFd = Native.accept(listenFd, IntPtr.Zero, IntPtr.Zero);
            if (clientFd < 0)
            {
                PrintLastError("accept");
                continue;
            }
            
            int one = 1;
            _ = Native.setsockopt(clientFd, Native.IPPROTO_TCP, TCP_NODELAY, ref one, sizeof(int));

            Task.Run(() =>
            {
                HandleClient(ref clientFd);
            });
        }
    }
    
    private static ReadOnlySpan<byte> Body => "{\"message\":\"Hello, World!\"}"u8;
    private static ReadOnlySpan<byte> HeaderStr =>
        "HTTP/1.1 200 OK\r\n"u8 +
        "Content-Type: application/json; charset=UTF-8\r\n"u8 +
        "Content-Length: 27\r\n"u8 +
        "Connection: keep-alive\r\n"u8 +
        "\r\n"u8;

    private static ReadOnlySpan<byte> FullResponse =>
        "HTTP/1.1 200 OK\r\n"u8 +
        "Content-Type: application/json; charset=UTF-8\r\n"u8 +
        "Content-Length: 27\r\n"u8 +
        "Connection: keep-alive\r\n"u8 +
        "\r\n"u8 +
        "{\"message\":\"Hello, World!\"}"u8;

    private static void HandleClient(ref int clientFd)
    {
        try
        {
            HandleClientKeepAliveMinimal(clientFd, HeaderStr, Body);
        }
        finally
        {
            Native.close(clientFd);
        }
    }
    
    private static void HandleClientKeepAliveMinimal(int fd, ReadOnlySpan<byte> responseHeader, ReadOnlySpan<byte> responseBody)
    {
        byte[] buf = new byte[8192];
        int filled = 0;

        while (true)
        {
            // read until we see \r\n\r\n
            int headersEnd = -1;
            while (headersEnd < 0)
            {
                // if buffer is full and still no CRLFCRLF, just bail (too big / invalid)
                if (filled == buf.Length) return;

                long got;
                unsafe
                {
                    fixed (byte* p = &buf[filled])
                    {
                        got = Native.recv(fd, (IntPtr)p, (ulong)(buf.Length - filled), 0);
                    }
                }
                if (got <= 0) return; // client closed or error

                filled += (int)got;
                headersEnd = FindCrlfCrlf(buf.AsSpan(0, filled));
            }

            // we got a full request head (ignore any extra data—super naive)
            // send the response
            unsafe
            {
                fixed (byte* ph = FullResponse)
                    SendAll(fd, (IntPtr)ph, (ulong)FullResponse.Length);
                
                //fixed (byte* ph = responseHeader)
                //    SendAll(fd, (IntPtr)ph, (ulong)responseHeader.Length);
                //fixed (byte* pb = responseBody)
                //    SendAll(fd, (IntPtr)pb, (ulong)responseBody.Length);
            }

            // compact any leftover bytes *after* the header block (pipelined next request)
            int after = headersEnd + 4;
            int remaining = filled - after;
            if (remaining > 0)
                Buffer.BlockCopy(buf, after, buf, 0, remaining);
            filled = remaining;

            // loop to serve the next request on the same connection
        }
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private static int FindCrlfCrlf(ReadOnlySpan<byte> s)
    {
        // returns the index of the first '\r' in the "\r\n\r\n" sequence, or -1 if not found
        for (int i = 3; i < s.Length; i++)
        {
            if (s[i - 3] == (byte)'\r' && s[i - 2] == (byte)'\n' &&
                s[i - 1] == (byte)'\r' && s[i]     == (byte)'\n')
                return i - 3;
        }
        return -1;
    }

    private static void SendAll(int fd, IntPtr buf, ulong len)
    {
        ulong sent = 0;
        while (sent < len)
        {
            long n = Native.send(fd, buf + (int)sent, len - sent, Native.MSG_NOSIGNAL);
            if (n < 0)
            {
                // If the peer closed (EPIPE) or reset, just stop sending.
                PrintLastError("send");
                break;
            }
            sent += (ulong)n;
        }
    }

    private static void ThrowIfError(int rc, string where)
    {
        if (rc < 0)
        {
            PrintLastError(where);
            throw new InvalidOperationException(where + " failed");
        }
    }

    private static void PrintLastError(string where)
    {
        // errno is in Marshal.GetLastPInvokeError() in .NET 8+
        try
        {
            int errno = Marshal.GetLastPInvokeError();
            Console.Error.WriteLine($"{where} errno={errno}");
        }
        catch
        {
            Console.Error.WriteLine($"{where} failed");
        }
    }
}
*/

/*

// Program.cs
// High-concurrency non-blocking epoll HTTP/1.1 server (Linux).
// - One worker per core with SO_REUSEPORT
// - No parsing: waits only for \r\n\r\n
// - Sends response immediately in EPOLLIN; enables EPOLLOUT only on EAGAIN/partial
// - Single write per response (header+body)
// - epoll_event.data is 64-bit; store fd as 32-bit in the 64-bit slot

using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static Native;

internal static class Native
{
    // sockets
    public const int AF_INET = 2, SOCK_STREAM = 1, IPPROTO_TCP = 6;
    public const int SOL_SOCKET = 1, SO_REUSEADDR = 2, SO_REUSEPORT = 15;
    public const int TCP_NODELAY = 1;
    public const int MSG_NOSIGNAL = 0x4000;

    // accept4 / fcntl
    public const int SOCK_NONBLOCK = 0x800;
    public const int SOCK_CLOEXEC  = 0x80000;
    public const int F_GETFL = 3, F_SETFL = 4;
    public const int O_NONBLOCK = 0x800;

    // epoll
    public const int EPOLLIN = 0x001, EPOLLOUT = 0x004, EPOLLERR = 0x008, EPOLLHUP = 0x010;
    public const int EPOLL_CLOEXEC = 0x80000;
    public const int EPOLL_CTL_ADD = 1, EPOLL_CTL_MOD = 3, EPOLL_CTL_DEL = 2;

    // errno
    public const int EINTR = 4, EAGAIN = 11, EWOULDBLOCK = 11, ENOSYS = 38, EPIPE = 32, ECONNRESET = 104;

    [StructLayout(LayoutKind.Sequential)]
    public struct in_addr { public uint s_addr; }

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_in
    {
        public ushort sin_family;
        public ushort sin_port;
        public in_addr sin_addr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] sin_zero;
    }

    // 64-bit epoll data field (matches epoll_data_t on 64-bit)
    [StructLayout(LayoutKind.Sequential)]
    public struct epoll_event
    {
        public uint events;
        public ulong data;
    }

    [DllImport("libc", SetLastError = true)] public static extern int socket(int domain, int type, int protocol);
    [DllImport("libc", SetLastError = true)] public static extern int setsockopt(int sockfd, int level, int optname, ref int optval, uint optlen);
    [DllImport("libc", SetLastError = true)] public static extern int bind(int sockfd, ref sockaddr_in addr, uint addrlen);
    [DllImport("libc", SetLastError = true)] public static extern int listen(int sockfd, int backlog);
    [DllImport("libc", SetLastError = true)] public static extern int accept4(int sockfd, IntPtr addr, IntPtr addrlen, int flags);
    [DllImport("libc", SetLastError = true)] public static extern int accept(int sockfd, IntPtr addr, IntPtr addrlen);
    [DllImport("libc", SetLastError = true)] public static extern int fcntl(int fd, int cmd, int arg);
    [DllImport("libc", SetLastError = true)] public static extern long recv(int sockfd, IntPtr buf, ulong len, int flags);
    [DllImport("libc", SetLastError = true)] public static extern long send(int sockfd, IntPtr buf, ulong len, int flags);
    [DllImport("libc", SetLastError = true)] public static extern int close(int fd);

    [DllImport("libc", SetLastError = true)] public static extern int epoll_create1(int flags);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_ctl(int epfd, int op, int fd, ref epoll_event ev);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_wait(int epfd, [In, Out] epoll_event[] events, int maxevents, int timeout);

    public static ushort HostToNetwork16(ushort v) => (ushort)((v << 8) | (v >> 8));
}

public sealed class Conn
{
    public int Fd;
    public byte[] Buf = new byte[8192];
    public int Start;      // first unread byte
    public int End;        // 1 past last unread byte
    public bool WantWrite; // true if write is pending (partial or EAGAIN)
    public int RespSent;   // bytes of Response already sent
    
    public ReadOnlySpan<byte> Window => Buf.AsSpan(Start, End - Start);
    
    public int Free => Buf.Length - End;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void CompactIfNeeded()
    {
        if (Start == 0) return;
        int len = End - Start;
        if (len > 0)
            Buffer.BlockCopy(Buf, Start, Buf, 0, len);
        Start = 0;
        End = len;
    }
}

public class Program
{
    static readonly byte[] Response = BuildResponse();
    const int Backlog = 1024;

    public static void Main()
    {
        int workers = Environment.ProcessorCount; // one per core
        //int workers = 2; // one per core
        Console.WriteLine($"Starting {workers} workers on :8080 (SO_REUSEPORT) …");

        var threads = new Thread[workers];
        for (int i = 0; i < workers; i++)
        {
            int wi = i; // capture
            threads[i] = new Thread(() => RunWorker(8080, wi)) { IsBackground = true, Name = $"epoll-worker-{wi}" };
            threads[i].Start();
        }

        Console.WriteLine("Press Ctrl+C to exit.");
        Thread.Sleep(Timeout.Infinite);
    }

    static void RunWorker(int port, int workerIndex)
    {
        int listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ThrowIfErr(listenFd, "socket");

        int one = 1;
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, ref one, (uint)sizeof(int));
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEPORT, ref one, (uint)sizeof(int));

        var addr = new sockaddr_in
        {
            sin_family = (ushort)AF_INET,
            sin_port   = HostToNetwork16((ushort)port),
            sin_addr   = new in_addr { s_addr = 0 }, // INADDR_ANY
            sin_zero   = new byte[8]
        };
        ThrowIfErr(bind(listenFd, ref addr, (uint)Marshal.SizeOf<sockaddr_in>()), "bind");
        ThrowIfErr(listen(listenFd, Backlog), "listen");

        // non-blocking listen socket
        int fl = fcntl(listenFd, F_GETFL, 0);
        if (fl >= 0) fcntl(listenFd, F_SETFL, fl | O_NONBLOCK);

        int ep = epoll_create1(EPOLL_CLOEXEC);
        ThrowIfErr(ep, "epoll_create1");

        var lev = new epoll_event { events = (uint)EPOLLIN, data = (ulong)(uint)listenFd };
        ThrowIfErr(epoll_ctl(ep, EPOLL_CTL_ADD, listenFd, ref lev), "epoll_ctl ADD listen");

        var conns = new Dictionary<int, Conn>(capacity: 16384);
        var events = new epoll_event[32768];

        if (workerIndex == 0)
            Console.WriteLine("Listening on http://0.0.0.0:8080");

        while (true)
        {
            int n = epoll_wait(ep, events, events.Length, -1);
            if (n < 0)
            {
                int err = Marshal.GetLastPInvokeError();
                if (err == EINTR) continue;
                throw new InvalidOperationException("epoll_wait failed errno=" + err);
            }

            for (int i = 0; i < n; i++)
            {
                int fd = (int)events[i].data;
                uint evs = events[i].events;

                if (fd == listenFd)
                {
                    // accept all queued
                    while (true)
                    {
                        int cfd = accept4(listenFd, IntPtr.Zero, IntPtr.Zero, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        if (cfd < 0)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK) break;
                            if (err == ENOSYS)
                            {
                                cfd = accept(listenFd, IntPtr.Zero, IntPtr.Zero);
                                if (cfd < 0) break;
                                int fl2 = fcntl(cfd, F_GETFL, 0);
                                if (fl2 >= 0) fcntl(cfd, F_SETFL, fl2 | O_NONBLOCK);
                            }
                            else break;
                        }

                        int one2 = 1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, ref one2, (uint)sizeof(int));
                        var cev = new epoll_event { events = (uint)EPOLLIN, data = (ulong)(uint)cfd };
                        epoll_ctl(ep, EPOLL_CTL_ADD, cfd, ref cev);

                        conns[cfd] = new Conn { Fd = cfd };
                    }
                    continue;
                }

                // error/hangup
                if ((evs & (EPOLLHUP | EPOLLERR)) != 0)
                {
                    CloseConn(fd, conns);
                    continue;
                }

                // readable
                if ((evs & EPOLLIN) != 0)
                {
                    if (!conns.TryGetValue(fd, out var c)) { CloseQuiet(fd); continue; }

                    // read until would-block or until we see \r\n\r\n
                    while (true)
                    {
                        if (c.Free == 0)
                        {
                            // compact once if possible
                            if (c.Start > 0) c.CompactIfNeeded();
                            if (c.Free == 0) { CloseConn(fd, conns); break; } // header too large
                        }

                        long got;
                        unsafe
                        {
                            fixed (byte* p = &c.Buf[c.End])
                                got = recv(fd, (IntPtr)p, (ulong)c.Free, 0);
                        }

                        if (got > 0)
                        {
                            c.End += (int)got;
                            int idx = FindCrlfCrlf(c.Buf.AsSpan(c.Start, c.End - c.Start));
                            if (idx >= 0)
                            {
                                // header end found at (c.Start + idx) .. (c.Start + idx + 3)
                                int after = c.Start + idx + 4;
                                // Advance Start to after headers (leave any pipelined bytes for next loop)
                                c.Start = after;

                                // Try to send immediately (stay on EPOLLIN if fully sent)
                                c.WantWrite = false;
                                c.RespSent = 0;

                                long nSent;
                                unsafe
                                {
                                    fixed (byte* p = Response)
                                        nSent = send(fd, (IntPtr)p, (ulong)Response.Length, MSG_NOSIGNAL);
                                }

                                if (nSent == Response.Length)
                                {
                                    // fully sent; keep EPOLLIN so we can read next request right away
                                }
                                else if (nSent >= 0)
                                {
                                    c.WantWrite = true;
                                    c.RespSent = (int)nSent;
                                    var wev = new epoll_event { events = (uint)EPOLLOUT, data = (ulong)(uint)fd };
                                    epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref wev);
                                }
                                else
                                {
                                    int err = Marshal.GetLastPInvokeError();
                                    if (err == EAGAIN || err == EWOULDBLOCK)
                                    {
                                        c.WantWrite = true;
                                        c.RespSent = 0;
                                        var wev = new epoll_event { events = (uint)EPOLLOUT, data = (ulong)(uint)fd };
                                        epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref wev);
                                    }
                                    else
                                    {
                                        CloseConn(fd, conns);
                                    }
                                }

                                // If buffer grew too big, compact window (cheap)
                                if (c.Start >= c.End) { c.Start = c.End = 0; }
                                else if (c.Start > 0 && (c.End - c.Start) < (c.Buf.Length / 2))
                                {
                                    c.CompactIfNeeded();
                                }

                                break; // switch to write (if needed) or continue on next epoll tick
                            }

                            // else: need more bytes to find CRLFCRLF; continue recv
                            continue;
                        }
                        else if (got == 0)
                        {
                            CloseConn(fd, conns); // orderly close
                            break;
                        }
                        else
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK) break;
                            CloseConn(fd, conns);
                            break;
                        }
                    }
                }

                // writable
                if ((evs & EPOLLOUT) != 0)
                {
                    if (!conns.TryGetValue(fd, out var c)) { CloseQuiet(fd); continue; }
                    if (!c.WantWrite)
                    {
                        // spurious; back to read
                        var rev = new epoll_event { events = (uint)EPOLLIN, data = (ulong)(uint)fd };
                        epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref rev);
                        continue;
                    }

                    while (true)
                    {
                        long nSent;
                        unsafe
                        {
                            fixed (byte* p = Response)
                                nSent = send(fd, (IntPtr)(p + c.RespSent), (ulong)(Response.Length - c.RespSent), MSG_NOSIGNAL);
                        }

                        if (nSent > 0)
                        {
                            c.RespSent += (int)nSent;
                            if (c.RespSent == Response.Length)
                            {
                                c.WantWrite = false;
                                c.RespSent = 0;
                                // done writing → go back to EPOLLIN
                                var rev = new epoll_event { events = (uint)EPOLLIN, data = (ulong)(uint)fd };
                                epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref rev);
                                break;
                            }
                            continue; // partial, try again
                        }
                        else if (nSent == 0)
                        {
                            // treat as would-block
                            break;
                        }
                        else
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK) break;
                            if (err == EPIPE || err == ECONNRESET) { CloseConn(fd, conns); break; }
                            CloseConn(fd, conns);
                            break;
                        }
                    }
                }
            }
        }
    }

    static void CloseConn(int fd, Dictionary<int, Conn> map)
    {
        map.Remove(fd);
        CloseQuiet(fd);
    }

    static void CloseQuiet(int fd)
    {
        try { close(fd); } catch { }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static int FindCrlfCrlf(ReadOnlySpan<byte> s)
    {
        for (int i = 3; i < s.Length; i++)
            if (s[i - 3] == (byte)'\r' && s[i - 2] == (byte)'\n' && s[i - 1] == (byte)'\r' && s[i] == (byte)'\n')
                return i - 3;
        return -1;
    }

    static byte[] BuildResponse()
    {
        ReadOnlySpan<byte> body = "{\"message\":\"Hello, World!\"}"u8;
        string head =
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/json; charset=UTF-8\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: keep-alive\r\n" +
            "\r\n";
        byte[] hb = Encoding.UTF8.GetBytes(head);
        byte[] buf = new byte[hb.Length + body.Length];
        Buffer.BlockCopy(hb, 0, buf, 0, hb.Length);
        body.CopyTo(buf.AsSpan(hb.Length));
        return buf;
    }

    static void ThrowIfErr(int rc, string where)
    {
        if (rc >= 0) return;
        int errno = Marshal.GetLastPInvokeError();
        throw new InvalidOperationException($"{where} failed errno={errno}");
    }
}
*/

/*
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static Native;

internal static class Native
{
    public const int AF_INET = 2, SOCK_STREAM = 1, IPPROTO_TCP = 6;
    public const int SOL_SOCKET = 1, SO_REUSEADDR = 2, SO_REUSEPORT = 15, SO_LINGER = 13;
    public const int TCP_NODELAY = 1;
    public const int MSG_NOSIGNAL = 0x4000;
    public const int SOCK_NONBLOCK = 0x800;
    public const int SOCK_CLOEXEC  = 0x80000;
    public const int F_GETFL = 3, F_SETFL = 4;
    public const int O_NONBLOCK = 0x800;
    public const int EPOLLIN = 0x001, EPOLLOUT = 0x004, EPOLLERR = 0x008, EPOLLHUP = 0x010;
    public const int EPOLL_CLOEXEC = 0x80000;
    public const int EPOLL_CTL_ADD = 1, EPOLL_CTL_MOD = 3, EPOLL_CTL_DEL = 2;
    public const int EINTR = 4, EAGAIN = 11, EWOULDBLOCK = 11, ENOSYS = 38, EPIPE = 32, ECONNRESET = 104;
    public const int EMFILE = 24, ENFILE = 23;

    [StructLayout(LayoutKind.Sequential)]
    public struct in_addr { public uint s_addr; }

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_in
    {
        public ushort sin_family;
        public ushort sin_port;
        public in_addr sin_addr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct epoll_event
    {
        public uint events;
        public ulong data;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct linger
    {
        public int l_onoff;
        public int l_linger;
    }

    [DllImport("libc", SetLastError = true)] public static extern int socket(int domain, int type, int protocol);
    [DllImport("libc", SetLastError = true)] public static extern int setsockopt(int sockfd, int level, int optname, ref int optval, uint optlen);
    [DllImport("libc", SetLastError = true)] public static extern int setsockopt(int sockfd, int level, int optname, ref linger optval, uint optlen);
    [DllImport("libc", SetLastError = true)] public static extern int bind(int sockfd, ref sockaddr_in addr, uint addrlen);
    [DllImport("libc", SetLastError = true)] public static extern int listen(int sockfd, int backlog);
    [DllImport("libc", SetLastError = true)] public static extern int accept4(int sockfd, IntPtr addr, IntPtr addrlen, int flags);
    [DllImport("libc", SetLastError = true)] public static extern int accept(int sockfd, IntPtr addr, IntPtr addrlen);
    [DllImport("libc", SetLastError = true)] public static extern int fcntl(int fd, int cmd, int arg);
    [DllImport("libc", SetLastError = true)] public static extern long recv(int sockfd, IntPtr buf, ulong len, int flags);
    [DllImport("libc", SetLastError = true)] public static extern long send(int sockfd, IntPtr buf, ulong len, int flags);
    [DllImport("libc", SetLastError = true)] public static extern int close(int fd);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_create1(int flags);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_ctl(int epfd, int op, int fd, ref epoll_event ev);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_wait(int epfd, [In, Out] epoll_event[] events, int maxevents, int timeout);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ushort HostToNetwork16(ushort v) => (ushort)((v << 8) | (v >> 8));
}

public sealed class Conn
{
    public int Fd;
    public byte[] Buf = new byte[4096]; // grows up to MaxHeader
    public int Start;
    public int End;
    public bool WantWrite;
    public int RespSent;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void CompactIfNeeded()
    {
        if (Start == 0) return;
        int len = End - Start;
        if (len > 0)
            Buffer.BlockCopy(Buf, Start, Buf, 0, len);
        Start = 0;
        End = len;
    }
}

public class Program
{
    // Backing arrays; exposed as ReadOnlySpan<byte> below
    static readonly byte[] _response200 = Build200();
    static readonly byte[] _response431 = BuildSimpleResponse(431, "Request Header Fields Too Large");

    // Public spans used throughout
    static ReadOnlySpan<byte> Response200 => _response200;
    static ReadOnlySpan<byte> Response431 => _response431;

    const int Backlog = 2048;
    const int MaxHeader = 16 * 1024;

    public static void Main()
    {
        int workers = Environment.ProcessorCount;
        Console.WriteLine($"Starting {workers} workers on :8080 (SO_REUSEPORT) …");

        var threads = new Thread[workers];
        for (int i = 0; i < workers; i++)
        {
            int wi = i;
            threads[i] = new Thread(() => RunWorker(8080, wi)) { IsBackground = true, Name = $"epoll-worker-{wi}" };
            threads[i].Start();
        }

        Console.WriteLine("Press Ctrl+C to exit.");
        Thread.Sleep(Timeout.Infinite);
    }

    static void RunWorker(int port, int workerIndex)
    {
        int listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ThrowIfErr(listenFd, "socket");

        int one = 1;
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, ref one, (uint)sizeof(int));
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEPORT, ref one, (uint)sizeof(int));

        var addr = new sockaddr_in
        {
            sin_family = (ushort)AF_INET,
            sin_port   = HostToNetwork16((ushort)port),
            sin_addr   = new in_addr { s_addr = 0 }, // 0.0.0.0
            sin_zero   = new byte[8]
        };
        ThrowIfErr(bind(listenFd, ref addr, (uint)Marshal.SizeOf<sockaddr_in>()), "bind");
        ThrowIfErr(listen(listenFd, Backlog), "listen");

        int fl = fcntl(listenFd, F_GETFL, 0);
        if (fl >= 0) fcntl(listenFd, F_SETFL, fl | O_NONBLOCK);

        int ep = epoll_create1(EPOLL_CLOEXEC);
        ThrowIfErr(ep, "epoll_create1");

        var lev = new epoll_event { events = (uint)EPOLLIN, data = (ulong)(uint)listenFd };
        ThrowIfErr(epoll_ctl(ep, EPOLL_CTL_ADD, listenFd, ref lev), "epoll_ctl ADD listen");

        var conns = new Dictionary<int, Conn>(capacity: 1024);
        var events = new epoll_event[512];

        if (workerIndex == 0)
            Console.WriteLine("Listening on http://0.0.0.0:8080");

        var evIn  = new epoll_event { events = (uint)EPOLLIN };
        var evOut = new epoll_event { events = (uint)EPOLLOUT };

        while (true)
        {
            int n = epoll_wait(ep, events, events.Length, -1);
            if (n < 0)
            {
                int err = Marshal.GetLastPInvokeError();
                if (err == EINTR) continue;
                throw new InvalidOperationException("epoll_wait failed errno=" + err);
            }

            for (int i = 0; i < n; i++)
            {
                int fd = (int)events[i].data;
                uint evs = events[i].events;

                if (fd == listenFd)
                {
                    // Accept burst
                    for (int j = 0; j < 64; j++)
                    {
                        int cfd = accept4(listenFd, IntPtr.Zero, IntPtr.Zero, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        if (cfd < 0)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK) break;
                            if (err == ENOSYS)
                            {
                                cfd = accept(listenFd, IntPtr.Zero, IntPtr.Zero);
                                if (cfd < 0) break;
                                int fl2 = fcntl(cfd, F_GETFL, 0);
                                if (fl2 >= 0) fcntl(cfd, F_SETFL, fl2 | O_NONBLOCK);
                            }
                            else if (err == EMFILE || err == ENFILE)
                            {
                                // Clear one from the pending queue if we hit fd limits
                                int dump = accept(listenFd, IntPtr.Zero, IntPtr.Zero);
                                if (dump >= 0) close(dump);
                                break;
                            }
                            else break;
                        }

                        // TCP_NODELAY
                        int one2 = 1;
                        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, ref one2, (uint)sizeof(int));

                        // Disable SO_LINGER to avoid RST-on-close
                        var lg = new linger { l_onoff = 0, l_linger = 0 };
                        setsockopt(cfd, SOL_SOCKET, SO_LINGER, ref lg, (uint)Marshal.SizeOf<linger>());

                        evIn.data = (ulong)(uint)cfd;
                        epoll_ctl(ep, EPOLL_CTL_ADD, cfd, ref evIn);
                        conns[cfd] = new Conn { Fd = cfd };
                    }
                    continue;
                }

                // HUP/ERR: try to flush pending write if any, else close
                if ((evs & (EPOLLHUP | EPOLLERR)) != 0)
                {
                    if (conns.TryGetValue(fd, out var cx) && cx.WantWrite && cx.RespSent < Response200.Length)
                    {
                        long nSent;
                        unsafe
                        {
                            fixed (byte* p = Response200)
                                nSent = send(fd, (IntPtr)(p + cx.RespSent), (ulong)(Response200.Length - cx.RespSent), MSG_NOSIGNAL);
                        }

                        if (nSent > 0)
                        {
                            cx.RespSent += (int)nSent;
                            if (cx.RespSent == Response200.Length)
                            {
                                CloseConn(fd, conns);
                            }
                            else
                            {
                                var eout = new epoll_event { events = (uint)EPOLLOUT, data = (ulong)(uint)fd };
                                epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref eout);
                            }
                        }
                        else
                        {
                            int err = (nSent == 0) ? EAGAIN : Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK)
                            {
                                var eout = new epoll_event { events = (uint)EPOLLOUT, data = (ulong)(uint)fd };
                                epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref eout);
                            }
                            else
                            {
                                CloseConn(fd, conns);
                            }
                        }
                    }
                    else
                    {
                        CloseConn(fd, conns);
                    }
                    continue;
                }

                if ((evs & EPOLLIN) != 0)
                {
                    if (!conns.TryGetValue(fd, out var c)) { CloseQuiet(fd); continue; }

                    while (true)
                    {
                        // Grow or compact buffer if needed
                        if (c.End == c.Buf.Length)
                        {
                            if (c.Start > 0) c.CompactIfNeeded();
                            if (c.End == c.Buf.Length)
                            {
                                if (c.Buf.Length < MaxHeader)
                                {
                                    var bigger = new byte[Math.Min(c.Buf.Length * 2, MaxHeader)];
                                    Buffer.BlockCopy(c.Buf, 0, bigger, 0, c.End);
                                    c.Buf = bigger;
                                }
                                else
                                {
                                    // Too large header; send 431 then close
                                    unsafe
                                    {
                                        fixed (byte* p = Response431)
                                            send(fd, (IntPtr)p, (ulong)Response431.Length, MSG_NOSIGNAL);
                                    }
                                    CloseConn(fd, conns);
                                    break;
                                }
                            }
                        }

                        long got;
                        unsafe
                        {
                            fixed (byte* p = &c.Buf[c.End])
                                got = recv(fd, (IntPtr)p, (ulong)(c.Buf.Length - c.End), 0);
                        }

                        if (got > 0)
                        {
                            c.End += (int)got;

                            // Serve all full requests already available; if we switch to EPOLLOUT, pause reading
                            if (TryServeBufferedRequests(c, fd, ep, ref evIn, ref evOut, conns))
                                break; // EPOLLOUT will resume when writable

                            // else: no full request yet; keep reading
                        }
                        else if (got == 0)
                        {
                            CloseConn(fd, conns);
                            break;
                        }
                        else
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK) break; // no more for now
                            if (err == ECONNRESET || err == EPIPE) { CloseConn(fd, conns); break; }
                            CloseConn(fd, conns);
                            break;
                        }
                    }
                }

                if ((evs & EPOLLOUT) != 0)
                {
                    if (!conns.TryGetValue(fd, out var c)) { CloseQuiet(fd); continue; }
                    if (!c.WantWrite)
                    {
                        evIn.data = (ulong)(uint)fd;
                        epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evIn);
                        continue;
                    }

                    while (true)
                    {
                        long nSent;
                        unsafe
                        {
                            fixed (byte* p = Response200)
                                nSent = send(fd, (IntPtr)(p + c.RespSent), (ulong)(Response200.Length - c.RespSent), MSG_NOSIGNAL);
                        }

                        if (nSent > 0)
                        {
                            c.RespSent += (int)nSent;
                            if (c.RespSent == Response200.Length)
                            {
                                c.WantWrite = false;
                                c.RespSent = 0;

                                // After finishing a write, immediately serve any fully buffered next requests (pipelining)
                                if (!TryServeBufferedRequests(c, fd, ep, ref evIn, ref evOut, conns))
                                {
                                    // Nothing ready: go back to EPOLLIN
                                    evIn.data = (ulong)(uint)fd;
                                    epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evIn);
                                }
                                break;
                            }
                            continue; // still more to write
                        }
                        else
                        {
                            // Treat send==0 like EAGAIN
                            int err = (nSent == 0) ? EAGAIN : Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK) break; // stay in EPOLLOUT
                            if (err == EPIPE || err == ECONNRESET) { CloseConn(fd, conns); break; }
                            CloseConn(fd, conns);
                            break;
                        }
                    }
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool TryServeBufferedRequests(
        Conn c,
        int fd,
        int ep,
        ref Native.epoll_event evIn,
        ref Native.epoll_event evOut,
        Dictionary<int, Conn> conns)
    {
        while (true)
        {
            int idx = FindCrlfCrlf(c.Buf, c.Start, c.End);
            if (idx < 0) return false; // need more data

            c.Start = idx + 4;

            // Immediate send attempt
            long nSent;
            unsafe
            {
                fixed (byte* p = Response200)
                    nSent = send(fd, (IntPtr)p, (ulong)Response200.Length, MSG_NOSIGNAL);
            }

            if (nSent == Response200.Length)
            {
                // Response done; keep looping in case there’s another full request
                if (c.Start >= c.End) { c.Start = c.End = 0; }
                else if (c.Start > 0) c.CompactIfNeeded();
                continue;
            }
            else if (nSent >= 0)
            {
                // Partial — switch to EPOLLOUT
                c.WantWrite = true;
                c.RespSent = (int)nSent;
                evOut.data = (ulong)(uint)fd;
                epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evOut);
                return true; // writing will resume in EPOLLOUT
            }
            else
            {
                int err = Marshal.GetLastPInvokeError();
                if (err == EAGAIN || err == EWOULDBLOCK)
                {
                    c.WantWrite = true;
                    c.RespSent = 0;
                    evOut.data = (ulong)(uint)fd;
                    epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evOut);
                }
                else
                {
                    CloseConn(fd, conns);
                }
                return true;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void CloseConn(int fd, Dictionary<int, Conn> map)
    {
        map.Remove(fd);
        CloseQuiet(fd);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void CloseQuiet(int fd)
    {
        try { close(fd); } catch { }
    }

    // Optimized for small HTTP headers (typical wrk request ~75 bytes)
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static int FindCrlfCrlf(byte[] buf, int start, int end)
    {
        int len = end - start;
        if (len < 4) return -1;

        for (int i = start; i <= end - 4; i++)
        {
            if (buf[i] == (byte)'\r'
                && buf[i + 1] == (byte)'\n'
                && buf[i + 2] == (byte)'\r'
                && buf[i + 3] == (byte)'\n')
            {
                return i;
            }
        }
        return -1;
    }

    static byte[] Build200()
    {
        ReadOnlySpan<byte> body = "{\"message\":\"Hello, World!\"}"u8;
        string head =
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/json; charset=UTF-8\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: keep-alive\r\n" +
            "\r\n";
        byte[] hb = Encoding.UTF8.GetBytes(head);
        byte[] buf = new byte[hb.Length + body.Length];
        Buffer.BlockCopy(hb, 0, buf, 0, hb.Length);
        body.CopyTo(buf.AsSpan(hb.Length));
        return buf;
    }

    static byte[] BuildSimpleResponse(int status, string reason)
    {
        ReadOnlySpan<byte> body = "{}"u8;
        string head =
            $"HTTP/1.1 {status} {reason}\r\n" +
            "Content-Type: application/json\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: close\r\n\r\n";
        byte[] hb = Encoding.UTF8.GetBytes(head);
        byte[] buf = new byte[hb.Length + body.Length];
        Buffer.BlockCopy(hb, 0, buf, 0, hb.Length);
        body.CopyTo(buf.AsSpan(hb.Length));
        return buf;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void ThrowIfErr(int rc, string where)
    {
        if (rc >= 0) return;
        int errno = Marshal.GetLastPInvokeError();
        throw new InvalidOperationException($"{where} failed errno={errno}");
    }
}
*/

// Program.cs
// Ultra high-concurrency non-blocking epoll HTTP/1.1 server (Linux).
// - Header buffer grows up to 16 KiB
// - Serve all pipelined requests already buffered before yielding
// - Treat send()==0 like EAGAIN
// - Disable SO_LINGER to avoid RST-on-close
// - Handle EMFILE/ENFILE gracefully on accept
// - On EPOLLHUP/EPOLLERR/EPOLLRDHUP: flush pending write if any before closing
// - Return 431 on oversized headers
// - Responses exposed as ReadOnlySpan<byte>, and pinned once for low-overhead send
// Build: dotnet run -c Release -p:AllowUnsafeBlocks=true
// Test:  wrk -t32 -c512 -d15s http://localhost:8080

using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static Native;

internal static class Native
{
    public const int AF_INET = 2, SOCK_STREAM = 1, IPPROTO_TCP = 6;
    public const int SOL_SOCKET = 1, SO_REUSEADDR = 2, SO_REUSEPORT = 15, SO_LINGER = 13;
    public const int TCP_NODELAY = 1;
    public const int MSG_NOSIGNAL = 0x4000;
    public const int SOCK_NONBLOCK = 0x800;
    public const int SOCK_CLOEXEC  = 0x80000;
    public const int F_GETFL = 3, F_SETFL = 4;
    public const int O_NONBLOCK = 0x800;

    public const int EPOLLIN   = 0x001;
    public const int EPOLLOUT  = 0x004;
    public const int EPOLLERR  = 0x008;
    public const int EPOLLHUP  = 0x010;
    public const int EPOLLRDHUP = 0x2000; // peer closed its write half (half-close)

    public const int EPOLL_CLOEXEC = 0x80000;
    public const int EPOLL_CTL_ADD = 1, EPOLL_CTL_MOD = 3, EPOLL_CTL_DEL = 2;

    public const int EINTR = 4, EAGAIN = 11, EWOULDBLOCK = 11, ENOSYS = 38, EPIPE = 32, ECONNRESET = 104;
    public const int EMFILE = 24, ENFILE = 23;

    [StructLayout(LayoutKind.Sequential)]
    public struct in_addr { public uint s_addr; }

    [StructLayout(LayoutKind.Sequential)]
    public struct sockaddr_in
    {
        public ushort sin_family;
        public ushort sin_port;
        public in_addr sin_addr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct epoll_event
    {
        public uint events;
        public ulong data;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct linger
    {
        public int l_onoff;
        public int l_linger;
    }

    [DllImport("libc", SetLastError = true)] public static extern int socket(int domain, int type, int protocol);
    [DllImport("libc", SetLastError = true)] public static extern int setsockopt(int sockfd, int level, int optname, ref int optval, uint optlen);
    [DllImport("libc", SetLastError = true)] public static extern int setsockopt(int sockfd, int level, int optname, ref linger optval, uint optlen);
    [DllImport("libc", SetLastError = true)] public static extern int bind(int sockfd, ref sockaddr_in addr, uint addrlen);
    [DllImport("libc", SetLastError = true)] public static extern int listen(int sockfd, int backlog);
    [DllImport("libc", SetLastError = true)] public static extern int accept4(int sockfd, IntPtr addr, IntPtr addrlen, int flags);
    [DllImport("libc", SetLastError = true)] public static extern int accept(int sockfd, IntPtr addr, IntPtr addrlen);
    [DllImport("libc", SetLastError = true)] public static extern int fcntl(int fd, int cmd, int arg);
    [DllImport("libc", SetLastError = true)] public static extern long recv(int sockfd, IntPtr buf, ulong len, int flags);
    [DllImport("libc", SetLastError = true)] public static extern long send(int sockfd, IntPtr buf, ulong len, int flags);
    [DllImport("libc", SetLastError = true)] public static extern int close(int fd);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_create1(int flags);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_ctl(int epfd, int op, int fd, ref epoll_event ev);
    [DllImport("libc", SetLastError = true)] public static extern int epoll_wait(int epfd, [In, Out] epoll_event[] events, int maxevents, int timeout);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ushort HostToNetwork16(ushort v) => (ushort)((v << 8) | (v >> 8));
}

public sealed class Conn
{
    public int Fd;
    public byte[] Buf = new byte[4096]; // grows up to MaxHeader
    public int Start;
    public int End;
    public bool WantWrite;
    public int RespSent;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void CompactIfNeeded()
    {
        if (Start == 0) return;
        int len = End - Start;
        if (len > 0)
            Buffer.BlockCopy(Buf, Start, Buf, 0, len);
        Start = 0;
        End = len;
    }
}

public unsafe class Program
{
    // Backing arrays; exposed as ReadOnlySpan<byte>
    static readonly byte[] _response200 = Build200();
    static readonly byte[] _response431 = BuildSimpleResponse(431, "Request Header Fields Too Large");

    // Public spans (requested)
    static ReadOnlySpan<byte> Response200 => _response200;
    static ReadOnlySpan<byte> Response431 => _response431;

    // Pinned handles & cached pointers for hot send paths
    static readonly GCHandle _h200 = GCHandle.Alloc(_response200, GCHandleType.Pinned);
    static readonly GCHandle _h431 = GCHandle.Alloc(_response431, GCHandleType.Pinned);
    static readonly byte* _p200 = (byte*)_h200.AddrOfPinnedObject();
    static readonly byte* _p431 = (byte*)_h431.AddrOfPinnedObject();
    static readonly int _len200 = _response200.Length;
    static readonly int _len431 = _response431.Length;

    const int Backlog = 16384;
    const int MaxHeader = 16 * 1024;

    public static void Main()
    {
        // We intentionally never free the handles; process-lifetime pin.
        int workers = Environment.ProcessorCount;
        Console.WriteLine($"Starting {workers} workers on :8080 (SO_REUSEPORT) …");

        var threads = new Thread[workers];
        for (int i = 0; i < workers; i++)
        {
            int wi = i;
            threads[i] = new Thread(() => RunWorker(8080, wi)) { IsBackground = true, Name = $"epoll-worker-{wi}" };
            threads[i].Start();
        }

        Console.WriteLine("Press Ctrl+C to exit.");
        Thread.Sleep(Timeout.Infinite);
    }

    static void RunWorker(int port, int workerIndex)
    {
        int listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ThrowIfErr(listenFd, "socket");

        int one = 1;
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, ref one, (uint)sizeof(int));
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEPORT, ref one, (uint)sizeof(int));

        var addr = new sockaddr_in
        {
            sin_family = (ushort)AF_INET,
            sin_port   = HostToNetwork16((ushort)port),
            sin_addr   = new in_addr { s_addr = 0 }, // 0.0.0.0
            sin_zero   = new byte[8]
        };
        ThrowIfErr(bind(listenFd, ref addr, (uint)Marshal.SizeOf<sockaddr_in>()), "bind");
        ThrowIfErr(listen(listenFd, Backlog), "listen");

        int fl = fcntl(listenFd, F_GETFL, 0);
        if (fl >= 0) fcntl(listenFd, F_SETFL, fl | O_NONBLOCK);

        int ep = epoll_create1(EPOLL_CLOEXEC);
        ThrowIfErr(ep, "epoll_create1");

        var lev = new epoll_event { events = (uint)EPOLLIN, data = (ulong)(uint)listenFd };
        ThrowIfErr(epoll_ctl(ep, EPOLL_CTL_ADD, listenFd, ref lev), "epoll_ctl ADD listen");

        var conns = new Dictionary<int, Conn>(capacity: 1024);
        var events = new epoll_event[1];

        if (workerIndex == 0)
            Console.WriteLine("Listening on http://0.0.0.0:8080");

        // We also listen for EPOLLRDHUP on client sockets
        var evIn  = new epoll_event { events = (uint)(EPOLLIN | EPOLLRDHUP) };
        var evOut = new epoll_event { events = (uint)EPOLLOUT };

        while (true)
        {
            int n = epoll_wait(ep, events, events.Length, -1);
            if (n < 0)
            {
                int errX = Marshal.GetLastPInvokeError();
                if (errX == EINTR) continue;
                throw new InvalidOperationException("epoll_wait failed errno=" + errX);
            }

            for (int i = 0; i < n; i++)
            {
                int fd = (int)events[i].data;
                uint evs = events[i].events;

                if (fd == listenFd)
                {
                    // Accept burst
                    for (int j = 0; j < 2; j++)
                    {
                        int cfd = accept4(listenFd, IntPtr.Zero, IntPtr.Zero, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        if (cfd < 0)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK) break;
                            if (err == ENOSYS)
                            {
                                cfd = accept(listenFd, IntPtr.Zero, IntPtr.Zero);
                                if (cfd < 0) break;
                                int fl2 = fcntl(cfd, F_GETFL, 0);
                                if (fl2 >= 0) fcntl(cfd, F_SETFL, fl2 | O_NONBLOCK);
                            }
                            else if (err == EMFILE || err == ENFILE)
                            {
                                int dump = accept(listenFd, IntPtr.Zero, IntPtr.Zero);
                                if (dump >= 0) close(dump);
                                break;
                            }
                            else break;
                        }

                        // TCP_NODELAY
                        int one2 = 1;
                        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, ref one2, (uint)sizeof(int));

                        // Disable SO_LINGER to avoid RST-on-close
                        var lg = new linger { l_onoff = 0, l_linger = 0 };
                        setsockopt(cfd, SOL_SOCKET, SO_LINGER, ref lg, (uint)Marshal.SizeOf<linger>());

                        // Add with EPOLLIN | EPOLLRDHUP
                        evIn.data = (ulong)(uint)cfd;
                        epoll_ctl(ep, EPOLL_CTL_ADD, cfd, ref evIn);
                        conns[cfd] = new Conn { Fd = cfd };
                    }
                    continue;
                }

                // HUP/ERR/RDHUP: try to flush pending write if any, else close
                if ((evs & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) != 0)
                {
                    if (conns.TryGetValue(fd, out var cx) && cx.WantWrite && cx.RespSent < _len200)
                    {
                        long nSent = Native.send(fd, (IntPtr)(_p200 + cx.RespSent), (ulong)(_len200 - cx.RespSent), MSG_NOSIGNAL);
                        if (nSent > 0)
                        {
                            cx.RespSent += (int)nSent;
                            if (cx.RespSent == _len200)
                            {
                                CloseConn(fd, conns);
                            }
                            else
                            {
                                var eout = new epoll_event { events = (uint)EPOLLOUT, data = (ulong)(uint)fd };
                                epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref eout);
                            }
                        }
                        else
                        {
                            int err = (nSent == 0) ? EAGAIN : Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK)
                            {
                                var eout = new epoll_event { events = (uint)EPOLLOUT, data = (ulong)(uint)fd };
                                epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref eout);
                            }
                            else
                            {
                                CloseConn(fd, conns);
                            }
                        }
                    }
                    else
                    {
                        CloseConn(fd, conns);
                    }
                    continue;
                }

                if ((evs & EPOLLIN) != 0)
                {
                    if (!conns.TryGetValue(fd, out var c)) { CloseQuiet(fd); continue; }

                    while (true)
                    {
                        // Grow or compact buffer if needed
                        if (c.End == c.Buf.Length)
                        {
                            if (c.Start > 0) c.CompactIfNeeded();
                            if (c.End == c.Buf.Length)
                            {
                                if (c.Buf.Length < MaxHeader)
                                {
                                    var bigger = new byte[Math.Min(c.Buf.Length * 2, MaxHeader)];
                                    Buffer.BlockCopy(c.Buf, 0, bigger, 0, c.End);
                                    c.Buf = bigger;
                                }
                                else
                                {
                                    // Too large header; send 431 then close
                                    Native.send(fd, (IntPtr)_p431, (ulong)_len431, MSG_NOSIGNAL);
                                    CloseConn(fd, conns);
                                    break;
                                }
                            }
                        }

                        long got;
                        fixed (byte* p = &c.Buf[c.End])
                            got = Native.recv(fd, (IntPtr)p, (ulong)(c.Buf.Length - c.End), 0);

                        if (got > 0)
                        {
                            c.End += (int)got;

                            // Serve all full requests already available; if we switch to EPOLLOUT, pause reading
                            if (TryServeBufferedRequests(c, fd, ep, ref evIn, ref evOut, conns))
                                break; // EPOLLOUT will resume when writable
                            // else: no full request yet; keep reading
                        }
                        else if (got == 0)
                        {
                            CloseConn(fd, conns);
                            break;
                        }
                        else
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK) break; // no more for now
                            if (err == ECONNRESET || err == EPIPE) { CloseConn(fd, conns); break; }
                            CloseConn(fd, conns);
                            break;
                        }
                    }
                }

                if ((evs & EPOLLOUT) != 0)
                {
                    if (!conns.TryGetValue(fd, out var c)) { CloseQuiet(fd); continue; }
                    if (!c.WantWrite)
                    {
                        evIn.data = (ulong)(uint)fd;
                        epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evIn);
                        continue;
                    }

                    while (true)
                    {
                        long nSent = Native.send(fd, (IntPtr)(_p200 + c.RespSent), (ulong)(_len200 - c.RespSent), MSG_NOSIGNAL);

                        if (nSent > 0)
                        {
                            c.RespSent += (int)nSent;
                            if (c.RespSent == _len200)
                            {
                                c.WantWrite = false;
                                c.RespSent = 0;

                                // Immediately serve any fully buffered next requests (pipelining)
                                if (!TryServeBufferedRequests(c, fd, ep, ref evIn, ref evOut, conns))
                                {
                                    // Nothing ready: back to EPOLLIN | EPOLLRDHUP
                                    evIn.data = (ulong)(uint)fd;
                                    epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evIn);
                                }
                                break;
                            }
                            continue; // still more to write
                        }
                        else
                        {
                            // Treat send==0 like EAGAIN
                            int err = (nSent == 0) ? EAGAIN : Marshal.GetLastPInvokeError();
                            if (err == EAGAIN || err == EWOULDBLOCK) break; // stay in EPOLLOUT
                            if (err == EPIPE || err == ECONNRESET) { CloseConn(fd, conns); break; }
                            CloseConn(fd, conns);
                            break;
                        }
                    }
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool TryServeBufferedRequests(
        Conn c,
        int fd,
        int ep,
        ref Native.epoll_event evIn,
        ref Native.epoll_event evOut,
        Dictionary<int, Conn> conns)
    {
        while (true)
        {
            int idx = FindCrlfCrlf(c.Buf, c.Start, c.End);
            if (idx < 0) return false; // need more data

            c.Start = idx + 4;

            // Immediate send attempt using pinned pointer
            long nSent = Native.send(fd, (IntPtr)_p200, (ulong)_len200, MSG_NOSIGNAL);

            if (nSent == _len200)
            {
                // Response done; keep looping in case there’s another full request
                if (c.Start >= c.End) { c.Start = c.End = 0; }
                else if (c.Start > 0) c.CompactIfNeeded();
                continue;
            }
            else if (nSent >= 0)
            {
                // Partial — switch to EPOLLOUT
                c.WantWrite = true;
                c.RespSent = (int)nSent;
                evOut.data = (ulong)(uint)fd;
                epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evOut);
                return true; // writing will resume in EPOLLOUT
            }
            else
            {
                int err = Marshal.GetLastPInvokeError();
                if (err == EAGAIN || err == EWOULDBLOCK)
                {
                    c.WantWrite = true;
                    c.RespSent = 0;
                    evOut.data = (ulong)(uint)fd;
                    epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evOut);
                }
                else
                {
                    CloseConn(fd, conns);
                }
                return true;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void CloseConn(int fd, Dictionary<int, Conn> map)
    {
        map.Remove(fd);
        CloseQuiet(fd);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void CloseQuiet(int fd)
    {
        try { Native.close(fd); } catch { }
    }

    // Optimized for small HTTP headers (typical wrk request ~75 bytes)
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static int FindCrlfCrlf(byte[] buf, int start, int end)
    {
        int len = end - start;
        if (len < 4) return -1;

        for (int i = start; i <= end - 4; i++)
        {
            if (buf[i] == (byte)'\r'
                && buf[i + 1] == (byte)'\n'
                && buf[i + 2] == (byte)'\r'
                && buf[i + 3] == (byte)'\n')
            {
                return i;
            }
        }
        return -1;
    }

    static byte[] Build200()
    {
        ReadOnlySpan<byte> body = "{\"message\":\"Hello, World!\"}"u8;
        string head =
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/json; charset=UTF-8\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: keep-alive\r\n" +
            "\r\n";
        byte[] hb = Encoding.UTF8.GetBytes(head);
        byte[] buf = new byte[hb.Length + body.Length];
        Buffer.BlockCopy(hb, 0, buf, 0, hb.Length);
        body.CopyTo(buf.AsSpan(hb.Length));
        return buf;
    }

    static byte[] BuildSimpleResponse(int status, string reason)
    {
        ReadOnlySpan<byte> body = "{}"u8;
        string head =
            $"HTTP/1.1 {status} {reason}\r\n" +
            "Content-Type: application/json\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: close\r\n\r\n";
        byte[] hb = Encoding.UTF8.GetBytes(head);
        byte[] buf = new byte[hb.Length + body.Length];
        Buffer.BlockCopy(hb, 0, buf, 0, hb.Length);
        body.CopyTo(buf.AsSpan(hb.Length));
        return buf;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static void ThrowIfErr(int rc, string where)
    {
        if (rc >= 0) return;
        int errno = Marshal.GetLastPInvokeError();
        throw new InvalidOperationException($"{where} failed errno={errno}");
    }
}
