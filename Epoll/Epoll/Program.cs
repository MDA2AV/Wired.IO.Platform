using System.Text;
using static Epoll.Native;

namespace Epoll;

internal unsafe class Program
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
    
    private const int Backlog = 16384;
    private const int MaxHeader = 16 * 1024;

    public static void Main(string[] args)
    {
        // We intentionally never free the handles; process-lifetime pin.
        var workers = Environment.ProcessorCount / 2;
        //var workers = 23;
        Console.WriteLine($"Starting {workers} workers on :8080 (SO_REUSEPORT) …");

        var threads = new Thread[workers];
        for (var i = 0; i < workers; i++)
        {
            threads[i] = new Thread(RunWorker)
            {
                IsBackground = true, Name = $"epoll-worker-{i}"
            };
            threads[i].Start();
        }
        
        Console.ReadLine();
    }
    
    
    
    private static void RunWorker()
    {
        SetSockOpt(8080, out var listenFd, out var ep);

        var lev = new epoll_event { events = EPOLLIN, data = (uint)listenFd };
        ThrowIfErr(epoll_ctl(ep, EPOLL_CTL_ADD, listenFd, ref lev), "epoll_ctl ADD listen");

        var conns = new Dictionary<int, Connection>(capacity: 1024);
        var events = new epoll_event[32];

        // We also listen for EPOLLRDHUP on client sockets
        var evIn = new epoll_event { events = EPOLLIN | EPOLLRDHUP };
        var evOut = new epoll_event { events = EPOLLOUT };

        while (true)
        {
            var n = epoll_wait(ep, events, events.Length, -1);
            // epoll_wait error
            if (n < 0)
            {
                var errX = Marshal.GetLastPInvokeError();
                if (errX == EINTR) continue;
                throw new InvalidOperationException("epoll_wait failed errno=" + errX);
            }

            // Go through all epoll events
            for (var i = 0; i < n; i++)
            {
                var fd = (int)events[i].data;
                var evs = events[i].events;
                
                if (fd == listenFd)
                {
                    //Console.WriteLine(fd);
                    
                    //if ((evs & EPOLLIN) == 0) continue;
                    
                    var cfd = accept4(listenFd, IntPtr.Zero, IntPtr.Zero, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    // Create a dummy addrlen variable
                    //uint addrlen = 0;
                    //var cfd = accept4(listenFd, IntPtr.Zero, ref addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        
                    if (cfd == -1)
                    {
                        int err = Marshal.GetLastPInvokeError();
                        if (err == EAGAIN)
                        {
                            Console.WriteLine("EAGAIN " + fd + " " + Environment.CurrentManagedThreadId);
                            continue;
                        } // no more to accept

                        if (err == EINTR)
                        {
                            Console.WriteLine("EINTR " + Environment.CurrentManagedThreadId);
                            continue;
                        } // interrupted, retry
                        
                        Console.WriteLine($"accept4 failed errno={err}");
                        continue;
                    }

                    // Only proceed with valid fd > 0
                    var one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, ref one, sizeof(int));
        
                    var lg = new linger { l_onoff = 0, l_linger = 0 };
                    setsockopt(cfd, SOL_SOCKET, SO_LINGER, ref lg, (uint)Marshal.SizeOf<linger>());

                    evIn.data = (ulong)(uint)cfd;
                    epoll_ctl(ep, EPOLL_CTL_ADD, cfd, ref evIn);
                    conns[cfd] = new Connection { Fd = cfd };

                    /*
                    while (true)
                    {
                        var cfd = accept4(listenFd, IntPtr.Zero, IntPtr.Zero, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        // Create a dummy addrlen variable
                        //uint addrlen = 0;
                        //var cfd = accept4(listenFd, IntPtr.Zero, ref addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
                        
                        if (cfd == -1)
                        {
                            int err = Marshal.GetLastPInvokeError();
                            if (err == EAGAIN)
                            {
                                Console.WriteLine("EAGAIN " + Environment.CurrentManagedThreadId);
                                break;
                            } // no more to accept

                            if (err == EINTR)
                            {
                                Console.WriteLine("EINTR " + Environment.CurrentManagedThreadId);
                                continue;
                            } // interrupted, retry
                        
                            Console.WriteLine($"accept4 failed errno={err}");
                            break;
                        }

                        // Only proceed with valid fd > 0
                        var one = 1;
                        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, ref one, sizeof(int));
        
                        var lg = new linger { l_onoff = 0, l_linger = 0 };
                        setsockopt(cfd, SOL_SOCKET, SO_LINGER, ref lg, (uint)Marshal.SizeOf<linger>());

                        evIn.data = (ulong)(uint)cfd;
                        epoll_ctl(ep, EPOLL_CTL_ADD, cfd, ref evIn);
                        conns[cfd] = new Connection { Fd = cfd };
                    }
                    */
                    
                    /*
                    Console.WriteLine($"Listen event on thread {Thread.CurrentThread.Name}");
                    var cfd = accept4(listenFd, IntPtr.Zero, IntPtr.Zero, SOCK_NONBLOCK | SOCK_CLOEXEC);
                    Console.WriteLine($"  accept4 returned: {cfd}, errno={Marshal.GetLastPInvokeError()}");
                    
                    if (cfd < 0)
                    {
                        var err = Marshal.GetLastPInvokeError();
                        if (err == EAGAIN) 
                            continue; // No more connections
    
                        Console.WriteLine($"accept4 failed: errno={err}");
                        continue; // Don't add invalid fd!
                    }

                    // TCP_NODELAY
                    var one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, ref one, sizeof(int));

                    // Disable SO_LINGER to avoid RST-on-close
                    var lg = new linger { l_onoff = 0, l_linger = 0 };
                    setsockopt(cfd, SOL_SOCKET, SO_LINGER, ref lg, (uint)Marshal.SizeOf<linger>());

                    // Add with EPOLLIN | EPOLLRDHUP
                    evIn.data = (ulong)(uint)cfd;
                    epoll_ctl(ep, EPOLL_CTL_ADD, cfd, ref evIn);
                    conns[cfd] = new Connection { Fd = cfd };
                    */

                    continue;
                }

                if ((evs & EPOLLIN) != 0)
                {
                    if (!conns.TryGetValue(fd, out var c)) { CloseQuiet(fd); continue; }
                    
                    /*
                    while (true)
                    {
                        long got;
                        fixed (byte* p = &c.Buf[c.Tail])
                            got = recv(fd, (IntPtr)p, (ulong)(c.Buf.Length - c.Tail), 0);

                        if (got > 0)
                        {
                            c.Tail += (int)got;

                            // Serve all full requests already available; if we switch to EPOLLOUT, pause reading
                            if (TryServeBufferedRequests(c, fd, ep, ref evIn, ref evOut, conns))
                                break; // EPOLLOUT will resume when writable
                            // else: no full request yet; keep reading
                            break;
                        }
                        else if (got == 0)
                        {
                            CloseConn(fd, conns);
                            break;
                        }
                        else
                        {
                            var err = Marshal.GetLastPInvokeError();
                            if (err is EAGAIN or EWOULDBLOCK) break; // no more for now
                            if (err is ECONNRESET or EPIPE)
                            {
                                CloseConn(fd, conns);
                                break;
                            }

                            CloseConn(fd, conns);
                            break;
                        }
                    }
                    */
                    
                    long got;
                    fixed (byte* p = &c.Buf[c.Tail])
                        got = recv(fd, (IntPtr)p, (ulong)(c.Buf.Length - c.Tail), 0);

                    if (got > 0)
                    {
                        c.Tail += (int)got;
                        TryServeBufferedRequests(c, fd, ep, ref evIn, ref evOut, conns);
                    }
                    else if (got == 0)
                    {
                        Console.WriteLine("Closing " + fd);
                        CloseConn(fd, conns);
                    }
                    else
                    {
                        var err = Marshal.GetLastPInvokeError();
                        //Console.WriteLine("EPOLLIN ERR " + err);
                        if (err is not (EAGAIN or EWOULDBLOCK))
                            CloseConn(fd, conns);
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
                        long nSent = send(fd, (IntPtr)(_p200 + c.RespSent), (ulong)(_len200 - c.RespSent), MSG_NOSIGNAL);
                        
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
                        
                        // Treat send==0 like EAGAIN
                        int err = (nSent == 0) ? EAGAIN : Marshal.GetLastPInvokeError();
                        Console.WriteLine("EPOLLOUT ERR " + err);
                        if (err == EAGAIN) break; // stay in EPOLLOUT
                        if (err is EPIPE or ECONNRESET) { CloseConn(fd, conns); break; }
                        CloseConn(fd, conns);
                        break;
                    }
                }
            }
        }
    }
    private static bool TryServeBufferedRequests(
        Connection c,
        int fd,
        int ep,
        ref Native.epoll_event evIn,
        ref Native.epoll_event evOut,
        Dictionary<int, Connection> conns)
    {
        while (true)
        {
            int idx = FindCrlfCrlf(c.Buf, c.Head, c.Tail);
            if (idx < 0) return false; // need more data
            
            // Advance the buffer
            c.Head = idx + 4;
            
            // Full request available!
            
            // Immediate send attempt using pinned pointer
            long nSent = send(fd, (IntPtr)_p200, (ulong)_len200, MSG_NOSIGNAL);
            
            // Sent successfully, try to serve another case
            if (nSent == _len200)
            {
                // Reached the end...
                if (c.Head >= c.Tail) { 
                    c.Head = c.Tail = 0;
                    return false;
                }

                if (c.Head > 0) c.CompactIfNeeded();

                continue;
            }
            
            // Sent partially, enable EPOLLOUT
            if (nSent >= 0)
            {
                // Partial — switch to EPOLLOUT
                c.WantWrite = true;
                c.RespSent = (int)nSent;
                evOut.data = (ulong)(uint)fd;
                epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evOut);
                return true; // writing will resume in EPOLLOUT
            }
            
            int err = Marshal.GetLastPInvokeError();
            if (err == EAGAIN)
            {
                c.WantWrite = true;
                c.RespSent = 0;
                evOut.data = (ulong)(uint)fd;
                epoll_ctl(ep, EPOLL_CTL_MOD, fd, ref evOut);
            }
            else
                CloseConn(fd, conns);
            
            return true;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void CloseConn(int fd, Dictionary<int, Connection> map)
    {
        map.Remove(fd);
        CloseQuiet(fd);
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void CloseQuiet(int fd)
    {
        try
        {
            close(fd); 
        }
        catch
        {
            // ignored
        }
    }
    
    private static void SetSockOpt(in int port, out int listenFd, out int ep)
    {
        listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ThrowIfErr(listenFd, "socket");

        var one = 1;
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, ref one, (uint)sizeof(int));
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEPORT, ref one, (uint)sizeof(int));

        var addr = new sockaddr_in
        {
            sin_family = AF_INET,
            sin_port   = HostToNetwork16((ushort)port),
            sin_addr   = new in_addr { s_addr = 0 }, // 0.0.0.0
            sin_zero   = new byte[8]
        };
        ThrowIfErr(bind(listenFd, ref addr, (uint)Marshal.SizeOf<sockaddr_in>()), "bind");
        ThrowIfErr(listen(listenFd, Backlog), "listen");

        int fl = fcntl(listenFd, F_GETFL, 0);
        if (fl >= 0) fcntl(listenFd, F_SETFL, fl | O_NONBLOCK);

        ep = epoll_create1(EPOLL_CLOEXEC);
        ThrowIfErr(ep, "epoll_create1");
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ThrowIfErr(int rc, string where)
    {
        if (rc >= 0) return;
        var errno = Marshal.GetLastPInvokeError();
        throw new InvalidOperationException($"{where} failed errno={errno}");
    }
    
    // TODO: Needs improvement, use SIMD?
    // Optimized for small HTTP headers (typical wrk request ~75 bytes)
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int FindCrlfCrlf(byte[] buf, int head, int tail)
    {
        //return buf.AsSpan().IndexOf("\r\n\r\n"u8);
        
        int len = tail - head;
        if (len < 4) return -1;

        for (int i = head; i <= tail - 4; i++)
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

    private static byte[] Build200()
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

    private static byte[] BuildSimpleResponse(int status, string reason)
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
}