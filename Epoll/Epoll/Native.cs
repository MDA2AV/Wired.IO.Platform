namespace Epoll;

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
    public const uint EPOLLET = 0x80000000;  // ← Add this!

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
    //[DllImport("libc", SetLastError = true)] public static extern int accept4(int sockfd, IntPtr addr, ref uint addrlen, int flags);
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
