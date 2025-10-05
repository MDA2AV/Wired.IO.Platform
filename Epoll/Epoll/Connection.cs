namespace Epoll;

[SkipLocalsInit]
internal sealed class Connection
{
    public int Fd;
    
    public byte[] Buf = new byte[4096]; // grows up to MaxHeader
    public int Head;
    public int Tail;
    
    public bool WantWrite;
    public int RespSent;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void CompactIfNeeded()
    {
        if (Head == 0) return;
        int len = Tail - Head;
        if (len > 0)
            Buffer.BlockCopy(Buf, Head, Buf, 0, len);
        Head = 0;
        Tail = len;
    }
}