namespace CryptoBenchmark;

// Command-line settings: how many messages per batch, how many loops, and how big each message is.
public sealed record Options(int MessagesCount, int LoopCounter, int MessageSize)
{
    // The largest plaintext RSA-2048 OAEP-SHA256 can encrypt: 256 - 2 * 32 - 2 = 190 B.
    public const int MaxRsaPlaintext = 190;

    public bool RsaFits => MessageSize <= MaxRsaPlaintext;

    public static Options Parse(string[] args)
    {
        var messagesCount = 1000;

        var loopCounter = 10;

        var messageSize = MaxRsaPlaintext;

        for (var i = 0; i < args.Length; i += 2)
        {
            if (i + 1 >= args.Length)
                throw new ArgumentException($"Missing value for {args[i]}");

            var value = int.Parse(args[i + 1]);

            switch (args[i])
            {
                case "--messages-count": messagesCount = value; break;
                case "--loop-counter": loopCounter = value; break;
                case "--message-size": messageSize = value; break;
                default: throw new ArgumentException($"Unknown option: {args[i]}");
            }
        }

        return new Options(messagesCount, loopCounter, messageSize);
    }
}
