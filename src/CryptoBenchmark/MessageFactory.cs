namespace CryptoBenchmark;

// Builds the batch of messages. Random(42) makes every run use the same bytes.
public static class MessageFactory
{
    public static byte[][] Create(int count, int size)
    {
        var random = new Random(42);

        var messages = new byte[count][];

        for (var i = 0; i < count; i++)
        {
            messages[i] = new byte[size];

            random.NextBytes(messages[i]);
        }

        return messages;
    }
}
