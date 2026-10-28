namespace CryptoBenchmark;

// Part B contract: produce a tag/signature for a message, then check it.
public interface IAuthenticator
{
    string Name { get; }

    byte[] Sign(byte[] message);

    bool Verify(byte[] message, byte[] signature);
}
