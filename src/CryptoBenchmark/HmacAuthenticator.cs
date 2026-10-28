using System.Security.Cryptography;

namespace CryptoBenchmark;

// Symmetric authentication: HMAC-SHA256 with one 32 B key shared by both sides (proves integrity, not WHO sent it).
public sealed class HmacAuthenticator(byte[] key) : IAuthenticator
{
    public const string MethodName = "HMAC-SHA256";

    public string Name => MethodName;

    public byte[] Sign(byte[] message) => HMACSHA256.HashData(key, message);

    public bool Verify(byte[] message, byte[] signature)
    {
        var expected = HMACSHA256.HashData(key, message);

        // Constant time: an early exit would leak how many bytes matched.
        return CryptographicOperations.FixedTimeEquals(expected, signature);
    }
}
