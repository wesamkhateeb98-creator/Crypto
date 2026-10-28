namespace CryptoBenchmark;

// Part A contract: encrypt a whole batch, then decrypt it back.
public interface ICipher
{
    string Name { get; }

    EncryptedBatch Encrypt(byte[][] messages);

    byte[][] Decrypt(EncryptedBatch batch);
}

// The encrypted batch: one ciphertext per message, plus the RSA-wrapped AES key (hybrid only).
public sealed record EncryptedBatch(byte[]? WrappedKey, byte[][] Items)
{
    public long TotalBytes => (WrappedKey?.Length ?? 0) + Items.Sum(item => (long)item.Length);
}
