using System.Security.Cryptography;

namespace CryptoBenchmark;

// Hybrid encryption: once per batch, RSA wraps a fresh AES key; AES-GCM encrypts every message.
public sealed class HybridCipher : ICipher
{
    public const string MethodName = "Hybrid RSA+AES-GCM";

    private readonly RSA _privateKey;

    private readonly RSA _publicKey;

    public HybridCipher(RSA privateKey)
    {
        _privateKey = privateKey;

        _publicKey = RSA.Create();

        _publicKey.ImportRSAPublicKey(privateKey.ExportRSAPublicKey(), out _);
    }

    public string Name => MethodName;

    public EncryptedBatch Encrypt(byte[][] messages)
    {
        var aesKey = RandomNumberGenerator.GetBytes(32);

        // One slow RSA operation per batch: wrap the 32 B AES key with the receiver's PUBLIC key.
        var wrappedKey = _publicKey.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);

        using var aes = new AesGcm(aesKey, SymmetricCipher.TagSize);

        return new EncryptedBatch(wrappedKey, messages.Select(message => SymmetricCipher.Seal(aes, message)).ToArray());
    }

    public byte[][] Decrypt(EncryptedBatch batch)
    {
        // Unwrap the AES key with the PRIVATE key, then decrypt fast with AES.
        var aesKey = _privateKey.Decrypt(batch.WrappedKey!, RSAEncryptionPadding.OaepSHA256);

        using var aes = new AesGcm(aesKey, SymmetricCipher.TagSize);

        return batch.Items.Select(item => SymmetricCipher.Open(aes, item)).ToArray();
    }
}
