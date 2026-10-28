using System.Security.Cryptography;

namespace CryptoBenchmark;

// Symmetric encryption: one random 32 B AES key, shared by sender and receiver (AES-256-GCM).
public sealed class SymmetricCipher(byte[] key) : ICipher
{
    public const string MethodName = "AES-256-GCM";

    public const int NonceSize = 12;

    public const int TagSize = 16;

    public string Name => MethodName;

    public EncryptedBatch Encrypt(byte[][] messages)
    {
        using var aes = new AesGcm(key, TagSize);

        return new EncryptedBatch(null, messages.Select(message => Seal(aes, message)).ToArray());
    }

    public byte[][] Decrypt(EncryptedBatch batch)
    {
        using var aes = new AesGcm(key, TagSize);

        return batch.Items.Select(item => Open(aes, item)).ToArray();
    }

    // Output layout: nonce (12 B) | ciphertext (same size as the message) | tag (16 B).
    public static byte[] Seal(AesGcm aes, byte[] message)
    {
        var output = new byte[NonceSize + message.Length + TagSize];

        var nonce = output.AsSpan(0, NonceSize);

        var ciphertext = output.AsSpan(NonceSize, message.Length);

        var tag = output.AsSpan(NonceSize + message.Length, TagSize);

        // A fresh nonce for every message: reusing a nonce with the same key breaks GCM.
        RandomNumberGenerator.Fill(nonce);

        aes.Encrypt(nonce, message, ciphertext, tag);

        return output;
    }

    public static byte[] Open(AesGcm aes, byte[] sealedMessage)
    {
        var length = sealedMessage.Length - NonceSize - TagSize;

        var message = new byte[length];

        // Throws AuthenticationTagMismatchException if one bit was changed.
        aes.Decrypt(
            sealedMessage.AsSpan(0, NonceSize),
            sealedMessage.AsSpan(NonceSize, length),
            sealedMessage.AsSpan(NonceSize + length, TagSize),
            message);

        return message;
    }
}
