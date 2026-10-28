using System.Security.Cryptography;

namespace CryptoBenchmark;

// Asymmetric encryption: RSA-2048 OAEP-SHA256. Anyone encrypts with the PUBLIC key; only the owner decrypts with the PRIVATE key.
public sealed class AsymmetricCipher : ICipher
{
    public const string MethodName = "RSA-2048 OAEP-SHA256";

    private readonly RSA _privateKey;

    private readonly RSA _publicKey;

    public AsymmetricCipher(RSA privateKey)
    {
        _privateKey = privateKey;

        // The sender only has the public half.
        _publicKey = RSA.Create();

        _publicKey.ImportRSAPublicKey(privateKey.ExportRSAPublicKey(), out _);
    }

    public string Name => MethodName;

    public EncryptedBatch Encrypt(byte[][] messages) =>
        new(null, messages.Select(message => _publicKey.Encrypt(message, RSAEncryptionPadding.OaepSHA256)).ToArray());

    public byte[][] Decrypt(EncryptedBatch batch) =>
        batch.Items.Select(item => _privateKey.Decrypt(item, RSAEncryptionPadding.OaepSHA256)).ToArray();
}
