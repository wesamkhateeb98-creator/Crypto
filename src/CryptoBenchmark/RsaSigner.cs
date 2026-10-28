using System.Security.Cryptography;

namespace CryptoBenchmark;

// Asymmetric authentication: RSA-2048 PSS-SHA256. Sign with the PRIVATE key, anyone verifies with the PUBLIC key (256 B signature).
public sealed class RsaSigner : IAuthenticator
{
    public const string MethodName = "RSA-2048 PSS-SHA256";

    private readonly RSA _privateKey;

    private readonly RSA _publicKey;

    public RsaSigner(RSA privateKey)
    {
        _privateKey = privateKey;

        // The verifier only has the public half.
        _publicKey = RSA.Create();

        _publicKey.ImportRSAPublicKey(privateKey.ExportRSAPublicKey(), out _);
    }

    public string Name => MethodName;

    public byte[] Sign(byte[] message) =>
        _privateKey.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    public bool Verify(byte[] message, byte[] signature) =>
        _publicKey.VerifyData(message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
}
