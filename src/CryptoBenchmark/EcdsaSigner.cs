using System.Security.Cryptography;

namespace CryptoBenchmark;

// Asymmetric authentication: ECDSA P-256 with SHA-256. Signature is r | s in IEEE P1363 format (32 + 32 = 64 B).
public sealed class EcdsaSigner : IAuthenticator
{
    public const string MethodName = "ECDSA P-256";

    private const DSASignatureFormat Format = DSASignatureFormat.IeeeP1363FixedFieldConcatenation;

    private readonly ECDsa _privateKey;

    private readonly ECDsa _publicKey;

    public EcdsaSigner(ECDsa privateKey)
    {
        _privateKey = privateKey;

        // The verifier only has the public half.
        _publicKey = ECDsa.Create();

        _publicKey.ImportSubjectPublicKeyInfo(privateKey.ExportSubjectPublicKeyInfo(), out _);
    }

    public string Name => MethodName;

    public byte[] Sign(byte[] message) =>
        _privateKey.SignData(message, HashAlgorithmName.SHA256, Format);

    public bool Verify(byte[] message, byte[] signature) =>
        _publicKey.VerifyData(message, signature, HashAlgorithmName.SHA256, Format);
}
