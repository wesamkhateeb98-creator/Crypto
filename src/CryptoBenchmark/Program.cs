using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using CryptoBenchmark;

CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

var outputPath = Path.GetFullPath("output.md");

File.WriteAllText(outputPath, string.Empty);

var options = Options.Parse(args);

var messages = MessageFactory.Create(options.MessagesCount, options.MessageSize);

var keyTimes = new List<(string Key, TimeSpan Time)>();

var aesKey = TimeKey("AES-256 (32 B random)", () => RandomNumberGenerator.GetBytes(32));

var hmacKey = TimeKey("HMAC-SHA256 (32 B random)", () => RandomNumberGenerator.GetBytes(32));

// .NET creates RSA/EC keys lazily: exporting the public key forces the real generation inside the timer.
var rsaEncryptionKey = TimeKey("RSA-2048 (encryption)", () => ForceRsa(RSA.Create(2048)));

var rsaSigningKey = TimeKey("RSA-2048 (signing)", () => ForceRsa(RSA.Create(2048)));

var ecdsaKey = TimeKey("ECDSA P-256", () => ForceEcdsa(ECDsa.Create(ECCurve.NamedCurves.nistP256)));

var ciphers = new List<ICipher> { new SymmetricCipher(aesKey) };

if (options.RsaFits)
    ciphers.Add(new AsymmetricCipher(rsaEncryptionKey));

ciphers.Add(new HybridCipher(rsaEncryptionKey));

var authenticators = new List<IAuthenticator>
{
    new HmacAuthenticator(hmacKey),
    new RsaSigner(rsaSigningKey),
    new EcdsaSigner(ecdsaKey),
};

// Warm-up: run every method once over the whole batch, so tiered JIT finishes (during the 2 s delay) before measuring.
foreach (var cipher in ciphers)
    cipher.Decrypt(cipher.Encrypt(messages));

foreach (var authenticator in authenticators)
    messages.Select(message => authenticator.Verify(message, authenticator.Sign(message))).ToArray();

using var writer = new StreamWriter(outputPath) { AutoFlush = true };

var report = new Report(writer, options);

report.WriteSettings(keyTimes, ciphers.Count + authenticators.Count);

if (!options.RsaFits)
{
    report.WriteLine($"> Pure RSA encryption skipped: RSA-2048 OAEP-SHA256 encrypts at most {Options.MaxRsaPlaintext} B (256 - 2*32 - 2), message is {options.MessageSize} B. Hybrid and signatures still run.");

    report.WriteLine();
}

Thread.Sleep(TimeSpan.FromSeconds(2));

var partA = new List<Measurement>();

report.WritePartAHeader();

for (var loop = 1; loop <= options.LoopCounter; loop++)
{
    foreach (var cipher in ciphers)
    {
        var measurement = Measurement.Run(
            "A",
            cipher.Name,
            () => cipher.Encrypt(messages),
            cipher.Decrypt,
            batch => batch.TotalBytes,
            decrypted => decrypted.Zip(messages).All(pair => pair.First.AsSpan().SequenceEqual(pair.Second)));

        partA.Add(measurement);

        report.WritePartARow(loop, measurement);
    }
}

var partB = new List<Measurement>();

report.WritePartBHeader();

for (var loop = 1; loop <= options.LoopCounter; loop++)
{
    foreach (var authenticator in authenticators)
    {
        var measurement = Measurement.Run(
            "B",
            authenticator.Name,
            () => messages.Select(authenticator.Sign).ToArray(),
            signatures => messages.Zip(signatures).Select(pair => authenticator.Verify(pair.First, pair.Second)).ToArray(),
            signatures => signatures.Sum(signature => (long)signature.Length),
            results => results.All(valid => valid),
            signatures => !authenticator.Verify(Tamper(messages[0]), signatures[0]));

        partB.Add(measurement);

        report.WritePartBRow(loop, measurement);
    }
}

report.WritePartASummary(partA);

report.WritePartBSummary(partB);

report.WriteLine();

report.WriteLine($"Output written to: {outputPath}");

T TimeKey<T>(string name, Func<T> generate)
{
    var stopwatch = Stopwatch.StartNew();

    var key = generate();

    keyTimes.Add((name, stopwatch.Elapsed));

    return key;
}

static RSA ForceRsa(RSA rsa)
{
    rsa.ExportRSAPublicKey();

    return rsa;
}

static ECDsa ForceEcdsa(ECDsa ecdsa)
{
    ecdsa.ExportSubjectPublicKeyInfo();

    return ecdsa;
}

// Copy of the message with one bit flipped: a valid signature must no longer verify.
static byte[] Tamper(byte[] message)
{
    var copy = (byte[])message.Clone();

    copy[0] ^= 0x01;

    return copy;
}
