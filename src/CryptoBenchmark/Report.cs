using System.Runtime.InteropServices;

namespace CryptoBenchmark;

// Writes every line to the console AND to output.md, as Markdown tables.
public sealed class Report(TextWriter file, Options options)
{
    public void WriteLine(string line = "")
    {
        Console.WriteLine(line);

        file.WriteLine(line);
    }

    public void WriteSettings(IReadOnlyList<(string Key, TimeSpan Time)> keyTimes, int methodsCount)
    {
        var totalOps = (long)methodsCount * options.MessagesCount * options.LoopCounter * 2;

        WriteLine("# Crypto benchmark: symmetric vs asymmetric");

        WriteLine();

        WriteLine("## Settings");

        WriteLine();

        WriteLine("| Setting | Value |");

        WriteLine("|---|---|");

        WriteLine("| Part A (encryption) | AES-256-GCM, RSA-2048 OAEP-SHA256, Hybrid (RSA-2048 wraps an AES-256 key) |");

        WriteLine("| Part B (authentication) | HMAC-SHA256, RSA-2048 PSS-SHA256, ECDSA P-256 SHA-256 |");

        WriteLine("| Key sizes | AES 256 bit, HMAC 256 bit, RSA 2048 bit, ECDSA P-256 (256 bit) |");

        WriteLine($"| Messages per batch | {options.MessagesCount} |");

        WriteLine($"| Message size | {options.MessageSize} B |");

        WriteLine($"| Loops | {options.LoopCounter} |");

        WriteLine($"| Total ops | {totalOps} ({methodsCount} methods x {options.MessagesCount} messages x {options.LoopCounter} loops x 2 ops) |");

        WriteLine($"| .NET runtime | {RuntimeInformation.FrameworkDescription} |");

        WriteLine($"| OS | {RuntimeInformation.OSDescription} |");

        WriteLine("| GC | Workstation, non-concurrent |");

        WriteLine("| Delay before loops | 2 seconds |");

        foreach (var (key, time) in keyTimes)
            WriteLine($"| Key generation: {key} | {Ms(time)} ms |");

        WriteLine();
    }

    public void WritePartAHeader()
    {
        WriteLine("## Part A: Encryption (per loop)");

        WriteLine();

        WriteLine("| Loop | Method | Encrypt (ms) | Decrypt (ms) | Allocated (B) | Ciphertext (B) | Overhead (%) | Messages/s | GC pause (ms) | Round-trip |");

        WriteLine("|---:|---|---:|---:|---:|---:|---:|---:|---:|:---:|");
    }

    public void WritePartARow(int loop, Measurement m)
    {
        WriteLine($"| {loop} | {m.Method} | {Ms(m.Op1Time)} | {Ms(m.Op2Time)} | {m.AllocatedBytes:N0} | {PerMessage(m):0.##} | {Overhead(m):0.00} | {Rate(m.TotalTime):N0} | {Ms(m.GcPause)} | {Mark(m.Ok)} |");
    }

    public void WritePartBHeader()
    {
        WriteLine();

        WriteLine("## Part B: Authentication (per loop)");

        WriteLine();

        WriteLine("| Loop | Method | Sign (ms) | Verify (ms) | Allocated (B) | Signature (B) | Signs/s | Verifies/s | GC pause (ms) | Valid | Tamper detected |");

        WriteLine("|---:|---|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|");
    }

    public void WritePartBRow(int loop, Measurement m)
    {
        WriteLine($"| {loop} | {m.Method} | {Ms(m.Op1Time)} | {Ms(m.Op2Time)} | {m.AllocatedBytes:N0} | {PerMessage(m):0.##} | {Rate(m.Op1Time):N0} | {Rate(m.Op2Time):N0} | {Ms(m.GcPause)} | {Mark(m.Ok)} | {Mark(m.TamperDetected == true)} |");
    }

    public void WritePartASummary(IReadOnlyList<Measurement> all)
    {
        WriteLine();

        WriteLine($"## Part A summary (average of {options.LoopCounter} loops, GC pause = total)");

        WriteLine();

        WriteLine("| Method | Encrypt (ms) | Decrypt (ms) | Allocated (B) | Ciphertext (B) | Overhead (%) | Messages/s | GC pause total (ms) | Round-trip |");

        WriteLine("|---|---:|---:|---:|---:|---:|---:|---:|:---:|");

        var averages = Average(all);

        foreach (var m in averages)
            WriteLine($"| {m.Method} | {Ms(m.Op1Time)} | {Ms(m.Op2Time)} | {m.AllocatedBytes:N0} | {PerMessage(m):0.##} | {Overhead(m):0.00} | {Rate(m.TotalTime):N0} | {Ms(m.GcPause)} | {Mark(m.Ok)} |");

        var aes = averages.Single(m => m.Method == SymmetricCipher.MethodName);

        var rsa = averages.SingleOrDefault(m => m.Method == AsymmetricCipher.MethodName);

        var hybrid = averages.Single(m => m.Method == HybridCipher.MethodName);

        var aesVsRsa = rsa is null
            ? $"AES vs RSA: skipped (message size {options.MessageSize} B > {Options.MaxRsaPlaintext} B)"
            : $"AES is {Ratio(rsa.TotalTime, aes.TotalTime)}x faster than RSA";

        WriteLine();

        WriteLine($"**Result:** {aesVsRsa}; hybrid is {Ratio(hybrid.TotalTime, aes.TotalTime)}x the cost of pure AES.");
    }

    public void WritePartBSummary(IReadOnlyList<Measurement> all)
    {
        WriteLine();

        WriteLine($"## Part B summary (average of {options.LoopCounter} loops, GC pause = total)");

        WriteLine();

        WriteLine("| Method | Sign (ms) | Verify (ms) | Allocated (B) | Signature (B) | Signs/s | Verifies/s | GC pause total (ms) | Valid | Tamper detected |");

        WriteLine("|---|---:|---:|---:|---:|---:|---:|---:|:---:|:---:|");

        var averages = Average(all);

        foreach (var m in averages)
            WriteLine($"| {m.Method} | {Ms(m.Op1Time)} | {Ms(m.Op2Time)} | {m.AllocatedBytes:N0} | {PerMessage(m):0.##} | {Rate(m.Op1Time):N0} | {Rate(m.Op2Time):N0} | {Ms(m.GcPause)} | {Mark(m.Ok)} | {Mark(m.TamperDetected == true)} |");

        var hmac = averages.Single(m => m.Method == HmacAuthenticator.MethodName);

        var rsa = averages.Single(m => m.Method == RsaSigner.MethodName);

        var ecdsa = averages.Single(m => m.Method == EcdsaSigner.MethodName);

        WriteLine();

        WriteLine($"**Result:** HMAC is {Ratio(ecdsa.TotalTime, hmac.TotalTime)}x faster than ECDSA (sign + verify); "
            + $"ECDSA signs {Ratio(rsa.Op1Time, ecdsa.Op1Time)}x faster than RSA; "
            + $"RSA verifies {Ratio(ecdsa.Op2Time, rsa.Op2Time)}x faster than ECDSA.");
    }

    // One row per method: average times, allocations and output; TOTAL GC pause; Ok only if every loop was Ok.
    private static List<Measurement> Average(IReadOnlyList<Measurement> all) =>
        all.GroupBy(m => m.Method)
            .Select(g => new Measurement(
                g.First().Part,
                g.Key,
                TimeSpan.FromTicks((long)g.Average(m => m.Op1Time.Ticks)),
                TimeSpan.FromTicks((long)g.Average(m => m.Op2Time.Ticks)),
                (long)g.Average(m => m.AllocatedBytes),
                (long)g.Average(m => m.OutputBytes),
                TimeSpan.FromTicks(g.Sum(m => m.GcPause.Ticks)),
                g.All(m => m.Ok),
                g.All(m => m.TamperDetected != false)))
            .ToList();

    private double PerMessage(Measurement m) => (double)m.OutputBytes / options.MessagesCount;

    private double Overhead(Measurement m) => (PerMessage(m) - options.MessageSize) * 100 / options.MessageSize;

    private double Rate(TimeSpan time) => options.MessagesCount / time.TotalSeconds;

    private static string Ratio(TimeSpan slow, TimeSpan fast) => (slow / fast).ToString("0.00");

    private static string Ms(TimeSpan time) => time.TotalMilliseconds.ToString("0.000");

    private static string Mark(bool ok) => ok ? "✅" : "❌";
}
