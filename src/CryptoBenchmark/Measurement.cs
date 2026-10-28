using System.Diagnostics;

namespace CryptoBenchmark;

// One timed run of one method over one batch.
// Op1/Op2 = Encrypt/Decrypt in Part A, Sign/Verify in Part B.
// OutputBytes = ciphertext bytes (Part A) or tag/signature bytes (Part B) for the whole batch.
public sealed record Measurement(
    string Part,
    string Method,
    TimeSpan Op1Time,
    TimeSpan Op2Time,
    long AllocatedBytes,
    long OutputBytes,
    TimeSpan GcPause,
    bool Ok,
    bool? TamperDetected)
{
    public TimeSpan TotalTime => Op1Time + Op2Time;

    public static Measurement Run<TOutput, TResult>(
        string part,
        string method,
        Func<TOutput> op1,
        Func<TOutput, TResult> op2,
        Func<TOutput, long> outputBytes,
        Func<TResult, bool> isOk,
        Func<TOutput, bool>? tamperDetected = null)
    {
        // Managed heap only: memory OpenSSL allocates natively is not counted.
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();

        var pauseBefore = GC.GetTotalPauseDuration();

        var stopwatch = Stopwatch.StartNew();

        var output = op1();

        var op1Time = stopwatch.Elapsed;

        stopwatch.Restart();

        var result = op2(output);

        var op2Time = stopwatch.Elapsed;

        var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;

        var gcPause = GC.GetTotalPauseDuration() - pauseBefore;

        // Checks run after the clock stops, so they do not count in the timings.
        return new Measurement(
            part,
            method,
            op1Time,
            op2Time,
            allocated,
            outputBytes(output),
            gcPause,
            isOk(result),
            tamperDetected?.Invoke(output));
    }
}
