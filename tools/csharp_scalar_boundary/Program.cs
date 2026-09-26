// Public/synthetic source-execution probe; never supply live session material.
// Calls unmodified MIT-licensed HarpoS7 sources from an external checkout.
using System.Numerics;
using System.Security.Cryptography;
using HarpoS7.Family0.Data;
using HarpoS7.Family0.Monoliths;
using HarpoS7.Family0.Transforms;

static string Hash(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

static void Check(string label, byte[] value, string expected)
{
    string actual = Hash(value);
    Console.WriteLine($"{label}_sha256={actual}");
    if (actual != expected) throw new Exception($"source differential mismatch: {label}");
}

static byte[] Integer(BigInteger value)
{
    byte[] output = new byte[20];
    if (!value.TryWriteBytes(output, out _, isUnsigned: true, isBigEndian: false)) throw new Exception("uint160 required");
    return output;
}

static int Normalize(byte[] buffer)
{
    for (int i = 1; i <= 32; i++) if (Monolith1.Execute(buffer, buffer) != 0) return i;
    throw new Exception("normalization bound exceeded");
}

static byte[] Raw(byte[] key, byte[] r)
{
    byte[] output = new byte[72];
    Transform7.Execute(output, r.ToArray(), new byte[20], key);
    return output;
}

byte[] key = Convert.FromHexString("9808369442d4f3b63f9aa40856ddf798579966bc2a9c382c3fbf13a4d00aaa98ffefc9ab38da5537");
byte[] r = Integer(BigInteger.Parse("978004156713030480091955929130383740779312767983"));
byte[] generator = Transform7Data.Data.Span.Slice(0xD8, 40).ToArray();
byte[] generatorRaw = Raw(generator, r);
byte[] keyRaw = Raw(key, r);
Check("generator_raw", generatorRaw, "3e175c7f1a1d66d2b192a9089624d8ca91c17074d2401a6d0fc1a5a726386483");
Check("key_raw", keyRaw, "525391c756e42b9fb3575066389966188c822ae71b1963a993245cc3f51393ba");
int generatorIterations = Normalize(generatorRaw), keyIterations = Normalize(keyRaw);
Console.WriteLine($"generator_normalizations={generatorIterations}");
Console.WriteLine($"key_normalizations={keyIterations}");
if (generatorIterations != 2 || keyIterations != 2) throw new Exception("normalization count mismatch");
byte[] work = new byte[20];
Monolith2.Execute(work, generatorRaw);
if (work.All(value => value == 0)) throw new Exception("first nonce rejected");
byte[] transform1 = new byte[60];
PreSeedTransform.Execute(transform1, Enumerable.Range(0, 24).Select(value => (byte)value).ToArray());
byte[] m8 = new byte[92];
Monolith8.Execute(m8.AsSpan(20), keyRaw);
byte[] m11 = new byte[120];
Transform13.Execute(m11.AsSpan(60), m8.AsSpan(20));
transform1.CopyTo(m11, 0);
Monolith11.Execute(m8, m11);
byte[] seed = new byte[60];
m8.AsSpan(0, 20).CopyTo(seed);
work.CopyTo(seed, 20);
r.CopyTo(seed, 40);
Check("preseed", transform1, "2f887ffb4c2a3b430f4ba7e70b4f9f31dbbbea0e5cac6071727100f17e0dcdc9");
Check("seed", seed, "f1c44e2fbf2c8271d45f05e5690ebade88692c7380c9af438fcedfebd79bcc8a");
