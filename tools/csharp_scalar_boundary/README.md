# Offline upstream C# scalar/caller probe

This optional checkout diagnostic compiles unmodified HarpoS7 Family0 and
Utilities sources from an external local checkout. It is not a Python runtime
dependency and does not require a PLC. Preserve HarpoS7's MIT attribution and
license. Never substitute live keys, challenges or entropy for these fixed
public/synthetic inputs.

The recorded checkout revision is `b4ba7fab14bcca4274e69a4d6524a5a61fcd329d`.
The probe was run with .NET SDK 10.0.401/runtime 10.0.12 and an already cached
CommunityToolkit.HighPerformance 8.2.2 `net7.0` assembly. Source files are
unchanged, but this retargeted .NET 10 build is not the original .NET 8 binary.

Set the two build properties to absolute paths: `HarpoRoot` is the directory
containing `HarpoS7.Family0` and `HarpoS7.Utilities`; `ToolkitAssembly` is the
existing cached DLL, not a package feed. The NuGet configuration has **no
sources** and the project has no package references. If the required SDK,
framework reference pack or cached DLL is missing, stop; these commands are
not permission to download or install them.

From this directory:

```sh
export DOTNET_CLI_HOME="$PWD/cli-home"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
dotnet restore Probe.csproj --configfile NuGet.Config
dotnet build Probe.csproj --no-restore --disable-build-servers -p:UseSharedCompilation=false \
  -p:HarpoRoot=/path/to/HarpoS7 \
  -p:ToolkitAssembly=/path/to/CommunityToolkit.HighPerformance.dll
dotnet bin/Debug/net10.0/Probe.dll
```

The harness checks original Transform7's two complete 72-byte outputs,
normalization counts, actual PreSeedTransform and the final 60-byte seed for
the bundled-key scalar-carry counterexample. It invokes original C# monoliths
in SeedTransform's call order with deterministic entropy and a 32-iteration
normalization bound. It does **not** call the random `SeedTransform.Execute`
entry point, prove whole-program equivalence or validate PLC acceptance.

The seed checksum is
`f1c44e2fbf2c8271d45f05e5690ebade88692c7380c9af438fcedfebd79bcc8a`,
matching original Python and the exact reference. The uncorrected modular
candidate's checksum is
`55d4fe6a138671c909403571138d5fbef3a28581fb0c84facf558f22e0190ba2`.
Every expected output and normalization count is asserted; drift fails the
probe rather than silently updating its checksums. `bin`, `obj` and the local
SDK profile are ignored build artifacts.
