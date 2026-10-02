"""Machine-transpiled monolith transforms, retired from the runtime.

DO NOT EDIT — regenerate via ``tools/transpile_harpo_monolith.py``.

These modules are mechanically transpiled from the C# sources in
``HarpoS7.Family0.Monoliths`` (MIT, https://github.com/bonk-dev/HarpoS7).
Each ``monolithN.execute(dst, src)`` is a straight-line uint32 arithmetic
port of the corresponding ``MonolithN.Execute`` method, verified byte-for-
byte against the upstream test vectors. See ``ARCHITECTURE.md`` in
``s7commplus/session_auth/`` for what each one turned out to compute.

Subpackages:
    nine/    Monolith9 parts (split for Python's parser limits)
    ten/     Monolith10 parts (split for Python's parser limits)
    data/    Vendored HarpoS7 tables (fingerprint, Transform1/7/12, SharedData)
"""
