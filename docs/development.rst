Development and releases
========================

Set up a checkout
-----------------

This source-checkout workflow is for developing and testing ``s7commplus``.
Applications should instead install the stable release from `PyPI
<https://pypi.org/project/s7commplus/>`_ as described in
:doc:`getting-started`.

.. code-block:: console

   git clone https://github.com/gijzelaerr/s7commplus.git
   cd s7commplus
   python -m venv .venv
   . .venv/bin/activate
   python -m pip install -e '.[test,docs]' build twine

Run the complete checks
-----------------------

.. code-block:: console

   pytest
   mypy s7commplus
   ruff check s7commplus tests
   ruff format --check s7commplus tests
   sphinx-build -W --keep-going -b html docs docs/_build/html
   python -m build
   twine check dist/*
   pre-commit run --all-files

Real-PLC tests are opt-in and require an explicitly selected, disposable test
DB. Follow :doc:`real-plc-testing` for TLS configuration, the safe runner, and
sanitized evidence collection.

Build the documentation
-----------------------

The same warning-strict Sphinx command runs in GitHub Actions and Read the
Docs. Open ``docs/_build/html/index.html`` after a local build.

Session authentication research
-------------------------------

The checkout includes analysis tools for the HarpoS7-derived authentication
transforms. They regenerate exact Boolean models, print recovered gate
formulas, decompile arithmetic tape dependencies, and benchmark model costs:

.. code-block:: console

   python -m tools.recover_monolith5_gates --formula 0
   python -m tools.recover_monolith7_full --verify tools/monolith7_full_model.json
   python -m tools.decompile_transform12 --phase2 --output-slot 27
   python -m tools.benchmark_session_auth_models
   python -m tools.verify_session_auth
   python -m tools.transform7_reference --random-cases 2
   python -m tools.recover_scalar_curve
   python -m tools.recover_scalar_shadow --catalogue
   python -m tools.recover_scalar_encodings --summary
   python -m tools.trace_scalar_defects --effective-scalar 0
   python -m tools.transport_scalar_defects --effective-scalar 0
   python -m tools.predict_scalar_defects --effective-scalar 0
   python -m tools.recover_scalar_relation_terms
   python -m tools.prove_scalar_predicate_guards
   python -m tools.scalar_representative_program --effective-scalar 0
   python -m tools.prove_scalar_representative_rules
   python -m tools.scalar_stage_plan --effective-scalar 0
   python -m tools.scalar_stage_plan --stage 80 --branch 1

The tools run from the checkout and do not replace the packaged runtime.
Read the `analysis and verification boundary
<https://github.com/gijzelaerr/s7commplus/blob/master/s7commplus/session_auth/ARCHITECTURE.md>`_
and `model benchmark findings
<https://github.com/gijzelaerr/s7commplus/blob/master/s7commplus/session_auth/MODEL_BENCHMARKS.md>`_
before using a recovered evaluator as an implementation.

The `SessionKey maintainer and evidence guide
<https://github.com/gijzelaerr/s7commplus/blob/master/s7commplus/session_auth/MAINTAINER_GUIDE.md>`_
maps handwritten interfaces, source/fixture provenance, failure triage and the
remaining proof boundaries. For one offline source-correspondence check, pass
``--upstream-root /path/to/HarpoS7`` to ``tools.verify_session_auth``; add
``--models`` to regenerate saved Boolean models and check setup proof
accounting. The command does not fetch upstream code or contact a PLC.

The `scalar-stage research notes
<https://github.com/gijzelaerr/s7commplus/blob/master/tools/SCALAR_RESEARCH.md>`_
derive a complete 160-stage compact scalar shadow, prove stage-specific
coordinate encodings, and retain reachable on-curve carry and representation
counterexamples. Observed carry events can also be lifted into symbolic
coordinate corrections and replayed as projective scales, with all stage
boundaries checked against the exact source trace. This still requires
source-observed carry events and representative tags; it is not an independent
compact exact implementation or permission to replace runtime arithmetic.
The polynomial/tag predictor instead predicts carries and full Transform7
output without executing a full exact arithmetic trace. It retains
source-dependent polynomial and tag dependencies. The generalized shadow also
retains the relation-error terms when the ordinary ladder invariant is lost.
The optional Z3 command proves primitive-domain guard and lift lemmas, not
the whole predictor or generated runtime kernels.
The residue/lift evaluator now uses standalone exact primitive rules in place
of folded arithmetic. Its separate optional Z3 command proves addition and
subtraction rules against the integer-model AST across all unsigned 160-bit
inputs. Multiplication retains a modular product and a lift bit, checked with
the independent fold oracle and packed runtime. The evaluator still traverses
the recovered source graph; stage-level carry/tag compression remains open.
The bounded stage-plan compiler instead combines field operations into sparse
polynomials with explicit carry variables and formula anchors where expansion
would grow too large. It evaluates carry guards and lazy lift rules without
replaying the complete arithmetic trace or repairing descendant polynomials.
Use ``--stage`` to inspect output equations, carry-site provenance, and retained
lift dependencies. Three additional optional solver obligations prove constant
carry exclusions. Structural frontier checks validate correction ordering, not
algebraic equivalence of the entire compiler. The plans remain source-specific;
neither a compact curve replacement nor a speed improvement is claimed.

Release process
---------------

The package version is declared in ``pyproject.toml``. A GitHub Release tag
must match it exactly with a ``v`` prefix; version ``0.1.0`` therefore uses tag
``v0.1.0``. The release workflow reruns tests, typing, lint, documentation, and
distribution validation before publishing through PyPI trusted publishing.

Publishing requires a protected GitHub environment named ``pypi`` and a PyPI
trusted publisher bound to ``gijzelaerr/s7commplus``, ``release.yml``, and that
environment. No long-lived PyPI token is stored in GitHub.
