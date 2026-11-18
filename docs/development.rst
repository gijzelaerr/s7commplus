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

``pip install -e '.[test]'`` keeps an installed dependency that still satisfies
the new requirements, so after a test dependency changes, add ``--upgrade`` to
pick up its newest allowed release (for example the ``gherkin-official`` that
``pytest-bdd`` 9 allows, which no longer emits a ``DeprecationWarning``).

Emulator tests
--------------

Tests that start ``S7CommPlusServer`` take their port from
``get_free_tcp_port()`` or ``get_free_tcp_ports(n)`` in ``tests/conftest.py``.
A fixed port lets two test runs at once, such as two checkouts or several
branches tested in parallel, start emulators on the same port, so a client can
reach the other run's emulator. ``tests/test_no_fixed_test_ports.py`` fails on
any four- or five-digit port literal under ``tests/``. Port 102, the S7 default
for real PLCs, is allowed.

Continuous integration
----------------------

Every pull request runs ``quality`` (type checks, lint, docs, build and
package checks) and the test matrix: Python 3.10 and 3.14 on two Ubuntu and two
Windows images, and on macOS one Python per image (``macos-15`` with 3.10,
``macos-26`` with 3.14), because GitHub runs few macOS jobs at a time. Branch
protection on ``master`` requires all of these checks, so auto-merge waits
for them. A new push to a pull request cancels its previous run.

Build the documentation
-----------------------

The same warning-strict Sphinx command runs in GitHub Actions and Read the
Docs. Open ``docs/_build/html/index.html`` after a local build.

Session authentication research
-------------------------------

The research behind the V1 SessionKey implementation, that is the recovery,
proof and model tools, the analyses of the transpiled HarpoS7 code and the
tests that check them (formerly run with ``pytest --analysis`` and
``--slow``), lives in the separate s7commplus-research repository. It is a
copy of this repository at commit ``7b5d3e4``, so its proof reports and paths
still match.

This checkout keeps what the runtime's own tests need: the transpiled
monoliths and their data in ``old/``, the reference transforms and the
fingerprint recovery in ``tools/``, and the artifact verifier that pre-commit
runs. Read the `analysis and verification boundary
<https://github.com/gijzelaerr/s7commplus/blob/master/s7commplus/v1_session_key/ARCHITECTURE.md>`_,
the `model benchmark findings
<https://github.com/gijzelaerr/s7commplus/blob/master/s7commplus/v1_session_key/MODEL_BENCHMARKS.md>`_
and the `SessionKey maintainer and evidence guide
<https://github.com/gijzelaerr/s7commplus/blob/master/s7commplus/v1_session_key/MAINTAINER_GUIDE.md>`_
before changing the runtime SessionKey code.

Release process
---------------

Pull requests do not edit ``CHANGES.md``; each describes its user-visible changes
in a "Changelog" section of its description. Before a release, write the
release's section of ``CHANGES.md`` from the pull requests merged since the
previous tag, for example the list that this prints:

.. code-block:: console

   gh pr list --state merged --search "merged:>=YYYY-MM-DD" --json number,title,url

Group the entries under the usual headings, keep each pull request number, and
add an upgrade note for any renamed or removed public API.

The package version is declared in ``pyproject.toml``. A GitHub Release tag
must match it exactly with a ``v`` prefix; version ``0.1.0`` therefore uses tag
``v0.1.0``. The release workflow reruns tests, typing, lint, documentation, and
distribution validation before publishing through PyPI trusted publishing.

Publishing requires a protected GitHub environment named ``pypi`` and a PyPI
trusted publisher bound to ``gijzelaerr/s7commplus``, ``release.yml``, and that
environment. No long-lived PyPI token is stored in GitHub.
