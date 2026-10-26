# Contributing

Fork the repository, create a branch, and open a pull request against `main`. Keep each pull
request focused. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities privately per [SECURITY.md](SECURITY.md), not in issues.

Every pull request runs the test suite, the public scrub (credentials, private IP ranges, user
home paths, email addresses, AI attribution) and the sign-off check; all must pass.

## Running the checks

```
python -m pytest -q tests
cd "OSINT Profiler" && python -m pytest -q tests
python -m compileall -q "OSINT Profiler/osint_profiler" "Phone Lookup/src"
```

Phone Lookup (inside its own virtual environment):

```
cd "Phone Lookup"
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e .
.venv/Scripts/python.exe -m unittest discover -s tests
```

PowerShell launchers use Pester 5.7.1:

```
Import-Module Pester -RequiredVersion 5.7.1; Invoke-Pester -Path tests/powershell
```

There is no linter in v1; `compileall` is the syntax gate.

## Rules

- Never commit wheels, container images, case data, databases, or secrets. The public-tree tests
  enforce this.
- A new third-party dependency needs a hash-pinned lock entry, a `shared/build/fetch_wheelhouse.py`
  run, and regenerated notices via `shared/build/gen_third_party_notices.py`.
- A bug fix starts with a failing test that reproduces it; one fix per commit.
- Do not weaken or bypass the gates (network probe, typed `RUN`, subject authorization, refusal
  exit codes). Changes that loosen them will not be merged.
- The toolkit is Windows-first. POSIX support is welcome when it sits behind the provider seam.

## License

Contributions are licensed under Apache-2.0, the same as the project (inbound = outbound).

Sign off each commit (`git commit -s`) to certify the
[Developer Certificate of Origin](https://developercertificate.org/). The sign-off check fails a
pull request with any commit that lacks its author's `Signed-off-by:` line. There is no CLA.
