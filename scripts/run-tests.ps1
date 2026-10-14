# Runs the unit tests on Windows without installing the package.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\run-tests.ps1 [-Coverage]
param([switch]$Coverage)
Set-Location (Join-Path $PSScriptRoot "..")
$env:PYTHONPATH = "src"
if ($Coverage) {
  python -m coverage run -m unittest discover -s tests -t . -v
  python -m coverage combine | Out-Null
  python -m coverage report
} else {
  python -m unittest discover -s tests -t . -v
}
exit $LASTEXITCODE
