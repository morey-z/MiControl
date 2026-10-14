# Fetch the exact official Frida asset; this script never installs or loads it.
$ErrorActionPreference = 'Stop'
$release = Invoke-RestMethod 'https://api.github.com/repos/frida/frida/releases/tags/17.15.3'
$asset = $release.assets | Where-Object name -eq 'frida-gadget-17.15.3-windows-x86_64.dll.xz'
if ($null -eq $asset) { throw 'Frida release asset not found' }
$destination = Join-Path $PSScriptRoot '../src-tauri/resources/hid-tap'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$archive = Join-Path $destination 'frida-gadget.dll.xz'
Invoke-WebRequest $asset.url -Headers @{Accept='application/octet-stream'} -OutFile $archive
$expected = 'B566D70189B6D551AD8F4E0BEA24DE08A3D4C0F559BB35B2BDB67D45182240C2'
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'Frida archive SHA-256 mismatch'
}
$extractor = @'
import hashlib,lzma,pathlib,sys
p=pathlib.Path(sys.argv[1])
data=lzma.decompress(p.read_bytes())
assert hashlib.sha256(data).hexdigest()=='6fca4007b2284c765a6c15c967a741f536b5865bf83867326a54029a3b752748'
p.with_suffix('').write_bytes(data)
'@
python -c $extractor $archive
if ($LASTEXITCODE -ne 0) { throw 'Frida extraction/hash check failed (Python 3 required)' }
