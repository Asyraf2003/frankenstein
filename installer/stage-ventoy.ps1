[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Iso,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$Sha256,
    [ValidatePattern('^[A-Za-z]$')][string]$DriveLetter = 'D'
)
$ErrorActionPreference = 'Stop'
$source = Get-Item -LiteralPath $Iso
if ($source.PSIsContainer -or $source.Extension -ne '.iso') { throw 'Select an ISO file.' }
if ($source.Name -notmatch '^frankenstein-[A-Za-z0-9._-]+\.iso$') { throw 'Expected a Frankenstein ISO filename.' }
$volumeRoot = $DriveLetter.ToUpperInvariant() + ':\'
if ($volumeRoot.TrimEnd('\') -eq $env:SystemDrive) { throw 'Windows system volume is forbidden.' }
$volume = New-Object System.IO.DriveInfo($volumeRoot)
if (-not $volume.IsReady -or $volume.VolumeLabel -ne 'Ventoy') { throw 'Selected volume must be the existing Ventoy data partition.' }
if ($volume.AvailableFreeSpace -lt $source.Length) { throw 'Insufficient free space; no files have been changed.' }
$destination = Join-Path $volumeRoot $source.Name
if (Test-Path -LiteralPath $destination) { throw 'Destination already exists; refusing to replace an ISO.' }
if ((Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash -ne $Sha256) { throw 'Source ISO checksum mismatch.' }
$temporary = Join-Path $volumeRoot ('.frankenstein-' + [guid]::NewGuid().ToString('N') + '.partial')
try {
    Copy-Item -LiteralPath $source.FullName -Destination $temporary
    if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $Sha256) { throw 'USB copy checksum mismatch.' }
    # Same-volume rename exposes the ISO to Ventoy only after the complete copy verifies.
    Move-Item -LiteralPath $temporary -Destination $destination
    Write-Output "Verified ISO copied: $destination"
    Write-Output 'No partitions, existing ISOs or EFI files were changed. Physical boot remains unverified.'
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
