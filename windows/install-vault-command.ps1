param(
    [Parameter(Mandatory=$true)][string]$ProjectDirectory,
    [string]$Distribution = 'Ubuntu-24.04'
)
$ErrorActionPreference = 'Stop'
$project = (Resolve-Path -LiteralPath $ProjectDirectory).Path
if ($project -match '[%"\r\n]' -or $Distribution -notmatch '^[A-Za-z0-9._-]+$') { throw 'Unsupported project path or distribution' }
foreach ($name in @('vaultwarden.py', 'service.json')) {
    if (-not (Test-Path -LiteralPath (Join-Path $project $name) -PathType Leaf)) { throw "Missing $name" }
}
$linuxProject = & wsl.exe -d $Distribution -u root --exec wslpath -a ($project.Replace('\', '/'))
if ($LASTEXITCODE -ne 0 -or -not $linuxProject) { throw 'Cannot resolve WSL project directory' }
$linuxProject = $linuxProject.Trim()
if ($linuxProject -match '[%"\r\n]') { throw 'Unsupported WSL project directory' }
$bin = Join-Path $env:LOCALAPPDATA 'Frankenstein\bin'
[IO.Directory]::CreateDirectory($bin) | Out-Null
$target = Join-Path $bin 'vault.cmd'
$linuxPs = $linuxProject.Replace("'", "''")
$keepalive = "Start-Process -WindowStyle Hidden -FilePath wsl.exe -ArgumentList @('-d','$Distribution','-u','root','--exec','python3',([char]34+'$linuxPs/vaultwarden.py'+[char]34),'--config',([char]34+'$linuxPs/service.json'+[char]34),'keepalive')"
$script = "@echo off`r`n" + '@rem Frankenstein Vaultwarden controller; data stays in the enrolled service.' + "`r`n" +
    "wsl.exe -d $Distribution -u root --exec python3 `"$linuxProject/vaultwarden.py`" --config `"$linuxProject/service.json`" %*`r`n" +
    'if errorlevel 1 exit /b %errorlevel%' + "`r`n" +
    'if /I not "%~1"=="on" exit /b 0' + "`r`n" +
    "powershell.exe -NoLogo -NoProfile -Command `"$keepalive`"`r`n"
if ((Test-Path -LiteralPath $target) -and (Get-Content -LiteralPath $target -Raw) -ne $script) {
    throw 'Existing vault command differs; preserved for review'
}
[IO.File]::WriteAllText($target, $script, [Text.Encoding]::ASCII)
$current = [Environment]::GetEnvironmentVariable('Path', 'User')
$parts = @($current -split ';' | Where-Object { $_ })
if ($parts -notcontains $bin) {
    [Environment]::SetEnvironmentVariable('Path', (($parts + $bin) -join ';'), 'User')
}
if (($env:Path -split ';') -notcontains $bin) { $env:Path += ';' + $bin }
Write-Output "Installed $target"
Write-Output 'New PowerShell windows: vault on | vault off | vault status | vault cloud-backup'
