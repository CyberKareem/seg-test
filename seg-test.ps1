<#
.SYNOPSIS
  seg-test.ps1 - PCI segmentation reachability test, one-shot per source VLAN. (Windows)

.DESCRIPTION
  Windows-native sibling of seg-test.sh. Same evidence layout, same nmap invocations,
  same archive + SHA-256 format, so runs from either script are directly comparable
  across cycles. clients\<name>.env is the SAME file format as the bash kit, so a
  client configured on Linux runs unchanged here.

  Self-contained kit: the script, cde-all.txt, clients\<name>.env and the downloaded
  installers travel together in one folder. Results land in .\evidence\ beside the
  script. Nothing is written outside the kit folder except the Nmap/Npcap install itself.

  IMPORTANT - what the FREE Nmap/Npcap builds can and cannot do (nmap.org/book/inst-windows):
    * "The Zip archive is available to Nmap OEM customers only" - there is no portable
      nmap to drop in a folder. It must be installed.
    * "Nmap OEM installers also accept /S for silent installation" - the free installer
      does NOT. Neither does the free Npcap. BOTH INSTALLS ARE INTERACTIVE.
  So -Init downloads the official signed installers and verifies them against the SHA-256
  pins in $DEPS; -InstallDeps then launches them and you click through, once per host.
  Budget for that in the change request: it is a kernel-mode NDIS driver on a production
  host, and it cannot be pushed unattended without an Nmap OEM licence.

  Usage:
    .\seg-test.ps1 -Check                                  # what's present/missing
    .\seg-test.ps1 -Init <client>                          # scaffold + download installers (no admin)
    .\seg-test.ps1 -Init <client> -InstallDeps             # ...and install nmap + Npcap (ADMIN, interactive)
    .\seg-test.ps1 -Client <name> <VLAN> -DryRun           # preview, no packets, no admin
    .\seg-test.ps1 -Client <name> <VLAN>                   # real scan (ADMIN)
    .\seg-test.ps1 -PinDeps                                # print SHA-256 pins to paste below

  Options:
    -Check              report which required tools are present/missing, then exit
    -InstallDeps        download + install nmap and Npcap (needs admin). The free
                        installers have no silent mode, so you click through them once
                        per host. Combine with -Check, -Init, or a real run.
    -FullTcp            also run a rate-limited all-ports TCP scan (slow)
    -SkipUdp            skip the UDP selected-ports scan
    -ExpectCidr <cidr>  abort unless a local interface is inside <cidr>
    -Force              continue even if the -ExpectCidr guard fails
    -DryRun             show exactly what would run, send no packets, no admin needed
    -AcceptUnpinned     allow a dependency download whose SHA-256 is not pinned below

  Prerequisites:
    - Windows 8 / Server 2012 or later (Get-NetIPConfiguration, Test-NetConnection)
    - PowerShell 5.1+ (ships with Windows 10 / Server 2016+)
    - Windows 10 1803+ / Server 2019+ for the built-in curl.exe and tar.exe. tar.exe is
      REQUIRED: the archive is always .tar.gz, matching the Linux kit. There is no .zip fallback.
    - Local administrator, for Npcap install and for nmap raw sockets (-sS / -sU)
    - Npcap. WITHOUT IT nmap cannot do -sS, -sU, or --reason TTL, and the test is
      degraded to a -sT TCP connect scan with no UDP coverage and no TTL evidence.

  Evidence layout (identical to seg-test.sh):
    evidence\<VLAN>-<timestamp>\
      run.log
      baseline\  cde-targets.clean.txt run-metadata.txt start.txt end.txt
                 ip-addr.txt ip-route.txt ip-neigh.txt trace-to-cde-anchor.txt
      nmap\      01-host-discovery{,-pn} 02-tcp-common 03-tcp-full 04-udp-selected  (.nmap/.gnmap/.xml)
      manual\    <hotspot>.txt  open-ports-summary.txt
      pcap\  screenshots\
    evidence\<client>-<VLAN>-<timestamp>.tar.gz + .sha256

  Does NOT:
    - Make Pass/Fail decisions (human task at report time)
    - Capture pcap, brute-force, exploit, or run nmap vuln scripts
    - Touch any IP not in cde-all.txt / the client's hot-spot lists
#>

[CmdletBinding()]
param(
  [Parameter(Position = 0)][string]$SourceSegment,
  [string]$Client,
  [string]$Init,
  [string]$ExpectCidr,
  [switch]$Check,
  [switch]$InstallDeps,
  [switch]$PinDeps,
  [switch]$FullTcp,
  [switch]$SkipUdp,
  [switch]$Force,
  [switch]$DryRun,
  [switch]$AcceptUnpinned,
  [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------- config

# TCP common ports - identical to seg-test.sh
$TCP_COMMON_PORTS = '21,22,23,25,53,80,110,135,139,143,389,443,445,1433,1521,3306,3389,5432,5900,5985,5986,6379,8080,8443,9200'

# UDP selected ports - identical to seg-test.sh
$UDP_PORTS = '53,67,68,69,123,137,138,161,162,500,514,4500'

# Pinned dependency downloads.
#
#   Sha256 = '' means UNPINNED. An unpinned download is refused unless you pass
#   -AcceptUnpinned. Run  .\seg-test.ps1 -PinDeps  ONCE on your own machine: it
#   downloads each file, prints its SHA-256, and you paste the values in here.
#   The pin then travels with the kit, so every client run verifies what it fetched.
#
#   Check https://nmap.org/download#windows and https://npcap.com/#download for the
#   current versions before pinning.
# The kit downloads the official signed installers and verifies them against these pins.
# Neither free installer supports silent mode (/S is an Nmap OEM feature), so -InstallDeps
# launches them interactively. The Nmap installer offers to install Npcap as part of its
# run - keep that selected. The separate Npcap entry covers the case where it was
# deselected, blocked, or is older than the pin below.
#
# Hashes below were captured on 2026-09-14 from the vendor sites. VERIFY them against
# https://nmap.org/download#windows and https://npcap.com/#download before an engagement,
# and re-pin with  .\seg-test.ps1 -PinDeps  when you move to a newer version.
$DEPS = @{
  Nmap  = @{
    Version = '7.991'
    Url     = 'https://nmap.org/dist/nmap-7.991-setup.exe'
    Sha256  = '93bfd37bdb31a7adfd932beb5dbce06025da691d01a0939e806ea704f7367657'
    File    = 'nmap-setup.exe'
  }
  Npcap = @{
    Version = '1.89'
    Url     = 'https://npcap.com/dist/npcap-1.89.exe'
    Sha256  = '8aed85e900d783d1308506e919587d3e540451947af8a82f2d04f819e44305cc'
    File    = 'npcap-setup.exe'
  }
}

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ClientsDir = Join-Path $ScriptDir 'clients'
$ToolsDir   = Join-Path $ScriptDir 'tools'
$NmapDir    = Join-Path $ToolsDir 'nmap'

# ------------------------------------------------------------------- helpers

function Write-Head($Text) { Write-Host $Text }

# Write an evidence file with LF line endings and no BOM (byte-parity with the bash
# kit), and echo the same text to the console so it lands in the transcript.
# Tee-Object is deliberately NOT used: on Windows PowerShell 5.1 it has no -Encoding
# parameter (added in PS 6) and unconditionally writes UTF-16LE with a BOM, which
# would make these files binary to grep/diff and unlike every other evidence file.
function Write-Evidence {
  param([string]$Path, [string]$Text, [switch]$Quiet)
  if ($null -eq $Text) { $Text = '' }
  $norm = ($Text -replace "`r`n", "`n")
  if ($norm.Length -gt 0 -and -not $norm.EndsWith("`n")) { $norm += "`n" }
  [IO.File]::WriteAllText($Path, $norm, (New-Object System.Text.UTF8Encoding($false)))
  if (-not $Quiet) { Write-Host $Text }
}

# Append one line, LF + UTF-8-no-BOM. Appends (not buffered) so partial hot-spot
# evidence survives an abort mid-loop, matching bash's `tee -a` / `>>`.
function Add-EvidenceLine {
  param([string]$Path, [string]$Text)
  if ($null -eq $Text) { $Text = '' }
  $norm = ($Text -replace "`r`n", "`n")
  if (-not $norm.EndsWith("`n")) { $norm += "`n" }
  [IO.File]::AppendAllText($Path, $norm, (New-Object System.Text.UTF8Encoding($false)))
}

# Same, for a list of lines.
function Write-EvidenceLines {
  param([string]$Path, [string[]]$Lines, [switch]$Quiet)
  Write-Evidence -Path $Path -Text (($Lines) -join "`n") -Quiet:$Quiet
}

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { $false }
}

# Resolve nmap.exe: a portable copy dropped in the kit wins, then the standard install
# locations, then PATH. (A portable tools\nmap\ is still honoured if you extract one
# yourself - the kit just cannot fetch one, because Nmap no longer publishes it.)
function Get-NmapPath {
  $portable = Join-Path $NmapDir 'nmap.exe'
  if (Test-Path -LiteralPath $portable) { return $portable }
  foreach ($d in @("$env:ProgramFiles\Nmap", "${env:ProgramFiles(x86)}\Nmap")) {
    if ([string]::IsNullOrWhiteSpace($d)) { continue }
    $c = Join-Path $d 'nmap.exe'
    if (Test-Path -LiteralPath $c) { return $c }
  }
  $onPath = Get-Command nmap.exe -ErrorAction SilentlyContinue
  if ($onPath) { return $onPath.Source }
  return $null
}

# Npcap presence. This gates -sS / -sU / --reason TTL, so it must prove the DRIVER is
# actually loaded - not merely that something named Npcap exists on disk.
#
# Get-Service is NOT usable here: in Windows PowerShell 5.1 it is backed by
# ServiceController.GetServices(), which enumerates SERVICE_WIN32_* only. Npcap
# registers as SERVICE_KERNEL_DRIVER, so Get-Service -Name 'npcap' returns nothing
# even on a correctly installed host. Query Win32_SystemDriver instead.
#
# Fails CLOSED: any uncertainty returns $false, which aborts the run rather than
# letting it proceed to a silently degraded scan.
function Test-Npcap {
  $running = $false
  try {
    $d = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='npcap'" -ErrorAction Stop
    if ($d -and $d.State -eq 'Running') { $running = $true }
  } catch {
    # WMI/CIM can be locked down on hardened hosts - fall back to sc.exe.
    $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
      $sc = (& sc.exe query npcap 2>&1 | Out-String)
      if ($sc -match 'STATE\s*:\s*4\s+RUNNING') { $running = $true }
    } catch { } finally { $ErrorActionPreference = $prevEap }
  }
  if (-not $running) { return $false }

  # Driver is running; nmap also needs the user-mode libraries to link against.
  foreach ($dir in @("$env:SystemRoot\System32\Npcap", "$env:SystemRoot\System32")) {
    if (Test-Path -LiteralPath (Join-Path $dir 'wpcap.dll')) { return $true }
  }
  return $false
}

function Get-DependencyStatus {
  $nmap = Get-NmapPath
  [pscustomobject]@{
    Nmap      = [bool]$nmap
    NmapPath  = $nmap
    Npcap     = Test-Npcap
    Curl      = [bool](Get-Command curl.exe -ErrorAction SilentlyContinue)
    Tar       = [bool](Get-Command tar.exe  -ErrorAction SilentlyContinue)
    Admin     = Test-IsAdmin
    PSVersion = $PSVersionTable.PSVersion.ToString()
  }
}

function Show-DependencyReport {
  $s = Get-DependencyStatus
  Write-Head '--- Dependency check ---'
  $rows = @(
    @{ N = 'nmap.exe';   Ok = $s.Nmap;  Fix = 'run (ADMIN):  .\seg-test.ps1 -Check -InstallDeps' }
    @{ N = 'Npcap';      Ok = $s.Npcap; Fix = 'run:  .\seg-test.ps1 -InstallDeps     (ADMIN; gates -sS/-sU/TTL)' }
    @{ N = 'curl.exe';   Ok = $s.Curl;  Fix = 'built into Windows 10 1803+; HTTPS hot-spots will be skipped' }
    @{ N = 'tar.exe';    Ok = $s.Tar;   Fix = 'REQUIRED for .tar.gz parity with the Linux kit; ships with Windows 10 1803+ / Server 2019+' }
    @{ N = 'local admin';Ok = $s.Admin; Fix = 're-open PowerShell as Administrator' }
  )
  foreach ($r in $rows) {
    if ($r.Ok) { Write-Head ("  [ok]      {0}" -f $r.N) }
    else       { Write-Head ("  [MISSING] {0}  -> {1}" -f $r.N, $r.Fix) }
  }
  Write-Head ("  [info]    PowerShell {0}" -f $s.PSVersion)
  if ($s.NmapPath) { Write-Head ("  [info]    nmap: {0}" -f $s.NmapPath) }

  if (-not $s.Npcap) {
    Write-Head ''
    Write-Head 'WARNING: Npcap not detected. Without it nmap cannot run -sS (SYN), -sU (UDP),'
    Write-Head '         or report --reason TTL. The run would degrade to a -sT connect scan:'
    Write-Head '         no UDP coverage and no TTL evidence. Fix this before a real test.'
  }
  # curl is optional (HTTPS hot-spots only); nmap, Npcap, tar and admin are required.
  return ($s.Nmap -and $s.Npcap -and $s.Admin -and $s.Tar)
}

function Invoke-Download {
  # -PinOnly is used only by Invoke-PinDeps, which exists to COMPUTE hashes. It suppresses
  # the refusals below so a missing pin is not a fatal error while pinning. Install paths
  # never pass it, so an unpinned Npcap install remains impossible.
  param([string]$Url, [string]$OutFile, [string]$ExpectedSha, [string]$Label, [switch]$PinOnly)

  try {
    [Net.ServicePointManager]::SecurityProtocol =
      [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
  } catch { }

  Write-Head (">>> Downloading {0}: {1}" -f $Label, $Url)
  $prev = $ProgressPreference
  $ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is ~10x faster without the bar
  try {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
  } catch {
    # Never leave an unverified partial behind - a later run would reuse it.
    Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
    throw ("download failed for {0}: {1}" -f $Label, $_.Exception.Message)
  } finally {
    $ProgressPreference = $prev
  }

  $actual = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash.ToLower()
  if ([string]::IsNullOrWhiteSpace($ExpectedSha)) {
    Write-Head ("    SHA-256 (UNPINNED): {0}" -f $actual)
    if (-not $PinOnly) {
      if ($Label -like 'Npcap*') {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        throw ("{0} has no pinned SHA-256, and -AcceptUnpinned deliberately does NOT cover the Npcap kernel driver. Verify the hash above against https://npcap.com/#download and paste it into the `$DEPS block at the top of this script." -f $Label)
      }
      if (-not $AcceptUnpinned) {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        throw ("{0} has no pinned SHA-256. Verify the hash above against the vendor, paste it into `$DEPS, or re-run with -AcceptUnpinned." -f $Label)
      }
      Write-Head '    -AcceptUnpinned given; continuing WITHOUT hash verification.'
    }
  } elseif ($actual -ne $ExpectedSha.ToLower()) {
    Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
    throw ("{0} SHA-256 MISMATCH`n  expected: {1}`n  actual:   {2}" -f $Label, $ExpectedSha.ToLower(), $actual)
  } else {
    Write-Head ("    SHA-256 verified: {0}" -f $actual)
  }
  return $actual
}

# -PinDeps: fetch each dependency to a temp dir, print copy-paste-ready pins, discard.
function Invoke-PinDeps {
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("segtest-pin-" + [guid]::NewGuid().ToString('n'))
  New-Item -ItemType Directory -Path $tmp -Force | Out-Null
  $results = @{}
  try {
    foreach ($name in @('Nmap','Npcap')) {
      $d = $DEPS[$name]
      $out = Join-Path $tmp $d.File
      try {
        $results[$name] = Invoke-Download -Url $d.Url -OutFile $out -ExpectedSha '' -Label $name -PinOnly
      } catch {
        # Must not print an empty-looking pin - that would read as a valid value.
        $results[$name] = $null
        Write-Warning ("pin fetch FAILED for {0}: {1}" -f $name, $_.Exception.Message)
      }
    }
  } finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-Head ''
  Write-Head '============================================================'
  Write-Head ' Paste these into the $DEPS block near the top of this file:'
  Write-Head '============================================================'
  foreach ($name in @('Nmap','Npcap')) {
    if ($results[$name]) { Write-Head ("  {0}: Sha256 = '{1}'" -f $name, $results[$name]) }
    else                 { Write-Head ("  {0}: *** FETCH FAILED - no pin produced ***" -f $name) }
  }
  Write-Head '============================================================'
  Write-Head ' Verify each hash against the vendor page before trusting it:'
  Write-Head '   https://nmap.org/download#windows    https://npcap.com/#download'
  Write-Head '============================================================'
}

# Download the Nmap installer into tools\ (no admin), then run it silently (ADMIN).
# The Nmap installer bundles Npcap, so this normally satisfies both dependencies.
function Get-NmapInstaller {
  New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
  $d   = $DEPS.Nmap
  $exe = Join-Path $ToolsDir $d.File
  if (Test-Path -LiteralPath $exe) {
    # Re-verify a cached copy rather than trusting the file name.
    $have = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLower()
    if ($d.Sha256 -and $have -eq $d.Sha256.ToLower()) {
      Write-Head (">>> Using cached, hash-verified {0}" -f $d.File)
      return $exe
    }
    Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
  }
  Invoke-Download -Url $d.Url -OutFile $exe -ExpectedSha $d.Sha256 -Label ("nmap " + $d.Version) | Out-Null
  return $exe
}

function Install-Nmap {
  if (Get-NmapPath) { Write-Head '>>> nmap already present; skipping install.'; return }
  $exe = Get-NmapInstaller
  if (-not (Test-IsAdmin)) {
    Write-Head (">>> Installer downloaded and hash-verified: {0}" -f $exe)
    Write-Head '>>> Installing needs Administrator. Re-open PowerShell as Administrator and run:'
    Write-Head '      .\seg-test.ps1 -Check -InstallDeps'
    return
  }
  Write-Head ''
  Write-Head '============================================================'
  Write-Head ' INTERACTIVE INSTALL - the free Nmap installer has no silent mode.'
  Write-Head ' (nmap.org: "Nmap OEM installers also accept /S for silent installation.")'
  Write-Head ' An installer window will open. Click through it, and KEEP the bundled'
  Write-Head ' Npcap component selected - Npcap is what gates -sS, -sU and --reason TTL.'
  Write-Head ' This installs a kernel-mode NDIS driver: client change approval required.'
  Write-Head '============================================================'
  $proc = Start-Process -FilePath $exe -PassThru
  # Deliberately NO timeout+Kill: terminating a kernel-driver install mid-write can
  # leave the host with a half-registered NDIS filter. Wait for the operator.
  $proc.WaitForExit()
  if (Get-NmapPath) { Write-Head (">>> nmap installed: {0}" -f (Get-NmapPath)) }
  else { Write-Head '!!! nmap.exe still not found. Was the install cancelled?' }
}

# Fetch + install Npcap. The FREE Npcap has no silent installer (that is an OEM
# feature), so this is interactive too. Needed only if the Nmap installer's bundled
# Npcap was deselected or is older than the pinned version.
function Install-Npcap {
  if (Test-Npcap) { Write-Head '>>> Npcap driver already running; skipping.'; return }
  if (-not (Test-IsAdmin)) { throw 'Npcap install needs local administrator. Re-open PowerShell as Administrator.' }
  New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
  $d   = $DEPS.Npcap
  $exe = Join-Path $ToolsDir $d.File
  if (Test-Path -LiteralPath $exe) {
    $have = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLower()
    if (-not ($d.Sha256 -and $have -eq $d.Sha256.ToLower())) {
      Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
    }
  }
  if (-not (Test-Path -LiteralPath $exe)) {
    Invoke-Download -Url $d.Url -OutFile $exe -ExpectedSha $d.Sha256 -Label ("Npcap " + $d.Version) | Out-Null
  }

  Write-Head ''
  Write-Head '============================================================'
  Write-Head ' INTERACTIVE INSTALL - the free Npcap has no silent mode.'
  Write-Head ' Accept the licence and keep the defaults. WinPcap API compatibility'
  Write-Head ' may be selected; it is not required by nmap.'
  Write-Head ' This installs a kernel-mode NDIS driver: client change approval required.'
  Write-Head '============================================================'
  $proc = Start-Process -FilePath $exe -PassThru
  $proc.WaitForExit()    # no Kill: see Install-Nmap
  $ok = $false
  foreach ($try in 1..6) { Start-Sleep -Seconds 2; if (Test-Npcap) { $ok = $true; break } }
  if ($ok) { Write-Head '>>> Npcap installed and driver is running.' }
  else { Write-Head '!!! Npcap driver still not running. A reboot is usually required - reboot, then re-run -Check.' }
}

# Emit clean CDE target specs: strip '#' comments, split whitespace, drop blanks.
# Mirrors cde_specs() in seg-test.sh exactly.
function Get-CdeSpecs {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return @() }
  $out = New-Object System.Collections.Generic.List[string]
  foreach ($line in @(Get-Content -LiteralPath $Path -Encoding UTF8)) {
    $stripped = ($line -replace '#.*', '')
    foreach ($tok in ($stripped -split '\s+')) {
      if ($tok -ne '') { $out.Add($tok) }
    }
  }
  return $out.ToArray()
}

# Warn (do not fail) on any spec that isn't IPv4 / CIDR / octet range.
function Write-BadSpecWarning {
  param([string[]]$Specs)
  $re = '^([0-9]{1,3}(-[0-9]{1,3})?\.){3}[0-9]{1,3}(-[0-9]{1,3})?(/[0-9]{1,2})?$'
  $bad = @($Specs | Where-Object { $_ -notmatch $re })
  if ($bad.Count -gt 0) {
    Write-Warning ("these CDE entries don't look like IPv4/CIDR/range: " + ($bad -join ' '))
  }
}

# Returns the dotted-quad as an [int64] (0 .. 4294967295), or $null if malformed.
# int64 rather than uint32 deliberately: PowerShell parses the literal 0xFFFFFFFF as
# Int32 (-1), so uint32/uint64 masking arithmetic throws at runtime.
function ConvertTo-IpInteger {
  param([string]$Ip)
  if ($null -eq $Ip) { return $null }
  $o = $Ip.Split('.')
  if ($o.Count -ne 4) { return $null }
  [int64]$v = 0
  foreach ($part in $o) {
    # Reject zero-padded octets: bash's $((...)) reads '020' as octal 16, this would
    # read 20, and the two kits would disagree on the source-VLAN guard.
    if ($part -notmatch '^(0|[1-9][0-9]{0,2})$') { return $null }
    [int64]$n = [int64]$part
    if ($n -lt 0 -or $n -gt 255) { return $null }
    $v = ($v * 256) + $n
  }
  return $v
}

function Test-IpInCidr {
  param([string]$Ip, [string]$Cidr)
  if ($Cidr -match '^(.+)/([0-9]{1,2})$') {
    $net  = $Matches[1]
    $bits = [int]$Matches[2]
  } else { return $false }
  if ($bits -lt 0 -or $bits -gt 32) { return $false }
  $ipi  = ConvertTo-IpInteger $Ip
  $neti = ConvertTo-IpInteger $net
  if ($null -eq $ipi -or $null -eq $neti) { return $false }
  if ($bits -eq 0) { return $true }
  # All int64. 4294967295L is the literal form that does NOT become Int32 -1.
  [int64]$full = 4294967295
  [int64]$mask = ($full -shl (32 - $bits)) -band $full
  return ((($ipi -band $mask)) -eq (($neti -band $mask)))
}

# Strip a bash-style comment tail: a '#' that BEGINS A WORD (start of string, or preceded
# by whitespace) and is not inside a quoted span. Bash keeps a '#' glued to a word literal
# ("a"#b), which is the same rule the scalar branch applies via '\s+#.*$'.
function Remove-CommentTail {
  param([string]$Text)
  $m = [regex]::Match((Remove-QuotedSpans $Text), '(^|\s)#')
  if (-not $m.Success) { return $Text }
  return $Text.Substring(0, $m.Index + $m.Groups[1].Length)
}

# Blank out every quoted span so structural characters can be located without being
# confused by a quote-protected one. Returns a same-length string (offsets preserved).
function Remove-QuotedSpans {
  param([string]$Text)
  return [regex]::Replace($Text, '"[^"]*"|''[^'']*''', { param($m) ' ' * $m.Value.Length })
}

# Parse the SAME clients\<name>.env format the bash kit uses, as DATA (never executed).
# Handles: KEY="value" | KEY='value' | KEY=value | KEY=( "a" "b" ) across lines.
function Import-ClientEnv {
  param([string]$Path)
  $cfg = @{ CLIENT_NAME = ''; ROOT = ''; TRACE_ANCHOR = ''; EXPECTED_SRC_CIDR = '';
            TCP_HOTSPOTS = @(); HTTPS_HOTSPOTS = @() }
  $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8 | ForEach-Object { $_.TrimEnd("`r") })
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i].Trim()
    if ($line -eq '' -or $line.StartsWith('#')) { continue }

    # Array form:  KEY=(  ...entries...  )
    if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)=\(\s*(.*)$') {
      $key  = $Matches[1]
      $body = Remove-CommentTail $Matches[2]
      # Terminate on a ')' that is OUTSIDE a quoted string. A bare -notmatch '\)' would
      # stop on a parenthesis inside a hot-spot label (which bash treats as a literal),
      # truncate mid-token and leave the extractor with zero matches - silently emptying
      # the array. Blank the quoted spans before looking for the closing paren.
      $closed = (Remove-QuotedSpans $body) -match '\)'
      while (-not $closed) {
        $i++
        if ($i -ge $lines.Count) {
          throw ("unterminated array {0}=( in {1} - add the closing ')'" -f $key, $Path)
        }
        $next = Remove-CommentTail $lines[$i]
        if ($next.Trim() -eq '') { continue }
        $body += ' ' + $next
        $closed = (Remove-QuotedSpans $body) -match '\)'
      }
      # Cut at the position of that unquoted ')', not the first ')' in the raw text.
      $cut = (Remove-QuotedSpans $body).IndexOf(')')
      if ($cut -ge 0) { $body = $body.Substring(0, $cut) }
      $items = New-Object System.Collections.Generic.List[string]
      foreach ($m in [regex]::Matches($body, '"([^"]*)"|''([^'']*)''')) {
        $val = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        if ($val -ne '') { $items.Add($val) }
      }
      $cfg[$key] = $items.ToArray()
      continue
    }

    # Scalar form:  KEY="value" / KEY='value' / KEY=value   (inline # comment stripped)
    if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
      $key = $Matches[1]
      $val = $Matches[2].Trim()
      if ($val -match '^"([^"]*)"') { $val = $Matches[1] }
      elseif ($val -match "^'([^']*)'") { $val = $Matches[1] }
      else { $val = ($val -replace '\s+#.*$', '').Trim() }
      $cfg[$key] = $val
    }
  }
  return $cfg
}

function Write-ClientTemplate {
  param([string]$ClientName, [string]$File)
  $today = [datetime]::Now.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
  $body = @"
# clients/$ClientName.env - $ClientName PCI segmentation config.
# Created by: seg-test.ps1 -Init $ClientName  ($today)
# Read by BOTH seg-test.sh (sourced) and seg-test.ps1 (parsed as data).
# Keep it to plain KEY="value" and KEY=( "..." ) so both can read it.

# Display name used in headers/reports. Set to the real client name.
CLIENT_NAME="$ClientName"

# ROOT - where cde-all.txt and evidence/ live. Defaults to this kit's own folder.
# ROOT="C:\seg-test"

# TRACE_ANCHOR - one reachable CDE host for the baseline traceroute (optional).
TRACE_ANCHOR=""

# EXPECTED_SRC_CIDR - optional default subnet guard. The source VLAN differs per run,
# so it is usually cleaner to pass -ExpectCidr <cidr> on the command line instead.
EXPECTED_SRC_CIDR=""

# Manual TCP hot-spots to re-test each round (from the client's PRIOR report).
#   First engagement -> leave empty ().
# Format per entry: "OUTFILE_BASE|LABEL|SPACE_SEP_HOSTS|SPACE_SEP_PORTS"
#   e.g. "core-db|Core banking Oracle+SSH|10.10.10.5|1521 22"
TCP_HOTSPOTS=()

# Manual HTTPS hot-spots (curl -vk https://host/).
# Format per entry: "OUTFILE_BASE|LABEL|SPACE_SEP_HOSTS"
#   e.g. "esxi|ESXi web UI|10.10.20.28 10.10.20.29"
HTTPS_HOTSPOTS=()
"@
  # LF, no BOM: seg-test.sh SOURCES this file, and a trailing CR would end up inside
  # every value (CLIENT_NAME="alqaseh\r"), corrupting headers and paths on the Linux side.
  [IO.File]::WriteAllText($File, (($body -replace "`r`n", "`n").TrimEnd("`n") + "`n"),
                          (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-Init {
  param([string]$ClientName)
  if ($ClientName -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw "-Init client name must match ^[A-Za-z0-9._-]{1,64}$ (it becomes a file name)" }

  New-Item -ItemType Directory -Path $ClientsDir -Force | Out-Null
  $envFile = Join-Path $ClientsDir ("$ClientName.env")
  if (Test-Path -LiteralPath $envFile) {
    throw "$envFile already exists - refusing to overwrite. Edit it directly, or pick another client name."
  }
  Write-ClientTemplate -ClientName $ClientName -File $envFile

  $cde = Join-Path $ScriptDir 'cde-all.txt'
  $cdeState = 'created'
  if (Test-Path -LiteralPath $cde) {
    $cdeState = 'already present (left untouched)'
  } else {
    $tmpl = @'
# cde-all.txt - cardholder (CDE) targets. Each line/entry can be:
#   - a single IP        192.168.1.5
#   - a CIDR block       192.168.1.0/24
#   - an octet range     192.168.1.10-20   or   192.168.1-3.1-254
# One entry per line. '#' starts a comment (whole-line or inline). Blank lines ignored.
# nmap expands CIDRs/ranges automatically. Fill in for THIS client, then scan per VLAN.
# Examples (delete and replace):
# 10.20.30.5
# 10.20.30.0/24
# 10.20.31.10-40
'@
    Set-Content -LiteralPath $cde -Value $tmpl -Encoding ASCII
  }

  New-Item -ItemType Directory -Path (Join-Path $ScriptDir 'evidence') -Force | Out-Null

  Write-Head ''
  Write-Head '============================================================'
  Write-Head (" Client '{0}' initialised." -f $ClientName)
  Write-Head '============================================================'
  Write-Head (" Created : {0}" -f $envFile)
  Write-Head (" CDE list: {0}  ({1})" -f $cde, $cdeState)
  Write-Head (" Evidence: {0}" -f (Join-Path $ScriptDir 'evidence'))
  Write-Head ''

  # Always fetch the installer (the download needs no admin). INSTALLING is a
  # change-controlled action - it puts a kernel-mode NDIS driver on a client production
  # host - so it requires the explicit -InstallDeps opt-in, never ambient elevation.
  # This matches seg-test.sh do_init, which gates on INSTALL_DEPS and never on EUID.
  try {
    if ($InstallDeps) { Install-Nmap } else { Get-NmapInstaller | Out-Null }
  } catch { Write-Warning $_.Exception.Message }
  if ($InstallDeps -and -not (Test-Npcap)) {
    try { Install-Npcap } catch { Write-Warning $_.Exception.Message }
  }

  Write-Head ''
  Write-Head ' Next steps for THIS client:'
  Write-Head ('   1. Put the cardholder IPs in:   {0}   (one per line)' -f $cde)
  Write-Head ('   2. (optional) Edit {0}:' -f $envFile)
  Write-Head '        - TRACE_ANCHOR   -> a reachable CDE IP for the baseline traceroute'
  Write-Head '        - TCP_HOTSPOTS   -> prior-report findings to re-test (re-scans only)'
  Write-Head ('   3. Get the SIGNED authorization / ROE for {0} before sending any packet.' -f $ClientName)
  Write-Head '   4. Preview without scanning:'
  Write-Head ('        .\seg-test.ps1 -Client {0} <SOURCE_VLAN> -DryRun' -f $ClientName)
  Write-Head '   5. Run for real from inside each source VLAN (ADMIN):'
  Write-Head ('        .\seg-test.ps1 -Client {0} <SOURCE_VLAN> -ExpectCidr <that VLAN''s CIDR>' -f $ClientName)
  Write-Head '   6. Repeat step 5 for every source VLAN. Evidence lands in .\evidence\.'
  Write-Head '============================================================'
  Write-Head ''
  Show-DependencyReport | Out-Null
}

# ------------------------------------------------------------------- dispatch

if ($Help) {
  Get-Help -Full $MyInvocation.MyCommand.Path
  exit 0
}

if ($PinDeps) { Invoke-PinDeps; exit 0 }

if ($Check) {
  if ($InstallDeps) {
    try { Install-Nmap } catch { Write-Warning $_.Exception.Message }
    try { Install-Npcap }        catch { Write-Warning $_.Exception.Message }
    Write-Head ''
  }
  $ok = Show-DependencyReport
  if ($ok) { exit 0 } else { exit 1 }
}

if ($Init) { Invoke-Init -ClientName $Init; exit 0 }

if ([string]::IsNullOrWhiteSpace($Client)) {
  Write-Host 'ERROR: -Client <name> required (or -Init <name> to create one)'; exit 1
}
if ([string]::IsNullOrWhiteSpace($SourceSegment)) {
  Write-Host 'ERROR: source VLAN label required (positional)'; exit 1
}
# Allowlist, not denylist: these become path components and PowerShell's -Path
# parameters treat [ ] * ? as wildcards.
if ($SourceSegment -notmatch '^[A-Za-z0-9._-]{1,64}$') { Write-Host 'ERROR: source VLAN label must match ^[A-Za-z0-9._-]{1,64}$'; exit 1 }
if ($Client        -notmatch '^[A-Za-z0-9._-]{1,64}$') { Write-Host 'ERROR: -Client must match ^[A-Za-z0-9._-]{1,64}$'; exit 1 }

# ------------------------------------------------------------------- client config

$ClientEnv = Join-Path $ClientsDir ("$Client.env")
if (-not (Test-Path -LiteralPath $ClientEnv)) {
  Write-Host ("ERROR: client config not found: {0}" -f $ClientEnv)
  Write-Host ("Create it with:  .\seg-test.ps1 -Init {0}" -f $Client)
  Write-Host 'Available clients:'
  if (Test-Path -LiteralPath $ClientsDir) {
    Get-ChildItem -LiteralPath $ClientsDir -Filter '*.env' -ErrorAction SilentlyContinue |
      ForEach-Object { Write-Host ("  - " + $_.BaseName) }
  } else { Write-Host '  (none)' }
  exit 1
}

$cfg = Import-ClientEnv -Path $ClientEnv
$ClientDisplayName = [string]$cfg['CLIENT_NAME']
if ([string]::IsNullOrWhiteSpace($ClientDisplayName)) { Write-Host 'ERROR: client config missing CLIENT_NAME'; exit 1 }

$Root = [string]$cfg['ROOT']
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = $ScriptDir }
$TraceAnchor    = [string]$cfg['TRACE_ANCHOR']
$ExpectedSrcCidr = [string]$cfg['EXPECTED_SRC_CIDR']
if (-not [string]::IsNullOrWhiteSpace($ExpectCidr)) { $ExpectedSrcCidr = $ExpectCidr }
$TcpHotspots   = @($cfg['TCP_HOTSPOTS'])
$HttpsHotspots = @($cfg['HTTPS_HOTSPOTS'])

$CdeList = Join-Path $Root 'cde-all.txt'

if (-not [string]::IsNullOrWhiteSpace($ExpectedSrcCidr) -and $ExpectedSrcCidr -notmatch '/') {
  Write-Host ("ERROR: -ExpectCidr must be CIDR form, e.g. 10.20.44.0/24 (got '{0}')" -f $ExpectedSrcCidr); exit 1
}

$Specs = @(Get-CdeSpecs -Path $CdeList)
$CdeCount = $Specs.Count

# ------------------------------------------------------------------- dry run

if ($DryRun) {
  $st = Get-DependencyStatus
  Write-Head '============================================================'
  Write-Head (" DRY RUN - {0} / {1}   (no packets sent)" -f $ClientDisplayName, $SourceSegment)
  Write-Head '============================================================'
  Write-Head (" Client cfg:   {0}" -f $ClientEnv)
  Write-Head (" ROOT:         {0}" -f $Root)
  Write-Head (" CDE list:     {0}  ({1} target spec[s]: IPs / CIDRs / ranges)" -f $CdeList, $CdeCount)
  if ([string]::IsNullOrWhiteSpace($TraceAnchor)) { Write-Head ' Anchor:       (none - baseline traceroute skipped)' }
  else { Write-Head (" Anchor:       {0}" -f $TraceAnchor) }
  if ([string]::IsNullOrWhiteSpace($ExpectedSrcCidr)) { Write-Head ' Src guard:    (none - manual 5s source-IP eyeball only)' }
  else { Write-Head (" Src guard:    {0}" -f $ExpectedSrcCidr) }
  Write-Head (" Hot-spots:    {0} TCP group(s), {1} HTTPS group(s)" -f $TcpHotspots.Count, $HttpsHotspots.Count)
  Write-Head (" Evidence ->   {0}\evidence\{1}-<timestamp>\  (+ .tar.gz + .sha256)" -f $Root, $SourceSegment)
  Write-Head ''
  Write-Head ' Would run against every CDE target (nmap expands CIDRs/ranges):'
  Write-Head '   - host discovery : nmap -sn (with and without -Pn)'
  Write-Head ("   - TCP common     : -p {0}" -f $TCP_COMMON_PORTS)
  if ($FullTcp) { Write-Head '   - TCP full       : yes  (-p-  --max-rate 500)' } else { Write-Head '   - TCP full       : no  (pass -FullTcp)' }
  if ($SkipUdp) { Write-Head '   - UDP            : skipped (-SkipUdp)' } else { Write-Head ("   - UDP            : -p {0}" -f $UDP_PORTS) }
  Write-Head ''
  Write-Head ' CDE target specs (comments/blanks stripped):'
  if ($CdeCount -eq 0) { Write-Head ("     (no list at {0})" -f $CdeList) }
  else { foreach ($s in $Specs) { Write-Head ("     " + $s) } }
  Write-BadSpecWarning -Specs $Specs
  Write-Head ''
  if (-not $st.Npcap) {
    Write-Head ' !! Npcap NOT detected. A real run would lose -sS, -sU and --reason TTL.'
    Write-Head '    Fix with:  .\seg-test.ps1 -InstallDeps   (ADMIN)'
  }
  if (-not $st.Nmap)  { Write-Head ' !! nmap NOT found. Fix with (ADMIN):  .\seg-test.ps1 -Check -InstallDeps' }
  if (-not $st.Admin) { Write-Head ' !! Not running as Administrator. A real run needs it.' }
  Write-Head '============================================================'
  Write-Head ' No evidence written. Remove -DryRun to execute for real (needs ADMIN).'
  exit 0
}

# ------------------------------------------------------------------- prereqs

if (-not (Test-IsAdmin)) {
  Write-Host 'ERROR: must run as Administrator (nmap -sS / -sU need raw sockets)'; exit 1
}

$status = Get-DependencyStatus
if (-not $status.Nmap) {
  if ($InstallDeps) { Install-Nmap; $status = Get-DependencyStatus }
  else { Write-Host 'ERROR: nmap not found. Run (ADMIN):  .\seg-test.ps1 -Check -InstallDeps   (or add -InstallDeps to this run)'; exit 1 }
}
if (-not $status.Npcap) {
  if ($InstallDeps) { Install-Npcap; $status = Get-DependencyStatus }
}
if (-not $status.Npcap) {
  Write-Host ('ERROR: Npcap not detected. Without it nmap cannot run -sS, -sU, or report --reason TTL, ' +
               'so this run would silently lose UDP coverage and TTL evidence. ' +
               'Install it (.\seg-test.ps1 -InstallDeps, ADMIN) or run the test from the Linux kit.')
  exit 1
}

$NmapExe = $status.NmapPath

if (-not $status.Tar) {
  Write-Host 'ERROR: tar.exe not found. The Linux kit produces <base>.tar.gz + .sha256, and a silent'
  Write-Host '       switch to .zip would give this assessment two archive formats. tar.exe ships with'
  Write-Host '       Windows 10 1803+ / Server 2019+. Fix the host, or run this VLAN from the Linux kit.'
  exit 1
}

if (-not (Test-Path -LiteralPath $CdeList)) {
  Write-Host ("ERROR: CDE target list not found at {0}" -f $CdeList); exit 1
}
if ($CdeCount -le 0) {
  Write-Host ("ERROR: {0} has no target specs (only comments/blanks?)" -f $CdeList); exit 1
}
Write-BadSpecWarning -Specs $Specs

# ------------------------------------------------------------------- setup

# InvariantCulture is mandatory: Get-Date -Format renders in CurrentCulture, so on a
# host set to e.g. Arabic (Saudi Arabia) 'yyyy' would emit an UmAlQura year and the
# evidence folder + archive name would not match the bash kit or the engagement window.
$TS      = [datetime]::Now.ToString('yyyy-MM-dd-HHmm', [cultureinfo]::InvariantCulture)
$OutDir  = Join-Path $Root ("evidence\{0}-{1}" -f $SourceSegment, $TS)
foreach ($sub in @('baseline','nmap','manual','pcap','screenshots')) {
  New-Item -ItemType Directory -Path (Join-Path $OutDir $sub) -Force | Out-Null
}

$LogFile = Join-Path $OutDir 'run.log'
try { Start-Transcript -LiteralPath $LogFile -Force | Out-Null } catch { Write-Warning "transcript unavailable: $($_.Exception.Message)" }

function Stop-Log { try { Stop-Transcript | Out-Null } catch { } }

# Everything from here to the DONE banner runs inside try/catch/finally. The bash kit
# traps INT/TERM (seg-test.sh:509); this is the PowerShell equivalent. Without it an
# exception or Ctrl-C leaves run.log open and baseline\end.txt absent, so a partial run
# is indistinguishable from a clean one - the worst failure mode for audit evidence.
# (PS 5.1 runs finally on Ctrl-C in the console host, but not guaranteed in every host,
# hence end.txt is also stamped in the catch.)
$script:RunFailed = 0
try {

# ISO-8601 with offset, matching bash `date -Is`. InvariantCulture for the same reason
# as $TS, and because ':' in a .NET format string is the culture's time separator.
function Get-Stamp { [datetimeoffset]::Now.ToString('yyyy-MM-ddTHH:mm:sszzz', [cultureinfo]::InvariantCulture) }

$CdeClean = Join-Path $OutDir 'baseline\cde-targets.clean.txt'
Write-EvidenceLines -Path $CdeClean -Lines $Specs -Quiet

Write-Head '============================================================'
Write-Head (" {0} Segmentation Test - source: {1}" -f $ClientDisplayName, $SourceSegment)
Write-Head (" Client cfg:   {0}" -f $ClientEnv)
Write-Head (" Evidence dir: {0}" -f $OutDir)
Write-Head (" CDE targets:  {0} target spec(s) [IPs/CIDRs/ranges] -> nmap expands them" -f $CdeCount)
if ([string]::IsNullOrWhiteSpace($ExpectedSrcCidr)) { Write-Head ' Src guard:    (none - manual eyeball only)' }
else { Write-Head (" Src guard:    {0}" -f $ExpectedSrcCidr) }
Write-Head (" Hot-spots:    {0} TCP group(s), {1} HTTPS group(s)" -f $TcpHotspots.Count, $HttpsHotspots.Count)
Write-Head (" Full TCP:     {0}" -f $(if ($FullTcp) { 'yes' } else { 'no' }))
Write-Head (" Skip UDP:     {0}" -f $(if ($SkipUdp) { 'yes' } else { 'no' }))
Write-Head (" Started:      {0}" -f (Get-Stamp))
Write-Head '============================================================'

# nmap version + binary hash go into the evidence: which scanner produced this run.
$NmapVersionLine = ''
try { $NmapVersionLine = (& $NmapExe --version 2>&1 | Select-Object -First 1) } catch { $NmapVersionLine = '(unavailable)' }
$NmapSha = ''
try { $NmapSha = (Get-FileHash -LiteralPath $NmapExe -Algorithm SHA256).Hash.ToLower() } catch { $NmapSha = '(unavailable)' }

$argsEcho = ".\seg-test.ps1 -Client $Client $SourceSegment"
if ($FullTcp) { $argsEcho += ' -FullTcp' }
if ($SkipUdp) { $argsEcho += ' -SkipUdp' }
if (-not [string]::IsNullOrWhiteSpace($ExpectedSrcCidr)) { $argsEcho += " -ExpectCidr $ExpectedSrcCidr" }

$meta = @"
CLIENT_NAME: $ClientDisplayName
CLIENT_ENV: $ClientEnv
SOURCE_SEGMENT: $SourceSegment
TIMESTAMP_START: $(Get-Stamp)
HOSTNAME: $env:COMPUTERNAME
USER: $env:USERNAME
ARGS: $argsEcho
CDE_LIST: $CdeList
CDE_CLEAN: $CdeClean
CDE_SPEC_COUNT: $CdeCount
TRACE_ANCHOR: $(if ([string]::IsNullOrWhiteSpace($TraceAnchor)) { '(none)' } else { $TraceAnchor })
EXPECTED_SRC_CIDR: $(if ([string]::IsNullOrWhiteSpace($ExpectedSrcCidr)) { '(none)' } else { $ExpectedSrcCidr })
TCP_COMMON_PORTS: $TCP_COMMON_PORTS
UDP_PORTS: $UDP_PORTS
RUNNER: seg-test.ps1 (Windows) / PowerShell $($PSVersionTable.PSVersion)
OS: $([Environment]::OSVersion.VersionString)
NMAP_PATH: $NmapExe
NMAP_VERSION: $NmapVersionLine
NMAP_SHA256: $NmapSha
NPCAP_PRESENT: $($status.Npcap)
"@
Write-Evidence -Path (Join-Path $OutDir 'baseline\run-metadata.txt') -Text $meta -Quiet

# ------------------------------------------------------------------- 1. baseline

Write-Head ''
Write-Head '--- [1/6] Baseline ---'
Write-Evidence -Path (Join-Path $OutDir 'baseline\start.txt') -Text (Get-Stamp)

$ipAddr = (Get-NetIPConfiguration -Detailed -ErrorAction SilentlyContinue | Out-String -Width 4096).Trim()
if ([string]::IsNullOrWhiteSpace($ipAddr)) { $ipAddr = (& ipconfig /all | Out-String -Width 4096).Trim() }
Write-Evidence -Path (Join-Path $OutDir 'baseline\ip-addr.txt') -Text $ipAddr

$ipRoute = (Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric | Format-Table -AutoSize | Out-String -Width 4096).Trim()
if ([string]::IsNullOrWhiteSpace($ipRoute)) { $ipRoute = (& route print -4 | Out-String -Width 4096).Trim() }
Write-Evidence -Path (Join-Path $OutDir 'baseline\ip-route.txt') -Text $ipRoute

$ipNeigh = (Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Format-Table -AutoSize | Out-String -Width 4096).Trim()
if ([string]::IsNullOrWhiteSpace($ipNeigh)) { $ipNeigh = (& arp -a | Out-String -Width 4096).Trim() }
Write-Evidence -Path (Join-Path $OutDir 'baseline\ip-neigh.txt') -Text $ipNeigh

$traceFile = Join-Path $OutDir 'baseline\trace-to-cde-anchor.txt'
if (-not [string]::IsNullOrWhiteSpace($TraceAnchor)) {
  $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { Write-Evidence -Path $traceFile -Text (& tracert -d -w 2000 -h 8 $TraceAnchor 2>&1 | Out-String) }
  finally { $ErrorActionPreference = $prevEap }
} else {
  Write-Evidence -Path $traceFile -Text ("(no TRACE_ANCHOR set in {0} - skipping baseline traceroute)" -f $ClientEnv)
}

# Source IP(s), loudly. Glance at this to confirm you are in the VLAN you think.
$SrcIpList = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' -and
                 -not $_.IPAddress.StartsWith('169.254.') } |
  Select-Object -ExpandProperty IPAddress)
$SrcIps = ($SrcIpList -join ',')
Write-Head ''
Write-Head (">>> Source IP(s): {0}" -f $SrcIps)

if (-not [string]::IsNullOrWhiteSpace($ExpectedSrcCidr)) {
  $guardOk = $false
  foreach ($sip in $SrcIpList) { if (Test-IpInCidr -Ip $sip -Cidr $ExpectedSrcCidr) { $guardOk = $true; break } }
  if ($guardOk) {
    Write-Head (">>> Source-VLAN guard OK: a local interface is inside {0}" -f $ExpectedSrcCidr)
  } else {
    Write-Head ("!!! Source-VLAN guard FAILED: no interface in {0} (have: {1})" -f $ExpectedSrcCidr, $(if ($SrcIps) { $SrcIps } else { 'none' }))
    if ($Force) {
      Write-Head '!!! -Force given; continuing anyway (results may be from the WRONG VLAN).'
    } else {
      Write-Head '!!! Aborting so you do not scan from the wrong VLAN. Fix the VLAN/VPN, or re-run with -Force.'
      Write-Evidence -Path (Join-Path $OutDir 'baseline\end.txt') -Text (Get-Stamp)
      Stop-Log
      exit 3
    }
  }
} else {
  Write-Head '>>> No -ExpectCidr set. Confirm the above matches the expected VLAN. (5s pause)'
  Start-Sleep -Seconds 5
}

# ------------------------------------------------------------------- 2-5. nmap

$script:StageFailures = @()

function Invoke-Nmap {
  param([string[]]$NmapArgs, [string]$Stage)
  Write-Head ("    nmap {0}" -f ($NmapArgs -join ' '))
  # Native stderr redirected with 2>&1 arrives as ErrorRecords; under $ErrorActionPreference
  # = 'Stop' that would abort the run on nmap's first warning. Localise it.
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & $NmapExe @NmapArgs 2>&1 | ForEach-Object { Write-Host $_ }
  } finally {
    $ErrorActionPreference = $prevEap
  }
  if ($LASTEXITCODE -ne 0) {
    Write-Warning ("nmap exited {0} during {1}" -f $LASTEXITCODE, $Stage)
    $script:StageFailures += ("{0} (nmap exit {1})" -f $Stage, $LASTEXITCODE)
  }
}

Write-Head ''
Write-Head '--- [2/6] Host discovery ---'
Invoke-Nmap -Stage 'host discovery' -NmapArgs @(
  '-sn','-n','-iL',$CdeClean,'--reason','-oA',(Join-Path $OutDir 'nmap\01-host-discovery'))
Invoke-Nmap -Stage 'host discovery (-Pn)' -NmapArgs @(
  '-Pn','-sn','-n','-iL',$CdeClean,'--reason','-oA',(Join-Path $OutDir 'nmap\01-host-discovery-pn'))

Write-Head ''
Write-Head '--- [3/6] TCP common-ports scan ---'
Invoke-Nmap -Stage 'TCP common' -NmapArgs @(
  '-Pn','-n','-sS','-iL',$CdeClean,'-p',$TCP_COMMON_PORTS,'--reason','--open',
  '-oA',(Join-Path $OutDir 'nmap\02-tcp-common'))

Write-Head ''
if ($FullTcp) {
  Write-Head '--- [4/6] TCP full-port scan (rate-limited) ---'
  Invoke-Nmap -Stage 'TCP full' -NmapArgs @(
    '-Pn','-n','-sS','-iL',$CdeClean,'-p-','--max-rate','500','--reason',
    '-oA',(Join-Path $OutDir 'nmap\03-tcp-full'))
} else {
  Write-Head '--- [4/6] TCP full-port scan SKIPPED (pass -FullTcp to enable) ---'
}

Write-Head ''
if (-not $SkipUdp) {
  Write-Head '--- [5/6] UDP selected-ports scan ---'
  Invoke-Nmap -Stage 'UDP' -NmapArgs @(
    '-Pn','-n','-sU','-iL',$CdeClean,'-p',$UDP_PORTS,'--reason',
    '-oA',(Join-Path $OutDir 'nmap\04-udp-selected'))
} else {
  Write-Head '--- [5/6] UDP scan SKIPPED (-SkipUdp) ---'
}

# ------------------------------------------------------------------- 6. hot-spots

Write-Head ''
Write-Head ("--- [6/6] Manual hot-spot checks (from {0} prior findings) ---" -f $ClientDisplayName)

if ($TcpHotspots.Count -eq 0) {
  Write-Head ("  (no TCP hot-spots configured for {0} - nothing carried over)" -f $ClientDisplayName)
} else {
  foreach ($entry in $TcpHotspots) {
    $parts = $entry -split '\|'
    if ($parts.Count -lt 4) { Write-Warning ("malformed TCP_HOTSPOTS entry: {0}" -f $entry); continue }
    $base = $parts[0]; $label = $parts[1]
    $hosts = @($parts[2] -split '\s+' | Where-Object { $_ -ne '' })
    $ports = @($parts[3] -split '\s+' | Where-Object { $_ -ne '' })
    Write-Head ''
    Write-Head ("[hot-spot] {0}" -f $label)
    $outfile = Join-Path $OutDir ("manual\{0}.txt" -f $base)
    Write-Evidence -Path $outfile -Text '' -Quiet   # 0 bytes, like bash `: > "$outfile"`
    foreach ($ip in $hosts) {
      foreach ($p in $ports) {
        # Raw TcpClient, not Test-NetConnection: we need to distinguish a RST
        # (ConnectionRefused - the host IS reachable, only the service is down) from a
        # silent drop (TimedOut - the firewall is doing its job). Collapsing the two
        # would let a real segmentation gap be written up as remediated.
        $line = ''
        $tcp = $null
        try {
          $tcp = New-Object System.Net.Sockets.TcpClient
          $iar = $tcp.BeginConnect($ip, [int]$p, $null, $null)
          if ($iar.AsyncWaitHandle.WaitOne(5000, $false)) {
            try {
              $tcp.EndConnect($iar)
              $line = ("{0} [tcp] {1}:{2} - open (connect succeeded)" -f (Get-Stamp), $ip, $p)
            } catch [System.Net.Sockets.SocketException] {
              $line = ("{0} [tcp] {1}:{2} - {3} ({4})" -f (Get-Stamp), $ip, $p,
                       $_.Exception.SocketErrorCode, $_.Exception.Message)
            }
          } else {
            $line = ("{0} [tcp] {1}:{2} - TimedOut (no response in 5s)" -f (Get-Stamp), $ip, $p)
          }
        } catch {
          $line = ("{0} [tcp] {1}:{2} - error: {3}" -f (Get-Stamp), $ip, $p, $_.Exception.Message)
        } finally {
          if ($tcp) { $tcp.Close() }
        }
        Write-Head ("  " + $line)
        Add-EvidenceLine -Path $outfile -Text $line
      }
    }
  }
}

if ($HttpsHotspots.Count -eq 0) {
  Write-Head ("  (no HTTPS hot-spots configured for {0})" -f $ClientDisplayName)
} else {
  $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
  foreach ($entry in $HttpsHotspots) {
    $parts = $entry -split '\|'
    if ($parts.Count -lt 3) { Write-Warning ("malformed HTTPS_HOTSPOTS entry: {0}" -f $entry); continue }
    $base = $parts[0]; $label = $parts[1]
    $hosts = @($parts[2] -split '\s+' | Where-Object { $_ -ne '' })
    Write-Head ''
    Write-Head ("[hot-spot] {0}" -f $label)
    $outfile = Join-Path $OutDir ("manual\{0}.txt" -f $base)
    Write-Evidence -Path $outfile -Text '' -Quiet   # 0 bytes, like bash `: > "$outfile"`
    foreach ($ip in $hosts) {
      if ($curl) {
        # curl -v writes its entire trace to stderr; same ErrorRecord hazard as nmap.
        $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        # --output NUL discards the body, matching bash's `curl -vk ... >/dev/null`:
        # the evidence is the TLS/connection trace, not the page content.
        try { $out = (& curl.exe -vk --connect-timeout 5 --output NUL ("https://{0}/" -f $ip) 2>&1 | Out-String) }
        finally { $ErrorActionPreference = $prevEap }
      } else {
        $out = "(curl.exe not available on this host - HTTPS hot-spot not executed)"
      }
      Add-EvidenceLine -Path $outfile -Text $out
      Add-EvidenceLine -Path $outfile -Text ("--- {0} ---" -f $ip)
      Write-Head ("  checked {0}" -f $ip)
    }
  }
}

# ------------------------------------------------------------------- summary

Write-Head ''
Write-Head '--- Summary ---'
$Summary = Join-Path $OutDir 'manual\open-ports-summary.txt'
$sumLines = New-Object System.Collections.Generic.List[string]
$sumLines.Add(("# Open ports reached from {0} ({1}) at {2}" -f $SourceSegment, $ClientDisplayName, (Get-Stamp)))
$sumLines.Add(("# Source IPs: {0}" -f $SrcIps))
if ($script:StageFailures.Count -gt 0) {
  $sumLines.Add("#")
  $sumLines.Add("# *** SCAN INCOMPLETE - {0} nmap stage(s) did not exit cleanly:" -f $script:StageFailures.Count)
  foreach ($sf in $script:StageFailures) { $sumLines.Add("#     - $sf") }
  $sumLines.Add("# *** Treat the results below as PARTIAL. Do not report them as a clean result.")
}
$sumLines.Add('')
$gnmap = @(Get-ChildItem -LiteralPath (Join-Path $OutDir 'nmap') -Filter '*.gnmap' -ErrorAction SilentlyContinue)
$hits = @()
if ($gnmap.Count -gt 0) {
  $hits = @(Select-String -LiteralPath $gnmap.FullName -Pattern '/open/' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Line })
}
if ($hits.Count -gt 0) { foreach ($h in $hits) { $sumLines.Add($h) } }
else { $sumLines.Add('(no /open/ entries found in nmap gnmap files)') }
Write-EvidenceLines -Path $Summary -Lines $sumLines -Quiet
$sumLines | ForEach-Object { Write-Host $_ }

Write-Evidence -Path (Join-Path $OutDir 'baseline\end.txt') -Text (Get-Stamp)

# ------------------------------------------------------------------- archive

Write-Head ''
Write-Head '--- Packaging evidence (tamper-evident) ---'
$ArchiveBase = "{0}-{1}-{2}" -f $Client, $SourceSegment, $TS
$FolderName  = Split-Path -Leaf $OutDir
$EvidenceDir = Join-Path $Root 'evidence'
$archivePath = $null
Push-Location -LiteralPath $EvidenceDir
try {
  # tar.exe presence is enforced in preflight, so there is no silent .zip fallback.
  $candidate = Join-Path $EvidenceDir ("{0}.tar.gz" -f $ArchiveBase)
  & tar.exe -czf ("{0}.tar.gz" -f $ArchiveBase) $FolderName
  if ($LASTEXITCODE -ne 0) { throw "tar exited $LASTEXITCODE" }
  if (-not (Test-Path -LiteralPath $candidate)) { throw "tar reported success but $candidate is missing" }
  $archivePath = $candidate
  # sha256sum-compatible line: "<lowercase hash>  <filename>"
  $h = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLower()
  $shaFile = "$archivePath.sha256"
  # LF, no BOM: `sha256sum -c` on Linux rejects a CRLF/BOM checksum file.
  Write-Evidence -Path $shaFile -Text ("{0}  {1}" -f $h, (Split-Path -Leaf $archivePath)) -Quiet
  Write-Head ("Archive: {0}" -f $archivePath)
  Write-Head ("SHA-256: {0}" -f $h)
} catch {
  Write-Warning ("evidence archiving failed ({0}) - the raw folder is still at {1}" -f $_.Exception.Message, $OutDir)
} finally {
  Pop-Location
}

Write-Head ''
Write-Head '============================================================'
Write-Head (" DONE - {0} / {1}" -f $ClientDisplayName, $SourceSegment)
Write-Head (" Evidence: {0}" -f $OutDir)
if ($archivePath) { Write-Head (" Archive:  {0} (+ .sha256)" -f $archivePath) }
Write-Head (" Quick look: Get-Content '{0}'" -f $Summary)
if ($script:StageFailures.Count -gt 0) {
  Write-Head ""
  Write-Head (" *** SCAN INCOMPLETE: {0} nmap stage(s) did not exit cleanly." -f $script:StageFailures.Count)
  Write-Head " *** See the header of open-ports-summary.txt. Do NOT report this as a clean result."
}
Write-Head '============================================================'

}
catch {
  Write-Host ''
  Write-Host ("!!! RUN FAILED: {0}" -f $_.Exception.Message)
  Write-Host ("!!! Partial evidence retained at {0}" -f $OutDir)
  try {
    Write-Evidence -Path (Join-Path $OutDir 'baseline\end.txt') `
      -Text ("{0}  (ABORTED: {1})" -f (Get-Stamp), $_.Exception.Message) -Quiet
  } catch { }
  $script:RunFailed = 1
}
finally {
  Stop-Log
}

if ($script:RunFailed -ne 0) { exit 1 }
