<#
.SYNOPSIS
  Wiz container image SARIF enricher — adds security-severity CVSS scores,
  enriched alert titles, and produces a GitHub Job Summary markdown report.

.DESCRIPTION
  Input:  image.sarif — Wiz container image vulnerability SARIF (from wizcli docker scan)
  Output: image.sarif — Enriched in-place with security-severity scores
          wiz-summary.md — GitHub Job Summary markdown

  CVSS thresholds (matching org spec from Prisma parser pattern):
    CRITICAL=9.5  HIGH=8.0  MEDIUM=5.5  LOW=3.0  INFORMATIONAL=0.5  UNKNOWN=0.0
#>
param(
  [string]$ImageSarifPath      = "image.sarif",
  [string]$SummaryMarkdownPath = "wiz-summary.md"
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$esc       = [char]27
$validSevs = [System.Collections.Generic.HashSet[string]]@("CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL")
$script:sevOrd = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3; INFORMATIONAL=4; INFO=4; UNKNOWN=5 }

# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

function Get-Json([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json -Depth 100)
  } catch {
    Write-Host "[WARN] Cannot parse JSON: $Path — $($_.Exception.Message)"
    return $null
  }
}

function Safe-Str($v, [string]$default = "") {
  if ($null -eq $v) { return $default }
  $s = [string]$v
  return [string]::IsNullOrWhiteSpace($s) ? $default : $s.Trim()
}

function Trunc([string]$s, [int]$max) {
  if (-not $s) { return "" }
  return ($s.Length -le $max) ? $s : ($s.Substring(0, [Math]::Max(0, $max - 1)) + [char]0x2026)
}

function Set-Prop($obj, [string]$name, $value) {
  if ($null -eq $obj) { return }
  if ($obj -is [System.Collections.IDictionary]) { $obj[$name] = $value }
  else { $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force }
}

function Get-Prop($obj, [string]$name, $default = $null) {
  if ($null -eq $obj) { return $default }
  if ($obj -is [System.Collections.IDictionary]) { return $obj.Contains($name) ? $obj[$name] : $default }
  $p = $obj.PSObject.Properties[$name]
  return ($null -ne $p) ? $p.Value : $default
}

function Sev-Color([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL" { return "1;37;41" }
    "HIGH"     { return "1;31"    }
    "MEDIUM"   { return "1;33"    }
    "LOW"      { return "1;32"    }
    default    { return "0;37"    }
  }
}

function Sev-GhaLevel([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL" { return "error"   }
    "HIGH"     { return "error"   }
    "MEDIUM"   { return "warning" }
    default    { return "note"    }
  }
}

function Sec-Sev([string]$s) {
  switch ($s.ToUpper()) {
    "CRITICAL"      { return "9.5" }
    "HIGH"          { return "8.0" }
    "MEDIUM"        { return "5.5" }
    "LOW"           { return "3.0" }
    "INFORMATIONAL" { return "0.5" }
    default         { return "0.0" }
  }
}

function Sev-Rank([string]$s) {
  $v = $script:sevOrd[[string]$s]
  return ($null -ne $v) ? [int]$v : 99
}

# ── Parse "Key: value" lines from Wiz SARIF message.text ──────────────────────
function Parse-MsgText([string]$text) {
  $f = [ordered]@{}
  if (-not $text) { return $f }
  foreach ($line in ($text -split "`n")) {
    $line = $line.TrimEnd("`r")
    if ($line -match "^([A-Za-z][A-Za-z0-9 /\-\.]{0,58}):\s*(.*)$") {
      $k = $Matches[1].Trim().ToLower()
      $v = $Matches[2].Trim()
      if (-not $f.Contains($k)) { $f[$k] = $v }
    }
  }
  return $f
}

# ── Resolve severity from multiple SARIF sources ─────────────────────────────
function Resolve-Sev([object]$result, [hashtable]$ruleMap) {
  $msgText = Safe-Str (Get-Prop $result.message "text" "") ""
  $fields  = Parse-MsgText -text $msgText

  # Source 1 — message.text "Severity: X"
  $sev = Safe-Str $fields["severity"] ""
  if ($sev -and $validSevs.Contains($sev.ToUpper())) { return $sev.ToUpper() }

  # Source 2 — result.properties.severity
  $ps = Safe-Str (Get-Prop $result.properties "severity" "") ""
  if ($ps -and $validSevs.Contains($ps.ToUpper())) { return $ps.ToUpper() }

  # Source 3 — rule.properties.severity / security-severity
  $rid  = Safe-Str $result.ruleId ""
  $rule = if ($rid -and $ruleMap.ContainsKey($rid)) { $ruleMap[$rid] } else { $null }
  if ($rule -and $rule.properties) {
    $rs = Safe-Str (Get-Prop $rule.properties "severity" "") ""
    if ($rs -and $validSevs.Contains($rs.ToUpper())) { return $rs.ToUpper() }

    $ss = Safe-Str (Get-Prop $rule.properties "security-severity" "") ""
    if ($ss) {
      $score = [double]0
      if ([double]::TryParse($ss, [System.Globalization.NumberStyles]::Any,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$score)) {
        if     ($score -ge 9.0) { return "CRITICAL" }
        elseif ($score -ge 7.0) { return "HIGH" }
        elseif ($score -ge 4.0) { return "MEDIUM" }
        elseif ($score -gt 0.0) { return "LOW" }
        else                    { return "INFORMATIONAL" }
      }
    }
  }

  # Source 4 — SARIF result.level
  $lvl = Safe-Str $result.level ""
  if (-not $lvl -and $rule -and $rule.defaultConfiguration) {
    $lvl = Safe-Str $rule.defaultConfiguration.level ""
  }
  switch ($lvl.ToLower()) {
    "error"   { return "HIGH" }
    "warning" { return "MEDIUM" }
    "note"    { return "LOW" }
    "none"    { return "INFORMATIONAL" }
  }
  return "UNKNOWN"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SARIF ENRICHMENT — Adds security-severity, tags, [Wiz Cloud] naming
# ═══════════════════════════════════════════════════════════════════════════════
function Enrich-Sarif([object]$sarif) {
  if (-not $sarif -or -not $sarif.runs) { return $sarif }

  foreach ($run in $sarif.runs) {
    $ruleMap = @{}
    $rules = Get-Prop $run.tool.driver "rules" $null
    if ($rules) { foreach ($r in $rules) { if ($r -and $r.id) { $ruleMap[[string]$r.id] = $r } } }

    # Pass 1 — resolve severity per result
    $ruleSevMap = @{}
    $rulePkgMap = @{}
    if ($run.results) {
      foreach ($res in $run.results) {
        if (-not $res) { continue }
        $sev = Resolve-Sev -result $res -ruleMap $ruleMap
        $res | Add-Member -NotePropertyName level -NotePropertyValue (Sev-GhaLevel -s $sev) -Force

        $rid = Safe-Str $res.ruleId ""
        if ($rid) {
          if (-not $ruleSevMap.ContainsKey($rid)) {
            $ruleSevMap[$rid] = $sev
          } elseif ((Sev-Rank $sev) -lt (Sev-Rank $ruleSevMap[$rid])) {
            $ruleSevMap[$rid] = $sev
          }
          if (-not $rulePkgMap.ContainsKey($rid)) {
            $msgText = Safe-Str (Get-Prop $res.message "text" "") ""
            $f = Parse-MsgText -text $msgText
            $pkg = Safe-Str $f["component"] ""
            if (-not $pkg) {
              $pkgRaw = Safe-Str $f["package"] ""
              $pkg = if ($pkgRaw -match "^(.+?)\s*\(") { $Matches[1].Trim() } else { $pkgRaw }
            }
            $ver = Safe-Str $f["version"] ""
            if (-not $ver) { $ver = Safe-Str $f["installed version"] "" }
            if ($pkg) { $rulePkgMap[$rid] = @{ pkg = $pkg; ver = $ver } }
          }
        }
      }
    }

    # Pass 2 — enrich rules
    if ($rules) {
      foreach ($r in $rules) {
        if (-not $r -or -not $r.id) { continue }
        $rid = [string]$r.id
        $sev = if ($ruleSevMap.ContainsKey($rid)) { $ruleSevMap[$rid] } else { "UNKNOWN" }

        if ($null -eq (Get-Prop $r "properties" $null)) {
          $r | Add-Member -NotePropertyName properties -NotePropertyValue ([PSCustomObject]@{}) -Force
        }
        Set-Prop $r.properties "security-severity" (Sec-Sev -s $sev)
        Set-Prop $r.properties "severity" $sev

        $existingTags = @()
        $rawTags = Get-Prop $r.properties "tags" $null
        if ($rawTags) { $existingTags = @($rawTags) }
        if ($existingTags -notcontains "security") { $existingTags += "security" }
        if ($existingTags -notcontains "wiz")      { $existingTags += "wiz" }
        Set-Prop $r.properties "tags" $existingTags

        $rawName  = Safe-Str (Get-Prop $r "name" "") $rid
        $baseName = $rawName -replace "^\[Wiz[^\]]*\]\s*", ""
        $r | Add-Member -NotePropertyName name -NotePropertyValue "[Wiz Cloud] $baseName" -Force

        $pkgInfo   = if ($rulePkgMap.ContainsKey($rid)) { $rulePkgMap[$rid] } else { $null }
        $pkgSuffix = if ($pkgInfo -and $pkgInfo.pkg) {
          $vs = if ($pkgInfo.ver) { " $($pkgInfo.ver)" } else { "" }
          " | $($pkgInfo.pkg)$vs"
        } else { "" }
        $enrichedTitle = "[Wiz Cloud] $baseName$pkgSuffix"

        if ($null -eq $r.shortDescription) {
          $r | Add-Member -NotePropertyName shortDescription -NotePropertyValue ([PSCustomObject]@{ text = $enrichedTitle }) -Force
        } else {
          $r.shortDescription | Add-Member -NotePropertyName text -NotePropertyValue $enrichedTitle -Force
        }
        if ($null -eq $r.fullDescription) {
          $r | Add-Member -NotePropertyName fullDescription -NotePropertyValue ([PSCustomObject]@{ text = $enrichedTitle }) -Force
        }
      }
    }

    # Set tool driver name for GitHub Security tab differentiation
    if ($run.tool -and $run.tool.driver) {
      $run.tool.driver | Add-Member -NotePropertyName name -NotePropertyValue "WizCLI-Container" -Force
    }
  }
  return $sarif
}

# ═══════════════════════════════════════════════════════════════════════════════
# ROW EXTRACTION — Converts SARIF into display rows
# ═══════════════════════════════════════════════════════════════════════════════
function Get-SarifRows([object]$sarif) {
  $rows = [System.Collections.Generic.List[object]]::new()
  if (-not $sarif -or -not $sarif.runs) { return $rows }

  foreach ($run in $sarif.runs) {
    $ruleMap = @{}
    $rules = Get-Prop $run.tool.driver "rules" $null
    if ($rules) { foreach ($r in $rules) { if ($r -and $r.id) { $ruleMap[[string]$r.id] = $r } } }

    if (-not $run.results) { continue }
    foreach ($res in $run.results) {
      if (-not $res) { continue }

      $rid  = Safe-Str $res.ruleId "N/A"
      $sev  = Resolve-Sev -result $res -ruleMap $ruleMap
      $rule = if ($ruleMap.ContainsKey($rid)) { $ruleMap[$rid] } else { $null }

      $msgText = Safe-Str (Get-Prop $res.message "text" "") ""
      $f       = Parse-MsgText -text $msgText

      $component = Safe-Str $f["component"] ""
      if (-not $component) {
        $pkg = Safe-Str $f["package"] ""
        $component = if ($pkg -match "^(.+?)\s*\(") { $Matches[1].Trim() } else { $pkg }
      }
      if (-not $component) { $component = "N/A" }

      $version = Safe-Str $f["version"] ""
      if (-not $version) { $version = Safe-Str $f["installed version"] "" }
      if (-not $version) { $version = "N/A" }

      $fixed = Safe-Str $f["fixed version"] ""
      if (-not $fixed) { $fixed = "N/A" }

      $cveId = Safe-Str $f["cve"] ""
      if (-not $cveId) { $cveId = $rid }

      $desc = Safe-Str $f["description"] ""
      if (-not $desc -and $rule -and $rule.shortDescription -and $rule.shortDescription.text) {
        $desc = ([string]$rule.shortDescription.text) -replace "^\[Wiz[^\]]*\]\s*", ""
      }

      $rows.Add([ordered]@{
        ruleId    = $rid
        cveId     = $cveId
        severity  = $sev
        component = $component
        version   = $version
        fixed     = $fixed
        desc      = $desc
      })
    }
  }
  return ($rows | Sort-Object { Sev-Rank $_.severity })
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "${esc}[1;36m══════════════════════════════════════════════════════${esc}[0m"
Write-Host "${esc}[1;36m  WIZ CONTAINER IMAGE SCAN — SARIF ENRICHMENT${esc}[0m"
Write-Host "${esc}[1;36m══════════════════════════════════════════════════════${esc}[0m"

$imageSarif = Get-Json -Path $ImageSarifPath

if (-not $imageSarif) {
  Write-Host "[WARN] image.sarif not found at: $ImageSarifPath"
  Write-Host "::warning title=Wiz Scan::No SARIF output found — scan may have produced no results"
  exit 0
}

# Enrich SARIF
Write-Host "::group::Enriching image.sarif"
$imageSarif = Enrich-Sarif -sarif $imageSarif
$imageSarif | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $ImageSarifPath -Encoding utf8NoBOM
Write-Host "  ✔ image.sarif enriched and written back."
Write-Host "::endgroup::"

# Extract rows for console output and summary
$rows = @(Get-SarifRows -sarif $imageSarif)

# Console output
Write-Host ""
Write-Host "::group::Container Image Vulnerabilities ($($rows.Count) findings)"
if ($rows.Count -gt 0) {
  $hdr = "  {0,-30} {1,-24} {2,-12} {3,-18} {4,-18} {5}" -f "CVE","COMPONENT","SEVERITY","VERSION","FIXED","DESCRIPTION"
  Write-Host $hdr
  Write-Host ("  " + ("─" * 140))

  foreach ($r in $rows) {
    $col  = Sev-Color -s $r.severity
    $line = "  ${esc}[${col}m{0,-30}${esc}[0m {1,-24} ${esc}[${col}m{2,-12}${esc}[0m {3,-18} {4,-18} {5}" -f `
      (Trunc $r.cveId 30), (Trunc $r.component 24), $r.severity,
      (Trunc $r.version 18), (Trunc $r.fixed 18), (Trunc $r.desc 60)
    Write-Host $line
  }

  # Severity summary
  $cnts = @{}
  foreach ($r in $rows) { $cnts[$r.severity] = ($cnts[$r.severity] -as [int]) + 1 }
  $parts = @("CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL") |
    Where-Object { $cnts[$_] } |
    ForEach-Object { $c = Sev-Color -s $_; "${esc}[${c}m${_}: $($cnts[$_])${esc}[0m" }
  Write-Host ""
  Write-Host "  ┌─ Summary: $($parts -join '  │  ') ─┐"

  # GHA annotations
  foreach ($r in ($rows | Where-Object { $_.severity -in @("CRITICAL","HIGH") } | Select-Object -First 20)) {
    $lvl = Sev-GhaLevel $r.severity
    Write-Host "::${lvl} title=[Wiz] $($r.severity) in $($r.component)::$($r.cveId) — $($r.component) $($r.version) — Fix: $($r.fixed)"
  }
} else {
  Write-Host "  ${esc}[1;32m✔ No vulnerabilities found.${esc}[0m"
}
Write-Host "::endgroup::"

# ── GitHub Job Summary (Markdown) ─────────────────────────────────────────────
function Count-Sev($rows, [string]$sev) {
  if (-not $rows -or @($rows).Count -eq 0) { return 0 }
  return @($rows | Where-Object { $_.severity -eq $sev }).Count
}

$cCrit = Count-Sev $rows "CRITICAL"; $cHigh = Count-Sev $rows "HIGH"
$cMed  = Count-Sev $rows "MEDIUM";   $cLow  = Count-Sev $rows "LOW"

$statusBadge = if ($cCrit -gt 0) { "🔴 CRITICAL issues found" }
               elseif ($cHigh -gt 0) { "🟠 HIGH issues found" }
               else { "🟢 No critical/high issues" }

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Wiz Container Image Scan Report")
$md.Add("")
$md.Add("**Status:** $statusBadge")
$md.Add("")
$md.Add("## Summary")
$md.Add("")
$md.Add("| Metric | Count |")
$md.Add("|---|---:|")
$md.Add("| Total Findings | $($rows.Count) |")
$md.Add("| 🔴 Critical | $cCrit |")
$md.Add("| 🟠 High | $cHigh |")
$md.Add("| 🟡 Medium | $cMed |")
$md.Add("| 🟢 Low | $cLow |")
$md.Add("")

if ($rows.Count -gt 0) {
  $md.Add("## Findings")
  $md.Add("")
  $md.Add("| CVE | Component | Severity | Version | Fixed | Description |")
  $md.Add("|---|---|---|---|---|---|")
  foreach ($r in ($rows | Select-Object -First 200)) {
    $d     = (Trunc $r.desc 120) -replace '\|', '&#124;'
    $badge = switch ($r.severity) { "CRITICAL"{"🔴"} "HIGH"{"🟠"} "MEDIUM"{"🟡"} "LOW"{"🟢"} default{"⚪"} }
    $md.Add("| ``$($r.cveId)`` | $($r.component) | $badge $($r.severity) | $($r.version) | $($r.fixed) | $d |")
  }
  if ($rows.Count -gt 200) {
    $md.Add("")
    $md.Add("_$($rows.Count - 200) additional findings omitted — see uploaded SARIF for full list._")
  }
  $md.Add("")
}

$md.Add("---")
$md.Add("_Scan powered by [Wiz](https://www.wiz.io)_")

$md | Set-Content -LiteralPath $SummaryMarkdownPath -Encoding utf8NoBOM
Write-Host ""
Write-Host "✔ Summary written: $SummaryMarkdownPath ($($md.Count) lines)"

# Final notice
Write-Host ""
Write-Host "::notice title=Wiz Container Scan Complete::$($rows.Count) findings ($cCrit CRIT / $cHigh HIGH / $cMed MED / $cLow LOW)"

exit 0
