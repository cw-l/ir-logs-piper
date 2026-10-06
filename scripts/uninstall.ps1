# Copyright (C) 2026 https://github.com/cw-l
# SPDX-License-Identifier: AGPL-3.0-or-later


#requires -RunAsAdministrator

<#
.SYNOPSIS
    Removes the IR Logs Piper Fluent Bit deployment from this endpoint.

.DESCRIPTION
    1. Removes the "FluentBit-LogRotation" scheduled task
    2. Stops and deletes the Fluent Bit Windows service (found by its binary,
       fluent-bit.exe, not by name)
    3. Uninstalls the Fluent Bit program (MSI)
    4. Permanently deletes %ProgramData%\fluent-bit (config, buffer, storage,
       data, secrets) - unsent logs in the buffer are LOST.

    Does NOT touch logs already in R2 and does NOT revoke the R2 token.
    Safe to re-run: every step is skipped if already done.

.PARAMETER Force
    Skip the confirmation prompt (for unattended / remote use).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -Force
#>

[CmdletBinding()]
param (
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# ============================================================
# Paths
# ============================================================

if ([string]::IsNullOrWhiteSpace($env:ProgramData)) {
    throw "ProgramData environment variable is not set. Aborting."
}

$DataRoot = Join-Path $env:ProgramData "fluent-bit"
$InstallDir = Join-Path $env:ProgramFiles "fluent-bit"
$LogRotationTaskName = "FluentBit-LogRotation"

# ============================================================
# Functions
# ============================================================

function Get-FluentBitServices {
    # Any service whose binary is fluent-bit.exe, regardless of its name
    # (same rule as install.ps1)
    @(Get-CimInstance Win32_Service |
        Where-Object { $_.PathName -match 'fluent-bit\.exe' })
}

function Get-FluentBitUninstallEntries {

    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    # The MSI may register as "fluent-bit" or "Fluent Bit" - match both.
    @(Get-ItemProperty $RegistryPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match '^fluent[ -]?bit' })
}

function Get-DirectoryStats {
    param ([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [pscustomobject]@{ Files = 0; MB = 0 }
    }

    $Stats = Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum

    [pscustomobject]@{
        Files = $Stats.Count
        MB    = [math]::Round(($Stats.Sum / 1MB), 1)
    }
}

# ============================================================
# Start
# ============================================================

Write-Host ""
Write-Host "=========================================="
Write-Host "IR Logs Piper - Fluent Bit Uninstaller"
Write-Host "=========================================="
Write-Host ""

$Services = Get-FluentBitServices
$RotationTask = Get-ScheduledTask -TaskName $LogRotationTaskName -ErrorAction SilentlyContinue
$Entries = Get-FluentBitUninstallEntries
$Pending = Get-DirectoryStats (Join-Path $DataRoot "buffer")

Write-Host "Service   : $(if ($Services) { ($Services | ForEach-Object { "$($_.Name) ($($_.State))" }) -join ', ' } else { 'not present' })"
Write-Host "Rotation  : $(if ($RotationTask) { "$LogRotationTaskName (scheduled task)" } else { 'not present' })"
Write-Host "Program   : $(if ($Entries) { ($Entries | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" }) -join ', ' } else { 'not installed' })"
Write-Host "Data dir  : $(if (Test-Path -LiteralPath $DataRoot) { $DataRoot } else { 'not present' })"
Write-Host "Unsent    : $($Pending.Files) buffered file(s), $($Pending.MB) MB (will be LOST)"
Write-Host ""

# ============================================================
# Safety checks
# ============================================================

if (Test-Path -LiteralPath $DataRoot) {

    $Item = Get-Item -LiteralPath $DataRoot -Force

    if (-not $Item.PSIsContainer) {
        throw "Not a directory: $DataRoot"
    }

    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing to delete: $DataRoot is a junction/symlink."
    }
}

if (-not $Services -and -not $RotationTask -and -not $Entries -and -not (Test-Path -LiteralPath $DataRoot)) {
    Write-Host "Nothing to remove."
    return
}

# ============================================================
# Confirmation
# ============================================================

if (-not $Force) {

    Write-Warning "This permanently deletes $DataRoot, including credentials and unsent logs."
    Write-Warning "Logs already in R2 are not affected."

    $Answer = Read-Host "Type DELETE to continue"

    if ($Answer -cne "DELETE") {
        Write-Host "Cancelled. Nothing was changed."
        exit 1
    }
}

# ============================================================
# 1. Remove the log rotation task
# ============================================================
# Done before the service: the rotation script runs Start-Service in a
# finally block, so a task firing mid-uninstall would restart the service.

Write-Host ""
Write-Host "[1/4] Removing log rotation task..."

if ($RotationTask) {

    # Stop it first if it is mid-run
    Stop-ScheduledTask -TaskName $LogRotationTaskName -ErrorAction SilentlyContinue

    Unregister-ScheduledTask -TaskName $LogRotationTaskName -Confirm:$false -ErrorAction Stop

    if (Get-ScheduledTask -TaskName $LogRotationTaskName -ErrorAction SilentlyContinue) {
        throw "Scheduled task '$LogRotationTaskName' still present after removal."
    }

    Write-Host "Task removed."
}
else {
    Write-Host "Task not present. Skipped."
}

# ============================================================
# 2. Stop and remove the service(s)
# ============================================================

Write-Host ""
Write-Host "[2/4] Removing Windows service..."

if ($Services) {

    foreach ($S in $Services) {

        $Name = $S.Name
        Write-Host "Removing service '$Name'..."

        if ($S.State -ne "Stopped") {

            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue

            try {
                (Get-Service -Name $Name).WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
            }
            catch {
                Write-Warning "Service '$Name' did not stop within 30s. Terminating process."
            }
        }

        # Ensure no stray process keeps files locked
        Get-Process -Name "fluent-bit" -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue

        & sc.exe delete $Name | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe delete failed for '$Name' with exit code $LASTEXITCODE."
        }

        $Deadline = (Get-Date).AddSeconds(15)

        while ((Get-Service -Name $Name -ErrorAction SilentlyContinue) -and
               (Get-Date) -lt $Deadline) {
            Start-Sleep -Milliseconds 500
        }

        if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
            Write-Warning "Service '$Name' is marked for deletion and will disappear after a reboot."
        }
        else {
            Write-Host "Service '$Name' removed."
        }
    }
}
else {
    Write-Host "Service not present. Skipped."

    Get-Process -Name "fluent-bit" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

# ============================================================
# 3. Uninstall the program
# ============================================================

Write-Host ""
Write-Host "[3/4] Uninstalling Fluent Bit program..."

$RebootRequired = $false

if ($Entries) {

    foreach ($Entry in $Entries) {

        $ProductCode = $Entry.PSChildName

        if ($ProductCode -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') {
            throw "Cannot uninstall '$($Entry.DisplayName)' automatically (not an MSI product code: $ProductCode)."
        }

        Write-Host "Uninstalling $($Entry.DisplayName) $($Entry.DisplayVersion) $ProductCode"

        $Process = Start-Process `
            -FilePath "msiexec.exe" `
            -ArgumentList "/x $ProductCode /qn /norestart" `
            -Wait `
            -PassThru

        # 0 = ok, 3010 = ok/reboot needed, 1605/1614 = already removed
        if ($Process.ExitCode -notin @(0, 3010, 1605, 1614)) {
            throw "MSI uninstall failed. Exit code: $($Process.ExitCode)"
        }

        if ($Process.ExitCode -eq 3010) {
            $RebootRequired = $true
        }
    }

    if (Get-FluentBitUninstallEntries) {
        throw "Fluent Bit still registered after uninstall."
    }

    Write-Host "Program uninstalled."
}
else {
    Write-Host "Program not installed. Skipped."
}

if (Test-Path -LiteralPath $InstallDir) {
    Write-Warning "Leftover directory remains: $InstallDir (review and remove manually)."
}

# ============================================================
# 4. Delete ProgramData\fluent-bit
# ============================================================

Write-Host ""
Write-Host "[4/4] Deleting $DataRoot ..."

if (Test-Path -LiteralPath $DataRoot) {

    $Attempts = 5

    for ($i = 1; $i -le $Attempts; $i++) {

        try {
            Remove-Item -LiteralPath $DataRoot -Recurse -Force -ErrorAction Stop
            break
        }
        catch {
            if ($i -eq $Attempts) {
                throw "Failed to delete $DataRoot after $Attempts attempts: $($_.Exception.Message)"
            }

            Write-Host "Retry $i/$Attempts (files may be locked by AV/indexer)..."
            Start-Sleep -Seconds 3
        }
    }

    if (Test-Path -LiteralPath $DataRoot) {
        throw "$DataRoot still exists after deletion."
    }

    Write-Host "Deleted."
}
else {
    Write-Host "Directory not present. Skipped."
}

# ============================================================
# Summary
# ============================================================

Write-Host ""
Write-Host "=========================================="
Write-Host "Uninstall completed."
Write-Host "=========================================="
Write-Host "Logs already in R2 were NOT deleted."
Write-Host "Reminder: revoke this endpoint's R2 API token in Cloudflare."

if ($RebootRequired) {
    Write-Warning "A reboot is required to finish the uninstall."
}