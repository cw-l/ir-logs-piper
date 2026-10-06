# Copyright (C) 2026 https://github.com/cw-l
# SPDX-License-Identifier: AGPL-3.0-or-later


#requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# ============================================================
# Configuration
# ============================================================

$FluentBitVersion = "5.1.1"
$ServiceNameDefault = "fluent-bit"   # used only if the MSI did not register a service

# ============================================================
# Paths
# ============================================================

$MsiName = "fluent-bit-$FluentBitVersion-win64.msi"
$DownloadUrl = "https://packages.fluentbit.io/windows/$MsiName"
$MsiPath = Join-Path $env:TEMP $MsiName

$FluentBitExe = "$env:ProgramFiles\fluent-bit\bin\fluent-bit.exe"
$ConfigSource = Join-Path $PSScriptRoot "..\config"

$ConfigDestination = "$env:ProgramData\fluent-bit\conf"
$BufferDirectory = "$env:ProgramData\fluent-bit\buffer"
$DataDirectory = "$env:ProgramData\fluent-bit\data"
$StorageDirectory = "$env:ProgramData\fluent-bit\storage"
$SecretsDirectory = "$env:ProgramData\fluent-bit\secrets"
$CredentialsFile = Join-Path $SecretsDirectory "aws-credentials"
$StagingDirectory = "$env:ProgramData\fluent-bit\conf.staging"
$BackupDirectory = "$env:ProgramData\fluent-bit\conf.bak"
$LogsDirectory = "$env:ProgramData\fluent-bit\logs"
$LogFile = Join-Path $LogsDirectory "fluent-bit.log"
$LogRotationTaskName = "FluentBit-LogRotation"

# ============================================================
# Functions
# ============================================================

function ConvertTo-Version3 {
    # Normalize to Major.Minor.Build so 5.1.1 and 5.1.1.0 compare equal
    param ([Parameter(Mandatory)][string]$Value)

    $V = [version]$Value
    return [version]::new($V.Major, $V.Minor, [Math]::Max($V.Build, 0))
}

function Get-FluentBitInstalledVersion {

    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $Application = Get-ItemProperty $RegistryPaths -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -match 'fluent[\s-]?bit' -and
            $_.DisplayVersion
        } |
        Select-Object -First 1

    if ($Application) {
        return $Application.DisplayVersion
    }

    # Fallback: ask the binary itself (does not depend on MSI registry naming)
    if (Test-Path -LiteralPath $FluentBitExe -PathType Leaf) {
        try {
            $Output = (& $FluentBitExe --version | Out-String)

            if ($Output -match '(\d+\.\d+\.\d+)') {
                return $Matches[1]
            }
        }
        catch {
            Write-Warning "Unable to read version from ${FluentBitExe}: $($_.Exception.Message)"
        }
    }

    return $null
}

function Initialize-Directory {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path) {

        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            throw "Path exists but is not a directory: $Path"
        }

        Write-Host "Exists : $Path"
    }
    else {

        New-Item -Path $Path -ItemType Directory | Out-Null
        Write-Host "Created: $Path"
    }
}

function Set-SecureAcl {
    # Protected ACL (no inheritance): SYSTEM + local Administrators only.
    # Works for directories and files. Idempotent.
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    $IsDirectory = (Get-Item -LiteralPath $Path -Force).PSIsContainer
    $Acl = Get-Acl -LiteralPath $Path

    $Acl.SetAccessRuleProtection($true, $false)

    foreach ($Rule in @($Acl.Access)) {
        [void]$Acl.RemoveAccessRule($Rule)
    }

    $Inherit = if ($IsDirectory) { "ContainerInherit,ObjectInherit" } else { "None" }

    foreach ($WellKnown in @(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid,
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid
    )) {
        $Sid = New-Object System.Security.Principal.SecurityIdentifier($WellKnown, $null)
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Sid, "FullControl", $Inherit, "None", "Allow"
        )
        $Acl.AddAccessRule($Rule)
    }

    Set-Acl -LiteralPath $Path -AclObject $Acl
}

function Assert-SecureAcl {
    # Abort if anything other than SYSTEM / Administrators has access.
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    $AllowedSids = @("S-1-5-18", "S-1-5-32-544")
    $Acl = Get-Acl -LiteralPath $Path

    if (-not $Acl.AreAccessRulesProtected) {
        throw "Inheritance still enabled on: $Path"
    }

    foreach ($Rule in $Acl.Access) {
        $Sid = $Rule.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value

        if ($Sid -notin $AllowedSids) {
            throw "Unexpected ACE on ${Path}: $($Rule.IdentityReference)"
        }
    }
}

function Test-R2CredentialsFile {
    # True only if the file exists and holds a [default] profile with both values non-empty
    if (-not (Test-Path -LiteralPath $CredentialsFile -PathType Leaf)) {
        return $false
    }

    $Text = Get-Content -LiteralPath $CredentialsFile -Raw -ErrorAction SilentlyContinue

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return (
        $Text -match '(?m)^\[default\]\s*$' -and
        $Text -match '(?m)^\s*aws_access_key_id\s*=\s*\S+' -and
        $Text -match '(?m)^\s*aws_secret_access_key\s*=\s*\S+'
    )
}

function ConvertFrom-SecureInput {
    param (
        [Parameter(Mandatory)]
        [System.Security.SecureString]$Secure
    )

    $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

function New-R2CredentialsFile {
    # Prompts and writes/overwrites the credentials file. Secrets dir must already be locked.

    Write-Host ""
    Write-Host "Cloudflare R2 credentials are required."
    Write-Host ""

    $AccessKey = (ConvertFrom-SecureInput (Read-Host "R2 Access Key ID" -AsSecureString)).Trim()

    if ([string]::IsNullOrWhiteSpace($AccessKey)) {
        throw "R2 Access Key ID cannot be empty."
    }

    $SecretSecure = Read-Host "R2 Secret Access Key" -AsSecureString

    $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretSecure)
    try {
        $SecretKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }

    $SecretKey = $SecretKey.Trim()

    if ([string]::IsNullOrWhiteSpace($SecretKey)) {
        throw "R2 Secret Access Key cannot be empty."
    }

    # Temp file lives INSIDE the locked secrets dir: never exists with open permissions
    $TempFile = Join-Path $SecretsDirectory "aws-credentials.tmp"

    try {
        $CredentialsContent = "[default]`r`naws_access_key_id = $AccessKey`r`naws_secret_access_key = $SecretKey`r`n"

        Set-Content `
            -LiteralPath $TempFile `
            -Value $CredentialsContent `
            -Encoding ascii `
            -NoNewline `
            -Force

        # Atomic swap: no half-written credentials file after a crash
        Move-Item -LiteralPath $TempFile -Destination $CredentialsFile -Force

        Set-SecureAcl    $CredentialsFile
        Assert-SecureAcl $CredentialsFile

        Write-Host "Created and secured: $CredentialsFile"
    }
    finally {
        if (Test-Path -LiteralPath $TempFile) {
            Remove-Item -LiteralPath $TempFile -Force -ErrorAction SilentlyContinue
        }
        $SecretKey = $null
        $CredentialsContent = $null
    }
}

function Get-FluentBitServices {
    # Any service whose binary is fluent-bit.exe, regardless of its name
    return @(
        Get-CimInstance Win32_Service |
            Where-Object { $_.PathName -match 'fluent-bit\.exe' }
    )
}

function Disable-FluentBitServices {
    foreach ($S in (Get-FluentBitServices)) {

        Write-Host "Stopping and disabling service '$($S.Name)' until configuration is complete..."

        if ($S.State -ne "Stopped") {
            Stop-Service -Name $S.Name -Force
        }

        Set-Service -Name $S.Name -StartupType Disabled
    }
}

function Resolve-FluentBitService {
    # Adopt the MSI-registered service, or create one if the MSI did not. Returns the service name.

    $Found = @(Get-FluentBitServices)

    if ($Found.Count -gt 1) {
        $Names = ($Found | ForEach-Object { $_.Name }) -join ", "
        throw "Multiple Fluent Bit services found: $Names. Resolve manually."
    }

    if ($Found.Count -eq 1) {
        Write-Host "Adopting existing service: $($Found[0].Name)"
        return $Found[0].Name
    }

    Write-Host "No Fluent Bit service found. Creating '$ServiceNameDefault'..."

    New-Service `
        -Name $ServiceNameDefault `
        -DisplayName "Fluent Bit" `
        -Description "Fluent Bit log processor for IR Logs Piper" `
        -BinaryPathName "`"$FluentBitExe`" -c `"$ConfigDestination\fluent-bit.yaml`"" `
        -StartupType Disabled | Out-Null

    return $ServiceNameDefault
}

function Set-FluentBitServiceConfig {
    # Force a known end state regardless of what the MSI did
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    $Key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"

    if (-not (Test-Path -LiteralPath $Key)) {
        throw "Service registry key not found: $Key"
    }

    # Binary path (written directly: avoids sc.exe quoting problems)
    $ExpectedImagePath = "`"$FluentBitExe`" -c `"$ConfigDestination\fluent-bit.yaml`""

    Set-ItemProperty -Path $Key -Name ImagePath -Value $ExpectedImagePath

    if ((Get-ItemProperty -Path $Key).ImagePath -ne $ExpectedImagePath) {
        throw "Service ImagePath verification failed for '$Name'."
    }

    # Account
    Set-ItemProperty -Path $Key -Name ObjectName -Value "LocalSystem"

    # Credentials environment: merge, do not clobber. Drop static AWS_* key vars
    # (environment variables take precedence over the credentials file).
    $Existing = @()
    $Prop = Get-ItemProperty -Path $Key -Name Environment -ErrorAction SilentlyContinue
    if ($Prop -and $Prop.Environment) {
        $Existing = @($Prop.Environment)
    }

    $Drop = '^(AWS_SHARED_CREDENTIALS_FILE|AWS_PROFILE|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)='
    $Kept = @($Existing | Where-Object { $_ -notmatch $Drop })

    $NewEnvironment = $Kept + @(
        "AWS_SHARED_CREDENTIALS_FILE=$CredentialsFile",
        "AWS_PROFILE=default"
    )

    New-ItemProperty `
        -Path $Key `
        -Name Environment `
        -PropertyType MultiString `
        -Value $NewEnvironment `
        -Force | Out-Null

    # Start type
    Set-Service -Name $Name -StartupType Automatic

    # Recovery: restart on failure (3x, 60s apart), reset counter after 24h
    & sc.exe failure $Name reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set service recovery actions for '$Name'."
    }

    & sc.exe failureflag $Name 1 | Out-Null

    Write-Host "Service '$Name' configured: path, LocalSystem, Automatic, recovery, credentials environment."
}

function Test-FluentBitConfig {
    # Validate a config with Fluent Bit's own parser. Does not touch the live config.
    param (
        [Parameter(Mandatory)]
        [string]$ConfigPath
    )

    # Windows PowerShell 5.1 turns native stderr into terminating errors under
    # $ErrorActionPreference = "Stop"; relax it for this one call.
    $Previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    try {
        $Output = & $FluentBitExe -c $ConfigPath --dry-run 2>&1 | ForEach-Object { "$_" }
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $Previous
    }

    if ($ExitCode -ne 0) {
        Write-Host ($Output -join "`n")
        throw "Fluent Bit configuration dry-run failed (exit code $ExitCode). Live configuration was not modified."
    }

    Write-Host "Configuration dry-run passed."
}

function Restore-FluentBitConfig {
    foreach ($File in $RequiredConfigFiles) {
        Copy-Item `
            -LiteralPath (Join-Path $BackupDirectory $File) `
            -Destination (Join-Path $ConfigDestination $File) `
            -Force
    }

    Write-Host "Previous configuration restored from: $BackupDirectory"
}

function Start-FluentBitServiceChecked {
    # Start/restart, wait, and report whether the service is actually running.
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        $S = Get-Service -Name $Name -ErrorAction Stop

        if ($S.Status -eq "Running") {
            Write-Host "Restarting Fluent Bit service..."
            Restart-Service -Name $Name -Force
        }
        else {
            Write-Host "Starting Fluent Bit service..."
            Start-Service -Name $Name
        }
    }
    catch {
        Write-Warning "Service start failed: $($_.Exception.Message)"
        return $false
    }

    # Recheck after a short delay to catch early crashes
    Start-Sleep -Seconds 15

    return ((Get-Service -Name $Name -ErrorAction Stop).Status -eq "Running")
}

function Register-LogRotationTask {
    # Weekly SYSTEM task: if the engine log exceeds 10 MB, stop the service, keep one
    # previous copy (.1), start the service. Fluent Bit does not rotate log_file itself,
    # and an open log file cannot be renamed on Windows, hence the brief stop.
    # Event positions are tracked in the db files, so no events are lost.
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    $ScriptPath = Join-Path $FluentBitRoot "rotate-logs.ps1"

    $Template = @'
$ErrorActionPreference = "Stop"
$Service  = "__SERVICE__"
$Log      = "__LOG__"
$MaxBytes = 10MB

if (-not (Test-Path -LiteralPath $Log)) { exit 0 }
if ((Get-Item -LiteralPath $Log).Length -lt $MaxBytes) { exit 0 }

Stop-Service -Name $Service -Force
try {
    Move-Item -LiteralPath $Log -Destination "$Log.1" -Force
}
finally {
    Start-Service -Name $Service
}
'@

    $Content = $Template.Replace("__SERVICE__", $Name).Replace("__LOG__", $LogFile)

    Set-Content -LiteralPath $ScriptPath -Value $Content -Encoding ascii -Force
    Set-SecureAcl    $ScriptPath
    Assert-SecureAcl $ScriptPath

    $Action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

    $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3:00AM

    $Principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    # StartWhenAvailable: laptops that were asleep/off at 03:00 run it when they wake
    $Settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

    Register-ScheduledTask `
        -TaskName $LogRotationTaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Principal $Principal `
        -Settings $Settings `
        -Force | Out-Null

    Write-Host "Log rotation task registered: $LogRotationTaskName"
}

# ============================================================
# Start
# ============================================================

Write-Host ""
Write-Host "=========================================="
Write-Host "IR Logs Piper - Fluent Bit Installer"
Write-Host "=========================================="
Write-Host ""

# ============================================================
# 1. Validate repository configuration
# ============================================================

if (-not (Test-Path -LiteralPath $ConfigSource -PathType Container)) {
    throw "Configuration directory not found: $ConfigSource"
}

$RequiredConfigFiles = @(
    "fluent-bit.yaml",
    "inputs.yaml",
    "filters.yaml",
    "outputs.yaml"
)

foreach ($File in $RequiredConfigFiles) {

    $Path = Join-Path $ConfigSource $File

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required configuration file not found: $Path"
    }
}

Write-Host "Configuration files validated."

# ============================================================
# 2. Detect installed Fluent Bit
# ============================================================

$InstalledVersion = Get-FluentBitInstalledVersion
$InstallRequired = $false

if ($InstalledVersion) {

    Write-Host "Installed version: $InstalledVersion"
    Write-Host "Required version : $FluentBitVersion"

    try {
        $Comparison = (ConvertTo-Version3 $InstalledVersion).CompareTo(
            (ConvertTo-Version3 $FluentBitVersion)
        )
    }
    catch {
        throw "Unable to compare installed version '$InstalledVersion' with '$FluentBitVersion'."
    }

    if ($Comparison -eq 0) {

        Write-Host "Required version is already installed."

    }
    elseif ($Comparison -gt 0) {

        Write-Warning "Installed version ($InstalledVersion) is newer than requested version ($FluentBitVersion)."
        Write-Warning "No downgrade will be performed."

    }
    else {

        Write-Host "Installed version is older. Upgrade required."
        $InstallRequired = $true
    }

}
else {

    Write-Host "Fluent Bit is not installed. Fresh installation required."
    $InstallRequired = $true
}

# ============================================================
# 3. ProgramData directories + locked secrets directory
# ============================================================

Write-Host ""
Write-Host "Checking Fluent Bit directories..."

$FluentBitRoot = "$env:ProgramData\fluent-bit"

Initialize-Directory $FluentBitRoot

# Lock the root FIRST: everything created below inherits SYSTEM + Administrators only.
Set-SecureAcl $FluentBitRoot

Initialize-Directory $ConfigDestination
Initialize-Directory $BufferDirectory
Initialize-Directory $DataDirectory
Initialize-Directory $StorageDirectory
Initialize-Directory $SecretsDirectory
Initialize-Directory $LogsDirectory

# Enforce and verify on every directory, every run (also repairs pre-existing dirs).
# Buffer/storage/data hold raw event data; conf is read by a SYSTEM service.
foreach ($Dir in @(
    $FluentBitRoot,
    $ConfigDestination,
    $BufferDirectory,
    $DataDirectory,
    $StorageDirectory,
    $SecretsDirectory,
    $LogsDirectory
)) {
    Set-SecureAcl    $Dir
    Assert-SecureAcl $Dir
}

# ============================================================
# 4. R2 credentials gate (hard stop: nothing else runs without valid creds)
# ============================================================

Write-Host ""

if (Test-R2CredentialsFile) {

    # Existing file is valid: keep the keys, re-enforce the ACL
    Set-SecureAcl    $CredentialsFile
    Assert-SecureAcl $CredentialsFile
    Write-Host "Existing R2 credentials preserved; ACL re-enforced."

}
else {

    if (Test-Path -LiteralPath $CredentialsFile) {
        Write-Warning "Credentials file exists but is invalid or incomplete. Re-creating."
    }
    else {
        Write-Host "No R2 credentials file found."
    }

    New-R2CredentialsFile

    if (-not (Test-R2CredentialsFile)) {
        throw "Credentials file validation failed after creation: $CredentialsFile"
    }
}

# ============================================================
# 5. Install / Upgrade MSI
# ============================================================

if ($InstallRequired) {

    Write-Host ""
    Write-Host "Downloading Fluent Bit $FluentBitVersion..."
    Write-Host "URL: $DownloadUrl"

    if (Test-Path -LiteralPath $MsiPath) {
        Remove-Item -LiteralPath $MsiPath -Force
    }

    Invoke-WebRequest `
        -Uri $DownloadUrl `
        -OutFile $MsiPath

    if (-not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
        throw "MSI download failed: $MsiPath"
    }

    Write-Host "Installing Fluent Bit..."

    $Process = Start-Process `
        -FilePath "msiexec.exe" `
        -ArgumentList "/i `"$MsiPath`" /qn /norestart" `
        -Wait `
        -PassThru

    if ($Process.ExitCode -notin @(0, 3010)) {
        throw "Fluent Bit MSI installation failed. Exit code: $($Process.ExitCode)"
    }

    Remove-Item `
        -LiteralPath $MsiPath `
        -Force `
        -ErrorAction SilentlyContinue

    # The MSI may have registered and started a service on its default config:
    # stop and disable it immediately. Any later failure leaves it disabled.
    Disable-FluentBitServices

    $InstalledVersion = Get-FluentBitInstalledVersion

    if (-not $InstalledVersion) {
        throw "Fluent Bit installation completed but installed version could not be detected."
    }

    if ((ConvertTo-Version3 $InstalledVersion) -ne (ConvertTo-Version3 $FluentBitVersion)) {
        throw "Expected Fluent Bit $FluentBitVersion but detected $InstalledVersion."
    }

    Write-Host "Fluent Bit $InstalledVersion installed successfully."
}

if (-not (Test-Path -LiteralPath $FluentBitExe -PathType Leaf)) {
    throw "Fluent Bit executable not found: $FluentBitExe"
}

# ============================================================
# 6. Stage, validate (dry-run), back up, deploy configuration
# ============================================================

Write-Host ""
Write-Host "Staging and validating Fluent Bit configuration..."

if (Test-Path -LiteralPath $StagingDirectory) {
    Remove-Item -LiteralPath $StagingDirectory -Recurse -Force
}

Initialize-Directory $StagingDirectory   # inherits the locked root ACL

try {
    foreach ($File in $RequiredConfigFiles) {
        Copy-Item `
            -LiteralPath (Join-Path $ConfigSource $File) `
            -Destination (Join-Path $StagingDirectory $File) `
            -Force
    }

    # Abort here if the config is invalid: live config and service are untouched
    Test-FluentBitConfig -ConfigPath (Join-Path $StagingDirectory "fluent-bit.yaml")

    # Back up the current live config (only if a complete set exists)
    $HaveBackup = $true
    foreach ($File in $RequiredConfigFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $ConfigDestination $File) -PathType Leaf)) {
            $HaveBackup = $false
        }
    }

    if ($HaveBackup) {
        Initialize-Directory $BackupDirectory

        foreach ($File in $RequiredConfigFiles) {
            Copy-Item `
                -LiteralPath (Join-Path $ConfigDestination $File) `
                -Destination (Join-Path $BackupDirectory $File) `
                -Force
        }

        Write-Host "Previous configuration backed up to: $BackupDirectory"
    }
    else {
        Write-Host "No previous complete configuration found; nothing to back up."
    }

    # Deploy the exact files that passed validation
    Write-Host "Deploying Fluent Bit configuration..."

    foreach ($File in $RequiredConfigFiles) {
        Copy-Item `
            -LiteralPath (Join-Path $StagingDirectory $File) `
            -Destination (Join-Path $ConfigDestination $File) `
            -Force

        Write-Host "Copied: $File"
    }
}
finally {
    if (Test-Path -LiteralPath $StagingDirectory) {
        Remove-Item -LiteralPath $StagingDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================
# 7. Service: adopt or create, enforce known state
# ============================================================

Write-Host ""
Write-Host "Configuring Fluent Bit Windows service..."

$ServiceName = Resolve-FluentBitService
Set-FluentBitServiceConfig -Name $ServiceName
Register-LogRotationTask   -Name $ServiceName

# ============================================================
# 8. Start / restart, verify, roll back on failure
# ============================================================

if (-not (Start-FluentBitServiceChecked -Name $ServiceName)) {

    if ($HaveBackup) {

        Write-Warning "Service is not running with the new configuration. Rolling back..."

        Restore-FluentBitConfig

        if (Start-FluentBitServiceChecked -Name $ServiceName) {
            throw "New configuration failed at runtime. Rolled back to the previous configuration; service is running. Fix the configuration and re-run."
        }

        throw "Service failed with the new AND the previous configuration. Manual intervention required."
    }

    throw "Service '$ServiceName' is not running and there is no previous configuration to roll back to."
}

$Service = Get-Service -Name $ServiceName -ErrorAction Stop

Write-Host ""
Write-Host "=========================================="
Write-Host "Installation completed successfully."
Write-Host "=========================================="
Write-Host "Fluent Bit version: $InstalledVersion"
Write-Host "Service           : $ServiceName ($($Service.Status))"
Write-Host "Configuration     : $ConfigDestination"
Write-Host "Credentials       : $CredentialsFile"
Write-Host "=========================================="