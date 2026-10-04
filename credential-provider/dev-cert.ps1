<#
    PawLocker development code-signing certificate.

    Why this exists
    ---------------
    Windows does not require a credential provider to be Authenticode signed,
    but an *unsigned* DLL loaded into LogonUI is refused by:
      - WDAC / AppLocker / Device Guard policies (any managed machine)
      - Smart App Control (Windows 11 22H2 and later)
      - most EDR products
    Signing is also the only way to notice that the DLL in Program Files was
    swapped: that directory is ACL-protected, but ACLs are not integrity.

    This script maintains a *development* certificate:
      - created in Cert:\CurrentUser\My, private key non-exportable by default
      - self-signed, so it proves nothing to anyone else
      - good enough to make "sign -> verify -> load" work end to end locally

    For a real release, buy a code-signing (EV) certificate or use Azure Trusted
    Signing and pass its thumbprint to "sign.bat cert <thumbprint>". A self-signed
    certificate will never satisfy SmartScreen or a customer's WDAC policy.

    Actions
    -------
      ensure   create the certificate if missing, export the public .cer
      trust    add the .cer to LocalMachine Root + TrustedPublisher (needs admin)
      untrust  remove it from those two stores (needs admin)
      remove   delete the certificate from Cert:\CurrentUser\My

    NOTE: this file is intentionally ASCII-only, like the .bat files next to it.
#>

[CmdletBinding()]
param(
    [ValidateSet('ensure', 'trust', 'untrust', 'remove')]
    [string]$Action = 'ensure',

    # Recreate the certificate with an exportable private key. Only do this if
    # the key has to travel to another machine (a build server, for instance).
    [switch]$Exportable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Must match the code in sign.bat, which reads this file back out of the store.
$Subject = 'CN=PawLocker Development, O=PawLocker'

$BuildDir = Join-Path $PSScriptRoot 'build'
$CerPath = Join-Path $BuildDir 'pawlocker-dev.cer'
$ThumbPath = Join-Path $BuildDir 'devcert.thumbprint'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required. Run "sign.bat trust" and accept the elevation prompt.'
    }
}

function Get-DevCertificate {
    # Reuse the newest usable certificate instead of piling up a new one on
    # every invocation. Expiring within 30 days counts as unusable.
    $cutoff = (Get-Date).AddDays(30)
    Get-ChildItem -Path Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey -and $_.NotAfter -gt $cutoff } |
        Sort-Object -Property NotAfter -Descending |
        Select-Object -First 1
}

function New-DevCertificate {
    $exportPolicy = if ($Exportable) { 'Exportable' } else { 'NonExportable' }
    Write-Host "[*] Creating development certificate ($exportPolicy private key)"

    # New-SelfSignedCertificate -Type CodeSigningCert gives the certificate the
    # Code Signing EKU (1.3.6.1.5.5.7.3.3), which signtool insists on and which
    # distinguishes it from the many other things a self-signed cert could be.
    New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -FriendlyName 'PawLocker development code signing' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy $exportPolicy `
        -NotAfter (Get-Date).AddYears(3)
}

function Export-PublicCertificate {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    if (-not (Test-Path -LiteralPath $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
    }

    # Only the public half ever leaves the store.
    [IO.File]::WriteAllBytes($CerPath, $Certificate.Export('Cert'))
    # No trailing newline: sign.bat reads this with "set /p".
    [IO.File]::WriteAllText($ThumbPath, $Certificate.Thumbprint)

    Write-Host "[+] Public certificate: $CerPath"
    Write-Host "[+] Thumbprint:         $($Certificate.Thumbprint)"
}

function Get-LocalMachineStore {
    param([Parameter(Mandatory)][string]$Name)
    New-Object System.Security.Cryptography.X509Certificates.X509Store($Name, 'LocalMachine')
}

switch ($Action) {

    'ensure' {
        $cert = Get-DevCertificate
        if (-not $cert) {
            $cert = New-DevCertificate
        } else {
            Write-Host "[*] Reusing existing certificate (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"
        }
        Export-PublicCertificate -Certificate $cert
    }

    'trust' {
        Assert-Administrator
        if (-not (Test-Path -LiteralPath $CerPath)) {
            throw "Not found: $CerPath - run 'sign.bat devcert' first."
        }

        # LocalMachine, not CurrentUser: the DLL is loaded by LogonUI, which runs
        # as SYSTEM. SYSTEM has its own profile and cannot see the user's stores,
        # so trusting the certificate only for the current user would look
        # correct from an elevated prompt and still fail on the lock screen.
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CerPath)
        foreach ($name in @('Root', 'TrustedPublisher')) {
            $store = Get-LocalMachineStore -Name $name
            try {
                $store.Open('ReadWrite')
                $store.Add($cert)
                Write-Host "[+] Added to LocalMachine\$name"
            } finally {
                $store.Close()
            }
        }
        Write-Host "[!] This machine now trusts the PawLocker development certificate"
        Write-Host "    for code signing. Run 'sign.bat untrust' to undo it."
    }

    'untrust' {
        Assert-Administrator
        if (-not (Test-Path -LiteralPath $CerPath)) {
            throw "Not found: $CerPath - nothing to remove."
        }

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CerPath)
        foreach ($name in @('Root', 'TrustedPublisher')) {
            $store = Get-LocalMachineStore -Name $name
            try {
                $store.Open('ReadWrite')
                $store.Remove($cert)
                Write-Host "[-] Removed from LocalMachine\$name"
            } finally {
                $store.Close()
            }
        }
    }

    'remove' {
        $removed = 0
        Get-ChildItem -Path Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $Subject } |
            ForEach-Object {
                Remove-Item -LiteralPath $_.PSPath -Force
                $removed++
            }
        Write-Host "[-] Removed $removed certificate(s) from Cert:\CurrentUser\My"
        foreach ($path in @($CerPath, $ThumbPath)) {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        }
    }
}
