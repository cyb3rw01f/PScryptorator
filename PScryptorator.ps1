<#
.SYNOPSIS
This is a Proof of Concept reaserch project only. This file is for testing purposes onlt. Malicious use of this script is prohibitted.
Scans a test directory for files and copies them to a crypt folder. The files are then Encrypted using AES-GCM.

.DESCRIPTION
Encrypts files using AES-GCM, decrypts .crypt files, or runs a round-trip test.
AES-GCM authenticates ciphertext, so a flipped bit fails decrypt instead of producing garbage.
By default this script only reads the testdata folder next to the script, not the user profile.
Use -SourcePath to scan a different folder.

.PARAMETER SourcePath
Folder to scan for .doc, .docx, .xls, .xlsx, .pdf, and .jpg files.
Defaults to testdata next to this script.
To scan the user profile, pass -SourcePath $env:USERPROFILE. Do not use $env:HOMEPATH; it has no drive letter.

.PARAMETER CryptPath
Folder that receives copies and encrypted output.
Defaults to crypt next to this script.
Copies keep their relative path under this folder, so two files with the same name in different source folders do not overwrite each other.

.PARAMETER KeyPath
File that stores the Base64 AES key. Created on first run and reused after that.
Defaults to aes.key next to this script. Keep this file; encrypted files cannot be recovered without it.

.PARAMETER DestinationPath
Folder that receives decrypted files. Defaults to CryptPath.

.PARAMETER Decrypt
Decrypt .crypt files from CryptPath instead of encrypting.

.PARAMETER Test
Encrypt testdata copies in a temp folder, decrypt them, and compare hashes to the originals.

.NOTES
AES-GCM via Windows CNG (BCrypt). Older CBC .crypt files are not compatible; re-encrypt them.

Author of PScryptor script @cyberw01f

#>
param(
    [Parameter(Mandatory = $false)]
    [string]$SourcePath,

    [Parameter(Mandatory = $false)]
    [string]$CryptPath,

    [Parameter(Mandatory = $false)]
    [string]$KeyPath,

    [Parameter(Mandatory = $false)]
    [string]$DestinationPath,

    [switch]$Decrypt,

    [switch]$Test
)

$logo = @"
	=================================================================
			   _                         ___  _  __ 
		 ___ _   _| |__   ___ _ ____      __/ _ \/ |/ _|
		/ __| | | | '_ \ / _ \ '__\ \ /\ / / | | | | |_ 
	       | (__| |_| | |_) |  __/ |   \ V  V /| |_| | |  _|
		\___|\__, |_.__/ \___|_|    \_/\_/  \___/|_|_|  
		      |___/                                      
		
	==================================================================
	        *     *    *     /\__/\  *    ---    *
                   *            /      \    /     \    
                        *   *  |  -  -  |  |       |*   
                 *   __________| \     /|  |       |    
                   /              \ T / |   \     /    
                 /                      |  *  ---
                |  ||     |    |       /             *
                |  ||    /______\     / |*     *
                |  | \  |  /     \   /  |
                 \/   | |\ \      | | \ \
                      | | \ \     | |  \ \
                      | |  \ \    | |   \ \
                      '''   '''   '''    '''									   
			     @cyberw01f
"@

$label = @"  
                   PowerShell File Encryption Script  
                    Responsible use only permited
"@

function Create-AESKey() {

    Param(
       [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
       [Int]$KeySize=256
    )

    if ($KeySize -notin 128, 192, 256) {
        throw "KeySize must be 128, 192, or 256."
    }

    $keyBytes = New-Object byte[] ($KeySize / 8)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($keyBytes)
    }
    finally {
        $rng.Dispose()
    }

    return [System.Convert]::ToBase64String($keyBytes)
}

function Read-AESKeyFromFile {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $raw = (Get-Content -LiteralPath $Path -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Key file '$Path' is empty."
    }

    $keyBytes = [System.Convert]::FromBase64String($raw)
    if ($keyBytes.Length -notin 16, 24, 32) {
        throw "Key file '$Path' is not a 128, 192, or 256-bit AES key."
    }

    return $raw
}

function Write-AESKeyToFile {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $directory = Split-Path -Parent $Path
    if ($directory) {
        New-RequiredDirectory -Path $directory | Out-Null
    }

    Set-Content -LiteralPath $Path -Value $Key -Encoding ASCII
}

function Get-MatchingSourceFiles {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $extensions = @('.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg')
    return @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() })
}

function Resolve-AesKey {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$CreateIfMissing
    )

    if (Test-Path -LiteralPath $Path) {
        return [PSCustomObject]@{
            Key    = Read-AESKeyFromFile -Path $Path
            Status = 'reused'
        }
    }

    if (-not $CreateIfMissing) {
        throw "Key file '$Path' was not found."
    }

    $key = Create-AESKey
    Write-AESKeyToFile -Key $key -Path $Path
    return [PSCustomObject]@{
        Key    = $key
        Status = 'created'
    }
}

function Initialize-AesGcmCrypto {
    if ('PScryptorator.AesGcmCrypto' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PScryptorator
{
    public static class AesGcmCrypto
    {
        public const int NonceSize = 12;
        public const int TagSize = 16;

        public static void Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag)
        {
            Transform(key, nonce, plaintext, ciphertext, tag, true);
        }

        public static void Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext)
        {
            Transform(key, nonce, ciphertext, plaintext, tag, false);
        }

        private static void Transform(byte[] key, byte[] nonce, byte[] input, byte[] output, byte[] tag, bool encrypt)
        {
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
            {
                throw new ArgumentException("Key must be 16, 24, or 32 bytes.");
            }
            if (nonce == null || nonce.Length != NonceSize)
            {
                throw new ArgumentException("Nonce must be 12 bytes.");
            }
            if (tag == null || tag.Length != TagSize)
            {
                throw new ArgumentException("Tag must be 16 bytes.");
            }
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }
            if (output == null || output.Length != input.Length)
            {
                throw new ArgumentException("Output must be the same length as input.");
            }

            IntPtr hAlg = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            GCHandle nonceHandle = default(GCHandle);
            GCHandle tagHandle = default(GCHandle);

            try
            {
                int status = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
                Check(status, "BCryptOpenAlgorithmProvider");

                byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                status = BCryptSetProperty(hAlg, "ChainingMode", mode, mode.Length, 0);
                Check(status, "BCryptSetProperty");

                status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
                Check(status, "BCryptGenerateSymmetricKey");

                nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                info.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                info.dwInfoVersion = 1;
                info.pbNonce = nonceHandle.AddrOfPinnedObject();
                info.cbNonce = nonce.Length;
                info.pbTag = tagHandle.AddrOfPinnedObject();
                info.cbTag = tag.Length;

                int result = 0;
                if (encrypt)
                {
                    status = BCryptEncrypt(hKey, input, input.Length, ref info, null, 0, output, output.Length, out result, 0);
                    Check(status, "BCryptEncrypt");
                }
                else
                {
                    status = BCryptDecrypt(hKey, input, input.Length, ref info, null, 0, output, output.Length, out result, 0);
                    Check(status, "BCryptDecrypt");
                }
            }
            finally
            {
                if (nonceHandle.IsAllocated) { nonceHandle.Free(); }
                if (tagHandle.IsAllocated) { tagHandle.Free(); }
                if (hKey != IntPtr.Zero) { BCryptDestroyKey(hKey); }
                if (hAlg != IntPtr.Zero) { BCryptCloseAlgorithmProvider(hAlg, 0); }
            }
        }

        private static void Check(int status, string api)
        {
            if (status != 0)
            {
                throw new InvalidOperationException(api + " failed: 0x" + status.ToString("X8"));
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public uint dwFlags;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);
    }
}
'@
}

function ConvertTo-GcmFileBytes {
    Param(
        [Parameter(Mandatory = $true)]
        [byte[]]$KeyBytes,
        [Parameter(Mandatory = $true)]
        [byte[]]$Plaintext
    )

    Initialize-AesGcmCrypto

    $nonce = New-Object byte[] 12
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($nonce)
    }
    finally {
        $rng.Dispose()
    }

    $ciphertext = New-Object byte[] $Plaintext.Length
    $tag = New-Object byte[] 16
    [PScryptorator.AesGcmCrypto]::Encrypt($KeyBytes, $nonce, $Plaintext, $ciphertext, $tag)

    $magic = [System.Text.Encoding]::ASCII.GetBytes('PSCG')
    $blob = New-Object byte[] (4 + 1 + 12 + 16 + $ciphertext.Length)
    [System.Buffer]::BlockCopy($magic, 0, $blob, 0, 4)
    $blob[4] = 1
    [System.Buffer]::BlockCopy($nonce, 0, $blob, 5, 12)
    [System.Buffer]::BlockCopy($tag, 0, $blob, 17, 16)
    if ($ciphertext.Length -gt 0) {
        [System.Buffer]::BlockCopy($ciphertext, 0, $blob, 33, $ciphertext.Length)
    }
    return $blob
}

function ConvertFrom-GcmFileBytes {
    Param(
        [Parameter(Mandatory = $true)]
        [byte[]]$KeyBytes,
        [Parameter(Mandatory = $true)]
        [byte[]]$FileBytes,
        [Parameter(Mandatory = $true)]
        [string]$SourceFile
    )

    Initialize-AesGcmCrypto

    if ($FileBytes.Length -lt 33) {
        throw "File '$SourceFile' is too short to be an AES-GCM .crypt file."
    }

    $magic = [System.Text.Encoding]::ASCII.GetString($FileBytes, 0, 4)
    if ($magic -ne 'PSCG') {
        throw "File '$SourceFile' is not AES-GCM (missing PSCG header). Re-encrypt it with the current script."
    }

    $version = $FileBytes[4]
    if ($version -ne 1) {
        throw "File '$SourceFile' has unsupported GCM version $version."
    }

    $nonce = New-Object byte[] 12
    $tag = New-Object byte[] 16
    [System.Buffer]::BlockCopy($FileBytes, 5, $nonce, 0, 12)
    [System.Buffer]::BlockCopy($FileBytes, 17, $tag, 0, 16)

    $cipherLength = $FileBytes.Length - 33
    $ciphertext = New-Object byte[] $cipherLength
    if ($cipherLength -gt 0) {
        [System.Buffer]::BlockCopy($FileBytes, 33, $ciphertext, 0, $cipherLength)
    }

    $plaintext = New-Object byte[] $cipherLength
    [PScryptorator.AesGcmCrypto]::Decrypt($KeyBytes, $nonce, $ciphertext, $tag, $plaintext)
    return $plaintext
}

function New-RequiredDirectory {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    return New-Item -ItemType Directory -Path $Path -Force
}

function Get-RelativePathFromRoot {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string]$FullPath
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $itemFull = [System.IO.Path]::GetFullPath($FullPath)
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar

    if ($itemFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $itemFull.Substring($prefix.Length)
    }

    if ($itemFull.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return [string]::Empty
    }

    throw "Path '$FullPath' is not under '$Root'."
}

function Copy-FilesPreservingRelativePath {
    Param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$Files,
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot,
        [Parameter(Mandatory = $true)]
        [string]$DestinationRoot
    )

    $copied = @()
    foreach ($file in $Files) {
        $relativePath = Get-RelativePathFromRoot -Root $SourceRoot -FullPath $file.FullName
        $destinationFile = Join-Path $DestinationRoot $relativePath
        New-RequiredDirectory -Path (Split-Path -Parent $destinationFile) | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destinationFile -Force
        $copied += Get-Item -LiteralPath $destinationFile
    }
    return $copied
}


Function Encrypt-File
{

    Param(
       [Parameter(Mandatory=$true, Position=1)]
       [System.IO.FileInfo[]]$FileToEncrypt,
       [Parameter(Mandatory=$true, Position=2)]
       [String]$Key,
       [Parameter(Mandatory=$false, Position=3)]
       [String]$Suffix = '.crypt'
    )

    try
    {
        $EncryptionKey = [System.Convert]::FromBase64String($Key)
        if ($EncryptionKey.Length -notin 16, 24, 32) {
            throw 'Key must be 128, 192, or 256 bits.'
        }
    }
    Catch
    {
        Write-Error 'Unable to configure AES-GCM, verify you are using a valid key.'
        Return
    }

    $KeySize = $EncryptionKey.Length * 8
    Write-Verbose "Encrypting $($FileToEncrypt.Count) file(s) with AES-GCM ($KeySize-bit)"

    $EncryptedFiles = @()
    
    ForEach($File in $FileToEncrypt)
    {
        If($File.Name.EndsWith($Suffix))
        {
            Write-Error "$($File.FullName) already has a suffix of '$Suffix'."
            Continue
        }

        $DestinationFile = $File.FullName + $Suffix
        try
        {
            $plaintext = [System.IO.File]::ReadAllBytes($File.FullName)
            $blob = ConvertTo-GcmFileBytes -KeyBytes $EncryptionKey -Plaintext $plaintext
            [System.IO.File]::WriteAllBytes($DestinationFile, $blob)
            Remove-Item -LiteralPath $File.FullName
            Write-Verbose "Successfully encrypted $($File.FullName)"
            $EncryptedFiles += $DestinationFile
        }
        catch
        {
            Write-Error "Failed to encrypt $($File.FullName): $_"
            if (Test-Path -LiteralPath $DestinationFile) {
                Remove-Item -LiteralPath $DestinationFile -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return [PSCustomObject]@{
        Computer = $env:COMPUTERNAME
        Files    = $EncryptedFiles
    }
}

function Decrypt-File {
    Param(
        [Parameter(Mandatory = $true, Position = 1)]
        [System.IO.FileInfo[]]$FileToDecrypt,
        [Parameter(Mandatory = $true, Position = 2)]
        [String]$Key,
        [Parameter(Mandatory = $false, Position = 3)]
        [String]$Suffix = '.crypt',
        [Parameter(Mandatory = $false)]
        [string]$SourceRoot,
        [Parameter(Mandatory = $false)]
        [string]$DestinationPath
    )

    try {
        $EncryptionKey = [System.Convert]::FromBase64String($Key)
        if ($EncryptionKey.Length -notin 16, 24, 32) {
            throw 'Key must be 128, 192, or 256 bits.'
        }
    }
    catch {
        Write-Error 'Unable to configure AES-GCM, verify you are using a valid key.'
        return
    }

    if ($DestinationPath) {
        New-RequiredDirectory -Path $DestinationPath | Out-Null
    }

    $KeySize = $EncryptionKey.Length * 8
    Write-Verbose "Decrypting $($FileToDecrypt.Count) file(s) with AES-GCM ($KeySize-bit)"

    $DecryptedFiles = @()

    foreach ($File in $FileToDecrypt) {
        if (-not $File.Name.EndsWith($Suffix)) {
            Write-Error "$($File.FullName) does not have a suffix of '$Suffix'."
            continue
        }

        $plainName = $File.Name.Substring(0, $File.Name.Length - $Suffix.Length)
        if ($DestinationPath -and $SourceRoot) {
            $relativeCrypt = Get-RelativePathFromRoot -Root $SourceRoot -FullPath $File.FullName
            $relativePlain = $relativeCrypt.Substring(0, $relativeCrypt.Length - $Suffix.Length)
            $destinationFile = Join-Path $DestinationPath $relativePlain
        }
        elseif ($DestinationPath) {
            $destinationFile = Join-Path $DestinationPath $plainName
        }
        else {
            $destinationFile = Join-Path $File.DirectoryName $plainName
        }

        New-RequiredDirectory -Path (Split-Path -Parent $destinationFile) | Out-Null

        try {
            $fileBytes = [System.IO.File]::ReadAllBytes($File.FullName)
            $plaintext = ConvertFrom-GcmFileBytes -KeyBytes $EncryptionKey -FileBytes $fileBytes -SourceFile $File.FullName
            [System.IO.File]::WriteAllBytes($destinationFile, $plaintext)
            Write-Verbose "Successfully decrypted $($File.FullName)"
            $DecryptedFiles += $destinationFile
        }
        catch {
            Write-Error "Failed to decrypt $($File.FullName): $_"
            if ($destinationFile -and (Test-Path -LiteralPath $destinationFile)) {
                Remove-Item -LiteralPath $destinationFile -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return [PSCustomObject]@{
        Computer = $env:COMPUTERNAME
        Files    = $DecryptedFiles
    }
}

function Test-PScryptoratorRoundTrip {
    Param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$SourceFiles,
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot
    )

    $workRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("PScryptorator-test-" + [guid]::NewGuid().ToString('N'))
    $cryptPath = Join-Path $workRoot 'crypt'
    $outPath = Join-Path $workRoot 'out'
    $tempKeyPath = Join-Path $workRoot 'aes.key'

    try {
        New-RequiredDirectory -Path $cryptPath | Out-Null
        New-RequiredDirectory -Path $outPath | Out-Null

        $toEncrypt = Copy-FilesPreservingRelativePath -Files $SourceFiles -SourceRoot $SourceRoot -DestinationRoot $cryptPath

        $key = Create-AESKey
        Write-AESKeyToFile -Key $key -Path $tempKeyPath

        $encryptResult = Encrypt-File $toEncrypt $key
        if (-not $encryptResult -or $encryptResult.Files.Count -ne $SourceFiles.Count) {
            throw "Encryption step did not produce $($SourceFiles.Count) file(s)."
        }

        $toDecrypt = @(Get-ChildItem -LiteralPath $cryptPath -Recurse -File | Where-Object { $_.Name.EndsWith('.crypt') })
        $decryptResult = Decrypt-File $toDecrypt $key -SourceRoot $cryptPath -DestinationPath $outPath
        if (-not $decryptResult -or $decryptResult.Files.Count -ne $SourceFiles.Count) {
            throw "Decryption step did not produce $($SourceFiles.Count) file(s)."
        }

        $passed = 0
        $failed = 0
        foreach ($source in $SourceFiles) {
            $relativePath = Get-RelativePathFromRoot -Root $SourceRoot -FullPath $source.FullName
            $restored = Join-Path $outPath $relativePath
            if (-not (Test-Path -LiteralPath $restored)) {
                Write-Host "  FAIL  $relativePath (decrypted file missing)"
                $failed++
                continue
            }

            $originalHash = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash
            $restoredHash = (Get-FileHash -LiteralPath $restored -Algorithm SHA256).Hash
            if ($originalHash -eq $restoredHash) {
                Write-Host "  PASS  $relativePath"
                $passed++
            }
            else {
                Write-Host "  FAIL  $relativePath (hash mismatch)"
                $failed++
            }
        }

        $tamperSource = $toDecrypt[0]
        $tamperBytes = [System.IO.File]::ReadAllBytes($tamperSource.FullName)
        $tamperBytes[$tamperBytes.Length - 1] = $tamperBytes[$tamperBytes.Length - 1] -bxor 0xFF
        $tamperFile = Join-Path $workRoot 'tampered.crypt'
        [System.IO.File]::WriteAllBytes($tamperFile, $tamperBytes)
        $tamperOut = Join-Path $workRoot 'tamper-out'
        $ErrorActionPreference = 'SilentlyContinue'
        $tamperResult = Decrypt-File @((Get-Item -LiteralPath $tamperFile)) $key -SourceRoot $workRoot -DestinationPath $tamperOut 2>$null
        $ErrorActionPreference = 'Continue'
        if (-not $tamperResult -or $tamperResult.Files.Count -eq 0) {
            Write-Host "  PASS  tamper detection (AES-GCM tag)"
            $passed++
        }
        else {
            Write-Host "  FAIL  tamper detection (altered ciphertext decrypted)"
            $failed++
        }

        Write-Host "Result: $passed passed, $failed failed"
        return [PSCustomObject]@{
            Passed = $passed
            Failed = $failed
            WorkRoot = $workRoot
        }
    }
    finally {
        if (Test-Path -LiteralPath $workRoot) {
            Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host -f Magenta $logo
Write-Host
Write-Host -f Green $label

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if ([string]::IsNullOrWhiteSpace($SourcePath)) {
    $SourcePath = Join-Path $scriptRoot 'testdata'
}
if ([string]::IsNullOrWhiteSpace($CryptPath)) {
    $CryptPath = Join-Path $scriptRoot 'crypt'
}
if ([string]::IsNullOrWhiteSpace($KeyPath)) {
    $KeyPath = Join-Path $scriptRoot 'aes.key'
}

$SourcePath = [System.IO.Path]::GetFullPath($SourcePath)
$CryptPath = [System.IO.Path]::GetFullPath($CryptPath)
$KeyPath = [System.IO.Path]::GetFullPath($KeyPath)
if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
    $DestinationPath = $CryptPath
}
else {
    $DestinationPath = [System.IO.Path]::GetFullPath($DestinationPath)
}

if ($Decrypt -and $Test) {
    Write-Error 'Use either -Decrypt or -Test, not both.'
    return
}

if ($Test) {
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        Write-Error "Test source directory '$SourcePath' was not found."
        return
    }

    $files = Get-MatchingSourceFiles -Path $SourcePath
    if ($files.Count -eq 0) {
        Write-Error "No matching files found in '$SourcePath' to test."
        return
    }

    Write-Host "Mode:   Test (round-trip)"
    Write-Host "Source: $SourcePath"
    $testResult = Test-PScryptoratorRoundTrip -SourceFiles $files -SourceRoot $SourcePath
    if ($testResult.Failed -gt 0) {
        Write-Error 'Round-trip test failed.'
    }
    return
}

if ($Decrypt) {
    if (-not (Test-Path -LiteralPath $CryptPath)) {
        Write-Error "Crypt directory '$CryptPath' was not found."
        return
    }

    try {
        $resolvedKey = Resolve-AesKey -Path $KeyPath
    }
    catch {
        Write-Error $_
        return
    }

    $encryptedFiles = @(Get-ChildItem -LiteralPath $CryptPath -Recurse -File |
        Where-Object { $_.Name.EndsWith('.crypt') })
    if ($encryptedFiles.Count -eq 0) {
        Write-Warning "No .crypt files found in '$CryptPath'."
        return
    }

    Write-Host "Mode:   Decrypt"
    Write-Host "Crypt:  $CryptPath"
    Write-Host "Out:    $DestinationPath"
    Write-Host "Key:    $KeyPath ($($resolvedKey.Status))"

    $decryptResult = Decrypt-File $encryptedFiles $resolvedKey.Key -SourceRoot $CryptPath -DestinationPath $DestinationPath
    if ($decryptResult -and $decryptResult.Files) {
        Write-Host "Decrypted $($decryptResult.Files.Count) file(s)."
    }
    return
}

if (-not (Test-Path -LiteralPath $SourcePath)) {
    New-RequiredDirectory -Path $SourcePath | Out-Null
    Write-Host "Created test source directory: $SourcePath"
}

New-RequiredDirectory -Path $CryptPath | Out-Null

$files = Get-MatchingSourceFiles -Path $SourcePath
if ($files.Count -eq 0) {
    Write-Warning "No matching files found in '$SourcePath'. Add .doc, .docx, .xls, .xlsx, .pdf, or .jpg files and run again."
    return
}

try {
    $resolvedKey = Resolve-AesKey -Path $KeyPath -CreateIfMissing
}
catch {
    Write-Error $_
    return
}

Write-Host "Mode:   Encrypt"
Write-Host "Source: $SourcePath"
Write-Host "Crypt:  $CryptPath"
Write-Host "Key:    $KeyPath ($($resolvedKey.Status))"

$filesCrypt = Copy-FilesPreservingRelativePath -Files $files -SourceRoot $SourcePath -DestinationRoot $CryptPath
$filesCrypt = @($filesCrypt | Where-Object { $_.FullName -ne $KeyPath })

if ($filesCrypt.Count -eq 0) {
    Write-Warning "Nothing to encrypt in '$CryptPath'."
    return
}

$encryptResult = Encrypt-File $filesCrypt $resolvedKey.Key
if ($encryptResult -and $encryptResult.Files) {
    Write-Host "Encrypted $($encryptResult.Files.Count) file(s)."
}
