# PScryptorator

A PowerShell proof of concept that copies a small set of file types into a working folder and encrypts those copies with AES-GCM. It can also decrypt them and run a self-check.

This is a research/testing script. It is not a backup tool, not a password manager, and not something to point at files you care about unless you understand what it will do. Malicious use is prohibited.

By default it only reads the `testdata` folder next to the script. It does **not** walk your user profile unless you pass `-SourcePath`.

## What you need

- Windows
- Windows PowerShell 5.1 or later
- Permission to run local scripts

From the repo folder:

```powershell
Set-Location C:\path\to\PScryptorator
Set-ExecutionPolicy -Scope Process Bypass
```

## Quick start

```powershell
# Encrypt the included samples (safe default)
.\PScryptorator.ps1

# Prove encrypt → decrypt still matches the originals
.\PScryptorator.ps1 -Test

# Restore plaintext from the .crypt files
.\PScryptorator.ps1 -Decrypt -DestinationPath .\decrypted
```

The first encrypt run creates `aes.key` next to the script. Later runs reuse that key. If you lose `aes.key`, the `.crypt` files cannot be recovered.

The script prints the **path** to the key file. It does not print the key.

## How a run works

### Encrypt (default)

1. Find `.doc`, `.docx`, `.xls`, `.xlsx`, `.pdf`, and `.jpg` files under the source folder (`testdata` unless you override it).
2. Copy them into `crypt`, keeping the same relative folders. `testdata\docs\sample.doc` becomes `crypt\docs\sample.doc`.
3. Encrypt each copy in place to `*.crypt` and delete the unencrypted copy in `crypt`.
4. Leave the originals in `testdata` alone.

Two files with the same name in different folders stay separate. `testdata\sample.doc` and `testdata\docs\sample.doc` do not overwrite each other.

### Decrypt

Reads every `*.crypt` file under `crypt`, using `aes.key`, and writes plaintext either next to those files or to `-DestinationPath`. The `.crypt` files stay on disk. Folder structure is preserved.

### Test

Copies `testdata` into a temp directory, encrypts, decrypts, and compares SHA256 hashes to the originals. It also flips one byte of a ciphertext file and checks that decrypt refuses it. `testdata`, `crypt`, and `aes.key` are not changed.

## Layout

```
PScryptorator/
  PScryptorator.ps1   # the script
  testdata\           # sample files you can encrypt (not modified)
  crypt\              # encrypted copies (created on first encrypt)
  aes.key             # 256-bit AES key, Base64, one line
  decrypted\          # only if you pass -DestinationPath .\decrypted
```

`crypt\` and `aes.key` are gitignored so a commit does not publish ciphertext or the key.

## Commands

```powershell
.\PScryptorator.ps1
.\PScryptorator.ps1 -Decrypt
.\PScryptorator.ps1 -Decrypt -DestinationPath .\decrypted
.\PScryptorator.ps1 -Test
.\PScryptorator.ps1 -SourcePath D:\lab\samples
.\PScryptorator.ps1 -SourcePath D:\lab\samples -CryptPath D:\lab\output
.\PScryptorator.ps1 -KeyPath D:\lab\aes.key
```

| Parameter | Default | Purpose |
| --- | --- | --- |
| `-SourcePath` | `.\testdata` | Folder to scan for matching files |
| `-CryptPath` | `.\crypt` | Folder for copies and `.crypt` output |
| `-KeyPath` | `.\aes.key` | Where the AES key is stored |
| `-DestinationPath` | same as `-CryptPath` | Where decrypt writes plaintext |
| `-Decrypt` | off | Decrypt instead of encrypt |
| `-Test` | off | Isolated round-trip + tamper check |

Do not pass both `-Decrypt` and `-Test`.

If you deliberately want to scan a user profile, use `-SourcePath $env:USERPROFILE`. Do not use `$env:HOMEPATH`; that value has no drive letter and will resolve to the wrong place.

## Encryption details

Each `.crypt` file is AES-256-GCM through Windows CNG (`bcrypt`). GCM encrypts the file and attaches an authentication tag. If someone changes a byte of the ciphertext, decrypt fails instead of writing a corrupt file.

File layout:

```
PSCG          4 bytes, ASCII magic
version       1 byte, currently 1
nonce         12 bytes, random per file
tag           16 bytes
ciphertext    remainder (same length as the plaintext)
```

Older versions of this script used AES-CBC. Those `.crypt` files will not decrypt here. Encrypt the originals again with the current script.

The key is a random 256-bit value stored as Base64 in `aes.key`. The same key is reused so you can decrypt later. That file is a secret. Do not commit it, paste it into chat, or copy `.crypt` files without it.

AES-GCM here loads each file into memory. That is fine for the sample documents. It is not aimed at multi-gigabyte files.

## Safety notes

- Default source is `testdata`. Add your own samples there, or pass a folder you intend to test.
- Originals in the source folder are copied, not deleted.
- `Encrypt-File` deletes the **copy** in `crypt` after it writes `*.crypt`. Do not point `-CryptPath` at your only copy of something.
- There is no password prompt and no key wrapping. Anyone who can read `aes.key` can decrypt the files.
- This is a learning project, not a substitute for BitLocker, 7-Zip AES, or age/gpg.

## Author

[@cyberw01f](https://github.com/cyb3rw01f)
