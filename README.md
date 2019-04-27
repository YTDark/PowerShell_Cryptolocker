# PowerShell_Cryptolocker
PowerShell AES TCP Cryptolocker

Launch server
 - Wait for a connection

Launch Client
- Start-Encrytion function will try to connect to the server and send the key
- if Succesfull will start encryption of all the files in the userprofile\Documents\test folder
- Start-Decryption function will try to connect to the server to get the key
- if Succesfull will start decryption of all the files in the userprofile\Documents\test folder

NOTICE - For education purpose only
