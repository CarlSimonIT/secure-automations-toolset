# secure-automations-toolset

## Overview
**secure-automations-toolset** (SAT) incorporates the [Bitwarden CLI](https://bitwarden.com/help/cli/) and the [Bitwarden Secrets Manager CLI](https://bitwarden.com/help/secrets-manager-cli/) to provide a highly secure pre-production environment of Hyper-V hosts and Hyper-V VMs running Windows Server. 

## Demonstration
_YouTube video goes here_

## Requirements
In addition to `secure-automations-toolset.psm1`, the PowerShell script module file, other necessary conditions for using SAT are:  
* Internet connectivity. 
* PowerShell 7. 
* A Bitwarden account with a Bitwarden Vault in the Free tier or above. Paying for Bitwarden is not necessary. 
* A bare-metal instance of the Windows OS featuring a GUI and with Hyper-V installed.
* The ability to log into that instance of Windows with a non-admin account + credentials of an account holding membership in the local Administrators group. Logging into Windows as admin will not be necessary. 

Optional items: 
* A personal [Microsoft Account](https://account.microsoft.com/account/) (MSA) in the Free tier and configured to be a [passwordless account](https://support.microsoft.com/en-us/windows/go-passwordless-with-your-microsoft-account-585a71d7-2295-4878-aeac-a014984df856). 
* OneDrive desktop application with the MSA signed-in and syncing to the cloud. Do not enable [OneDrive Backup](https://support.microsoft.com/en-us/office/turn-on-onedrive-backup-4e44ceab-bcdf-4d17-9ae0-6f00f6080adb) unless you can confirm that the contents of your Documents, Desktop, and Pictures libraries are below 5GB. [Data loss](https://askleo.com/onedrive-backup-versus-using-onedrive-for-backup-even-though-onedrive-isnt-backup/) can result. 

## Start
### PowerShell 7
Launch Windows PowerShell in the context of a local admin. Execute the line below to download & install PowerShell 7. 

```powershell
Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI"
```

> [!NOTE]
> Several alternatives for installing [PowerShell 7 on Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows) are available. 

Close Windows PowerShell. 

### Bitwarden
Visit [vault.bitwarden.com](https://vault.bitwarden.com/#/login) and select **create account**. Sign up for a [free Bitwarden vault](https://bitwarden.com/go/start-free/). Create a Bitwarden Organization with a title to match your lab environment. Accept the free offer for Bitwarden Secrets Manager. 

_YouTube video goes here._

### Download & import the SAT module
```powershell
Import-Module .\secure-automations-toolset.psm1
```

Launch PowerShell 7 as admin. 

### Install Hyper-V
Launch PowerShell 7 as admin. Save your work & close all open applications aside from PowerShell 7. Installing Hyper-V requires a reboot. 

```powershell

```
