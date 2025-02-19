# secure-automations-toolset
Integrate Bitwarden into your workflow for managing Active Directory domains and Microsoft Entra tenants.

# Initial Setup (Start Here) 

## Create a Bitwarden account and sign up for a Bitwarden Vault in the Free tier
Before the first command...
* Visit [vault.bitwarden.com](https://vault.bitwarden.com/#/login) and select **create account**. 
* Sign up for a [free Bitwarden vault](https://bitwarden.com/go/start-free/). 
* Create a Bitwarden Organization.

```powershell
${Bitwarden Organization Name} = "Kerberos Networks"
```

Before the first command on bw.exe |
-- Accept the free offer for Bitwarden Secrets Manager
-- Configure a Machine Account titled randomly >
---         ${MA Title} = "MA $(New-Guid)"
---         ${MA Title} | Set-Clipboard
-- Configure an Access Token for the MA that expires after a week.

```powershell
${AT Title} = "AT $(New-Guid)"
${AT Title} | Set-Clipboard
```


## Install PowerShell 7




Test. Test. Test. 

> [!NOTE]

> [!WARNING]

> [!NOTE]
> Guest sharing settings that are specific to M365 Groups and Teams will also affect the connected SPO Site. Investigate later. 

