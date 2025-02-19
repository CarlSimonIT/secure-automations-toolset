# secure-automations-toolset
Integrate Bitwarden into your workflow for managing Active Directory domains and Microsoft Entra tenants.

# Bitwarden Initial Setup (Start Here)  
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
  ---         ${AT Title} = "AT $(New-Guid)"
  ---         ${AT Title} | Set-Clipboard



Test. Test. Test. 

> [!NOTE]

> [!WARNING]

> [!NOTE]
> Guest sharing settings that are specific to M365 Groups and Teams will also affect the connected SPO Site. Investigate later. 

