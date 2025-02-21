function _AuthenticateIntoBitwardenPasswordManagerCLI {
  Set-StrictMode -Version 3
  _PrerequisiteConditions

  # Capture status of Bitwarden Password Manager CLI. Only values of interest for our purposes are 'locked' and 'unauthenticated'
  $RedirectedErrors = $(
    ${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
  ) 2>&1

  # Authenticate into Bitwarden Password Manager CLI
  switch (${Authentication Status of the Bitwarden CLI}) {
    'unauthenticated' {
      $emailaddr = Read-Host -Prompt "Username of Bitwarden account" # -MaskInput
      [string[]]$(bw.exe login $emailaddr) | ForEach-Object {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          $env:BW_SESSION = $Matches['BW_SESSION']
        }
      }
      break
    }
    'locked' {
      [string[]]$(bw.exe unlock) | ForEach-Object {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          $env:BW_SESSION = $Matches['BW_SESSION']
        }
      }
      break
    }
    default {
      break
    }
  }
}
Set-Alias -Name Unlock-BwCli -Value _AuthenticateIntoBitwardenPasswordManagerCLI

function _PrerequisiteConditions {
  Set-StrictMode -Version 3

  # Use named matches to capture the well-known SID of the user account that owns the PowerShell process executing these commands
  $WhoAmI = whoami.exe /all
  for ($i = 0; $i -lt $WhoAmI.Length; $i++) {
    if (
      $WhoAmI[$i] -match '^Mandatory Label\\\D+Label\s+(?<Well_Known_SID>\S+)'
    ) {
      $Well_Known_SID = $Matches['Well_Known_SID']
    }
  }

  ## Exit the script if the PowerShell process is running in an elevated context. Generally speaking, avoid launching processes at IL-High or above unless absolutely necessary. 
  #if (
  #  -not (
  #    ($Well_Known_SID -eq "S-1-16-8192") -or ($Well_Known_SID -eq "S-1-16-4096")
  #  )
  #) {
  #  Write-Error -Message "`r`n  PowerShell process executing these commands is running in an elevated security context.`r`n    Launch PowerShell as non-admin and reattempt.`r`n"
  #  Pause
  #  exit
  #}

  # Confirm presence of x64 version of "Microsoft Visual C++ 2015 - 2022 Redistributable" | Invoke-WebRequest bombs out the 1st time because of no DNS resource record on the DNS server. Gotta write error-handling code. 
  # Somehow turn this into a loop that detects if the user has installed...
  while (
    -not (
      (Get-CimInstance -ClassName 'Win32_Product').Where({($_.Name -match [regex]::Escape('Microsoft Visual C++ 2022 X64 Minimum Runtime')) -or ($_.Name -match [regex]::Escape('Microsoft Visual C++ 2022 X86 Minimum Runtime'))})
    )
  ) {
    Write-Host -ForegroundColor 'Magenta' -Object "`r`nBitwarden Secrets Manager CLI (bws.exe) requires VCRUNTIME140.dll.`r`nDownload & install either...`r`n  vc_redist.x64.exe`tfrom`t'https://aka.ms/vs/17/release/vc_redist.x64.exe'`r`nor...`r`n  vc_redist.x86.exe`tfrom`t'https://aka.ms/vs/17/release/vc_redist.x86.exe'`r`nReference:`r`n  'https://answers.microsoft.com/en-us/windows/forum/all/vcruntime140dll-and-msvcp140dll-missing-in-windows/caf454d1-49f4-4d2b-b74a-c83fb7c38625'`r`n"
    Write-Host -ForegroundColor 'Yellow' -Object "Instructions: Keep this PowerShell 7 terminal up. Launch another PowerShell 7 process as Admin.`r`nRun the green lines below to download & install the 64-bit version of the C++ runtime.`r`nClose the PowerShell 7 process running as admin and re-launch as non-admin"
    <#
      ${query.exe session} = query.exe session
      for (
        $i = 0; $i -lt ${query.exe session}.Length; $i++
      ) 
      {
        if (
          ${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'
        )
        {
          ${explorer Owner} = $Matches['explorer_Owner']
        }
      }

      $_Var_Name = 'TempSessionVar'
      try {
        Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
      } 
      catch {
        New-Variable -Name $_Var_Name -Value $null
      }

      while (
        -not (
          $TempSessionVar
        )
      ) {
        $RedirectedError = $(
          Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" `
          -SessionVariable 'TempSessionVar' `
          -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe"
        ) 2>&1
      }
      & "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe" /quiet
    #>
    @'


    ${query.exe session} = query.exe session; for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'){${explorer Owner} = $Matches['explorer_Owner']}}; $_Var_Name = 'TempSessionVar'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null};      while (-not ($TempSessionVar)) {$RedirectedError = $(Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe") 2>&1};      & "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe" /quiet;       

    
'@ | Write-Host -ForegroundColor 'DarkGreen'
    #Pause
    ${query.exe session} = query.exe session; 
    for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'){${explorer Owner} = $Matches['explorer_Owner']}}; 
    $_Var_Name = 'TempSessionVar'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null};      
    while (-not ($TempSessionVar)) {$RedirectedError = $(Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe") 2>&1};      
    & "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe" /quiet;       
  }

  # Confirm presence of Bitwarden Password Manager CLI (bw.exe) in a $env:Path directory. 
  $pathFolders = $env:Path -split ';'                          # Load each of the semicolon-separated directory paths into an array element
  if (
    $pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")            # If final element is the empty string of length-0...
  ) {
    $pathFolders = $pathFolders[0..($pathFolders.Length - 2)]  # Then eliminate that element from the array
  }
  while (
    -not (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "bw.exe") -ErrorAction 'SilentlyContinue') -contains $true
    )
  ) {
    Write-Host -ForegroundColor 'DarkRed' -Object "Fucking shit.  Do you see what's wrong with this code? `$pathFolders is specific to the owner of pwsh.exe but the code below establishes bw.exe  in the %path% for the Owner of explorer.exe`n`rGod dammit, how could I miss that.`r`n"
    
    Write-Host -ForegroundColor 'Magenta' -Object "Executable for the Bitwarden Password Manager CLI (bw.exe) is not among the `$env:Path directories."
    Write-Host -ForegroundColor 'Yellow' -Object "Instructions: Keep this PowerShell 7 session open and launch an additional PowerShell 7 process on a non-elevated security context.`r`nRun the green lines below to download, extract, and relocate the Bitwarden Password Manager CLI to the 1st %path% directory containing your username.`r`nReturn to this PowerShell session and hit Enter."
    <#
      ${query.exe session} = query.exe session
      for (
        $i = 0; $i -lt ${query.exe session}.Length; $i++
      ) 
      {
        if (
          ${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'
        )
        {
          ${explorer Owner} = $Matches['explorer_Owner']
        }
      }

      $_Var_Name = 'TempSessionVar'
      try {
        Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
      } 
      catch {
        New-Variable -Name $_Var_Name -Value $null
      }

      while (
        -not (
          $TempSessionVar
        )
      ) {
        $RedirectedError = $(
          Invoke-WebRequest -Uri "https://vault.bitwarden.com/download/?app=cli&platform=windows" `
          -SessionVariable 'TempSessionVar' `
          -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip"
        ) 2>&1
      }
      Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip" `
      -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]
    #>
    @'
 

     ${query.exe session} = query.exe session; for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'){${explorer Owner} = $Matches['explorer_Owner']}}; $_Var_Name = 'TempSessionVar'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}; while (-not ($TempSessionVar)) {$RedirectedError = $(Invoke-WebRequest -Uri "https://vault.bitwarden.com/download/?app=cli&platform=windows" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip") 2>&1};      Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip" -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]; 


'@ | Write-Host -ForegroundColor 'DarkGreen'
    #Pause
    ${query.exe session} = query.exe session; 
    for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'){${explorer Owner} = $Matches['explorer_Owner']}}; 
    $_Var_Name = 'TempSessionVar'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}; 
    while (-not ($TempSessionVar)) {$RedirectedError = $(Invoke-WebRequest -Uri "https://vault.bitwarden.com/download/?app=cli&platform=windows" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip") 2>&1};      
    Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip" -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]; 
  }

  # Confirm presence of the jq JSON processor. Necessary for writing into the Bitwarden Password Manager via the Bitwarden CLI
  $pathFolders = $env:Path -split ';'                       # Load each of the semicolon-separated directory paths into an array element
  if (
    $pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")            # If final element is the empty string of length-0...
  ) {
    $pathFolders = $pathFolders[0..($pathFolders.Length - 2)]  # Then eliminate that element from the array
  }
  while (
    -not (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "jq-windows-amd64.exe") -ErrorAction 'SilentlyContinue') -contains $true
    )
  ) {
    Write-Host -ForegroundColor 'Magenta' -Object "Executable for jq (jq-windows-amd64.exe) is not among the `$env:Path directories."
    Write-Host -ForegroundColor 'Yellow' -Object "Instructions: Keep this PowerShell 7 session open and launch an additional PowerShell 7 process as non-admin.`r`nRun the green lines below to download and relocate the jq command-line JSON processor to the first %path% directory containing your username.`r`nReturn to this window upon completion`r`n  Reference: https://jqlang.github.io/jq/"
    <#
      ${query.exe session} = query.exe session
      for (
        $i = 0; $i -lt ${query.exe session}.Length; $i++
      ) 
      {
        if (
          ${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'
        )
        {
          ${explorer Owner} = $Matches['explorer_Owner']
        }
      }

      $_Var_Name = 'TempSessionVar'
      try {
        Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
      } 
      catch {
        New-Variable -Name $_Var_Name -Value $null
      }

      while (
        -not (
          $TempSessionVar
        )
      ) {
        $RedirectedError = $(
          Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" `
          -SessionVariable 'TempSessionVar' `
          -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe"
        ) 2>&1
      }
      Copy-Item -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe" `
      -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]    
    #>
    @'


      ${query.exe session} = query.exe session; for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'){${explorer Owner} = $Matches['explorer_Owner']}}; $_Var_Name = 'TempSessionVar'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}; while (-not ($TempSessionVar)) {$RedirectedError = $(Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe") 2>&1};       Copy-Item -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe" -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]; 



'@ | Write-Host -ForegroundColor 'DarkGreen'
    #Pause
    ${query.exe session} = query.exe session; 
    for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'){${explorer Owner} = $Matches['explorer_Owner']}}; 
    $_Var_Name = 'TempSessionVar'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}; 
    while (-not ($TempSessionVar)) {$RedirectedError = $(Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe") 2>&1};       
    Copy-Item -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe" -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]; 
  }
  
  # Confirm presence of Bitwarden Secrets Manager CLI (bws.exe) in a $env:Path directory. 
  $pathFolders = $env:Path -split ';'                          # Load each of the semicolon-separated directory paths into an array element
  if (
    $pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")            # If final element is the empty string of length-0..
  )
  {
    $pathFolders = $pathFolders[0..($pathFolders.Length - 2)]  # Then eliminate that element from the array
  }
  while (
    -not (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "bws.exe") -ErrorAction 'SilentlyContinue') -contains $true
    )
  ) {
    Write-Host -ForegroundColor 'Magenta' -Object "Executable for the Bitwarden Secrets Manager CLI (bws.exe) is not among the `$env:Path directories."
    Write-Host -ForegroundColor 'Yellow' -Object "Instructions: Run the green lines below to download, extract, and relocate the Bitwarden Secrets Manager CLI to the first %path% directory containing your username:"
    <#
      ${query.exe session} = query.exe session
      for (
        $i = 0; $i -lt ${query.exe session}.Length; $i++
      ) 
      {
        if (
          ${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'
        )
        {
          ${explorer Owner} = $Matches['explorer_Owner']
        }
      }

      $_Var_Name = 'TempSessionVar'
      try {
        Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
      } 
      catch {
        New-Variable -Name $_Var_Name -Value $null
      }

      while (
        -not (
          $TempSessionVar
        )
      ) {
        $RedirectedError = $(
          Invoke-WebRequest -Uri "https://github.com/bitwarden/sdk/releases/download/bws-v1.0.0/bws-x86_64-pc-windows-msvc-1.0.0.zip" `
          -SessionVariable 'TempSessionVar' `
          -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip"
        ) 2>&1
      }
      Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip" `
      -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]
    #>
    @'


      ${query.exe session} = query.exe session; for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'){${explorer Owner} = $Matches['explorer_Owner']}}; $_Var_Name = 'TempSessionVar'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}; while (-not ($TempSessionVar)) {$RedirectedError = $(Invoke-WebRequest -Uri "https://github.com/bitwarden/sdk/releases/download/bws-v1.0.0/bws-x86_64-pc-windows-msvc-1.0.0.zip" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip") 2>&1}; Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip" -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]; 


'@ | Write-Host -ForegroundColor 'DarkGreen'
    #Pause
    ${query.exe session} = query.exe session; 
    for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {if (${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'){${explorer Owner} = $Matches['explorer_Owner']}}; 
    $_Var_Name = 'TempSessionVar'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}; 
    while (-not ($TempSessionVar)) {$RedirectedError = $(Invoke-WebRequest -Uri "https://github.com/bitwarden/sdk/releases/download/bws-v1.0.0/bws-x86_64-pc-windows-msvc-1.0.0.zip" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip") 2>&1}; 
    Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip" -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]; 
  }

  # Code that's executed when PowerShell detects that a request to close the PowerShell host process has been submitted. 
  ${ScriptBlock to Run at PowerShell Engine Shutdown Event} = {
    $pathFolders = $env:Path -split ';'                          # Load each of the semicolon-separated directory paths into an array element
    if (
      $pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")            # If final element is the empty string of length-0..
    ) 
    {
      $pathFolders = $pathFolders[0..($pathFolders.Length - 2)]  # Then eliminate that element from the array
    }
  
    if (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "bw.exe") -ErrorAction 'SilentlyContinue') -contains $true
    ) {
      ${Bitwarden CLI Authentication Status} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
      switch
      (
        ${Bitwarden CLI Authentication Status}
      ) 
      {
        'unauthenticated' {break}                     # Scriptblock exits if "bw.exe status" evaluates to 'unauthenticated' or 'locked'
        'locked'          {break}
        'unlocked'        {bw.exe lock | Out-Null}    # Lock the Bitwarden Password Manager CLI if "bw.exe status" evaluates to 'unlocked'
        default           {break}
      }
    }
  }

  # Register for the Event representing the PowerShell engine shutdown
  $HT = @{
    SourceIdentifier = ([System.Management.Automation.PsEngineEvent]::Exiting)
    Action = ${ScriptBlock to Run at PowerShell Engine Shutdown Event} 
  }
  Register-EngineEvent @HT | Out-Null
}

function _PrerequisiteConditionsRemote {
  Set-StrictMode -Version 3

  $(whoami.exe) -match '^(?<NetBios_Domain>\w+)\\(?<User_Name>[a-zA-Z0-9-._ ]+)$'
  $User_Name = $User_Name

  while (
    -not (
      (Get-CimInstance -ClassName 'Win32_Product').Where({($_.Name -match [regex]::Escape('Microsoft Visual C++ 2022 X64 Minimum Runtime')) -or ($_.Name -match [regex]::Escape('Microsoft Visual C++ 2022 X86 Minimum Runtime'))})
    )
  ) {
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    while (-not ($TempSessionVar)) {
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\$User_Name\Downloads\vc_redist.x64.exe"
      ) 2>&1
    }
    & "$env:SystemDrive\Users\$User_Name\Downloads\vc_redist.x64.exe" /quiet
  }

  $pathFolders = $env:Path -split ';'
  if ($pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")) {$pathFolders = $pathFolders[0..($pathFolders.Length - 2)]}
  while (
    -not (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "bw.exe") -ErrorAction 'SilentlyContinue') -contains $true
    )
  ) {
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    while (-not ($TempSessionVar)) {
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://vault.bitwarden.com/download/?app=cli&platform=windows" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\$User_Name\Downloads\bw-windows.zip"
      ) 2>&1
    }
    Expand-Archive -Path "$env:SystemDrive\Users\$User_Name\Downloads\bw-windows.zip" -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\$User_Name")})[0]
  }

  $pathFolders = $env:Path -split ';'
  if ($pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")) {$pathFolders = $pathFolders[0..($pathFolders.Length - 2)]}
  while (
    -not (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "jq-windows-amd64.exe") -ErrorAction 'SilentlyContinue') -contains $true
    )
  ) {
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    while (-not ($TempSessionVar)) {
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\$User_Name\Downloads\jq-windows-amd64.exe"
      ) 2>&1
    }
    Copy-Item -Path "$env:SystemDrive\Users\$User_Name\Downloads\jq-windows-amd64.exe" -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\$User_Name")})[0]
  }
  
  $pathFolders = $env:Path -split ';'
  if ($pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")){$pathFolders = $pathFolders[0..($pathFolders.Length - 2)]}
  while (-not ((Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "bws.exe") -ErrorAction 'SilentlyContinue') -contains $true)) {
    $_Var_Name = 'TempSessionVar'
    try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}

    while (-not ($TempSessionVar)) {
      $RedirectedError = $(
        Invoke-WebRequest -Uri "https://github.com/bitwarden/sdk/releases/download/bws-v1.0.0/bws-x86_64-pc-windows-msvc-1.0.0.zip" -SessionVariable 'TempSessionVar' -OutFile "$env:SystemDrive\Users\$User_Name\Downloads\bws-windows.zip"
      ) 2>&1
    }
    Expand-Archive -Path "$env:SystemDrive\Users\$User_Name\Downloads\bws-windows.zip" -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\$User_Name")})[0]
  }

  ${ScriptBlock to Run at PowerShell Engine Shutdown Event} = {
    $pathFolders = $env:Path -split ';'
    if ($pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")) {$pathFolders = $pathFolders[0..($pathFolders.Length - 2)]}  
    if ((Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "bw.exe") -ErrorAction 'SilentlyContinue') -contains $true) {
      ${Bitwarden CLI Authentication Status} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
      switch (${Bitwarden CLI Authentication Status}) {
        'unauthenticated' {break}
        'locked'          {break}
        'unlocked'        {bw.exe lock | Out-Null}
        default           {break}
      }
    }
  }

  $HT = @{
    SourceIdentifier = ([System.Management.Automation.PsEngineEvent]::Exiting)
    Action = ${ScriptBlock to Run at PowerShell Engine Shutdown Event} 
  }
  Register-EngineEvent @HT | Out-Null
}

function Add-BitwardenPassword {
  [CmdletBinding(
    ConfirmImpact         = 'Low',
    SupportsShouldProcess = $True,
    SupportsPaging        = $true,
    HelpURI               = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding     = $true
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "SamAccountName of the Active Directory user account",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('un')]
    [string]$SamAccountName,

    [Parameter(
      Position = 1,
      HelpMessage = "Domain-level operations require an account with password length of 128 or less. Try adding a replica DC to the domain with a domain admin whose password is 129 characters-operation will fail. Joining a machine to the domain, however, will succeed.",
      ValueFromPipelineByPropertyName = $False
    )]    
    [ValidateRange(8,127)]
    [int32]$len = 127,

    [Parameter(
      Position = 2,
      HelpMessage = "OPTIONAL: Name of the Item in Bitwarden. Random GUID assigned if left blank.`r`nKnowing the username of the AD account is enough.`r`nUniqueness is only required attribute when titling an Item in Bitwarden Password Manager.",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('item')]
    [string]$BitwardenItemName = (New-Guid).ToString(),

    [Parameter(
      Position = 3,
      HelpMessage = "NetBIOS name of the Active Directory domain. This is different from the Domain Name System name of the Active Directory domain.`r`n`r`nReference from Microsoft Learn:`r`n  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('dom')]
    [string]$NetBiosNameOfActiveDirectoryDomain = $NetBiosNameOfActiveDirectoryDomain,

    [Parameter(
      Position = 4,
      HelpMessage = "Name of the organization in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('org')]
    [string]$BitwardenOrganizationName = $BitwardenOrganizationName,

    [Parameter(
      Position = 5,
      HelpMessage = "Name of the collection in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('col')]
    [string]$BitwardenPwdManagerCollectionName = $BitwardenPwdManagerCollectionName,

    [Parameter(
      Position = 6,
      HelpMessage = "Name of the project in Bitwarden Secrets Manager",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('proj')]
    [string]$BitwardenSecretsManagerProjectName = $BitwardenSecretsManagerProjectName,
    
    [Parameter(
      Position = 7,
      HelpMessage = "A machine account name and an access token value are stored in the 'username' and 'password' sub-properties of the 'login' property of an 'item' in Bitwarden Password Manager. The -AT parameter accepts the NAME of the item object that corresponds to the machine account.",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$AT = ${Machine Account 01-Access Token}
  )

  Set-StrictMode -Version 3
  _PrerequisiteConditions

  <# Hold off on the repeated checks for whether the Bitwarden CLI status is 'unlocked' | Might be what's causing terribly slow operations |
    $RedirectedErrors = $(${Authentication Status of the Bitwarden CLI} = (bw.exe status | ConvertFrom-Json).status) 2>&1 # Save to variable the status of bw.exe

    if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {_AuthenticateIntoBitwardenPasswordManagerCLI}      # Authenticate if status is anything aside from 'unlocked'
  #>

  ($env:BWS_ACCESS_TOKEN) ??= (bw.exe get password ${Machine Account 01-Access Token})

  # Verify whether the AD account already exists in the 'Active Directory Domain Services' collection of the Bitwarden organization
  
  # Initialize new variable for referencing Bitwarden Organization ID
  $_Var_Name = 'BitwardenOrganizationId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Bitwarden Organization ID
  $BitwardenOrganizationId = bw.exe list organizations `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenOrganizationName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no Bitwarden Organization ID produced
  if (
    !($BitwardenOrganizationId)
  ) {
    Write-Error -Message "Bitwarden organization name supplied did not resolve to a UUID. Confirm correct spelling of the organization's name in Kerberos Networks' Bitwarden account"
    Pause
    break
  }

  # Initialize new variable for referencing the Collection ID in Bitwarden Password Manager
  $_Var_Name = 'CollectionId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Collection ID from Bitwarden Password Manager
  $CollectionId = bw.exe list --organizationid $BitwardenOrganizationId org-collections `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenPwdManagerCollectionName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no collection ID produced
  if (
    !($CollectionId)
  ) {
    Write-Error -Message "Collection name supplied did not resolve to a UUID. No collection in Bitwarden Password Manager matches that name. Confirm correct spelling of the collection's name in Kerberos Networks' Bitwarden account"
    Pause
    break
  }

  if (
    -not $BitwardenItemName
  ) {
    # Initialize new variable for referencing an Item in Bitwarden Password Manager
    $_Var_Name = 'ItemInBitwarden'
    try {
      Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
    } 
    catch {
      New-Variable -Name $_Var_Name -Value $null
    }

    # Query the Bitwarden Organization for an item of that name. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
    $RedirectedErrors = $(
      $ItemInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId item $BitwardenItemName
    ) 2>&1

    # Destroy variable & exit function if that item is already present
    if (
      $ItemInBitwarden
    ) {
      Write-Error -Message "Bitwarden Password Manager reports that an Item already has that name.`r`n  Eliminate the '-BitwardenItemName' parameter-argument pair and reattempt."
      pause
      Remove-Variable 'ItemInBitwarden'
      break
    }
  }

  # Initialize new variable for referencing <domain>\<username>
  $_Var_Name = 'UsernameInBitwarden'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Query the Bitwarden Organization for that <domain>\<username> value. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
  $RedirectedErrors = $(
    $UsernameInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId username "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName"
  ) 2>&1

  # exit function if that username is already present
  if (
    $UsernameInBitwarden
  ) {
    Write-Warning -Message "Active Directory account with username '$UsernameInBitwarden' is already present. Attempt:`r`n`tConvertTo-SecureString -String `$(Get-BitwardenPassword -un '$SamAccountName') -AsPlainText -Force"
    break
  }

  # Can now CONFIRM that Bitwarden Password Manager does not contain any credentials that match with the parameter-argument pairs supplied to the function

  # Calling the Bitwarden Secrets Manager CLI
  
  # Save to variable Project ID from Bitwarden Secrets Manager
  $BitwardenSecretsManagerProjectId = bws.exe project list --access-token $env:BWS_ACCESS_TOKEN | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenSecretsManagerProjectName} | Select-Object -ExpandProperty 'id'

  # Use bw.exe to define the secret value (generating non-locally would be ideal) and save to variable the Secret ID from Bitwarden Secrets Manager
  $BitwardenSecretsManagerSecretId = bws.exe secret create --access-token $env:BWS_ACCESS_TOKEN $BitwardenItemName $(_AutoGeneratedSecurePassword $len) $BitwardenSecretsManagerProjectId | ConvertFrom-Json | Select-Object -ExpandProperty 'id'

  # Save to separate variables the properties of the object that will eventually be used to define a new Item in Bitwarden Password Manager
  $EscapedUsername = "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName" -replace '\\','\\'
  ${bw item-name}           = '.name="%Bw_Item_Name%"' -replace '%Bw_Item_Name%',$BitwardenItemName
  ${bw item-login.username} = '.login.username="%Bw_Item_Login_Username%"' -replace '%Bw_Item_Login_Username%',$EscapedUsername
  ${bw item-login.password} = '.login.password="%Bw_Item_Login_Password%"' -replace '%Bw_Item_Login_Password%',$BitwardenSecretsManagerSecretId
  ${bw item-organizationId} = '.organizationId="%Id_of_Bw_Org%"' -replace '%Id_of_Bw_Org%',$BitwardenOrganizationId
  ${bw item-notes}          = '.notes="%Item_Notes%"' -replace '%Item_Notes%',""
  ${bw item-collectionId}   = '.collectionIds=["%id_of_Org_Collection%"]' -replace '%id_of_Org_Collection%',$CollectionId

  # Write into Bitwarden Password Manager (1) <dom>\<un> > 'username' sub-property, and (2) UUID of secret > 'password' sub-property. 
  bw.exe get template item | jq-windows-amd64.exe ${bw item-name} | jq-windows-amd64.exe ${bw item-login.username} | jq-windows-amd64.exe ${bw item-login.password} | jq-windows-amd64.exe ${bw item-organizationId} | jq-windows-amd64.exe ${bw item-notes} | jq-windows-amd64.exe ${bw item-collectionId} | bw.exe encode | bw.exe create item > $null

  # Force a sync and exit
  $RedirectedError = $(
    bw.exe sync
  ) 2>&1
}

function Get-BitwardenPassword {
  [CmdletBinding(
    ConfirmImpact         = 'Low',
    SupportsShouldProcess = $True,
    SupportsPaging        = $true,
    HelpURI               = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding     = $true
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "SamAccountName of the Active Directory user account",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('un')]
    [string]$SamAccountName,

    [Parameter(
      Position = 1,
      HelpMessage = "OPTIONAL: Name of the Item in Bitwarden.`r`nKnowing the username of the AD account is enough.",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('item')]
    [string]$BitwardenItemName,

    [Parameter(
      Position = 2,
      HelpMessage = "NetBIOS name of the Active Directory domain. This is different from the Domain Name System name of the Active Directory domain.`r`n`r`nReference from Microsoft Learn:`r`n  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('dom')]
    [string]$NetBiosNameOfActiveDirectoryDomain = $NetBiosNameOfActiveDirectoryDomain,

    [Parameter(
      Position = 3,
      HelpMessage = "Name of the organization in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('org')]
    [string]$BitwardenOrganizationName = $BitwardenOrganizationName,

    [Parameter(
      Position = 4,
      HelpMessage = "Name of the collection in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('col')]
    [string]$BitwardenPwdManagerCollectionName = $BitwardenPwdManagerCollectionName,

    [Parameter(
      Position = 5,
      HelpMessage = "Name of the project in Bitwarden Secrets Manager",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('proj')]
    [string]$BitwardenSecretsManagerProjectName = $BitwardenSecretsManagerProjectName,
    
    [Parameter(
      Position = 6,
      HelpMessage = "A machine account name and an access token value are stored in the 'username' and 'password' sub-properties of the 'login' property of an 'item' in Bitwarden Password Manager. The -AT parameter accepts the NAME of the item object that corresponds to the machine account.",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$AT = ${Machine Account 01-Access Token}
  )

  <# WTF even is strict mode? |
    Set-StrictMode -Version 3
  #>
  
  _PrerequisiteConditions

  <# Hold off on the repeated checks for whether the Bitwarden CLI status is 'unlocked' | Might be what's causing terribly slow operations |
    $RedirectedErrors = $(${Authentication Status of the Bitwarden CLI} = (bw.exe status | ConvertFrom-Json).status) 2>&1 # Save to variable the status of bw.exe

    if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {_AuthenticateIntoBitwardenPasswordManagerCLI}      # Authenticate if status is anything aside from 'unlocked'
  #>

  ($env:BWS_ACCESS_TOKEN) ??= (bw.exe get password ${Machine Account 01-Access Token})
  
  # Initialize new variable for referencing Bitwarden Organization ID
  $_Var_Name = 'BitwardenOrganizationId' 
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Bitwarden Organization ID
  $BitwardenOrganizationId = bw.exe list organizations `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenOrganizationName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no Bitwarden Organization ID produced
  if (
    -not $BitwardenOrganizationId
  ) {
    break
  }

  # Initialize new variable for referencing the Collection ID in Bitwarden Password Manager
  $_Var_Name = 'CollectionId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Collection ID from Bitwarden Password Manager
  $CollectionId = bw.exe list --organizationid $BitwardenOrganizationId org-collections `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenPwdManagerCollectionName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no collection ID produced
  if (
    -not $CollectionId
  ) {
    break
  }

  $BitwardenSecretsManagerSecretId = bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json | Select-Object -ExpandProperty 'login' | Where-Object {$_.username -eq "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName"} | Select-Object -ExpandProperty 'password'

  if (
    -not $BitwardenSecretsManagerSecretId
  ) {
    Write-Error "Bitwarden does not contain an identity with those details or the local Bitwarden Password Manager CLI needs to undergo a synchronization. Execute the line below and reattempt the query:`r`n`tbw.exe sync"
    Pause
    break
  }

  #Write-Host -ForegroundColor 'Magenta' -Object "For what reason are we not automatically converting to a secure string?"
  
  bws.exe secret get --access-token $env:BWS_ACCESS_TOKEN $BitwardenSecretsManagerSecretId | ConvertFrom-Json | Select-Object -ExpandProperty 'value'
}

Add-Type -TypeDefinition @"
   public enum PrimeMethods
   {
      Standard,
      SieveOfEratosthenes,
      SieveOfSundaram
   }
"@
function Get-PrimeNumbers {
    <#
        .SYNOPSIS
            Get Prime numbers.
        .DESCRIPTION
            This function will calculate the prime numbers from 2 to the amount specified using the
            Amount parameter. You have a choice of using three different methods to calculate the
            prime numbers; the Standard method, the Sieve Of Eratosthenes or the Sieve Of Sundaram.
        .EXAMPLE
            Get-PrimeNumbers 100
            This will list the first 100 prime numbers.
        .EXAMPLE
            Get-PrimeNumbers 100 -Method 'SieveOfEratosthenes'
            This will list the first 100 prime numbers using the Sieve Of Eratosthenes method.
        .NOTES
            These functions were translated from c# to PowerShell from a post on stackoverflow,
            written/collected by David Johnstone, but other authors were responsible for some of them.
            Author: Øyvind Kallstad
            Date: 09.05.2015
            Version: 1.0
        .LINK
            https://communary.net/2015/09/18/powershell-prime/
            http://stackoverflow.com/questions/1042902/most-elegant-way-to-generate-prime-numbers
            http://en.wikipedia.org/wiki/Sieve_of_Sundaram
            http://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
            http://en.wikipedia.org/wiki/Prime_number
    #>
    [CmdletBinding()]
    param (
        # The amount of prime numbers to get. The default value is 10.
        [Parameter(Position = 0)]
        [ValidateRange(1,[int]::MaxValue)]
        [int] $Amount = 10,

        # The method used to get the prime numbers. Choices are 'Standard', 'SieveOfEratosthenes' and 'SieveOfSundaram'.
        # The default value is 'Standard'.
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [PrimeMethods] $Method = 'Standard'
    )

    function Get-PrimeNumbersStandardMethod {
        param ([int]$Amount)

        $primes = New-Object System.Collections.ArrayList
        [void]$primes.Add(2)
        $nextPrime = 3
        while ($primes.Count -lt $Amount) {
            $squareRoot = [math]::Sqrt($nextPrime)
            $isPrime = $true
            for ($i = 0; $primes[$i] -le $squareRoot; $i++) {
                if (($nextPrime % $primes[$i]) -eq 0) {
                    $isPrime = $false
                    break
                }
            }
            if ($isPrime) {
                [void]$primes.Add($nextPrime)
            }
            $nextPrime += 2
        }
        Write-Output $primes
    }

    function Invoke-ApproximateNthPrime {
        param ([int]$nn)
        [double]$n = $nn
        [double]$p = 0
        if ($nn -ge 7022) {
            $p = $n * [math]::Log($n) + $n * ([math]::Log([math]::Log($n)) - 0.9385)
        }
        elseif ($nn -ge 6) {
            $p = $n * [math]::Log($n) + $n * [math]::Log([math]::Log($n))
        }
        elseif ($nn -gt 0) {
            $p = (2,3,5,7,11)[($nn - 1)]
        }
        Write-Output ([int]$p)
    }

    function Invoke-SieveOfEratosthenes {
        param([int]$Limit)
        $bits = New-Object -TypeName System.Collections.BitArray -ArgumentList (($Limit + 1), $true)
        $bits[0] = $false
        $bits[1] = $false
        for ($i = 0; ($i * $i) -le $Limit; $i++) {
            if ($bits[$i]) {
                for (($j = $i * $i); $j -le $Limit; $j += $i) {
                    $bits[$j] = $false
                }
            }
        }
        Write-Output (,($bits))
    }

    function Invoke-SieveOfSundaram {
        param([int]$Limit)
        $limit /= 2
        $bits = New-Object -TypeName System.Collections.BitArray -ArgumentList (($Limit + 1), $true)
        for ($i = 1; (3 * ($i + 1)) -lt $Limit; $i++) {
            for ($j = 1; ($i + $j + 2 * $i * $j) -le $Limit; $j++) {
                $bits[($i + $j + 2 * $i * $j)] = $false
            }
        }
        Write-Output (,($bits))
    }

    function Get-PrimeNumbersSieveOfEratosthenes {
        param([int]$Amount)
        $limit = Invoke-ApproximateNthPrime $Amount
        [System.Collections.BitArray]$bits = Invoke-SieveOfEratosthenes $limit
        $primes = New-Object System.Collections.ArrayList
        $found = 0
        for ($i = 0; $i -lt $limit -and $found -lt $Amount; $i++) {
            if ($bits[$i]) {
                [void]$primes.Add($i)
                $found++
            }
        }
        Write-Output $primes
    }
    function Get-PrimeNumbersSieveOfSundaram {
        param([int]$Amount)
        $limit = Invoke-ApproximateNthPrime $Amount
        [System.Collections.BitArray]$bits = Invoke-SieveOfSundaram $limit
        $primes = New-Object System.Collections.ArrayList
        [void]$primes.Add(2)
        $found = 1
        for ($i = 1; (2 * ($i + 1)) -le $limit -and $found -lt $Amount; $i++) {
            if ($bits[$i]) {
                [void]$primes.Add((2 * $i + 1))
                $found++
            }
        }
        Write-Output $primes
    }

    switch ($Method) {
        'Standard' {Get-PrimeNumbersStandardMethod $Amount;break}
        'SieveOfEratosthenes' {Get-PrimeNumbersSieveOfEratosthenes $Amount;break}
        'SieveOfSundaram' {Get-PrimeNumbersSieveOfSundaram $Amount;break}
    }
}

function New-Server2025onUnclusteredHyperVHost { # Spins up a new Hyper-V running Server 2025 |
  [CmdletBinding(
    SupportsShouldProcess   = $True,
    ConfirmImpact           = 'low',
    DefaultParameterSetName = 'DomainController',
    SupportsPaging          = $true,
    HelpURI                 = 'https://www.altaro.com/hyper-v/customize-vm-powershell/',
    PositionalBinding       = $False
  )]
  [OutputType('DomainController',[string])]
  [OutputType('MemberServer',[string])]
  [OutputType('MemberServerStaticIP',[string])]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [Parameter(
      Position = 0,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$'
    )]
    [string]
    $ip,

    [Parameter(
      Position = 1,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [Parameter(
      Position = 1,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $gw,

    [Parameter(
      Position = 2,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [Parameter(
      Position = 2,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $dns,

    [Parameter(
      Position = 3,
      ParameterSetName = 'MemberServer',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID.`r`nDistinguishedName of OUs in AD will match this regular expression:`r`n`t^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$`r`nGUIDs (aka UUIDs) will match this regular expression:`r`n`t^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`r`n`r`nCopy and paste these examples into PowerShell:`r`n`t'OU=Demonstration,OU=Of,DC=Regex,DC=Pattern,DC=Matching' -match '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$'`r`n`t(New-Guid).ToString() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'"
    )]
    [Parameter(
      Position = 3,
      ParameterSetName = 'MemberServerStaticIP',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID"
    )]
    [ValidatePattern(
      '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )]
    [string]
    $OU,

    [Parameter(
      Position = 4,
      ParameterSetName = 'MemberServer',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. 'Join2Domain0_Tier0' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [Parameter(
      Position = 4,
      ParameterSetName = 'MemberServerStaticIP',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. 'Join2Domain0_Tier0' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [ValidateSet(
      'Join2Domain0_Tier0',
      'Join2Domain0_Tier1'
    )]
    [string]
    $Acct,

    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!"
    )]
    [string]
    $Name0fVM = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Primary differences between Datacenter and Standard is that Standard does not support Storage Spaces Direct, the Hyper-V Host Guardian, the Network Controller, or running more than 2 VMs.`r`nVM deployments of Datacenter and bare-metal deployments of Standard will be rare.`r`nComprehensive feature reference:`r`n`thttps://learn.microsoft.com/en-us/windows-server/get-started/editions-comparison?pivots=windows-server-2025"
    )]
    [ValidateSet(
      'Standard',
      'StandardDesktopExperience',
      'Datacenter',
      'DatacenterDesktopExperience'
    )]
    [string]
    $Edition = 'Standard',

    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Supply name of an AD Computer object. Remember that domain controllers are ALSO AD Computer objects! Stated differently, the ObjectClass of a DC also 'computer'."
    )]
    [ValidateLength(1,15)]
    [ValidatePattern(
      '^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$'
    )]
    [string]
    $Name0fGuestOS = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Help message."
    )]
    [string]
    $hvHost = "$env:ComputerName",

    [Int32]$cpu = 2,

    [Parameter(
      HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM"
    )]
    [int64]
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,

    [Parameter(
      HelpMessage = "I dont think that uniquely naming Hyper-V virtual switches is necessary or desirable."
    )]
    [ValidateSet(
      'SET-enabled External vSwitch',
      'vSwitchNAT'
    )]
    [string]
    $net = "SET-enabled External vSwitch",

    [Parameter(
      HelpMessage = "Make sure the Hyper-V host has tons of RAM"
    )]
    [ValidateSet(
      'StartIfRunning',
      'Start',
      'Nothing'
    )]
    [string]
    $ActionWhenBareMetalHostBoots = 'Start',

    [Parameter(
      HelpMessage = "No need to right-click each row in Hyper-V Manager and select Shut Down."
    )]
    [ValidateSet(
      'Save',
      'TurnOff',
      'Shutdown'
    )]
    [string]
    $ActionOnBareMetalHostShutdown = 'Shutdown',

    [Parameter(
      Mandatory = $True,
      HelpMessage = "I should've started using unattend.xml and autounattend.xml a long, long time ago...`r`nNote for later: Come up with a PVA that matches on a regular expression for this variable."
    )]
    [string]$xml,

    [ValidateRange(1,100)]
    [Int32]
    $Buffer = 20,

    [Parameter(
      ParameterSetName = 'MemberServer',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Checkpoints and domain controllers do not mix."
    )]
    [Parameter(
      ParameterSetName = 'MemberServerStaticIP',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Checkpoints and domain controllers do not mix."
    )]
    [ValidateSet(
      'Disabled',
      'Production',
      'ProductionOnly',
      'Standard'
    )]
    [string]
    $CheckpointType = 'Standard',

    [ValidateSet(
      'Pause',
      'None'
    )]
    [string]
    $StorageDisconnectedAction = 'Pause',

    [int32]
    $HwThreadCountPerCore = '1',

    [ValidateRange(1,4096)]
    [int32]
    $VlanID,

    [Parameter(
      Position = 99,
      Mandatory = $true,
      HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]
    $Notes
  )
  
  $RedirectedError = $(${Does This VM Already Exist?} = Get-VM -Name $Name0fVM) 2>&1
  if (${Does This VM Already Exist?}) {
    Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
    break
  }

  $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
  $message01 = ".vhdx file is confirmed to be in place."
  switch ($Edition) {
    'Standard' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'Standard'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break
    }
    'StandardDesktopExperience' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'StandardDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    'Datacenter' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DataCenter'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    'DatacenterDesktopExperience' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DatacenterDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
  }

  ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
  ${Current VM Version} = (Get-VMHost).SupportedVmVersions | Where-Object {$_ -match ${Current VM Version}}

  $HT = @{
    Name               = $Name0fVM
    ComputerName       = $hvHost
    Generation         = 2
    MemoryStartupBytes = $ram
    Version            = ${Current VM Version}
  }
  try {${New VM} = Get-VM -Name $HT.Name -ErrorAction 'Stop'}catch {${New VM} = New-VM @HT}

  # Create a copy of the .vhdx file located at ${Base VHD Path}. Filename begins with name of VM and then the VM id. 
  ${Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id).vhdx"
  Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path}

  $HT = @{ # Attach VHD containing Guest OS to VM |
    VMName = $Name0fVM
    Path = ${Guest OS Disk Path}
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{
    VMName = $Name0fVM
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  ${Guest OS Disk} = Get-VMHardDiskDrive @HT
  
  $uuid1 = (New-Guid).ToString()
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$($uuid1).vhdx"
  try {${Storage1 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'} catch {${Storage1 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}

  $uuid2 = (New-Guid).ToString()
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$($uuid2).vhdx"
  try {${Storage2 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'} catch {${Storage2 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}

  ($PSCmdlet.ParameterSetName -eq 'DomainController') ? 
  (& {
    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'O' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "AD DS Vol" > $null
    Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null

    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'P' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk" > $null
    Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null
  }) : 
  (& {
    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    #Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null
    #${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage1 VHDX}.Path | Get-Disk
    #${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid1" > $null
    #${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage1" | Out-Null
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid1" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null

    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    #Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
    #${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage2 VHDX}.Path | Get-Disk
    #${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid2" > $null
    #${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage2" | Out-Null
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid2" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
  })

  $HT = @{ # Create new VHD for storage and attach to VM | 'Storage1 VHDX' |
    VMName = $Name0fVM
    Path = ${Storage1 VHDX}.Path
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '1'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{ # Create new VHD for storage and attach to VM | 'Storage2 VHDX' |
    VMName = $Name0fVM
    Path = ${Storage2 VHDX}.Path
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '2'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{ # Set memory quantity & behavior of VM |
    VMName = $Name0fVM
    DynamicMemoryEnabled = $True
    MinimumBytes = 256MB
    MaximumBytes = $ram
    Buffer = $Buffer
  }
  Set-VMMemory @HT

  $HT = @{ # VM priority when auto-launching at Hyper-V Host boot if cumulative assigned memory exhausts total physical memory |
    VMName = $Name0fVM
    Priority = '50'
  }
  Set-VMMemory @HT

  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Guest Service Interface'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Heartbeat'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Key-Value Pair Exchange'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Shutdown'
  # Member servers in a domain should sync with a DC that does not host the PDC Emulator, and non-PDCe DCs should sync with the DC that hosts the PDC Emulator.
  Disable-VMIntegrationService -VMName $Name0fVM -Name 'Time Synchronization'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'VSS'

  $HT = @{ # Quantity of vCPUs |
    VMName = $Name0fVM
    Count = $cpu
  }
  Set-VMProcessor @HT

  $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
    VMName = $Name0fVM
    Reserve = '0'
    Maximum = '100'
  }
  Set-VMProcessor @HT

  $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
    VMName = $Name0fVM
    RelativeWeight = '100'
  }
  Set-VMProcessor @HT

  $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
    VMName = $Name0fVM
    EnableHostResourceProtection = $True
  }
  Set-VMProcessor @HT

  $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false |
    VMName = $Name0fVM
    CompatibilityForMigrationEnabled = $False
  }
  Set-VMProcessor @HT

  $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
    VMName = $Name0fVM
    HwThreadCountPerCore = $HwThreadCountPerCore
  }
  Set-VMProcessor @HT

  $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
    Name = $Name0fVM
    AutomaticStartAction = $ActionWhenBareMetalHostBoots
    AutomaticStopAction = $ActionOnBareMetalHostShutdown
    AutomaticStartDelay = $(60 * ((Get-VM).Count - 1))
  }
  Set-VM @HT

  $HT = @{ # Firmware settings |
    VMName = $Name0fVM
    FirstBootDevice = ${Guest OS Disk}
    SecureBootTemplate = 'MicrosoftWindows'
    EnableSecureBoot = 'On'
  }
  Set-VMFirmware @HT

  # Dynamic Parameter Sets are the way to go
  ($PSCmdlet.ParameterSetName -eq 'DomainController') ? 
  (& { # VM Checkpoints and domain controllers don't mix |
    Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $false
  }) : 
  (& { # Automatic Checkpoints | Virtual Machine Checkpoints |
    Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $True
    Set-VM -Name $Name0fVM -CheckpointType $CheckpointType
  })

  Set-VM -VMName $Name0fVM -AutomaticCriticalErrorAction $StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120 # Automatic Response to Disconnected Storage. 

  Set-VM -VMName $Name0fVM -Notes $Notes

  ((Get-VMSwitch $net).EmbeddedTeamingEnabled) ? 
  (& {
    Get-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
    ${VM NetAdapter-SET} = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $Name0fVM
    Connect-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $Name0fVM -SwitchName $net
  }) : 
  (Connect-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM -SwitchName $net)

  Set-VMKeyProtector -VMName $Name0fVM -NewLocalKeyProtector
  Enable-VMTPM -VMName $Name0fVM

  ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
  #Mount-DiskImage -ImagePath ${Guest OS Disk Path} # > $null # requires elevated permissions # # Mount newly created .vhdx file if not using differencing disks. Shit, did I just find a use for sudo? 
  #Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
  #Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
  #Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
  $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
  $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
  $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

  #$_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | Format-Table -Autosize) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
  #$_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | Format-Table -Autosize) ?? (Import-Module -Name $_Module_Name) > $null
  
  <# Aspirations | 
    Switch statement directly below needs to be re-written. Only use PrimaryAdmin if the machine is creating the tree root domain or a child domain. 
    All other cases spin up a dummy local administrator like zzzDeleteMe.  Or is that even necessary in all other cases? 

    Is the injected password appearing in the .xml file in PLAIN TEXT!??! You gotta do something about that. 
    
    How do you securely delete the .xml file once deployment is complete? 
    Is there an entry in the unattend.xml file that forces a self-delete? Perhaps the supporting .cmd file can contain a line of code. 
  #>

    switch ($PSCmdlet.ParameterSetName) {
    'DomainController' {
      # Import XML document into an object instance of type XmlDocument
      ($XmlDocument = [xml]'<root></root>').Load($xml)

      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $Name0fGuestOS}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${Public DNS Domain}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $BitwardenOrganizationName}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $ip}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $gw}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $dns}

      # Password Injection: Autologon of 'PrimaryAdmin'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.PlainText = $false}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'PrimaryAdmin') + "Password")))}

      # Password Injection: 'Administrator'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.PlainText = $false}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'Administrator') + "AdministratorPassword")))}

      # Password Injection: 'PrimaryAdmin'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.PlainText = $false}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'PrimaryAdmin') + "Password")))}

      # Other items under the 'oobeSystem' pass
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${Public DNS Domain}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $BitwardenOrganizationName}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

      <# Investigations |
        $AltPath = "$ns\xml\unattend $(Call-DateVar).xml"
        $XmlDocument.Save($AltPath)
        code $AltPath

        $AltPath | Set-ClipBoard
        Remove-Variable 'XmlDocument'
      #>
      $XmlDocument.Save("$VHDVolume\unattend.xml")
      break
    }
    'MemberServer' {
      ($XmlDocument = [xml]'<root></root>').Load($xml)
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $Name0fGuestOS}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${Public DNS Domain}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $BitwardenOrganizationName}

      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${AD DNS}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $Acct}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $(Get-BitwardenPassword $Acct)}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${AD DNS}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $OU}
      <# Investigations |
        $AltPath = "$ns\xml\unattend $(Call-DateVar).xml"
        $XmlDocument.Save($AltPath)
        code $AltPath

        $AltPath | Set-ClipBoard
        Remove-Variable 'XmlDocument'
      #>
      $XmlDocument.Save("$VHDVolume\unattend.xml")
    }
    'Memb3rServer' {
      <#
        Set-Location -Path "$ns\GitHub\SvenGroot\GenerateAnswerFile\src\GenerateAnswerFile\bin\Debug\net8.0"
        $UniqueUnattend = "$ns\xml\unattend $(Call-DateVar).xml"
        $HT = @{
          OutputFile = $UniqueUnattend
          Install = "Preinstalled"
          ComputerName = $Name0fGuestOS
          LocalAccount = @("Administrators:BurnerAccount,$(Get-BitwardenPassword -un 'BurnerAccount')")
          DisableServerManager = $true
          JoinDomain = ${DNS Name of the Active Directory Forest Root Domain}
          JoinDomainUser = 'PrimaryAdmin'
          TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')
          JoinDomainPassword = $(Get-BitwardenPassword 'PrimaryAdmin')
          OUPath = $OU
          AutoLogonUser = 'BurnerAccount'
          AutoLogonPassword = $(Get-BitwardenPassword 'BurnerAccount')
          #FirstLogonCommand = 'ipconfig.exe /registerdns && timeout /T 0 && logoff.exe'
          FirstLogonCommand = 'ipconfig.exe /registerdns && cd\ && %SystemDrive%\Installs\Sysinternals\sdelete.exe -accepteula -nobanner %SystemDrive%\unattend.xml -p 2'
        }
        ./GenerateAnswerFile.exe @HT
        ($XmlDocument = [xml]'<root></root>').Load($UniqueUnattend)
        $XmlDocument.Save("$VHDVolume\unattend.xml") # requires elevated permissions
        Set-Location $env:SystemDrive\
      #>

      <#
      $path = "$VHDVolume\Windows\Setup\Scripts"; try {$path = Get-Item -Path $path -ErrorAction 'Stop'} catch {$path = New-Item -ItemType 'Directory' -Path $path}
      Copy-Item -Path "$lee\XmlConfigs\hostname-change_v2.ps1" -Destination "$path" -Force
      
      #>

      #      code "$path\hostname-change.ps1"
      #      $Join2Domain_Dhcp = "$lee\XmlConfigs\s2025\UnAttend 02 Domain Join with IP config via DHCP.xml"

    
      #     Set-Location "$VHDVolume\Windows\Setup\Scripts"
      #     ${C:hostname-change.ps1} -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"$($env:HashPwIddqd)" > "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      #     Set-Location -
    
      #         ${HostName Change} = Get-Content -Path "F:\Microsoft\OS\s25\Investigation 2023.1127.204958\hostname-change.ps1"
      #${HostName Change} = Get-Content -Path "$path\hostname-change_v2.ps1"

      #$escapedLocalPwIddqd = [regex]::Escape($env:LocalPwIddqd)
      #$escapedHashPwIddqd = [regex]::Escape($env:HashPwIddqd)
      #$escapedHashPwIddqd = $env:HashPwIddqd -replace '\$','\$' 
      #$escapedHashPwIddqd = $UnencryptedHashPw -replace '\$','\$' 

      ##READ## Making mistakes is the 2nd best way to learn. The 1st is learning from the mistakes of others. ##READ##
      #On 2023-11-28 I spent appx 90 minutes uncovering why my unattended domain joins were bombing out. 
      #After much investigation, the explantion was the presence of dollar signs in my password. 
      #Unescaped dollar signs were not being interpreted as literals, so PowerShell didn't treat those dollar signs as literals, and the password was incorrect. 
      #To be clear, I wouldn't have this problem if the domain-join password was being input in a secure fashion, like a CTRL + C, CTRL + V from a password manager. 
      #Assigning clear-text passwords to an user-scoped environment variable, e.g. $env:HashPwIddqd, is shit security, even 
      #if the user of that user-scoped environment variable is a highly protected account. 
      #Correct option is a digital vault like BeyondTrust Password Safe. 
      
      #${Code Block-Bytes} = [System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Join2Domain0_Tier1'))
      #${Code Block-Base64} = [System.Convert]::ToBase64String(${Code Block-Bytes})

      #[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Join2Domain0_Tier1')))


      #for ($i = 0; $i -lt ${HostName Change}.Count; $i++) {
      #  if (
      #    ${HostName Change}[$i] -match 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC'
      #  ) {
      #    ${HostName Change}[$i] = ${HostName Change}[$i] -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"'$($escapedLocalPwIddqd)'"   #  "'$($env:HashPwIddqd)'"
      #    # shit, might have to control for non-literals
      #  }
      #}
      #${HostName Change} | Set-Content -Path "$path\hostname-change_v2.ps1" -Confirm:$False -Force
      #      code "$path\hostname-change.ps1"
    
      <#
      
      ${OUPath Change} = Get-Content -Path "$path\hostname-change_v2.ps1"

      #$escapedOUPath = [regex]::Escape($OU)
      for ($j = 0; $j -lt ${OUPath Change}.Count; $j++) {
        if (
          ${OUPath Change}[$j] -match '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd'
        ) {
          ${OUPath Change}[$j] = ${OUPath Change}[$j] -replace '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd',$OU
        }
      }
      ${OUPath Change} | Set-Content -Path "$path\hostname-change_v2.ps1" -Confirm:$False -Force
      #      code "$path\hostname-change_v2.ps1"
    
      
      Copy-Item -Path $Join2Domain_Dhcp -Destination "$VHDVolume\" -Force
      [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))
      ($XmlDocument = [xml]'<root></root>').Load("$VHDVolume\$(Get-Item -Path $Join2Domain_Dhcp | Select-Object -ExpandProperty 'Name')")

      #        ($XmlDocument = [xml]'<root></root>').Load($UniqueUnattend)
      
      #        $XmlDocument.Save("$VHDVolume\unattend.xml")

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}

      # Password of the 'Administrator' account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -un 'Administrator')}}

      # Password of the 'BurnerAccount' local admin account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | Select-Object -ExpandProperty 'UserAccounts' | Select-Object -ExpandProperty 'LocalAccounts' | Select-Object -ExpandProperty 'LocalAccount' | Select-Object -ExpandProperty 'Password'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))}}

      # Password of the account for automatically logging on
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.AutoLogon.Password.Value) {$_.AutoLogon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))}}
      
      # enable DHCP client
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.IPv4Settings.DhcpEnabled = 'true'}}
      #       $XmlDocument.Save("$ns\xml\WTF.xml")              
      #       code "$ns\xml\WTF.xml"              

      $XmlDocument.Save("$VHDVolume\unattend.xml") # Copy UnAttended.xml into root of mounted VHDX file

      Copy-Item -Path "$lee\XmlConfigs\SetupComplete.cmd" -Destination "$VHDVolume\"
      #>

      break
    }
    'MemberServerStaticIP' {
            <#
      ($xml = [xml]'<root></root>').Load($UnattendXML)

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}
  
      # IPv4 address + CIDR-based subnet mask on network adapter. Will configure IPv6 after logon
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$ht = '#text'; $_.interfaces.interface.unicastIPaddresses.ipaddress.$ht = $ip}}
  
      # Default gateway address
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = $gw}}
  
      # DNS Server address -- Statically sets IP address of the server on the network that this machine will use for DNS queries. 
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client" } | ForEach-Object { if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = $dns}}

      # Password of the 'PrimaryAdmin' local admin account
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}
      
      #>


      <# For another day |
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\SetupComplete.cmd" -Destination "$VHDVolume\"
        try {Get-Item -Path "$VHDVolume\Windows\Setup\Scripts" -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path "$VHDVolume\Windows\Setup\Scripts" | Out-Null}
        # Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\hostname-change.ps1" -Destination "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\hostname-change.ps1" -Force
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\hostname-change.ps1" -Destination "$VHDVolume\Windows\Setup\Scripts"
        # Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\hostname-change.ps1" -Destination "$VHDVolume\Windows\Setup\Scripts" -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        #Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\s2025\UnAttend.DJ.xml" -Destination "$VHDVolume\"
        #Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\s2022\Unattend.DJ.xml" -Destination "$hvVol\Hyper-V Prep\XML Configs\s2022" -Force
      
        # Dang, might have to reconnect NAS each time? 

        #     Set-Location "$VHDVolume\Windows\Setup\Scripts"
        #     ${C:hostname-change.ps1} -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"$($env:HashPwIddqd)" > "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        #     Set-Location -
      
        #         ${HostName Change} = Get-Content -Path "F:\Microsoft\OS\s25\Investigation 2023.1127.204958\hostname-change.ps1"
        ${HostName Change} = Get-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        $escapedLocalPwIddqd = [regex]::Escape($env:LocalPwIddqd)
        #$escapedHashPwIddqd = [regex]::Escape($env:HashPwIddqd)
        #$escapedHashPwIddqd = $env:HashPwIddqd -replace '\$','\$' 
        #$escapedHashPwIddqd = $UnencryptedHashPw -replace '\$','\$' 

        ##READ## Making mistakes is the 2nd best way to learn. The 1st is learning from the mistakes of others. ##READ##
        #On 2023-11-28 I spent appx 90 minutes uncovering why my unattended domain joins were bombing out. 
        #After much investigation, the explantion was the presence of dollar signs in my password. 
        #Unescaped dollar signs were not being interpreted as literals, so PowerShell didn't treat those dollar signs as literals, and the password was incorrect. 
        #To be clear, I wouldn't have this problem if the domain-join password was being input in a secure fashion, like a CTRL + C, CTRL + V from a password manager. 
        #Assigning clear-text passwords to an user-scoped environment variable, e.g. $env:HashPwIddqd, is shit security, even 
        #if the user of that user-scoped environment variable is a highly protected account. 
        #Correct option is a digital vault like BeyondTrust Password Safe. 

        for ($i = 0; $i -lt ${HostName Change}.Count; $i++) {
          if (
            ${HostName Change}[$i] -match 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC'
          ) {
            ${HostName Change}[$i] = ${HostName Change}[$i] -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"'$($escapedLocalPwIddqd)'"   #  "'$($env:HashPwIddqd)'"
            # shit, might have to control for non-literals
          }
        }
        ${HostName Change} | Set-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1" -Confirm:$False -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      
        ${OUPath Change} = Get-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        $escapedOUPath = [regex]::Escape($OUPath)
        for ($j = 0; $j -lt ${OUPath Change}.Count; $j++) {
          if (
            ${OUPath Change}[$j] -match '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd'
          ) {
            ${OUPath Change}[$j] = ${OUPath Change}[$j] -replace '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd',$OUPath
          }
        }
        ${OUPath Change} | Set-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1" -Confirm:$False -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      
        ($xml = [xml]'<root></root>').Load($UnattendDJXML)
        $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | % {if ($_.ComputerName) {$_.ComputerName = $Name0fGuestOS}} # Set Guest OS %HostName% equal to $Name0fGuestOS
        $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.IPv4Settings.DhcpEnabled = 'true'}}
        $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = ''}}
        $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | % {if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = ''}}
        $xml.Save("$VHDVolume\unattend.xml") # Copy UnAttended.xml into root of mounted VHDX file
      #>

      # Copy UnAttended.xml into root of mounted VHDX file
      #$xml.Save("$VHDVolume\unattend.xml")

      break
    }
  }

  $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $pwsh7MSI = Get-ChildItem -Path "$env:SystemDrive\Installs\PowerShell 7" -Filter PowerShell*x64.msi -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
  Copy-Item -Path "$pwsh7MSI" -Destination "$dir"

  $dir = "$VHDVolume\Installs\OneDrive"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $OneDriveEXE = Get-Item -Path "$env:SystemDrive\Installs\OneDrive\OneDriveSetup.exe"
  Copy-Item -Path "$OneDriveEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\VS Code"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $VSCodeEXE = Get-Item -Path "$env:SystemDrive\Installs\VSCodeSetup-x64-*.exe"
  Copy-Item -Path "$VSCodeEXE" -Destination "$dir"

  try {
    Copy-Item -Path "$up\sysint\sdelete.exe" -Destination "$VHDVolume\" -ErrorAction 'Stop'
  } 
  catch {
    Invoke-WebRequest -Uri 'http://live.sysinternals.com/sdelete.exe' -OutFile "$VHDVolume\sdelete.exe"
  }

  Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
  Start-VM -Name $Name0fVM | Out-Null
  return $Name0fGuestOS

  <# Delete all children of VirtualHardDiskPath |
    Get-VM | Remove-VM -Force
    Get-ChildItem -Path (Get-VMHost).VirtualHardDiskPath -Recurse -File -Exclude "Server 2025*.vhdx" | Select-Object -ExpandProperty 'FullName' | Remove-Item -Force
    Get-ChildItem -Path (Get-VMHost).VirtualHardDiskPath -Recurse -Directory | Select-Object -ExpandProperty 'FullName' | Remove-Item -Force
  #>
}


function New-Server2025onZotacZboxMI642nano { # Spins up a new Hyper-V running Server 2025 |
  [CmdletBinding(
    SupportsShouldProcess   = $True,
    ConfirmImpact           = 'low',
    DefaultParameterSetName = 'DomainController',
    SupportsPaging          = $true,
    HelpURI                 = 'https://www.altaro.com/hyper-v/customize-vm-powershell/',
    PositionalBinding       = $False
  )]
  [OutputType('DomainController',[string])]
  [OutputType('MemberServer',[string])]
  [OutputType('MemberServerStaticIP',[string])]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [Parameter(
      Position = 0,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$'
    )]
    [string]
    $ip,

    [Parameter(
      Position = 1,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [Parameter(
      Position = 1,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $gw,

    [Parameter(
      Position = 2,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [Parameter(
      Position = 2,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $dns,

    [Parameter(
      Position = 3,
      ParameterSetName = 'MemberServer',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID.`r`nDistinguishedName of OUs in AD will match this regular expression:`r`n`t^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$`r`nGUIDs (aka UUIDs) will match this regular expression:`r`n`t^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`r`n`r`nCopy and paste these examples into PowerShell:`r`n`t'OU=Demonstration,OU=Of,DC=Regex,DC=Pattern,DC=Matching' -match '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$'`r`n`t(New-Guid).ToString() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'"
    )]
    [Parameter(
      Position = 3,
      ParameterSetName = 'MemberServerStaticIP',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID"
    )]
    [ValidatePattern(
      '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )]
    [string]
    $OU,

    [Parameter(
      Position = 4,
      ParameterSetName = 'MemberServer',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. 'Join2Domain0_Tier0' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [Parameter(
      Position = 4,
      ParameterSetName = 'MemberServerStaticIP',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. 'Join2Domain0_Tier0' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [ValidateSet(
      'Join2Domain0_Tier0',
      'Join2Domain0_Tier1'
    )]
    [string]
    $Acct,

    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!"
    )]
    [string]
    $Name0fVM = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Primary differences between Datacenter and Standard is that Standard does not support Storage Spaces Direct, the Hyper-V Host Guardian, the Network Controller, or running more than 2 VMs.`r`nVM deployments of Datacenter and bare-metal deployments of Standard will be rare.`r`nComprehensive feature reference:`r`n`thttps://learn.microsoft.com/en-us/windows-server/get-started/editions-comparison?pivots=windows-server-2025"
    )]
    [ValidateSet(
      'Standard',
      'StandardDesktopExperience',
      'Datacenter',
      'DatacenterDesktopExperience'
    )]
    [string]
    $Edition = 'Standard',

    <# -Kind | Delete when the time is right |
      [Parameter(
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = "Standalone non-domain instances of Windows Server in this lab are not currently supported."
      )]
      [ValidateSet(
        'DomainController',
        'MemberServer',
        'MemberServerStaticIP'
      )]
      [string]
      $Kind = 'MemberServer',
    #>

    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Supply name of an AD Computer object. Remember that domain controllers are ALSO AD Computer objects! Stated differently, the ObjectClass of a DC also 'computer'."
    )]
    [ValidateLength(1,15)]
    [ValidatePattern(
      '^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$'
    )]
    [string]
    $Name0fGuestOS = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Help message."
    )]
    [string]
    $hvHost = "$env:ComputerName",

    [Int32]$cpu = 2,

    [Parameter(
      HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM"
    )]
    [int64]
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,

    [Parameter(
      HelpMessage = "I dont think that uniquely naming Hyper-V virtual switches is necessary or desirable."
    )]
    [ValidateSet(
      'SET-enabled External vSwitch',
      'vSwitchNAT',
      'Isolated vSwitch'
    )]
    [string]
    $net = "SET-enabled External vSwitch",

    [Parameter(
      HelpMessage = "Make sure the Hyper-V host has tons of RAM"
    )]
    [ValidateSet(
      'StartIfRunning',
      'Start',
      'Nothing'
    )]
    [string]
    $ActionWhenBareMetalHostBoots = 'Start',

    [Parameter(
      HelpMessage = "No need to right-click each row in Hyper-V Manager and select Shut Down."
    )]
    [ValidateSet(
      'Save',
      'TurnOff',
      'Shutdown'
    )]
    [string]
    $ActionOnBareMetalHostShutdown = 'Shutdown',

    [Parameter(
      Mandatory = $True,
      HelpMessage = "I should've started using unattend.xml and autounattend.xml a long, long time ago...`r`nNote for later: Come up with a PVA that matches on a regular expression for this variable."
    )]
    [string]$xml,

    [ValidateRange(1,100)]
    [Int32]
    $Buffer = 20,

    [Parameter(
      ParameterSetName = 'MemberServer',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Checkpoints and domain controllers do not mix."
    )]
    [Parameter(
      ParameterSetName = 'MemberServerStaticIP',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Checkpoints and domain controllers do not mix."
    )]
    [ValidateSet(
      'Disabled',
      'Production',
      'ProductionOnly',
      'Standard'
    )]
    [string]
    $CheckpointType = 'Standard',

    [ValidateSet(
      'Pause',
      'None'
    )]
    [string]
    $StorageDisconnectedAction = 'Pause',

    [int32]
    $HwThreadCountPerCore = '1',

    [ValidateRange(1,4096)]
    [int32]
    $VlanID, # Hopefully this won't stay a mystery for long. 

    [Parameter(
      Position = 99,
      Mandatory = $true,
      HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]
    $Notes
  )

  <# Aspirations |
    - There's gotta be a PVA or something that exits the function if the environment isn't right. Detecting Windows Home edition or absence of Hyper-V should cause the function to fail. 
  #>

  <# Trials |
    $Name0fUcFs01Vm = "03.00 FS-App Deployment"
    $Name0fVm = $Name0fUcFs01Vm
    $Edition = 'Standard'
    $Notes = "Unclustered FS for the deployment of application installation files via GPO. DNS CNAME resource record = 'UcFs01'"

    $xml = "$IT1\cfg\wsim\Server 2025\non-DCs\1\tier1\unattend06.xml" # 
    $xml = "$IT1\cfg\wsim\Server 2025\non-DCs\1\tier1\unattend07.xml" # 07 is missing the AutoLogon items from the 'Microsoft-Windows-Shell-Setup' component of the 'oobeSystem' configuration pass
    $xml = "$IT1\cfg\wsim\Server 2025\non-DCs\1\tier1\unattend08.xml" # 08 is missing the entire 'Microsoft-Windows-Deployment' component from the 'specialize' configuration pass
    $xml = "$IT1\cfg\wsim\Server 2025\non-DCs\1\tier1\unattend09.xml" # 09 tears out the PowerShell code in the Extension brackets

    $Name0fGuestOS = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper()
    $hvHost = "$env:ComputerName"
    $OU = "OU=FS,OU=Tier 1 Servers,DC=ad,DC=kerberosnetworks,DC=com"
    $Acct = 'Join2Domain0_Tier1'
    $cpu = 2
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB
    $Buffer = 20
    #$ip = '10.44.10.19/23'
    #$gw = '10.44.11.2'
    #$dns = '8.8.8.8'
    $net = "SET-enabled External vSwitch"
    #$net = "vSwitchNAT"
    $ActionWhenBareMetalHostBoots = 'Start'
    $ActionOnBareMetalHostShutdown = 'Shutdown'
    $CheckpointType = 'Standard' # 'Disabled'
    $StorageDisconnectedAction = 'Pause'
    $HwThreadCountPerCore = 1;    
  #>

  <# Aspiration | Format of OU is confirmed. Now verify the OU exists |
    Write-Host -ForeGroundColor 'Cyan' -Object "  Define an appropriately permissioned AD account that can read Organizational Units"
    if (
      ($Kind -eq 'MemberServer') -or ($Kind -eq 'MemberServerStaticIP')
    ) {
      $NetBiosNameOfActiveDirectoryDomain = 'KNet'
      $DnsNameOfActiveDirectoryDomain = "ad.kerberosnetworks.com"
      $_Var_Name = 'OUReaderCred'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
      $SamAccountName = '_ouReader0'; if (!($OUReaderCred)) {$OUReaderCred = [PSCredential]::New("$NetBiosNameOfActiveDirectoryDomain\$SamAccountName",$(ConvertTo-SecureString -String $(Get-BitwardenPassword $SamAccountName) -AsPlainText -Force))}

      $RandomSelection = New-Object -TypeName 'System.Random'
      $IPs = Resolve-DnsName $DnsNameOfActiveDirectoryDomain | Select-Object -ExpandProperty 'IPAddress'
      $Name0fDC = Resolve-DnsName -Name $IPs[$RandomSelection.Next(0,$IPs.Count)] -Type 'Ptr' | Select-Object -ExpandProperty 'NameHost'
      #$cred = @{Server = $Name0fDC; Credential = $OUReaderCred}
      ($DomainDN),(${AD DNS}) = (Get-ADDomain | Select-Object -ExpandProperty 'DistinguishedName'),(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')
      try {${DC OUReader} = Get-PSSession -Name "$Name0fDC $SamAccountName" -ErrorAction 'Stop'} catch {${DC OUReader} = New-PSSession -CN $Name0fDC -Name "$Name0fDC $SamAccountName" @l0gin; icm -Session ${DC OUReader} @start; icm -Session ${DC OUReader} {Set-Location \; Clear-Host}}
      $adVol = icm -Session ${DC OUReader} {$adVol}

      try {Get-ADOrganizationalUnit -Identity $OU -ErrorAction 'Stop'} catch {}
    }
  #>
  
  $RedirectedError = $(${Does This VM Already Exist?} = Get-VM -Name $Name0fVM) 2>&1
  if (${Does This VM Already Exist?}) {
    Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
    break
  }

  $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
  $message01 = ".vhdx file is confirmed to be in place."
  switch ($Edition) {
    'Standard' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'Standard'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break
    }
    'StandardDesktopExperience' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'StandardDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    'Datacenter' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DataCenter'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    'DatacenterDesktopExperience' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DatacenterDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
  }

  <# Delete when the time is right |
    switch ($Kind) {
      'DomainController' {
        $IsDomainController = $True
        break
      }
      default {
        $IsDomainController = $False
        break
      }
    }
  #>

  ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
  ${Current VM Version} = (Get-VMHost).SupportedVmVersions | Where-Object {$_ -match ${Current VM Version}}

  $HT = @{
    Name               = $Name0fVM
    ComputerName       = $hvHost
    Generation         = 2
    MemoryStartupBytes = $ram
    Version            = ${Current VM Version}
  }
  try {
    ${New VM} = Get-VM -Name $HT.Name -ErrorAction 'Stop'
  }
  catch {
    ${New VM} = New-VM @HT
  }

  # Create a copy of the .vhdx file located at ${Base VHD Path}. Filename begins with name of VM and then the VM id. 
  ${Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id).vhdx"
  Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path}

  $HT = @{ # Attach VHD containing Guest OS to VM |
    VMName = $Name0fVM
    Path = ${Guest OS Disk Path}
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{
    VMName = $Name0fVM
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  ${Guest OS Disk} = Get-VMHardDiskDrive @HT
  
  $uuid1 = (New-Guid).ToString()
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$($uuid1).vhdx"
  try {${Storage1 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'} catch {${Storage1 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}

  $uuid2 = (New-Guid).ToString()
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$($uuid2).vhdx"
  try {${Storage2 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'} catch {${Storage2 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}

  ($PSCmdlet.ParameterSetName -eq 'DomainController') ? 
  (& {
    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'O' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "AD DS Vol" > $null
    Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null

    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'P' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk" > $null
    Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null
  }) : 
  (& {
    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    #Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null
    #${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage1 VHDX}.Path | Get-Disk
    #${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid1" > $null
    #${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage1" | Out-Null
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid1" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null

    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    #Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
    #${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage2 VHDX}.Path | Get-Disk
    #${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid2" > $null
    #${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage2" | Out-Null
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid2" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
  })

  $HT = @{ # Create new VHD for storage and attach to VM | 'Storage1 VHDX' |
    VMName = $Name0fVM
    Path = ${Storage1 VHDX}.Path
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '1'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{ # Create new VHD for storage and attach to VM | 'Storage2 VHDX' |
    VMName = $Name0fVM
    Path = ${Storage2 VHDX}.Path
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '2'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{ # Set memory quantity & behavior of VM |
    VMName = $Name0fVM
    DynamicMemoryEnabled = $True
    MinimumBytes = 256MB
    MaximumBytes = $ram
    Buffer = $Buffer
  }
  Set-VMMemory @HT

  $HT = @{ # VM priority when auto-launching at Hyper-V Host boot if cumulative assigned memory exhausts total physical memory |
    VMName = $Name0fVM
    Priority = '50'
  }
  Set-VMMemory @HT

    Enable-VMIntegrationService -VMName $Name0fVM -Name 'Guest Service Interface'
    Enable-VMIntegrationService -VMName $Name0fVM -Name 'Heartbeat'
    Enable-VMIntegrationService -VMName $Name0fVM -Name 'Key-Value Pair Exchange'
    Enable-VMIntegrationService -VMName $Name0fVM -Name 'Shutdown'
    # Member servers in a domain should sync with a DC that does not host the PDC Emulator, and non-PDCe DCs should sync with the DC that hosts the PDC Emulator.
    Disable-VMIntegrationService -VMName $Name0fVM -Name 'Time Synchronization'
    Enable-VMIntegrationService -VMName $Name0fVM -Name 'VSS'

  $HT = @{ # Quantity of vCPUs |
    VMName = $Name0fVM
    Count = $cpu
  }
  Set-VMProcessor @HT

  $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
    VMName = $Name0fVM
    Reserve = '0'
    Maximum = '100'
  }
  Set-VMProcessor @HT

  $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
    VMName = $Name0fVM
    RelativeWeight = '100'
  }
  Set-VMProcessor @HT

  $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
    VMName = $Name0fVM
    EnableHostResourceProtection = $True
  }
  Set-VMProcessor @HT

  $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false |
    VMName = $Name0fVM
    CompatibilityForMigrationEnabled = $False
  }
  Set-VMProcessor @HT

  $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
    VMName = $Name0fVM
    HwThreadCountPerCore = $HwThreadCountPerCore
  }
  Set-VMProcessor @HT

  $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
    Name = $Name0fVM
    AutomaticStartAction = $ActionWhenBareMetalHostBoots
    AutomaticStopAction = $ActionOnBareMetalHostShutdown
    AutomaticStartDelay = $(60 * ((Get-VM).Count - 1))
  }
  Set-VM @HT

  $HT = @{ # Firmware settings |
    VMName = $Name0fVM
    FirstBootDevice = ${Guest OS Disk}
    SecureBootTemplate = 'MicrosoftWindows'
    EnableSecureBoot = 'On'
  }
  Set-VMFirmware @HT

  # Dynamic Parameter Sets are the way to go
  ($PSCmdlet.ParameterSetName -eq 'DomainController') ? 
  (& { # VM Checkpoints and domain controllers don't mix |
    Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $false
  }) : 
  (& { # Automatic Checkpoints | Virtual Machine Checkpoints |
    Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $True
    Set-VM -Name $Name0fVM -CheckpointType $CheckpointType
  })

  Set-VM -VMName $Name0fVM -AutomaticCriticalErrorAction $StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120 # Automatic Response to Disconnected Storage. 

  Set-VM -VMName $Name0fVM -Notes $Notes

  ((Get-VMSwitch $net).EmbeddedTeamingEnabled) ? 
  (& {
    $NewName = "eth0-SET" # "Network Adapter-SET"
    Get-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM | Rename-VMNetworkAdapter -NewName $NewName
    ${VM NetAdapter-SET} = Get-VMNetworkAdapter -Name $NewName -VMName $Name0fVM
    Connect-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $Name0fVM -SwitchName $net
  }) : 
  (& {
    $NewName = "eth0"
    Get-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM | Rename-VMNetworkAdapter -NewName $NewName
    ${VM NetAdapter} = Get-VMNetworkAdapter -Name $NewName -VMName $Name0fVM
    Connect-VMNetworkAdapter -Name ${VM NetAdapter}.Name -VMName $Name0fVM -SwitchName $net
  })

  Set-VMKeyProtector -VMName $Name0fVM -NewLocalKeyProtector
  Enable-VMTPM -VMName $Name0fVM

  ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
  #Mount-DiskImage -ImagePath ${Guest OS Disk Path} # > $null # requires elevated permissions # # Mount newly created .vhdx file if not using differencing disks. Shit, did I just find a use for sudo? 
  #Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
  #Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
  #Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
  $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
  $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
  $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

  #$_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | Format-Table -Autosize) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
  #$_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | Format-Table -Autosize) ?? (Import-Module -Name $_Module_Name) > $null
  
  <# Aspirations | 
    Switch statement directly below needs to be re-written. Only use PrimaryAdmin if the machine is creating the tree root domain or a child domain. 
    All other cases spin up a dummy local administrator like zzzDeleteMe.  Or is that even necessary in all other cases? 

    Is the injected password appearing in the .xml file in PLAIN TEXT!??! You gotta do something about that. 
    
    How do you securely delete the .xml file once deployment is complete? 
    Is there an entry in the unattend.xml file that forces a self-delete? Perhaps the supporting .cmd file can contain a line of code. 
  #>

  switch ($PSCmdlet.ParameterSetName) {
    'DomainController' {
      # Import XML document into an object instance of type XmlDocument
      ($XmlDocument = [xml]'<root></root>').Load($xml)

      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $Name0fGuestOS}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${Public DNS Domain}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $BitwardenOrganizationName}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $ip}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $gw}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $dns}

      # Password Injection: Autologon of 'PrimaryAdmin'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.PlainText = $false}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'PrimaryAdmin') + "Password")))}

      # Password Injection: 'Administrator'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.PlainText = $false}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'Administrator') + "AdministratorPassword")))}

      # Password Injection: 'PrimaryAdmin'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.PlainText = $false}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'PrimaryAdmin') + "Password")))}

      # Other items under the 'oobeSystem' pass
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${Public DNS Domain}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $BitwardenOrganizationName}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

      <# Investigations |
        $AltPath = "$ns\xml\unattend $(Call-DateVar).xml"
        $XmlDocument.Save($AltPath)
        code $AltPath

        $AltPath | Set-ClipBoard
        Remove-Variable 'XmlDocument'
      #>
      $XmlDocument.Save("$VHDVolume\unattend.xml")
      break
    }
    'MemberServer' {
      ($XmlDocument = [xml]'<root></root>').Load($xml)
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $Name0fGuestOS}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${Public DNS Domain}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $BitwardenOrganizationName}

      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${AD DNS}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $Acct}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $(Get-BitwardenPassword $Acct)}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${AD DNS}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $OU}
      <# Investigations |
        $AltPath = "$ns\xml\unattend $(Call-DateVar).xml"
        $XmlDocument.Save($AltPath)
        code $AltPath

        $AltPath | Set-ClipBoard
        Remove-Variable 'XmlDocument'
      #>
      $XmlDocument.Save("$VHDVolume\unattend.xml")
    }
    'Memb3rServer' {
      <#
        Set-Location -Path "$ns\GitHub\SvenGroot\GenerateAnswerFile\src\GenerateAnswerFile\bin\Debug\net8.0"
        $UniqueUnattend = "$ns\xml\unattend $(Call-DateVar).xml"
        $HT = @{
          OutputFile = $UniqueUnattend
          Install = "Preinstalled"
          ComputerName = $Name0fGuestOS
          LocalAccount = @("Administrators:BurnerAccount,$(Get-BitwardenPassword -un 'BurnerAccount')")
          DisableServerManager = $true
          JoinDomain = ${DNS Name of the Active Directory Forest Root Domain}
          JoinDomainUser = 'PrimaryAdmin'
          TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')
          JoinDomainPassword = $(Get-BitwardenPassword 'PrimaryAdmin')
          OUPath = $OU
          AutoLogonUser = 'BurnerAccount'
          AutoLogonPassword = $(Get-BitwardenPassword 'BurnerAccount')
          #FirstLogonCommand = 'ipconfig.exe /registerdns && timeout /T 0 && logoff.exe'
          FirstLogonCommand = 'ipconfig.exe /registerdns && cd\ && %SystemDrive%\Installs\Sysinternals\sdelete.exe -accepteula -nobanner %SystemDrive%\unattend.xml -p 2'
        }
        ./GenerateAnswerFile.exe @HT
        ($XmlDocument = [xml]'<root></root>').Load($UniqueUnattend)
        $XmlDocument.Save("$VHDVolume\unattend.xml") # requires elevated permissions
        Set-Location $env:SystemDrive\
      #>

      <#
      $path = "$VHDVolume\Windows\Setup\Scripts"; try {$path = Get-Item -Path $path -ErrorAction 'Stop'} catch {$path = New-Item -ItemType 'Directory' -Path $path}
      Copy-Item -Path "$lee\XmlConfigs\hostname-change_v2.ps1" -Destination "$path" -Force
      
      #>

      #      code "$path\hostname-change.ps1"
      #      $Join2Domain_Dhcp = "$lee\XmlConfigs\s2025\UnAttend 02 Domain Join with IP config via DHCP.xml"

    
      #     Set-Location "$VHDVolume\Windows\Setup\Scripts"
      #     ${C:hostname-change.ps1} -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"$($env:HashPwIddqd)" > "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      #     Set-Location -
    
      #         ${HostName Change} = Get-Content -Path "F:\Microsoft\OS\s25\Investigation 2023.1127.204958\hostname-change.ps1"
      #${HostName Change} = Get-Content -Path "$path\hostname-change_v2.ps1"

      #$escapedLocalPwIddqd = [regex]::Escape($env:LocalPwIddqd)
      #$escapedHashPwIddqd = [regex]::Escape($env:HashPwIddqd)
      #$escapedHashPwIddqd = $env:HashPwIddqd -replace '\$','\$' 
      #$escapedHashPwIddqd = $UnencryptedHashPw -replace '\$','\$' 

      ##READ## Making mistakes is the 2nd best way to learn. The 1st is learning from the mistakes of others. ##READ##
      #On 2023-11-28 I spent appx 90 minutes uncovering why my unattended domain joins were bombing out. 
      #After much investigation, the explantion was the presence of dollar signs in my password. 
      #Unescaped dollar signs were not being interpreted as literals, so PowerShell didn't treat those dollar signs as literals, and the password was incorrect. 
      #To be clear, I wouldn't have this problem if the domain-join password was being input in a secure fashion, like a CTRL + C, CTRL + V from a password manager. 
      #Assigning clear-text passwords to an user-scoped environment variable, e.g. $env:HashPwIddqd, is shit security, even 
      #if the user of that user-scoped environment variable is a highly protected account. 
      #Correct option is a digital vault like BeyondTrust Password Safe. 
      
      #${Code Block-Bytes} = [System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Join2Domain0_Tier1'))
      #${Code Block-Base64} = [System.Convert]::ToBase64String(${Code Block-Bytes})

      #[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Join2Domain0_Tier1')))


      #for ($i = 0; $i -lt ${HostName Change}.Count; $i++) {
      #  if (
      #    ${HostName Change}[$i] -match 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC'
      #  ) {
      #    ${HostName Change}[$i] = ${HostName Change}[$i] -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"'$($escapedLocalPwIddqd)'"   #  "'$($env:HashPwIddqd)'"
      #    # shit, might have to control for non-literals
      #  }
      #}
      #${HostName Change} | Set-Content -Path "$path\hostname-change_v2.ps1" -Confirm:$False -Force
      #      code "$path\hostname-change.ps1"
    
      <#
      
      ${OUPath Change} = Get-Content -Path "$path\hostname-change_v2.ps1"

      #$escapedOUPath = [regex]::Escape($OU)
      for ($j = 0; $j -lt ${OUPath Change}.Count; $j++) {
        if (
          ${OUPath Change}[$j] -match '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd'
        ) {
          ${OUPath Change}[$j] = ${OUPath Change}[$j] -replace '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd',$OU
        }
      }
      ${OUPath Change} | Set-Content -Path "$path\hostname-change_v2.ps1" -Confirm:$False -Force
      #      code "$path\hostname-change_v2.ps1"
    
      
      Copy-Item -Path $Join2Domain_Dhcp -Destination "$VHDVolume\" -Force
      [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))
      ($XmlDocument = [xml]'<root></root>').Load("$VHDVolume\$(Get-Item -Path $Join2Domain_Dhcp | Select-Object -ExpandProperty 'Name')")

      #        ($XmlDocument = [xml]'<root></root>').Load($UniqueUnattend)
      
      #        $XmlDocument.Save("$VHDVolume\unattend.xml")

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}

      # Password of the 'Administrator' account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -un 'Administrator')}}

      # Password of the 'BurnerAccount' local admin account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | Select-Object -ExpandProperty 'UserAccounts' | Select-Object -ExpandProperty 'LocalAccounts' | Select-Object -ExpandProperty 'LocalAccount' | Select-Object -ExpandProperty 'Password'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))}}

      # Password of the account for automatically logging on
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.AutoLogon.Password.Value) {$_.AutoLogon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))}}
      
      # enable DHCP client
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.IPv4Settings.DhcpEnabled = 'true'}}
      #       $XmlDocument.Save("$ns\xml\WTF.xml")              
      #       code "$ns\xml\WTF.xml"              

      $XmlDocument.Save("$VHDVolume\unattend.xml") # Copy UnAttended.xml into root of mounted VHDX file

      Copy-Item -Path "$lee\XmlConfigs\SetupComplete.cmd" -Destination "$VHDVolume\"
      #>

      break
    }
    'MemberServerStaticIP' {
            <#
      ($xml = [xml]'<root></root>').Load($UnattendXML)

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}
  
      # IPv4 address + CIDR-based subnet mask on network adapter. Will configure IPv6 after logon
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$ht = '#text'; $_.interfaces.interface.unicastIPaddresses.ipaddress.$ht = $ip}}
  
      # Default gateway address
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = $gw}}
  
      # DNS Server address -- Statically sets IP address of the server on the network that this machine will use for DNS queries. 
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client" } | ForEach-Object { if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = $dns}}

      # Password of the 'PrimaryAdmin' local admin account
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}
      
      #>


      <# For another day |
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\SetupComplete.cmd" -Destination "$VHDVolume\"
        try {Get-Item -Path "$VHDVolume\Windows\Setup\Scripts" -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path "$VHDVolume\Windows\Setup\Scripts" | Out-Null}
        # Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\hostname-change.ps1" -Destination "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\hostname-change.ps1" -Force
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\hostname-change.ps1" -Destination "$VHDVolume\Windows\Setup\Scripts"
        # Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\hostname-change.ps1" -Destination "$VHDVolume\Windows\Setup\Scripts" -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        #Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\s2025\UnAttend.DJ.xml" -Destination "$VHDVolume\"
        #Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\s2022\Unattend.DJ.xml" -Destination "$hvVol\Hyper-V Prep\XML Configs\s2022" -Force
      
        # Dang, might have to reconnect NAS each time? 

        #     Set-Location "$VHDVolume\Windows\Setup\Scripts"
        #     ${C:hostname-change.ps1} -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"$($env:HashPwIddqd)" > "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        #     Set-Location -
      
        #         ${HostName Change} = Get-Content -Path "F:\Microsoft\OS\s25\Investigation 2023.1127.204958\hostname-change.ps1"
        ${HostName Change} = Get-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        $escapedLocalPwIddqd = [regex]::Escape($env:LocalPwIddqd)
        #$escapedHashPwIddqd = [regex]::Escape($env:HashPwIddqd)
        #$escapedHashPwIddqd = $env:HashPwIddqd -replace '\$','\$' 
        #$escapedHashPwIddqd = $UnencryptedHashPw -replace '\$','\$' 

        ##READ## Making mistakes is the 2nd best way to learn. The 1st is learning from the mistakes of others. ##READ##
        #On 2023-11-28 I spent appx 90 minutes uncovering why my unattended domain joins were bombing out. 
        #After much investigation, the explantion was the presence of dollar signs in my password. 
        #Unescaped dollar signs were not being interpreted as literals, so PowerShell didn't treat those dollar signs as literals, and the password was incorrect. 
        #To be clear, I wouldn't have this problem if the domain-join password was being input in a secure fashion, like a CTRL + C, CTRL + V from a password manager. 
        #Assigning clear-text passwords to an user-scoped environment variable, e.g. $env:HashPwIddqd, is shit security, even 
        #if the user of that user-scoped environment variable is a highly protected account. 
        #Correct option is a digital vault like BeyondTrust Password Safe. 

        for ($i = 0; $i -lt ${HostName Change}.Count; $i++) {
          if (
            ${HostName Change}[$i] -match 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC'
          ) {
            ${HostName Change}[$i] = ${HostName Change}[$i] -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"'$($escapedLocalPwIddqd)'"   #  "'$($env:HashPwIddqd)'"
            # shit, might have to control for non-literals
          }
        }
        ${HostName Change} | Set-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1" -Confirm:$False -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      
        ${OUPath Change} = Get-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        $escapedOUPath = [regex]::Escape($OUPath)
        for ($j = 0; $j -lt ${OUPath Change}.Count; $j++) {
          if (
            ${OUPath Change}[$j] -match '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd'
          ) {
            ${OUPath Change}[$j] = ${OUPath Change}[$j] -replace '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd',$OUPath
          }
        }
        ${OUPath Change} | Set-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1" -Confirm:$False -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      
        ($xml = [xml]'<root></root>').Load($UnattendDJXML)
        $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | % {if ($_.ComputerName) {$_.ComputerName = $Name0fGuestOS}} # Set Guest OS %HostName% equal to $Name0fGuestOS
        $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.IPv4Settings.DhcpEnabled = 'true'}}
        $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = ''}}
        $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | % {if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = ''}}
        $xml.Save("$VHDVolume\unattend.xml") # Copy UnAttended.xml into root of mounted VHDX file
      #>

      # Copy UnAttended.xml into root of mounted VHDX file
      #$xml.Save("$VHDVolume\unattend.xml")

      break
    }
  }

  $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $pwsh7MSI = Get-ChildItem -Path "$env:SystemDrive\Installs\PowerShell 7" -Filter "PowerShell*x64.msi" -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
  Copy-Item -Path "$pwsh7MSI" -Destination "$dir" -Force

  $dir = "$VHDVolume\Installs\OneDrive"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $OneDriveEXE = Get-Item -Path "$env:SystemDrive\Installs\OneDrive\OneDriveSetup.exe"
  Copy-Item -Path "$OneDriveEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\VS Code"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $VSCodeEXE = Get-Item -Path "$env:SystemDrive\Installs\VSCodeSetup-x64-*.exe"
  Copy-Item -Path "$VSCodeEXE" -Destination "$dir"

  try {
    Copy-Item -Path "$up\sysint\sdelete.exe" -Destination "$VHDVolume\" -ErrorAction 'Stop'
  } 
  catch {
    Invoke-WebRequest -Uri 'http://live.sysinternals.com/sdelete.exe' -OutFile "$VHDVolume\sdelete.exe"
  }

  $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $pwsh7MSI = Get-ChildItem -Path "$env:SystemDrive\Installs\PowerShell 7" -Filter "PowerShell*x64.msi" -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
  Copy-Item -Path "$pwsh7MSI" -Destination "$dir" -Force

  Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
  Start-VM -Name $Name0fVM | Out-Null
  return $Name0fGuestOS

  <# Delete all children of VirtualHardDiskPath |
    Get-VM | Remove-VM -Force
    Get-ChildItem -Path (Get-VMHost).VirtualHardDiskPath -Recurse -File -Exclude "Server 2025*.vhdx" | Select-Object -ExpandProperty 'FullName' | Remove-Item -Force
    Get-ChildItem -Path (Get-VMHost).VirtualHardDiskPath -Recurse -Directory | Select-Object -ExpandProperty 'FullName' | Remove-Item -Force
  #>
}


function New-Server2025viaPwshRemoting {
  [CmdletBinding(
    DefaultParameterSetName = 'Member Server',
    ConfirmImpact = 'low',
    HelpURI = 'https://www.altaro.com/hyper-v/customize-vm-powershell/'
  )]
  
  [OutputType('Forest Root Domain Controller')]
  [OutputType('Replica Domain Controller')]
  [OutputType('Member Server')]
  [OutputType('Member Server-Static IP Cfg')]

  param (
    [Parameter(
      Mandatory,
      HelpMessage = "Yes, even if work is being performed while locally logged into a node of a Hyper-V cluster, a PowerShell Remoting session is still required."
    )]
    [Alias('sess')]
    [System.Management.Automation.Runspaces.PSSession]
    $PowerShellRemotingSession,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Alias('aap')]
    [string]
    $AdministratorAccountPassword,
    
    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$'
    )]
    [string]
    $ip,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $gw,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $dns,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server',
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID.`r`nDistinguishedName of OUs in AD will match this regular expression:`r`n`t^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$`r`nGUIDs (aka UUIDs) will match this regular expression:`r`n`t^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`r`n`r`nCopy and paste these examples into PowerShell:`r`n`t'OU=Demonstration,OU=Of,DC=Regex,DC=Pattern,DC=Matching' -match '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$'`r`n`t(New-Guid).ToString() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg',
      HelpMessage = "The ValidateScript parameter validation attribute might be better than ValidatePattern. Binding an ObjectGUID to -OU and then converting to DistinguishedName should be possible with [ValidateScript()]"
    )]
    [ValidatePattern(
      '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )]
    [string]
    $OU,

    [Parameter(
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server',
      HelpMessage = "Verify group membership with ValidateScript PVA"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg',
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. 'Join2Domain0_Tier0' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [ValidateSet(
      'Join2Domain0_Tier0',
      'Join2Domain0_Tier1'
    )]
    [string]
    $DomainJoinAccount,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [Alias('djap')]
    [string]
    $DomainJoinAccountPassword,

    [Parameter(
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server',
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. '_dcPrepLocalAdmin1' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg',
      HelpMessage = "Verify group membership with ValidateScript PVA"
    )]
    [string]
    $AutoLogonAccount,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [Alias('alap')]
    [string]
    $AutoLogonAccountPassword,

    [string]
    $BurnerAccountPassword,

    [Parameter(
      HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!"
    )]
    [string]
    $Name0fVM = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      HelpMessage = "Primary differences between Datacenter and Standard is that Standard does not support Storage Spaces Direct, the Hyper-V Host Guardian, the Network Controller, or running more than 2 VMs.`r`nVM deployments of Datacenter and bare-metal deployments of Standard will be rare.`r`nComprehensive feature reference:`r`n`thttps://learn.microsoft.com/en-us/windows-server/get-started/editions-comparison?pivots=windows-server-2025"
    )]
    [ValidateSet(
      'Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience'
    )]
    [string]
    $Edition = 'Standard',

    [Parameter(
      HelpMessage = "Supply name of an AD Computer object. Remember that domain controllers are ALSO AD Computer objects! Stated differently, the ObjectClass of a DC also 'computer'."
    )]
    [ValidateLength(1,15)]
    [ValidatePattern(
      '^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$'
    )]
    [string]
    $Name0fGuestOS = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      ParameterSetName = 'Member Server'
    )]
    [Parameter(
      ParameterSetName = 'Member Server-Static IP Cfg'
    )]
    [boolean]
    $IsVirtualHyperVHost = $false,

    [Parameter(
      HelpMessage = "Two virtual CPUs should be enough"
    )]
    [Int32]
    $cpu = 2,

    [Parameter(
      HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM, so install the maximum amount on your Hyper-V hosts!"
    )]
    [int64]
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,
    
    [Parameter(
      HelpMessage = "I suspect that uniquely naming Hyper-V virtual switches (on a per-host basis) isn't necessary or desirable... and maybe it's not even practical!"
    )]
    [ValidateSet(
      'SET-enabled External vSwitch','vSwitchNAT','VLAN-enabled External vSwitch','Isolated vSwitch'
    )]
    [string]
    $net = "SET-enabled External vSwitch",

    [Parameter(
      HelpMessage = "Make sure the Hyper-V host has tons of RAM"
    )]
    [ValidateSet(
      'StartIfRunning','Start','Nothing'
    )]
    [string]
    $ActionWhenBareMetalHostBoots = 'Start',
    
    [Parameter(
      HelpMessage = "No need to right-click each row in Hyper-V Manager and select Shut Down."
    )]
    [ValidateSet(
      'Save','TurnOff','Shutdown'
    )]
    [string]
    $ActionOnBareMetalHostShutdown = 'Shutdown',
    
    [Parameter(
      Mandatory,
      HelpMessage = "I should've started using unattend.xml and autounattend.xml a long, long time ago...`r`nNote for later: Come up with a PVA that matches on a regular expression for this variable.`r`nMaybe try importing the XML file and if error results, fail the function"
    )]
    [string]
    $xml,

    [ValidateRange(1,100)]
    [Int32]
    $Buffer = 20,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server',
      HelpMessage = "Checkpoints and domain controllers do not mix"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Member Server-Static IP Cfg',
      HelpMessage = "Checkpoints and domain controllers do not mix"
    )]
    [ValidateSet(
      'Disabled','Production','ProductionOnly','Standard'
    )]
    [string]
    $CheckpointType = 'Standard',

    [ValidateSet(
      'Pause','None'
    )]
    [string]
    $StorageDisconnectedAction = 'Pause',

    [int32]
    $HwThreadCountPerCore = '1',

    [Parameter(
      HelpMessage = "Migration between AMD & Intel doesn't appear to be supported!"
    )]
    [Alias('LivMigCompat')]
    [boolean]
    $IsVmCompatibleAcrossDifferentProcessorSKUsOfASingleCompany = $false,

    [Parameter(
      HelpMessage = "Connect to VLAN for Workloads by default. Connecting a vNIC to the Migration (14) or Storage (16) networks doesn't make any sense."
    )]
    [ValidateSet(
      10,12
    )]
    [int32]
    $VlanID = 12,

    [Parameter(
      Mandatory,
      HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/"
    )]
    [string]
    $Notes
  )

  ${AD DNS} = 'ad.kerberosnetworks.com' # <-- Shit coding that I'm going to TEMPORARILY tolerate 
  
  #${Instance %HostName%} = 

  Invoke-Command -Session $PowerShellRemotingSession -ScriptBlock {
    # Installing from the PSGalaxy hosted on a network share and then importing would work better
    Import-Module "$((Get-VMHost).VirtualMachinePath)\Secure-Automations-Toolset.psm1"

    $RedirectedError = $(
      ${Does This VM Already Exist?} = Get-VM -Name $using:Name0fVM
    ) 2>&1
    if (${Does This VM Already Exist?}) {
      Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
      break
    }
  
    $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
    $message01 = ".vhdx file is confirmed to be in place."
    switch ($using:Edition) {
      'Standard' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break
      }
      'StandardDesktopExperience' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
      'Datacenter' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
      'DatacenterDesktopExperience' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
    }
  
    ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
    ${Current VM Version} = (Get-VMHost).SupportedVmVersions | Where-Object {$_ -match ${Current VM Version}}
    
    $HT = @{
      Name               = $using:Name0fVM
      ComputerName       = $env:ComputerName
      Generation         = 2
      MemoryStartupBytes = $using:ram
      Version            = ${Current VM Version}
    }
    try {
      ${New VM} = Get-VM -Name $HT.Name -ErrorAction 'Stop'
    } 
    catch {
      ${New VM} = New-VM @HT
    }
  
    # Create a copy of the .vhdx file located at ${Base VHD Path}. Filename begins with name of VM and then the VM id. 
    ${Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id).vhdx"
    Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path}
  
    # Attach VHD containing Guest OS to VM |
    $HT = @{
      VMName             = $using:Name0fVM
      Path               = ${Guest OS Disk Path}
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{
      VMName = $using:Name0fVM
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    ${Guest OS Disk} = Get-VMHardDiskDrive @HT
    
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$((New-Guid).ToString()).vhdx"
    try {
      ${Storage1 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'
    } 
    catch {
      ${Storage1 VHDX} = New-VHD -Path $dir -SizeBytes 500GB -Dynamic
    }
  
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$((New-Guid).ToString()).vhdx"
    try {
      ${Storage2 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'
    } 
    catch {
      ${Storage2 VHDX} = New-VHD -Path $dir -SizeBytes 500GB -Dynamic
    }

    switch ($using:PSCmdlet.ParameterSetName) {
      {($_ -eq 'Forest Root Domain Controller') -or ($_ -eq 'Replica Domain Controller')} {
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'O' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "AD DS Vol" > $null
        Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null
      
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'P' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 00" > $null
        Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null

        break
      }
      {($_ -eq 'Member Server') -or ($_ -eq 'Member Server-Static IP Cfg')} {
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 00" > $null
        Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null
    
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 01" > $null
        Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null           
        
        break
      }
      default {write "avoiding the 'default' keyword in the final pattern of the switch statement because we'll probably end up further tailoring disk deployments"}
    }

    $HT = @{ # Create new VHD for storage and attach to VM | 'Storage1 VHDX' |
      VMName             = $using:Name0fVM
      Path               = ${Storage1 VHDX}.Path
      ControllerType     = 'SCSI'
      ControllerNumber   = '0'
      ControllerLocation = '1'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{ # Create new VHD for storage and attach to VM | 'Storage2 VHDX' |
      VMName             = $using:Name0fVM
      Path               = ${Storage2 VHDX}.Path
      ControllerType     = 'SCSI'
      ControllerNumber   = '0'
      ControllerLocation = '2'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{ # Set memory quantity & behavior of VM |
      VMName               = $using:Name0fVM
      DynamicMemoryEnabled = $True
      MinimumBytes         = 256MB
      MaximumBytes         = $using:ram
      Buffer               = $using:Buffer
    }
    Set-VMMemory @HT

    $HT = @{ # VM priority when auto-launching at Hyper-V Host boot if cumulative assigned memory exhausts total physical memory |
      VMName   = $using:Name0fVM
      Priority = '50'
    }
    Set-VMMemory @HT
  
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Guest Service Interface'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Heartbeat'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Key-Value Pair Exchange'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Shutdown'
    # Member servers in a domain should sync with a DC that does not host the PDC Emulator, and non-PDCe DCs should sync with the DC that hosts the PDC Emulator.
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Time Synchronization'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'VSS'
  
    $HT = @{ # Expose virtualization extensions if the VM is to be a virtualized Hyper-V host |
      VMName = $using:Name0fVM
      ExposeVirtualizationExtensions = $using:IsVirtualHyperVHost
    }
    Set-VMProcessor @HT

    $HT = @{ # Quantity of vCPUs |
      VMName = $using:Name0fVM
      Count  = $using:cpu
    }
    Set-VMProcessor @HT

    $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
      VMName  = $using:Name0fVM
      Reserve = '0'
      Maximum = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
      VMName         = $using:Name0fVM
      RelativeWeight = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
      VMName                       = $using:Name0fVM
      EnableHostResourceProtection = $True
    }
    Set-VMProcessor @HT  

    $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false | UPDATE 2024-12-27: Migration between AMD & Intel isn't allowed by default! |
      VMName                           = $using:Name0fVM
      CompatibilityForMigrationEnabled = $using:IsVmCompatibleAcrossDifferentProcessorSKUsOfASingleCompany
    }
    Set-VMProcessor @HT  

    $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
      VMName               = $using:Name0fVM
      HwThreadCountPerCore = $using:HwThreadCountPerCore
    }
    Set-VMProcessor @HT  

    $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
      Name                 = $using:Name0fVM
      AutomaticStartAction = $using:ActionWhenBareMetalHostBoots
      AutomaticStopAction  = $using:ActionOnBareMetalHostShutdown
      AutomaticStartDelay  = $(60 * ((Get-VM).Count - 1))
    }
    Set-VM @HT  

    $HT = @{ # Firmware settings |
      VMName             = $using:Name0fVM
      FirstBootDevice    = ${Guest OS Disk}
      SecureBootTemplate = 'MicrosoftWindows'
      EnableSecureBoot   = 'On'
    }
    Set-VMFirmware @HT
  
    # VM Checkpoints and domain controllers don't mix |
    (($using:PSCmdlet.ParameterSetName -eq 'Forest Root Domain Controller') -or ($using:PSCmdlet.ParameterSetName -eq 'Replica Domain Controller')) ? 
    (Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $false) : 
    (& {
      Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $True
      Set-VM -Name $using:Name0fVM -CheckpointType $using:CheckpointType
    })
  
    Set-VM -VMName $using:Name0fVM -AutomaticCriticalErrorAction $using:StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120

    Set-VM -VMName $using:Name0fVM -Notes $using:Notes

    ((Get-VMSwitch $using:net).EmbeddedTeamingEnabled) ? 
    (& {
      Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
      $global:vNIC = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $using:Name0fVM
    }) : ($global:vNIC = Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM)

    Connect-VMNetworkAdapter -Name $vNIC.Name -VMName $using:Name0fVM -SwitchName $using:net
    Set-VMNetworkAdapter -Name $vNIC.Name -VMName $using:Name0fVM -MacAddressSpoofing 'On'
    Set-VMNetworkAdapterVlan -VMName $using:Name0fVM -VMNetworkAdapterName $vNIC.Name -Access -VlanId $using:VlanID

    # Bandwidth Management? 

    Set-VMKeyProtector -VMName $using:Name0fVM -NewLocalKeyProtector

    Enable-VMTPM -VMName $using:Name0fVM

    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
    $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
    $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

    $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}

    #Write-Host -ForegroundColor $(rFc) -Object "$($using:PSCmdlet.ParameterSetName)"

    $xml = $using:xml

    switch ($using:PSCmdlet.ParameterSetName) {
      'Forest Root Domain Controller' {
        # Import XML document into an object instance of type XmlDocument
        ($XmlDocument = [xml]'<root></root>').Load($xml)

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $using:ip}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $using:gw}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $using:dns}

        # Password Injection: Autologon of 'PrimaryAdmin'
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.PlainText = $false}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'PrimaryAdmin') + "Password")))}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.Autologon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($($using:AutoLogonAccountPassword + "Password")))}

        # Password Injection: 'Administrator'
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.PlainText = $false}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'Administrator') + "AdministratorPassword")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($($using:AdministratorAccountPassword + "AdministratorPassword")))}

        # Password Injection: 'PrimaryAdmin'
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.PlainText = $false}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($((Get-BitwardenPassword 'PrimaryAdmin') + "Password")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($($using:AutoLogonAccountPassword + "Password")))}

        # Other items under the 'oobeSystem' using:pass
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

        <# Investigations |
          $AltPath = "$ns\xml\unattend $(Call-DateVar).xml"
          $XmlDocument.Save($AltPath)
          code $AltPath

          $AltPath | Set-ClipBoard
          Remove-Variable 'XmlDocument'
        #>
        $XmlDocument.Save("$VHDVolume\unattend.xml")
        break
      }
      'Replica Domain Controller' {
        ($XmlDocument = [xml]'<root></root>').Load("$((Get-VMHost).VirtualMachinePath)\$xml")

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $using:ip}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $using:gw}        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $using:dns}
        
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')} # You should be capable of figuring out how to get this to work. 
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $using:DomainJoinAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $using:DomainJoinAccountPassword}        
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')} # You should be capable of figuring out how to get this to work. 
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $using:OU}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:AutoLogonAccountPassword) + "Password")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Username = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Domain = $using:NetBiosNameOfActiveDirectoryDomain}      
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:BurnerAccountPassword) + "AdministratorPassword")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Name = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Group = 'Administrators'}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.Domain = $using:NetBiosNameOfActiveDirectoryDomain}        
       
        $XmlDocument.Save("$VHDVolume\unattend.xml")
      
        break
      }
      'Member Server' {
        ($XmlDocument = [xml]'<root></root>').Load("$((Get-VMHost).VirtualMachinePath)\$xml")

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')} # You should be capable of figuring out how to get this to work. 
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $using:DomainJoinAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $using:DomainJoinAccountPassword}
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')} # You should be capable of figuring out how to get this to work. 
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $using:OU}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:AutoLogonAccountPassword) + "Password")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Username = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Domain = $using:NetBiosNameOfActiveDirectoryDomain}      
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:BurnerAccountPassword) + "AdministratorPassword")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Name = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Group = 'Administrators'}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.Domain = $using:NetBiosNameOfActiveDirectoryDomain}        
       
        $XmlDocument.Save("$VHDVolume\unattend.xml")
      
        break
      }
      'Member Server-Static IP Cfg' {
        ($XmlDocument = [xml]'<root></root>').Load("$((Get-VMHost).VirtualMachinePath)\$xml")

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $using:ip}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $using:gw}        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $using:dns}

        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $using:DomainJoinAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $using:DomainJoinAccountPassword}        
        #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = $(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $using:OU}
        
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:AutoLogonAccountPassword) + "Password")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Username = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.AutoLogon.Domain = $using:NetBiosNameOfActiveDirectoryDomain}      
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(($using:BurnerAccountPassword) + "AdministratorPassword")))}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Name = $using:AutoLogonAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.DomainAccount.Group = 'Administrators'}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.DomainAccounts.DomainAccountList.Domain = $using:NetBiosNameOfActiveDirectoryDomain}        
       
        $XmlDocument.Save("$VHDVolume\unattend.xml")
      
        break
      }
      default {write "Keeping the possibility of more parameter sets open"}
    }

    if ($using:PSCmdlet.ParameterSetName -eq 'Forest Root Domain Controller') {
      $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $pwsh7MSI = Get-ChildItem -Path "$env:SystemDrive\Installs\PowerShell 7" -Filter "PowerShell*x64.msi" -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
      Copy-Item -Path "$pwsh7MSI" -Destination "$dir" -Force
    
      $dir = "$VHDVolume\Installs\OneDrive"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $OneDriveEXE = Get-Item -Path "$env:SystemDrive\Installs\OneDrive\OneDriveSetup.exe"
      Copy-Item -Path "$OneDriveEXE" -Destination "$dir"
    
      $dir = "$VHDVolume\Installs\VS Code"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $VSCodeEXE = Get-Item -Path "$env:SystemDrive\Installs\VSCodeSetup-x64-*.exe"
      Copy-Item -Path "$VSCodeEXE" -Destination "$dir"
    
      # I am aware that this is here twice. 
      $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $pwsh7MSI = Get-ChildItem -Path "$env:SystemDrive\Installs\PowerShell 7" -Filter "PowerShell*x64.msi" -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
      Copy-Item -Path "$pwsh7MSI" -Destination "$dir" -Force    
    }
  
    Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
    Start-VM -Name $using:Name0fVM | Out-Null
    return $using:Name0fGuestOS
  }

  #return ${Instance %HostName%} #  $WhyDoesntThisFuckingWork
}

function Update-BitwardenPassword {
  [CmdletBinding(
    ConfirmImpact         = 'Low',
    SupportsShouldProcess = $True,
    SupportsPaging        = $true,
    HelpURI               = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding     = $true
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "SamAccountName of the Active Directory user account",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('un')]
    [string]$SamAccountName,

    [Parameter(
      Position = 1,
      Mandatory = $true,
      HelpMessage = "Domain-level operations require an account with password length of 128 or less. Try adding a replica DC to the domain with a domain admin whose password is 129 characters-operation will fail. Joining a machine to the domain, however, will succeed.",
      ValueFromPipelineByPropertyName = $False
    )]    
    [ValidateRange(16,256)]
    [int32]$len,

    [Parameter(
      Position = 2,
      Mandatory = $false,
      HelpMessage = "OPTIONAL: Name of the Item in Bitwarden. Random GUID assigned if left blank.`r`nKnowing the username of the AD account is enough.`r`nUniqueness is only required attribute when titling an Item in Bitwarden Password Manager.",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('item')]
    [string]$BitwardenItemName = (New-Guid).ToString(),

    [Parameter(
      Position = 3,
      Mandatory = $false,
      HelpMessage = "NetBIOS name of the Active Directory domain. This is different from the Domain Name System name of the Active Directory domain.`r`n`r`nReference from Microsoft Learn:`r`n  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('dom')]
    [string]$NetBiosNameOfActiveDirectoryDomain = $NetBiosNameOfActiveDirectoryDomain,

    [Parameter(
      Position = 4,
      Mandatory = $false,
      HelpMessage = "Name of the organization in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('org')]
    [string]$BitwardenOrganizationName = $BitwardenOrganizationName,

    [Parameter(
      Position = 5,
      Mandatory = $false,
      HelpMessage = "Name of the collection in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('col')]
    [string]$BitwardenPwdManagerCollectionName = $BitwardenPwdManagerCollectionName,

    [Parameter(
      Position = 6,
      Mandatory = $false,
      HelpMessage = "Name of the project in Bitwarden Secrets Manager",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('proj')]
    [string]$BitwardenSecretsManagerProjectName = $BitwardenSecretsManagerProjectName,
    
    [Parameter(
      Position = 7,
      Mandatory = $false,
      HelpMessage = "A machine account name and an access token value are stored in the 'username' and 'password' sub-properties of the 'login' property of an 'item' in Bitwarden Password Manager. The -AT parameter accepts the NAME of the item object that corresponds to the machine account.",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$AT = ${Machine Account 01-Access Token}
  )

  Set-StrictMode -Version 3
  _PrerequisiteConditions

  <# Hold off on the repeated checks for whether the Bitwarden CLI status is 'unlocked' | Might be what's causing terribly slow operations |
    $RedirectedErrors = $(${Authentication Status of the Bitwarden CLI} = (bw.exe status | ConvertFrom-Json).status) 2>&1 # Save to variable the status of bw.exe

    if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {_AuthenticateIntoBitwardenPasswordManagerCLI}      # Authenticate if status is anything aside from 'unlocked'
  #>

  ($env:BWS_ACCESS_TOKEN) ??= (bw.exe get password ${Machine Account 01-Access Token})
  
  # Verify whether the AD account already exists in the 'Active Directory Domain Services' collection of the Bitwarden organization
  
  # Initialize new variable for referencing Bitwarden Organization ID
  $_Var_Name = 'BitwardenOrganizationId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Bitwarden Organization ID
  $BitwardenOrganizationId = bw.exe list organizations `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenOrganizationName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no Bitwarden Organization ID produced
  if (
    !($BitwardenOrganizationId)
  ) {
    Write-Error -Message "Bitwarden organization name supplied did not resolve to a UUID. Confirm correct spelling of the organization's name in Kerberos Networks' Bitwarden account"
    Pause
    break
  }

  # Initialize new variable for referencing the Collection ID in Bitwarden Password Manager
  $_Var_Name = 'CollectionId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Collection ID from Bitwarden Password Manager
  $CollectionId = bw.exe list --organizationid $BitwardenOrganizationId org-collections `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenPwdManagerCollectionName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no collection ID produced
  if (
    !($CollectionId)
  ) {
    Write-Error -Message "Collection name supplied did not resolve to a UUID. No collection in Bitwarden Password Manager matches that name. Confirm correct spelling of the collection's name in Kerberos Networks' Bitwarden account"
    Pause
    break
  }

  # Initialize new variable for referencing an Item in Bitwarden Password Manager
  $_Var_Name = 'ItemInBitwarden'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Query the Bitwarden Organization for an item of that name. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
  $RedirectedErrors = $(
    $ItemInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId item $BitwardenItemName
  ) 2>&1

  # Destroy variable & exit function if that item is already present
  if (
    $ItemInBitwarden
  ) {
    Write-Error -Message "Bitwarden Password Manager reports that an Item already has that name.`r`n  Eliminate the '-BitwardenItemName' parameter-argument pair and reattempt."
    pause
    Remove-Variable 'ItemInBitwarden'
    break
  }

  # Initialize new variable for referencing <domain>\<username>
  $_Var_Name = 'UsernameInBitwarden'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Query the Bitwarden Organization for that <domain>\<username> value. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
  $RedirectedErrors = $(
    $UsernameInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId username "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName"
  ) 2>&1

  # exit function if that username is not present
  if (
    -not $UsernameInBitwarden
  ) {
    Write-Warning -Message "Active Directory account with username '$UsernameInBitwarden' is not present in Bitwarden"
    break
  }

  # Can now CONFIRM that Bitwarden Password Manager does not contain any credentials that match with the parameter-argument pairs supplied to the function

  # Calling the Bitwarden Secrets Manager CLI
  
  $BitwardenSecretsManagerSecretId = bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json | Select-Object -ExpandProperty 'login' | Where-Object {$_.username -eq "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName"} | Select-Object -ExpandProperty 'password'
  $newField = '.fields+=[{name:"%Field_Title%",value:"%Field_Value%",type:1}]' -replace '%Field_Title%',(Call-DateVar) -replace '%Field_Value%',$(bws.exe secret get --access-token $env:BWS_ACCESS_TOKEN $BitwardenSecretsManagerSecretId | ConvertFrom-Json | Select-Object -ExpandProperty 'value')
  $item = bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json
  $item | ConvertTo-Json | jq-windows-amd64.exe $newField | bw.exe encode | bw.exe edit item $item.id > $null  
  bws.exe secret edit --access-token $env:BWS_ACCESS_TOKEN --value $(_AutoGeneratedSecurePassword $len) $BitwardenSecretsManagerSecretId > $null  

  # Force a sync and exit
  $RedirectedError = $(
    bw.exe sync
  ) 2>&1
}

function New-Secret { # New application registration Secret via POST call to the Microsoft Graph API |
  [CmdletBinding(
    ConfirmImpact         = 'Low',
    SupportsShouldProcess = $True,
    SupportsPaging        = $true,
    HelpURI               = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding     = $false
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "Name of the access token as it is known in your Bitwarden Password Manager CLI",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$AccessTokenName,

    [Alias('AppRegDN')]
    [Parameter(
      Position = 1,
      Mandatory = $true,
      HelpMessage = "Value of displayName of the Application Registration in your Microsoft Entra tenant",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$ApplicationRegistrationDisplayName
  )
  begin {
    _PrerequisiteConditions

    ${Authentication Status of the Bitwarden CLI} = (bw.exe status | ConvertFrom-Json).status                     # Save to variable the status of bw.exe

    if (
      ${Authentication Status of the Bitwarden CLI} -ne 'unlocked'                                                # Authenticate if status is anything aside from 'unlocked'
    ) {
      Get-BitwardenPassword
    }
    
    # Load dependent modules. Probably should be written into manifest. 
    #$_Module_Name = "Microsoft.Graph.Identity.DirectoryManagement"; (Get-Module -Name $_Module_Name | ft -a) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
    #$_Module_Name = "Microsoft.Graph.Applications"; (Get-Module -Name $_Module_Name | ft -a) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
    #$_Module_Name = "MSAL.PS"; (Get-Module -Name $_Module_Name | ft -a) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
  
    # Object declaration + precursors to authentication 
    #"directory-reader@kerberosnetworks.com" | Set-Clipboard
    #${Tenant ID} = ${Tenant ID-KNet}
    #Connect-MgGraph -Scopes 'Directory.Read.All' -NoWelcome -TenantID ${Tenant ID}
    #$global:TenantID = (Get-MgOrganization).Id
    #$global:DnsDomain = (Get-MgDomain).Where({$_.IsDefault -eq $true}).Id
    ##& ${AppReg Authentications v3}
    #& ${global:AppReg Authentications v3}
  
    #if (!(${global:Application (Read)}))      {& ${_Application (Read)}}      # Get-Variable 'Application (Read)'        | Remove-Variable
    #if (!(${global:Application (ReadWrite)})) {& ${_Application (ReadWrite)}} # Get-Variable 'Application (ReadWrite)'   | Remove-Variable
  }
  process {
    $HT = @{
      Method  = 'GET'
      Uri     = "$mg/applications?`$filter=displayName eq '$($ApplicationRegistrationDisplayName)'&`$select=id"
      Headers = ${Application (Read)}
    }
    $MgApplicationId = Invoke-RestMethod @HT | Select-Object -ExpandProperty 'value' | Select-Object -ExpandProperty 'id'
  
    if (!($MgApplicationId)) {break}
  
    $PasswordCredentialDN = $ApplicationRegistrationDisplayName
    $passwordCredential = @{
      displayName   = $PasswordCredentialDN
      startDateTime = (Get-Date -Date $((Get-Date -AsUTC).AddDays(0)) -Format "yyyy-MM-ddTHH:mm:ssZ")
      endDateTime   = (Get-Date -Date $((Get-Date -AsUTC).AddMonths(6)) -Format "yyyy-MM-ddTHH:mm:ssZ")
    }
  
    $HT = @{
      Method  = 'GET'
      Uri     = "$mg/applications/$MgApplicationId"
      Headers = ${Application (Read)}
    }
    $MgApplicationKeyId = Invoke-RestMethod @HT | Select-Object -ExpandProperty 'passwordCredentials' | Select-Object -ExpandProperty 'keyId'
    
    ($MgApplicationKeyId) ? 
    (& {
      break
    }) :   
    (& {
      $projectUUID = (bws.exe project list --access-token $(bw.exe get password ${Access Token Name}) | ConvertFrom-Json)[0].id
      $HT = @{
        Method  = 'POST'
        Uri     = "$mg/applications/$MgApplicationId/addPassword"
        Headers = ${Application (ReadWrite)}
      }
      # Generate the secret & pipe DIRECTLY into Bitwarden Secrets Manager CLI
      $global:Id_of_Secret = Invoke-RestMethod @HT -Body (@{passwordCredential = $passwordCredential} | ConvertTo-Json) `
      | Select-Object -ExpandProperty 'secretText' `
      | % {bws.exe secret create --access-token $(bw.exe get password ${Access Token Name}) $passwordCredential.displayName $_ $projectUUID} `
      | ConvertFrom-Json `
      | % {$_.id}
    })
  
    # Confirm that the KeyId of the application registration can be queried. There is a delay between a successful 'GET' after the 'POST' completes 
    $HT = @{
      Method  = 'GET'
      Uri     = "$mg/applications/$MgApplicationId"
      Headers = ${Application (Read)}
    }
    while (!($MgApplicationKeyId)) {
      Start-Sleep 1
      $RedirectedErrors = $( 
        $MgApplicationKeyId = Invoke-RestMethod @HT | Select-Object -ExpandProperty 'passwordCredentials' | Select-Object -ExpandProperty 'keyId'
      ) 2>&1
    }

    $organizationUUID = (bws.exe project list --access-token $(bw.exe get password ${Access Token Name}) | ConvertFrom-Json)[0].organizationId
    # Now create an 'item' in Bitwarden Password Manager CLI. 'id' property of newly created secret   into Bitwarden Password Manager
    ${bw item-name}           = '.name="%App_Reg_Title%"' -replace '%App_Reg_Title%',$ApplicationRegistrationDisplayName                # displayName of the AppReg will be the 'name' of the soon-to-be created item in bw.exe and 
    ${bw item-login.username} = '.login.username="%App_Reg_Title%"' -replace '%App_Reg_Title%',$ApplicationRegistrationDisplayName      # displayName of the AppReg will also be that item's username
    ${bw item-login.password} = '.login.password="%Id_of_Secret_4_App_Reg%"' -replace '%Id_of_Secret_4_App_Reg%',$Id_of_Secret # Value of 'id' property of newly created secret in bws.exe will be 'password' of soon-to-be created item in bw.exe 
    ${bw item-organizationId} = '.organizationId="%Id_of_Bw_Org%"' -replace '%Id_of_Bw_Org%',$organizationUUID                 # Specify the organization ID so that the new item isn't deposited in the user space of the Bitwarden vault
    ${bw item-notes}          = '.notes="%Item_Notes%"' -replace '%Item_Notes%',""
    #$OrgCollectionId = bw.exe list --organizationid $organizationUUID org-collections | ConvertFrom-Json | ? {$_.name -eq "AppReg Secrets in Microsoft Entra"} | Select-Object -ExpandProperty 'id'
    $OrgCollectionId = bw.exe list --organizationid $organizationUUID org-collections | ConvertFrom-Json | ? {$_.name -eq "Microsoft Entra"} | Select-Object -ExpandProperty 'id'
    ${bw item-collectionId}   = '.collectionIds=["%id_of_Org_Collection%"]' -replace '%id_of_Org_Collection%',$OrgCollectionId
  }
  end {
    bw.exe get template item `
    | jq ${bw item-name} `
    | jq ${bw item-login.username} `
    | jq ${bw item-login.password} `
    | jq ${bw item-organizationId} `
    | jq ${bw item-notes} `
    | jq ${bw item-collectionId} `
    | bw.exe encode `
    | bw.exe create item `
    | ConvertFrom-Json > $null
  }
  clean {}
}

function Query-Secret {
  [CmdletBinding(
    ConfirmImpact         = 'Low',
    SupportsShouldProcess = $True,
    SupportsPaging        = $true,
    HelpURI               = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding     = $false
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "Name of the access token as it is known in your Bitwarden Password Manager CLI",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$AccessTokenName,

    [Alias('AppRegDN')]
    [Parameter(
      Position = 1,
      Mandatory = $true,
      HelpMessage = "Value of displayName of the Application Registration in your Microsoft Entra tenant",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$ApplicationRegistrationDisplayName
    #[Parameter(
    #  Position = 2,
    #  Mandatory = $false,
    #  HelpMessage = "Guid of project in Bitwarden. Defaults to 1st project if a guid is not supplied",
    #  ValueFromPipelineByPropertyName = $False
    #)]
    #[ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    #[string]$projectUUID
  )
  begin {
    _PrerequisiteConditions

    ${Authentication Status of the Bitwarden CLI} = (bw.exe status | ConvertFrom-Json).status                     # Save to variable the status of bw.exe

    if (
      ${Authentication Status of the Bitwarden CLI} -ne 'unlocked'                                                # Authenticate if status is anything aside from 'unlocked'
    ) {
      Get-BitwardenPassword
    }
    #$env:BWS_ACCESS_TOKEN = bw.exe get password $AccessTokenName

    #$projectUUID = (bws.exe project list | ConvertFrom-Json)[0].id
    $organizationUUID = (bws.exe project list --access-token $(bw.exe get password $AccessTokenName) | ConvertFrom-Json)[0].organizationId
  }
  process {
    #bws.exe secret get (bw.exe get password $ApplicationRegistrationDisplayName) | ConvertFrom-Json | Select-Object -ExpandProperty 'value'
    #bws.exe secret get --access-token $(bw.exe get password $AccessTokenName) $ApplicationRegistrationDisplayName $((bws.exe project list | ConvertFrom-Json)[0].id)
    $SecretId = bw.exe get --organizationid $organizationUUID item $((bw.exe get --organizationid $organizationUUID item $ApplicationRegistrationDisplayName | ConvertFrom-Json).id) `
    | ConvertFrom-Json `
    | Select-Object -ExpandProperty 'login' `
    | Select-Object -ExpandProperty 'password'
  }
  end {
    return (bws.exe secret get --access-token $(bw.exe get password $AccessTokenName) $SecretId | ConvertFrom-Json)[0].value
  }
  clean {$env:BWS_ACCESS_TOKEN = $null}
}

function Query-Secret2 {
  [CmdletBinding(
    ConfirmImpact         = 'Low',
    SupportsShouldProcess = $True,
    SupportsPaging        = $true,
    HelpURI               = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding     = $false
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "Name of the access token as it is known in your Bitwarden Password Manager CLI",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$AccessTokenName,

    [Alias('AppRegDN')]
    [Parameter(
      Position = 1,
      Mandatory = $true,
      HelpMessage = "Value of displayName of the Application Registration in your Microsoft Entra tenant",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$ApplicationRegistrationDisplayName
  )
  begin {
    _PrerequisiteConditions

    ${Authentication Status of the Bitwarden CLI} = (bw.exe status | ConvertFrom-Json).status                     # Save to variable the status of bw.exe

    if (
      ${Authentication Status of the Bitwarden CLI} -ne 'unlocked'                                                # Authenticate if status is anything aside from 'unlocked'
    ) {
      Get-BitwardenPassword
    }
    
    <# Another option for managing Environment Variables |
      [Environment]::SetEnvironmentVariable("https_proxy", "http://{proxy-url}:{proxy-port}", "Machine")
      $env:https_proxy -eq $Null
      $env:https_proxy = [System.Environment]::GetEnvironmentVariable("https_proxy","Machine")
      $env:https_proxy

      [System.Environment]::SetEnvironmentVariable("Hello_00", "http://{proxy-url}:{proxy-port}", "Machine")
      $env:Hello_00 -eq $Null
      $env:Hello_00 = [System.Environment]::GetEnvironmentVariable("Hello_00","Machine")
      $env:Hello_00
    #>

    $env:BWS_ACCESS_TOKEN = bw.exe get password $AccessTokenName

    $organizationUUID = (bws.exe project list --access-token $env:BWS_ACCESS_TOKEN | ConvertFrom-Json)[0].organizationId
  }
  process {
    $SecretId = bw.exe get --organizationid $organizationUUID item $((bw.exe get --organizationid $organizationUUID item $ApplicationRegistrationDisplayName | ConvertFrom-Json).id) `
    | ConvertFrom-Json `
    | Select-Object -ExpandProperty 'login' `
    | Select-Object -ExpandProperty 'password'
  }
  end {
    return (bws.exe secret get --access-token $env:BWS_ACCESS_TOKEN $SecretId | ConvertFrom-Json)[0].value
  }
  clean {$env:BWS_ACCESS_TOKEN = $null}
}

function New-TAP {
  [CmdletBinding(
    SupportsShouldProcess   = $True,
    ConfirmImpact           = 'Medium',
    HelpURI                 = 'https://learn.microsoft.com/en-us/graph/api/authentication-post-temporaryaccesspassmethods?view=graph-rest-1.0&tabs=http',
    PositionalBinding       = $true
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "value of the 'displayName' property of the user account in Microsoft Entra ID.`r`nSupport for non-ASCII characters (e.g. umlauts & accents) in development.",
      ValueFromPipelineByPropertyName = $False
    )]
    [ValidatePattern('^[a-z A-Z-]+$')]
    [string]$KnownName
  )
  begin {
    $_Module_Name = "Microsoft.Graph.Identity.DirectoryManagement"; (Get-Module -Name $_Module_Name) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
    $_Module_Name = "Microsoft.Graph.Applications"; (Get-Module -Name $_Module_Name) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
    $_Module_Name = "MSAL.PS"; (Get-Module -Name $_Module_Name) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
    "directory-reader@kerberosnetworks.com" | Set-Clipboard
    Connect-MgGraph -Scopes 'Directory.Read.All' -NoWelcome -TenantID ${Tenant ID-KNet}
    $global:TenantID = (Get-MgOrganization).Id
    $global:DnsDomain = (Get-MgDomain).Where({$_.IsDefault -eq $true}).Id
    & ${AppReg Authentications v3}
    $UserDN = $KnownName
    if (!(${global:Verify User Account-Admin or Standard})) {& ${_Verify User Account-Admin or Standard}}
    $MgUserId = Invoke-RestMethod -Method 'GET' -Uri "$mg/users?`$filter=displayName eq '$($UserDN)'&`$select=id" -Headers ${Verify User Account-Admin or Standard} | Select-Object -ExpandProperty 'value' | Select-Object -ExpandProperty 'id'

    # $MgUserId = $null means the argument value supplied to -KnownName parameter doesn't correspond to any user account in the tenant
    ($MgUserId) ?? (&{
      Write-Host -ForegroundColor 'DarkRed' -Object "No user account with `$KnownName = '$KnownName' is present in this Microsoft Entra tenant.`r`n`r`n"
      pause
      break
    })
    Write-Host -ForegroundColor 'Yellow' -Object "`r`n  Please wait...`r`n"
  }
  process {
    # GUIDs of all role-assignable security-enabled groups in the tenant
    $HT = @{
      Method = 'GET'
      Uri    = "$mg/groups?`$filter=isAssignableToRole eq true&`$top=999&`$select=id"
      Header =  ${Verify User Account-Admin or Standard}
    }
    $MgRoleAssignableGroupIds = Invoke-RestMethod @HT | Select-Object -ExpandProperty 'value' | Select-Object -ExpandProperty 'id'

    # GUIDs of each security-enabled group in which user account holds membership, if any
    $SecurityEnabledOnly = @{securityEnabledOnly = $true} | ConvertTo-Json
    $HT = @{
      Method = 'POST'
      Uri    = "$mg/users/$MgUserId/getMemberGroups"
      Header = ${Verify User Account-Admin or Standard}
    }
    $MgMemberGroupIds = Invoke-RestMethod @HT -Body $SecurityEnabledOnly | Select-Object -ExpandProperty 'value'

    # Sort each collection of GUIDs
    ($MgRoleAssignableGroupIds),($MgMemberGroupIds) = ($MgRoleAssignableGroupIds | Sort-Object),($MgMemberGroupIds | Sort-Object)

    # Isolate the GUIDs that are present in both collections, if any
    $_Var_Name = 'MgRoleAssignableMemberGroupIds'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
    $MgRoleAssignableMemberGroupIds = Compare-Object -ReferenceObject $MgMemberGroupIds -DifferenceObject $MgRoleAssignableGroupIds -IncludeEqual -ExcludeDifferent

    # Check whether the user account holds any permanently active role assignments
    $HT = @{
      Method = 'GET'
      Uri    = "$mg/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($MgUserId)'"
      Header = ${Verify User Account-Admin or Standard}
    }
    $MgUnifiedRoleAssignments = Invoke-RestMethod @HT | Select-Object -ExpandProperty 'value'
    
    # Check whether the user account holds any eligible role assignments
    $HT = @{
      Method = 'GET'
      Uri    = "$mg/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($MgUserId)'"
      Header = ${Verify User Account-Admin or Standard}
    }
    $MgRoleEligibilitySchedules = Invoke-RestMethod @HT | Select-Object -ExpandProperty 'value'    

    # Check whether the user account holds any active (non-permanent) role assignments
    $HT = @{
      Method = 'GET'
      Uri    = "$mg/roleManagement/directory/roleAssignmentSchedules?`$filter=principalId eq '$($MgUserId)'"
      Header = ${Verify User Account-Admin or Standard}
    }
    $MgRoleAssignmentSchedules = Invoke-RestMethod @HT | Select-Object -ExpandProperty 'value'

    $_Var_Name = 'HT'; Remove-Variable -Name $_Var_Name

    # One or more of the computed values in the body of the If statement being non-null means that the account is non-standard. 
    $IsStandardAccount = $false
    if (
      ($MgRoleAssignableMemberGroupIds -eq $null) -and `
      ($MgUnifiedRoleAssignments -eq $null) -and `
      ($MgRoleEligibilitySchedules -eq $null) -and `
      ($MgRoleAssignmentSchedules -eq $null)
    ) {
      $IsStandardAccount = $true
    }

    ($IsStandardAccount) ? (
      & {
        if (!(${Authentication Method-TAP (New)})) {
          Write-Host -ForegroundColor 'DarkBlue' -Object "Ensure that you have the ability to authenticate into Microsoft Entra ID using an account holding an active role assignment of 'Authentication Administrator' and then press Enter..."
          pause
        }
        if (!(${Authentication Method-TAP (New)})) {& ${_Authentication Method-TAP (New)}}
        $PSCmdlet.ShouldProcess("Generate a new 60-minute Temporary Access Pass the non-administrative user '$($UserDN)'?")

        $DateTimeOffset = Get-Date -Date $((Get-Date -AsUTC)) -Format "yyyy-MM-ddTHH:mm:ssZ"
        $temporaryAccessPassAuthenticationMethod = @{
          isUsableOnce      = $true
          lifetimeInMinutes = $(15)
          startDateTime     = $DateTimeOffset
        } | ConvertTo-Json
        $HashTable = @{
          Method = 'POST'
          Uri    = "$mg/users/$($MgUserId)/authentication/temporaryAccessPassMethods"
          Header = ${Authentication Method-TAP (New)}
        }
        $global:temporaryAccessPassAuthenticationMethod = $temporaryAccessPassAuthenticationMethod
        $global:HashTable = $HashTable
      }
    ) : 
    (
      & {
        if (!(${Authentication Method-Privileged TAP (New)})) {
          Write-Host -ForegroundColor 'DarkBlue' -Object "Ensure that you have the ability to authenticate into Microsoft Entra ID using an account holding an active role assignment of 'Privileged Authentication Administrator' and then press Enter..."
          pause 
        }
        if (!(${Authentication Method-Privileged TAP (New)})) {& ${_Authentication Method-Privileged TAP (New)}}
        $PSCmdlet.ShouldProcess("Generate a new 10-minute Temporary Access Pass the administrative user '$($UserDN)'?")

        $DateTimeOffset = Get-Date -Date $((Get-Date -AsUTC)) -Format "yyyy-MM-ddTHH:mm:ssZ"
        $temporaryAccessPassAuthenticationMethod = @{
          isUsableOnce      = $true
          lifetimeInMinutes = $(10)
          startDateTime     = $DateTimeOffset
        } | ConvertTo-Json
        $HashTable = @{
          Method = 'POST'
          Uri    = "$mg/users/$($MgUserId)/authentication/temporaryAccessPassMethods"
          Header = ${Authentication Method-Privileged TAP (New)}
        }
        $global:temporaryAccessPassAuthenticationMethod = $temporaryAccessPassAuthenticationMethod
        $global:HashTable = $HashTable
      }
    )
    
    $_Var_Name = 'TAP'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
    while (!($TAP)) {
      Start-Sleep 2
      $RedirectedErrors = $($TAP = Invoke-RestMethod @HashTable -Body $temporaryAccessPassAuthenticationMethod) 2>&1
    }
  }
  end {
    Write-Host -ForegroundColor Magenta -Object "`r`n`r`nTAP for $UserDN`:   $($TAP.temporaryAccessPass)"
    $global:TAP = $TAP
  }
  clean {
    #Remove-Variable -Name 'HashTable' # -Scope 'Global'
    #Remove-Variable -Name 'temporaryAccessPassAuthenticationMethod' # -Scope 'Global'
  }
}

function New-Account {
  [CmdletBinding(
    ConfirmImpact           = 'Medium',
    SupportsShouldProcess   = $True,
    DefaultParameterSetName = 'StandardAccount',
    SupportsPaging          = $true,
    HelpURI                 = 'https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0',
    PositionalBinding       = $false
  )]
  [OutputType('StandardAccount',[string])]
  [OutputType('AccountForAdministration',[string])]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "Full name by which the person or account should be known. Hyphens allowed.`r`nSupport for non-ASCII characters (e.g. umlauts & accents) in development.`r`n  Standard accounts: 'Yoel Yogurt' or 'Cindy Crouton'`r`n  Accounts for Administration: 'Teams Communications Support Specialist' or 'Windows Autopilot Operator'`r`n",
      ValueFromPipelineByPropertyName = $False
    )]
    [ValidatePattern('^[a-z A-Z-]+$')]
    [string]$KnownName,
    
    [Parameter(
      Position = 1,
      ParameterSetName = 'AccountForAdministration',
      HelpMessage = "Only apply the '-IsNonStandardAccount' switch when creating an account holding a permanently active role assignment",
      ValueFromPipelineByPropertyName = $False
    )]
    [switch]$IsNonStandardAccount,

    [Parameter(
      Position = 2,
      Mandatory = $true, 
      HelpMessage = "New employee's official job title in the organization",
      ValueFromPipelineByPropertyName = $False
    )]
    [ValidatePattern('^[0-9a-z A-Z-]+$')]
    [string]$JobTitle,

    [Parameter(
      Position = 3,
      Mandatory = $false, 
      HelpMessage = "Gotta eventually write admin units into this function!",
      ValueFromPipelineByPropertyName = $False
    )]
    [ValidatePattern('^[0-9a-z A-Z-]+$')]
    [string]$AdministrativeUnit
  )
  begin {
    $_Module_Name = "Microsoft.Graph.Identity.DirectoryManagement"; (Get-Module -Name $_Module_Name) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
    $_Module_Name = "Microsoft.Graph.Applications"; (Get-Module -Name $_Module_Name) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
    $_Module_Name = "MSAL.PS"; (Get-Module -Name $_Module_Name) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
    "directory-reader@kerberosnetworks.com" | Set-Clipboard
    Connect-MgGraph -Scopes 'Directory.Read.All' -NoWelcome -TenantID ${Tenant ID-KNet}
    $global:TenantID = (Get-MgOrganization).Id
    $global:DnsDomain = (Get-MgDomain).Where({$_.IsDefault -eq $true}).Id
    & ${AppReg Authentications v3}

    switch ($PSCmdlet.ParameterSetName) {
      'AccountForAdministration' {$IsNonStandardAccount = $True}
      'StandardAccount'          {$IsNonStandardAccount = $False}
      default                    {break}
    }
  
    $global:UserDN = $KnownName
    $global:UPNprefix = $UserDN.ToLower() -replace ' ','.';
    if (!(${global:User Account (Read)})) {& ${_User Account (Read)}}
  }
  process {
    $MgUser = Invoke-RestMethod -Method 'GET' -Uri "$mg/users?`$filter=displayName eq '$($UserDN)'" -Headers ${User Account (Read)} | Select-Object -ExpandProperty 'value'
    ($MgUser) ?? (
      & { # Generate new user account in Microsoft Entra ID |
        if (!(${global:User Account (ReadWrite)})) {& ${_User Account (ReadWrite)}}
        if (!(${global:Directory (ReadWrite)})) {& ${_Directory (ReadWrite)}}
        if (!(${global:Group (Read)})) {& ${_Group (Read)}}
        if (!(${global:Group Member-Users (AddRemove)})) {& ${_Group Member-Users (AddRemove)}}

        $passwordProfile = @{
          password = $(Entra-Pwd)
          forceChangePasswordNextSignIn = $false
        }
        $user = @{
          displayName = "$UserDN"
          userPrincipalName = "$UPNprefix@$DnsDomain"
          mailNickname = "$UPNprefix"
          jobtitle = $JobTitle
          accountEnabled = $true
          passwordPolicies = "DisablePasswordExpiration"
          passwordProfile = $passwordProfile
          usageLocation = 'US'
        }
        
        ${un/pw pair} = "$($user.passwordProfile.password) / $UPNprefix@$DnsDomain"

        while (!($MgUser)) {
          $HT = @{
            Method = 'POST'
            Uri    = "$mg/users"
            Header = ${User Account (ReadWrite)}
          }
          $MgUser = Invoke-RestMethod @HT -Body ($user | ConvertTo-Json)
        }
    
        $_Var_Name = 'MgUser'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
        while (!($MgUser)) {
          $HT = @{
            Method = 'GET'
            Uri    = "$mg/users?`$filter=displayName eq '$($UserDN)'"
            Header = ${User Account (Read)}
          }
          $MgUser = Invoke-RestMethod @HT | Select-Object -ExpandProperty 'value'
        }
        
        ${Org Theme Names} = @('OrgTheme1','OrgTheme2','OrgTheme3','OrgTheme4')
        $onPremisesExtensionAttributes = @{
          onPremisesExtensionAttributes = @{extensionAttribute15 = "$(Get-Random ${Org Theme Names})"}
        } | ConvertTo-Json
    
        $HT = @{
          Method = 'PATCH'
          Uri    = "$mg/users/$($MgUser.id)"
          Header = ${Directory (ReadWrite)}
        }
        Invoke-RestMethod @HT -Body $onPremisesExtensionAttributes 
        #Invoke-RestMethod -Body (@{onPremisesExtensionAttributes = @{extensionAttribute15 = "$(Get-Random ${Org Theme Names})"}} | ConvertTo-Json)

        # Provide new user membership in the "License Assignment-FLOW_FREE" security group
        $GroupDN = "License Assignment-FLOW_FREE"
        $MgGroup = Invoke-RestMethod -Method 'GET' -Uri "$mg/groups?`$filter=displayName eq '$($GroupDN)'" -Headers ${Group (Read)} | Select-Object -ExpandProperty 'value'
        $directoryObject = @{
          "@odata.id" = "$mg/directoryObjects/$($MgUser.id)"
        } | ConvertTo-Json
        $HT = @{
          Method = 'POST'
          Uri    = "$mg/groups/$($MgGroup.id)/members/`$ref"
          Header = ${Group Member-Users (AddRemove)}
        }      
        Invoke-RestMethod @HT -Body $directoryObject

        $HT = @{
          Method = 'GET'
          Uri    = "$mg/groups/$($MgGroup.id)/members/$($MgUser.id)"
          Header = ${Group (Read)}
        }
        $_Var_Name = 'MgMemberOfGroup'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
        while (!($MgMemberOfGroup)) {
          Start-Sleep 2
          $RedirectedErrors = $($MgMemberOfGroup = Invoke-RestMethod @HT) 2>&1
        }
        Start-Sleep 2
        # Set up a Temporary Access Pass for this new user |
        New-TAP -KnownName $UserDN
        Write-Host -ForegroundColor 'Blue' -Object "`r`n$(${un/pw pair})`r`n"
        "`r`n$(${un/pw pair})`r`n$($TAP.temporaryAccessPass)" | Set-Clipboard
      }
    )
  }
  end {}
  clean {}
}

function New-Server2025ReferenceVHDXonZotacZboxMI642nano_BeginProcessEnd { # Constructs a reference VHDX file of Windows Server 2025 |
  [CmdletBinding()]
  param (
    [Parameter(
      HelpMessage = "Supply 1 of the 4 editions of Windows Server: Datacenter, DatacenterDesktopExperience, Standard, or StandardDesktopExperience",
      Position = 0, 
      ValueFromPipelineByPropertyName = $False
    )]
    [ValidateSet('Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience')]
    [string]
    $Edition = 'Datacenter'
  )
  begin {
    $StartTime = Get-Date
    $dir = "$hvVol\Hyper-V Prep"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    $dir = "$dir\Reference VHDX"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    $dir = "$dir\Windows Server 2025"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    $dir = "$hvVol\Hyper-V Prep\Images"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    $dir = "$dir\Windows Server 2025"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}    
    <# Delete when the time is right |
      $dir = "$hvVol\Hyper-V Prep"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $dir = "$hvVol\Hyper-V Prep\Reference VHDX"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $dir = "$hvVol\Hyper-V Prep\Reference VHDX\Windows Server 2025"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $dir = "$hvVol\Hyper-V Prep\Images"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      $dir = "$hvVol\Hyper-V Prep\Images\Windows Server 2025"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    #>

    <# Aspirations |
      Write a logical tree that crawls through persistent storage, removable media, and 
      network shares in search of .iso file. Dont use filenames. 
      Calculate the .iso file's SHA-256 hash. 
      If found, copy to $hvVol
      And if not found, the code should download Server 2025 from the web. 
      - How to query from Microsoft the SHA-256 has of the latest version of an OS?
      - We might have to consider Cultures outside of en-us. 
    #>

    try {
      Get-Item -Path "$hvVol\Hyper-V Prep\Images\Windows Server 2025\${Latest Server 2025}.iso" @east | Out-Null
    } catch {
      $dir = "$hvVol\Hyper-V Prep\Images\Windows Server 2025"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
      Copy-Item -Path "$FIT\Microsoft\OS\Server 25\${Latest Server 2025}.iso" -Destination "$hvVol\Hyper-V Prep\Images\Windows Server 2025" -Force | Out-Null
    }

    $dir = "Hyper-V Prep\Images\Windows Server 2025"; try {Get-Item -Path "$hvVol\$dir\${Latest Server 2025}.iso" @east | Out-Null} catch {Copy-Item -Path "\\NAS1\Karmic_Koala\$dir\${Latest Server 2025}.iso" -Destination "$hvVol\$dir" -Force | Out-Null}

    ${Iso File Path} = "$hvVol\Hyper-V Prep\Images\Windows Server 2025\${Latest Server 2025}.iso"
    switch ($Edition) {
      'Standard' {
        #'Standard'                    {${Reference VHDX Path} = "$hvVol\Hyper-V Prep\Reference VHDX\Windows Server 2025\s25std ${Latest Server 2025}.vhdx"}
        #'Standard'                    {${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\s25std ${Latest Server 2025}.vhdx"}
        ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      }
      'StandardDesktopExperience' {
        #'StandardDesktopExperience'   {${Reference VHDX Path} = "$hvVol\Hyper-V Prep\Reference VHDX\Windows Server 2025\s25stddt ${Latest Server 2025}.vhdx"}
        #'StandardDesktopExperience'   {${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\s25stddt ${Latest Server 2025}.vhdx"}
        ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      }
      'Datacenter' {
        #'Datacenter'                  {${Reference VHDX Path} = "$hvVol\Hyper-V Prep\Reference VHDX\Windows Server 2025\s25 ${Latest Server 2025}.vhdx"}
        #'Datacenter'                  {${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\s25 ${Latest Server 2025}.vhdx"}
        ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      }
      'DatacenterDesktopExperience' {
        #'DatacenterDesktopExperience' {${Reference VHDX Path} = "$hvVol\Hyper-V Prep\Reference VHDX\Windows Server 2025\s25desk ${Latest Server 2025}.vhdx"}
        #'DatacenterDesktopExperience' {${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\s25desk ${Latest Server 2025}.vhdx"}
        ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      }
      default {'This should never appear because the ValidateSet PVA already guards against rogue input'}
    }
  }
  process {
    Mount-DiskImage -ImagePath ${Iso File Path} | Out-Null
    ${Mounted ISO Image} = Get-DiskImage -ImagePath ${Iso File Path} | Get-Volume
    ${Mounted Image Letter} = [string]${Mounted ISO Image}.DriveLetter + ':'
    #${Reference VHDX} = New-VHD -Path ${Reference VHDX Path} -SizeBytes 256GB -Dynamic
    New-VHD -Path ${Reference VHDX Path} -SizeBytes 256GB -Dynamic > $null
    Mount-DiskImage -ImagePath ${Reference VHDX Path} > $null
    ${Mounted Ref VHDX Disk} = Get-DiskImage -ImagePath ${Reference VHDX Path} | Get-Disk
    ${Mounted Ref VHDX Disk #} = ${Mounted Ref VHDX Disk}.Number
    Initialize-Disk -Number ${Mounted Ref VHDX Disk #} -PartitionStyle 'MBR'
    ${Mounted Ref VHDX Drive} = New-Partition -DiskNumber ${Mounted Ref VHDX Disk #} -AssignDriveLetter -UseMaximumSize -IsActive | Format-Volume -Confirm:$False
    ${Mounted Ref VHDX Letter} = [string]${Mounted Ref VHDX Drive}.DriveLetter + ':'

    switch ($Edition) {
      'Standard'                    {
        Dism.exe /apply-Image /ImageFile:"$(${Mounted Image Letter})\Sources\install.wim" /Index:1 /ApplyDir:"${Mounted Ref VHDX Letter}\"
        break
      }
      'StandardDesktopExperience'   {
        Dism.exe /apply-Image /ImageFile:"$(${Mounted Image Letter})\Sources\install.wim" /Index:2 /ApplyDir:"$(${Mounted Ref VHDX Letter})\"
        break
      }
      'Datacenter'                  {
        Dism.exe /apply-Image /ImageFile:"$(${Mounted Image Letter})\Sources\install.wim" /Index:3 /ApplyDir:"${Mounted Ref VHDX Letter}\"
        break
      }
      'DatacenterDesktopExperience' {
        Dism.exe /apply-Image /ImageFile:"$(${Mounted Image Letter})\Sources\install.wim" /Index:4 /ApplyDir:"$(${Mounted Ref VHDX Letter})\"
        break
      }
      default                       {'This should never appear because the ValidateSet PVA already guards against rogue input'}
    }

    #Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\s2025\UnAttend.xml" -Destination "${Mounted Ref VHDX Letter}\"

    #Copy-Item -Path "$ps\lee\XmlConfigs\s2025\UnAttend.xml" -Destination "${Mounted Ref VHDX Letter}\"

    bcdboot.exe ${Mounted Ref VHDX Letter}\Windows /s ${Mounted Ref VHDX Letter} /f BIOS

    MBR2GPT.EXE /Convert /Disk:${Mounted Ref VHDX Disk #} /allowFullOs
  }
  end {
    Dismount-DiskImage -ImagePath ${Iso File Path} | Out-Null
    Dismount-DiskImage -ImagePath ${Reference VHDX Path} | Out-Null
    $EndTime = Get-Date
    write "Duration: $(($EndTime - $StartTime).Minutes)m$(($EndTime - $StartTime).Seconds)s"
  }
}

function New-Server2025ReferenceVHDXonZotacZboxMI642nano { # Constructs a reference VHDX file of Windows Server 2025 |
  [CmdletBinding()]
  param (
    [Parameter(
      HelpMessage = "Supply 1 of the 4 editions of Windows Server: Datacenter, DatacenterDesktopExperience, Standard, or StandardDesktopExperience",
      Position = 0, 
      ValueFromPipelineByPropertyName = $False
    )]
    [ValidateSet('Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience')]
    [string]
    $Edition = 'Datacenter'
  )

  <# Trials |
    $Edition = 'Standard'
    $Edition = 'StandardDesktopExperience'
    $Edition = 'Datacenter'
    $Edition = 'DatacenterDesktopExperience'
  #>
  
  
  $StartTime = Get-Date
  $dir = "$hvVol\Hyper-V Prep"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\Reference VHDX"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\Windows Server 2025"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$hvVol\Hyper-V Prep\Images"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\Windows Server 2025"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}    

  <# Aspirations |
    Write a logical tree that crawls through persistent storage, removable media, and 
    network shares in search of .iso file. Dont use filenames. 
    Calculate the .iso file's SHA-256 hash. 
    If found, copy to $hvVol
    And if not found, the code should download Server 2025 from the web. 
    - How to query from Microsoft the SHA-256 has of the latest version of an OS?
    - We might have to consider Cultures outside of en-us. 
  #>

  try {
    Get-Item -Path "$hvVol\Hyper-V Prep\Images\Windows Server 2025\${Latest Server 2025}.iso" @east | Out-Null
  } catch {
    $dir = "$hvVol\Hyper-V Prep\Images\Windows Server 2025"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    Copy-Item -Path "$FIT\Microsoft\OS\Server 25\${Latest Server 2025}.iso" -Destination "$hvVol\Hyper-V Prep\Images\Windows Server 2025" -Force | Out-Null
  }

  $dir = "Hyper-V Prep\Images\Windows Server 2025"; try {Get-Item -Path "$hvVol\$dir\${Latest Server 2025}.iso" @east | Out-Null} catch {Copy-Item -Path "\\NAS1\Karmic_Koala\$dir\${Latest Server 2025}.iso" -Destination "$hvVol\$dir" -Force | Out-Null}

  ${Iso File Path} = "$hvVol\Hyper-V Prep\Images\Windows Server 2025\${Latest Server 2025}.iso"
  switch ($Edition) {
    'Standard' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      break
    }
    'StandardDesktopExperience' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      break
    }
    'Datacenter' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      break
    }
    'DatacenterDesktopExperience' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      break
    }
    default {'This should never appear because the ValidateSet PVA already guards against rogue input'}
  }

  ${Mounted Image Letter} = (Mount-DiskImage -ImagePath ${Iso File Path} | Get-DiskImage | Get-Volume | Select-Object -ExpandProperty 'DriveLetter') + ':'
  New-VHD -Path ${Reference VHDX Path} -SizeBytes 40GB -Dynamic > $null # Small size deliberately chosen because _THE C: SHOULD ONLY CARRY SYSTEM FILES!!_
  ${Mounted Ref VHDX Disk #} = Mount-DiskImage -ImagePath ${Reference VHDX Path} | Get-DiskImage | Get-Disk | Select-Object -ExpandProperty 'Number'
  Initialize-Disk -Number ${Mounted Ref VHDX Disk #} -PartitionStyle 'MBR'
  ${Mounted Ref VHDX Letter} = (New-Partition -DiskNumber ${Mounted Ref VHDX Disk #} -AssignDriveLetter -UseMaximumSize -IsActive | Format-Volume -FileSystem 'NTFS' -Confirm:$False | Select-Object -ExpandProperty 'DriveLetter') + ':'

  switch ($Edition) {
    'Standard'                    {
      Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:1 /ApplyDir:"${Mounted Ref VHDX Letter}\" > $null
      break
    }
    'StandardDesktopExperience'   {
      Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:2 /ApplyDir:"$(${Mounted Ref VHDX Letter})\" > $null
      break
    }
    'Datacenter'                  {
      Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:3 /ApplyDir:"${Mounted Ref VHDX Letter}\" > $null
      break
    }
    'DatacenterDesktopExperience' {
      Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:4 /ApplyDir:"$(${Mounted Ref VHDX Letter})\" > $null
      break
    }
    default                       {'This should never appear because the ValidateSet PVA already guards against rogue input'}
  }

  bcdboot.exe ${Mounted Ref VHDX Letter}\Windows /s ${Mounted Ref VHDX Letter} /f BIOS
  MBR2GPT.EXE /Convert /Disk:${Mounted Ref VHDX Disk #} /allowFullOs

  Dismount-DiskImage -ImagePath ${Iso File Path} | Out-Null
  Dismount-DiskImage -ImagePath ${Reference VHDX Path} | Out-Null
  $EndTime = Get-Date
  write "Duration: $(($EndTime - $StartTime).Minutes)m$(($EndTime - $StartTime).Seconds)s"
}

function New-Server2025onZotacZboxMI642nano_With_Differencing_Disks { # Spins up a new Hyper-V running Server 2025 |
  [CmdletBinding(
    SupportsShouldProcess   = $True,
    ConfirmImpact           = 'low',
    DefaultParameterSetName = 'MemberServer',   # 'non-domain'
    SupportsPaging          = $true,
    HelpURI                 = 'https://www.altaro.com/hyper-v/customize-vm-powershell/',
    PositionalBinding       = $False
  )]
  [OutputType('DomainController',[string])]
  [OutputType('MemberServerStaticIP',[string])]
  [OutputType('MemberServer',[string])]
  [OutputType('non-domain',[string])]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!"
    )]
    [string]
    $Name0fVM = (('WIN-' + ((Get-RandomFileName)[0..7] -join '') + ((Get-RandomFileName)[0..2] -join '')).ToUpper()),

    [Parameter(
      Position = 1,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "placeholder"
    )]
    [ValidateSet('Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience')]
    [string]
    $Edition = 'Standard',

    [Parameter(
      Position = 2,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "placeholder"
    )]
    [ValidateSet(
      'DomainController',
      'MemberServer',
      'Member Server with Static IP',
      'non-domain'
    )]
    [string]
    $Kind = 'MemberServer',

    [Parameter(
      Position = 3,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Supply name of an AD Computer object. Remember that domain controllers are ALSO AD Computer objects! Stated differently, the ObjectClass of a DC also 'computer'."
    )]
    [ValidateLength(1,15)]
    [ValidatePattern(
      '^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$'
    )]
    [string]
    $Name0fGuestOS = (('WIN-' + ((Get-RandomFileName)[0..7] -join '') + ((Get-RandomFileName)[0..2] -join '')).ToUpper()),

    [Parameter(
      Position = 4,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "placeholder"
    )]
    [string]
    $hvHost = "$env:ComputerName",

    [Parameter(
      Position = 5,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID"
    )]
    [Parameter(
      Position = 5,
      Mandatory = $True,
      ParameterSetName = 'MemberServer',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID.`r`nDistinguishedName of OUs in AD will match this regular expression:`r`n`t^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$`r`nGUIDs (aka UUIDs) will match this regular expression:`r`n`t^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`r`n`r`nCopy and paste these examples into PowerShell:`r`n`t'OU=Demonstration,OU=Of,DC=Regex,DC=Pattern,DC=Matching' -match '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$'`r`n`t(New-Guid).ToString() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'"
    )]
    [ValidatePattern(
      '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )]
    [string]
    $OU,

    [Parameter(
      Position = 6
    )]
    [Int32]
    $cpu = 2,

    [Parameter(
      Position = 7,
      HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM"
    )]
    [int64]
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,

    [Parameter(
      Position = 8
    )]
    [string]
    $net = "SET-enabled External vSwitch",

    [Parameter(
      Position = 9,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [Parameter(
      Position = 9,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$'
    )]
    [string]
    $ip,

    [Parameter(
      Position = 10,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [Parameter(
      Position = 10,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $gw,

    [Parameter(
      Position = 11,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [Parameter(
      Position = 11,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $dns,

    [Parameter(
      Position = 12
    )]
    [ValidateSet(
      'StartIfRunning',
      'Start',
      'Nothing'
    )]
    [string]
    $ActionWhenBareMetalHostBoots = 'Start',

    [Parameter(
      Position = 13
    )]
    [ValidateSet(
      'Save',
      'TurnOff',
      'Shutdown'
    )]
    [string]
    $ActionOnBareMetalHostShutdown = 'Shutdown',

    [Parameter(ParameterSetName = 'MemberServerStaticIP')][string]$UnattendXML = "$env:SystemDrive\Hyper-V Prep\XML Configs\s2025\UnAttend.0.xml",
    [string]$UnattendDJXML = "$hvVol\Hyper-V Prep\XML Configs\s2025\UnAttend.DJ.xml",
    [string]$Join2Domain_Dhcp = "$hvVol\Hyper-V Prep\XML Configs\s2025\UnAttend.1.No Static IP Config.xml",
    [string]$UnattendXMLNewADForest = "$hvVol\Hyper-V Prep\XML Configs\s2025\UnAttend.00.New AD Forest.xml",

    [ValidateRange(1,100)]
    [Int32]
    $Buffer = 20, 

    [ValidateSet(
      'Disabled',
      'Production',
      'ProductionOnly',
      'Standard'
    )]
    [string]
    $CheckpointType = 'Standard',

    [ValidateSet(
      'Pause',
      'None'
    )]
    [string]
    $StorageDisconnectedAction = 'Pause',

    [int32]
    $HwThreadCountPerCore = '1',

    #[ValidateRange(1,4096)][int32]$VlanID # Hopefully this won't stay a mystery for long. 

    [Parameter(
      Position = 99,
      Mandatory = $true,
      HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]
    $Notes
  )

  <# Aspirations |
    - There's gotta be a PVA or something that exits the function if the environment isn't right. Namely, if Home edition is detected. 
  #>

  <# Trials |
    $Name0fVM = "40.14 Minecraft"
    $Notes = "Minecraft"
    $Edition = "Standard"
    $Kind = "MemberServer"
    $Name0fGuestOS = (('WIN-' + ((Get-RandomFileName)[0..7] -join '') + ((Get-RandomFileName)[0..2] -join '')).ToUpper())
    $hvHost = "$env:ComputerName"
    $OU = "OU=Tier 1 Servers,DC=ad,DC=kerberosnetworks,DC=com"
    $cpu = 2
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2*2MB
    $gen = 2
    $Buffer = 20
    #     $net = "SET-enabled External vSwitch"
    $net = "vSwitchNAT"
    #     $UnattendXML = "$env:SystemDrive\Hyper-V Prep\XML Configs\s2025\UnAttend.0.xml"
    #     $UnattendDJXML = "$hvVol\Hyper-V Prep\XML Configs\s2025\UnAttend.DJ.xml"
    #     $Join2Domain_Dhcp = "$hvVol\Hyper-V Prep\XML Configs\s2025\UnAttend.1.No Static IP Config.xml"

    $Join2Domain_Dhcp = "$lee\XmlConfigs\s2025\UnAttend 02 Domain Join with IP config via DHCP.xml"
    #     code $Join2Domain_Dhcp

    # code "C:\Users\lowpr\OneDrive\IT\pwsh\lee\XmlConfigs\s2025\UnAttend.0.xml"

    $ActionWhenBareMetalHostBoots = 'nothing'
    $ActionOnBareMetalHostShutdown = 'Shutdown'
    $CheckpointType = 'Standard'
    $StorageDisconnectedAction = 'Pause'
    $HwThreadCountPerCore = 1
  #>

  <# Aspiration | Format of OU is confirmed. Now verify the OU exists |
    Write-Host -ForeGroundColor 'Cyan' -Object "  Define an appropriately permissioned AD account that can read Organizational Units"
    if (
      ($Kind -eq 'MemberServer') -or ($Kind -eq 'Member Server with Static IP')
    ) {
      $NetBiosNameOfActiveDirectoryDomain = 'KNet'
      $DnsNameOfActiveDirectoryDomain = "ad.kerberosnetworks.com"
      $_Var_Name = 'OUReaderCred'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
      $SamAccountName = '_ouReader0'; if (!($OUReaderCred)) {$OUReaderCred = [PSCredential]::New("$NetBiosNameOfActiveDirectoryDomain\$SamAccountName",$(ConvertTo-SecureString -String $(Get-BitwardenPassword $SamAccountName) -AsPlainText -Force))}

      $RandomSelection = New-Object -TypeName 'System.Random'
      $IPs = Resolve-DnsName $DnsNameOfActiveDirectoryDomain | Select-Object -ExpandProperty 'IPAddress'
      $Name0fDC = Resolve-DnsName -Name $IPs[$RandomSelection.Next(0,$IPs.Count)] -Type 'Ptr' | Select-Object -ExpandProperty 'NameHost'
      #$cred = @{Server = $Name0fDC; Credential = $OUReaderCred}
      ($DomainDN),(${AD DNS}) = (Get-ADDomain | Select-Object -ExpandProperty 'DistinguishedName'),(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')
      try {${DC OUReader} = Get-PSSession -Name "$Name0fDC $SamAccountName" @east} catch {${DC OUReader} = New-PSSession -CN $Name0fDC -Name "$Name0fDC $SamAccountName" @l0gin; icm -Session ${DC OUReader} @start; icm -Session ${DC OUReader} {Set-Location \; Clear-Host}}
      $adVol = icm -Session ${DC OUReader} {$adVol}

      try {Get-ADOrganizationalUnit -Identity $OU -ErrorAction 'Stop'} catch {}
    }
  #>
  
  $RedirectedError = $(${Does This VM Already Exist?} = Get-VM -Name $Name0fVM) 2>&1
  if (${Does This VM Already Exist?}) {
    Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
    break
  }

  $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
  $message01 = ".vhdx file is confirmed to be in place."
  switch ($Edition) {
    'Standard' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'Standard'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break
    }
    'StandardDesktopExperience' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'StandardDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    'Datacenter' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DataCenter'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    'DatacenterDesktopExperience' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DatacenterDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
  }

  switch ($Kind) {
    'DomainController' {
      $IsDomainController = $True
      break
    }
    default {
      $IsDomainController = $False
      break
    }
  }

  ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
  ${Current VM Version} = (Get-VMHost).SupportedVmVersions | ? {$_ -match ${Current VM Version}}

  $HT = @{
    Name               = $Name0fVM
    ComputerName       = $hvHost # "$($hvHost)"
    Path               = $((Get-VMHost).VirtualMachinePath) # (Get-VMHost).VirtualMachinePath 
    Generation         = 2
    MemoryStartupBytes = $ram
    Version            = ${Current VM Version} # "$(${Current VM Version})"
  }
  try {${New VM} = Get-VM -Name $HT.Name @east} catch {${New VM} = New-VM @HT}

  ($IsDomainController) ? (& {
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    #try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir @easc -Force | Out-Null}
    ${script:Guest OS Disk Path} = "$dir\$Name0fVM.vhdx"
    #${script:Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)\$Name0fVM.vhdx"
    Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path} # -Force
    Set-ItemProperty -Path ${Guest OS Disk Path} -Name IsReadOnly -Value $False
  }) : 
  (& {
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    ${Differencing Disk Path} = Join-Path -Path $dir -ChildPath "$Name0fVM.vhdx"
    $HT = @{
      Path = ${Differencing Disk Path}
      ParentPath = ${Base VHD Path}
      Differencing = $True
    } 
    New-VHD @HT | Out-Null
    ${script:Guest OS Disk Path} = ${Differencing Disk Path}
  })

  $HT = @{ # Attach VHD containing Guest OS to VM |
    VMName = $Name0fVM
    Path = ${Guest OS Disk Path}
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{
    VMName = $Name0fVM
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  ${Guest OS Disk} = Get-VMHardDiskDrive @HT

  <# Version 1 of persistent storage naming scheme + misc configs |
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)\Storage1 $(${New VM}.Id).vhdx"; try {${Storage1 VHDX} = Get-VHD -Path $dir @east} catch {${Storage1 VHDX} = New-VHD -Path $dir -SizeBytes 2000GB -Dynamic}
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)\Storage2 $(${New VM}.Id).vhdx"; try {${Storage2 VHDX} = Get-VHD -Path $dir @east} catch {${Storage2 VHDX} = New-VHD -Path $dir -SizeBytes 2000GB -Dynamic}
  #>

  $uuid1 = (New-Guid).ToString()
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)\$(${New VM}.Id)_$($uuid1).vhdx"
  try {${Storage1 VHDX} = Get-VHD -Path $dir @east} catch {${Storage1 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}

  $uuid2 = (New-Guid).ToString()
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)\$(${New VM}.Id)_$($uuid2).vhdx"
  try {${Storage2 VHDX} = Get-VHD -Path $dir @east} catch {${Storage2 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}

  ($IsDomainController) ? 
  (& {
    Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null
    ${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage1 VHDX}.Path | Get-Disk
    ${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle GPT
    ${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    ${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Active Directory Storage" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null

    Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
    ${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage2 VHDX}.Path | Get-Disk
    ${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle GPT
    ${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    ${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage2" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
  }) : 
  (& {
    Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null
    ${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage1 VHDX}.Path | Get-Disk
    ${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle GPT
    ${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage1" | Out-Null
    ${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid1" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null

    Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
    ${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage2 VHDX}.Path | Get-Disk
    ${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle GPT
    ${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage2" | Out-Null
    ${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid2" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
  })

  $HT = @{ # Create new VHD for storage and attach to VM | 'Storage1 VHDX' |
    VMName = $Name0fVM
    Path = ${Storage1 VHDX}.Path
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '1'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{ # Create new VHD for storage and attach to VM | 'Storage2 VHDX' |
    VMName = $Name0fVM
    Path = ${Storage2 VHDX}.Path
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '2'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{ # Set memory quantity & behavior of VM |
    VMName = $Name0fVM
    DynamicMemoryEnabled = $True
    MinimumBytes = 256MB
    MaximumBytes = $ram
    Buffer = $Buffer
  }
  Set-VMMemory @HT
 
  $HT = @{ # VM priority when auto-launching at Hyper-V Host boot if cumulative assigned memory exhausts total physical memory |
    VMName = $Name0fVM
    Priority = '50'
  }
  Set-VMMemory @HT

  <# No more time synchronization with the Hyper-V host! | Unless standalone non-domain |
    ${All VM Integration Services} = [object[]]$('Guest Service Interface','Heartbeat','Key-Value Pair Exchange','Shutdown','Time Synchronization','VSS')
    ${All VM Integration Services} | % {Enable-VMIntegrationService -VMName $Name0fVM $_}
  #>
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Guest Service Interface'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Heartbeat'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Key-Value Pair Exchange'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Shutdown'
  ($Kind -eq 'non-domain') ? (Enable-VMIntegrationService -VMName $Name0fVM -Name 'Time Synchronization') : (Disable-VMIntegrationService -VMName $Name0fVM -Name 'Time Synchronization')
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'VSS'

  $HT = @{ # Quantity of vCPUs |
    VMName = $Name0fVM
    Count = $cpu
  }
  Set-VMProcessor @HT

  $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
    VMName = $Name0fVM
    Reserve = '0'
    Maximum = '100'
  }
  Set-VMProcessor @HT

  $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
    VMName = $Name0fVM
    RelativeWeight = '100'
  }
  Set-VMProcessor @HT

  $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
    VMName = $Name0fVM
    EnableHostResourceProtection = $True
  }
  Set-VMProcessor @HT

  $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false |
    VMName = $Name0fVM
    CompatibilityForMigrationEnabled = $False
  }
  Set-VMProcessor @HT

  $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
    VMName = $Name0fVM
    HwThreadCountPerCore = $HwThreadCountPerCore
  }
  Set-VMProcessor @HT

  $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
    Name = $Name0fVM
    AutomaticStartAction = $ActionWhenBareMetalHostBoots
    AutomaticStopAction = $ActionOnBareMetalHostShutdown
    AutomaticStartDelay = $(60 * ((Get-VM).Count - 1))
  }
  Set-VM @HT

  $HT = @{ # Floppy, IDE, SCSI, and... PMEM!? What the fuck is PMEM? |
    VMName = $Name0fVM
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '0'
  }
  ${Virtual Hard Disk} = Get-VMHardDiskDrive @HT

  ${Virtual Network Adapter} = Get-VMNetworkAdapter -VMName $Name0fVM

  ${Virtual DVD Drive} = Get-VMDvdDrive -VMName $Name0fVM

  $HT = @{ # Firmware settings |
    VMName = $Name0fVM
    FirstBootDevice = ${Guest OS Disk}
    SecureBootTemplate = 'MicrosoftWindows'
    EnableSecureBoot = 'On'
  }
  Set-VMFirmware @HT

  ($Kind -eq 'DomainController') ? (& {
    Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $false # VM Checkpoints and domain controllers don't mix. 
  }) : 
  (& {
    Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $True # Automatic Checkpoints. 
    Set-VM -Name $Name0fVM -CheckpointType $CheckpointType # Virtual Machine Checkpoints. 
  })

  Set-VM -Name $Name0fVM -SnapshotFileLocation (Get-VMHost).VirtualMachinePath # Snapshots. How is a 'Snapshot' different from a 'Checkpoint'? 

  Set-VM -VMName $Name0fVM -AutomaticCriticalErrorAction $StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120 # Automatic Response to Disconnected Storage. 

  Set-VM -VMName $Name0fVM -Notes $Notes

  ((Get-VMSwitch $net).EmbeddedTeamingEnabled) ? (& {
    Get-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
    ${VM NetAdapter-SET} = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $Name0fVM
    Connect-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $Name0fVM -SwitchName $net
  }) : (Connect-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM -SwitchName $net)
 
  Set-VMKeyProtector -VMName $Name0fVM -NewLocalKeyProtector
  Enable-VMTPM -VMName $Name0fVM

  Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null # Mount newly created .vhdx file if not using differencing disks
  $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
  $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
  $VHDVolumeName = ([string]$VHDPart.DriveLetter).trimend()
  $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

  #$_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | Format-Table -Autosize) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
  $_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | Format-Table -Autosize) ?? (Import-Module -Name $_Module_Name) > $null
  
  <# Aspirations | 
    Switch statement directly below needs to be re-written. Only use PrimaryAdmin if the machine is creating the tree root domain or a child domain. 
    All other cases spin up a dummy local administrator like zzzDeleteMe.  Or is that even necessary in all other cases? 

    Is the injected password appearing in the .xml file in PLAIN TEXT!??! You gotta do something about that. 
    
    How do you securely delete the .xml file once deployment is complete? 
    Is there an entry in the unattend.xml file that forces a self-delete? Perhaps the supporting .cmd file can contain a line of code. 
  #>
    
  <# Reference Vars | Can we delete? |
    $NetBiosNameOfActiveDirectoryDomain = $global:NetBiosNameOfActiveDirectoryDomain
    $BitwardenOrganizationName          = $global:BitwardenOrganizationName
    $BitwardenPwdManagerCollectionName  = $global:BitwardenPwdManagerCollectionName
    $BitwardenSecretsManagerProjectName = $global:BitwardenSecretsManagerProjectName
    ${Machine Account 01-Access Token}  = ${global:Machine Account 01-Access Token}
  #>  
  
  switch ($Kind) {
    'DomainController' {
      Set-Location -Path "$ns\GitHub\SvenGroot\GenerateAnswerFile\src\GenerateAnswerFile\bin\Debug\net8.0"
      $UniqueUnattend = "$ns\xml\unattend $(Call-DateVar).xml"
      $Name0fGuestOS = (('WIN-' + ((Get-RandomFileName)[0..7] -join '') + ((Get-RandomFileName)[0..2] -join '')).ToUpper())
      $HT = @{
        OutputFile = $UniqueUnattend
        Install = "Preinstalled"
        ComputerName = $Name0fGuestOS
        LocalAccount = @("Administrators:Administrator,$(Get-BitwardenPassword -un 'Administrator')","Administrators:PrimaryAdmin,$(Get-BitwardenPassword -un 'PrimaryAdmin')")
        DisableServerManager = $true
        TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')
        AutoLogonUser = 'PrimaryAdmin'
        AutoLogonPassword = $(Get-BitwardenPassword 'PrimaryAdmin')
        FirstLogonCommand = 'C:\Installs\Sysinternals\sdelete.exe C:\unattend.xml -p 2 -accepteula -nobanner'
      }
      ./GenerateAnswerFile.exe @HT
      ($XmlDocument = [xml]'<root></root>').Load($UniqueUnattend)
      $XmlDocument.Save("$VHDVolume\unattend.xml")
      Set-Location $env:SystemDrive\

    }
    'D0ma1nControll3r' {
      # Import XML document into an object instance of type XmlDocument
      ($XmlDocument = [xml]'<root></root>').Load($UnattendXMLNewADForest)

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}

      # Password of the 'Administrator' account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -un 'Administrator')}}

      # Password of the 'PrimaryAdmin' local admin account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword -un 'PrimaryAdmin')}}

      # IPv4 address + CIDR-based subnet mask on network adapter. Will configure IPv6 after logon
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$ht = '#text'; $_.interfaces.interface.unicastIPaddresses.ipaddress.$ht = $ip}}
  
      # Default gateway address
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = $gw}}
  
      # DNS Server address -- Statically sets IP address of the server on the network that this machine will use for DNS queries. 
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client" } | ForEach-Object { if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = $dns}}

      # Copy UnAttended.xml into root of mounted VHDX file
      $XmlDocument.Save("$VHDVolume\unattend.xml")
      break
    }
    'MemberServer' {
      Set-Location -Path "$ns\GitHub\SvenGroot\GenerateAnswerFile\src\GenerateAnswerFile\bin\Debug\net8.0"
      $UniqueUnattend = "$ns\xml\unattend $(Call-DateVar).xml"
      $Name0fGuestOS = (('WIN-' + ((Get-RandomFileName)[0..7] -join '') + ((Get-RandomFileName)[0..2] -join '')).ToUpper())
      $HT = @{
        OutputFile = $UniqueUnattend
        Install = "Preinstalled"
        ComputerName = $Name0fGuestOS
        LocalAccount = @("Administrators:BurnerAccount,$(Get-BitwardenPassword -un 'BurnerAccount')")
        DisableServerManager = $true
        JoinDomain = ${DNS Name of the Active Directory Forest Root Domain}
        JoinDomainUser = 'PrimaryAdmin'
        TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')
        JoinDomainPassword = $(Get-BitwardenPassword 'PrimaryAdmin')
        OUPath = $OU
        AutoLogonUser = 'BurnerAccount'
        AutoLogonPassword = $(Get-BitwardenPassword 'BurnerAccount')
        #FirstLogonCommand = 'ipconfig.exe /registerdns && timeout /T 0 && logoff.exe'
        FirstLogonCommand = 'ipconfig.exe /registerdns && cd\ && %SystemDrive%\Installs\Sysinternals\sdelete.exe %SystemDrive%\unattend.xml -p 2 -accepteula -nobanner'
      }
      ./GenerateAnswerFile.exe @HT
      ($XmlDocument = [xml]'<root></root>').Load($UniqueUnattend)
      $XmlDocument.Save("$VHDVolume\unattend.xml")
      Set-Location $env:SystemDrive\
    }
    'Memb3rServer' {
      $path = "$VHDVolume\Windows\Setup\Scripts"; try {$path = Get-Item -Path $path @east} catch {$path = New-Item -ItemType 'Directory' -Path $path}
      Copy-Item -Path "$lee\XmlConfigs\hostname-change_v2.ps1" -Destination "$path" -Force
      #      code "$path\hostname-change.ps1"
      #      $Join2Domain_Dhcp = "$lee\XmlConfigs\s2025\UnAttend 02 Domain Join with IP config via DHCP.xml"

    
      #     Set-Location "$VHDVolume\Windows\Setup\Scripts"
      #     ${C:hostname-change.ps1} -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"$($env:HashPwIddqd)" > "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      #     Set-Location -
    
      #         ${HostName Change} = Get-Content -Path "F:\Microsoft\OS\s25\Investigation 2023.1127.204958\hostname-change.ps1"
      #${HostName Change} = Get-Content -Path "$path\hostname-change_v2.ps1"

      #$escapedLocalPwIddqd = [regex]::Escape($env:LocalPwIddqd)
      #$escapedHashPwIddqd = [regex]::Escape($env:HashPwIddqd)
      #$escapedHashPwIddqd = $env:HashPwIddqd -replace '\$','\$' 
      #$escapedHashPwIddqd = $UnencryptedHashPw -replace '\$','\$' 

      ##READ## Making mistakes is the 2nd best way to learn. The 1st is learning from the mistakes of others. ##READ##
      #On 2023-11-28 I spent appx 90 minutes uncovering why my unattended domain joins were bombing out. 
      #After much investigation, the explantion was the presence of dollar signs in my password. 
      #Unescaped dollar signs were not being interpreted as literals, so PowerShell didn't treat those dollar signs as literals, and the password was incorrect. 
      #To be clear, I wouldn't have this problem if the domain-join password was being input in a secure fashion, like a CTRL + C, CTRL + V from a password manager. 
      #Assigning clear-text passwords to an user-scoped environment variable, e.g. $env:HashPwIddqd, is shit security, even 
      #if the user of that user-scoped environment variable is a highly protected account. 
      #Correct option is a digital vault like BeyondTrust Password Safe. 
      
      #${Code Block-Bytes} = [System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Join2Domain0_Tier1'))
      #${Code Block-Base64} = [Convert]::ToBase64String(${Code Block-Bytes})

      #[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Join2Domain0_Tier1')))


      #for ($i = 0; $i -lt ${HostName Change}.Count; $i++) {
      #  if (
      #    ${HostName Change}[$i] -match 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC'
      #  ) {
      #    ${HostName Change}[$i] = ${HostName Change}[$i] -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"'$($escapedLocalPwIddqd)'"   #  "'$($env:HashPwIddqd)'"
      #    # shit, might have to control for non-literals
      #  }
      #}
      #${HostName Change} | Set-Content -Path "$path\hostname-change_v2.ps1" -Confirm:$False -Force
      #      code "$path\hostname-change.ps1"
    
      ${OUPath Change} = Get-Content -Path "$path\hostname-change_v2.ps1"

      #$escapedOUPath = [regex]::Escape($OU)
      for ($j = 0; $j -lt ${OUPath Change}.Count; $j++) {
        if (
          ${OUPath Change}[$j] -match '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd'
        ) {
          ${OUPath Change}[$j] = ${OUPath Change}[$j] -replace '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd',$OU
        }
      }
      ${OUPath Change} | Set-Content -Path "$path\hostname-change_v2.ps1" -Confirm:$False -Force
      #      code "$path\hostname-change_v2.ps1"



      
      
      Copy-Item -Path $Join2Domain_Dhcp -Destination "$VHDVolume\" -Force
      [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))      
      ($XmlDocument = [xml]'<root></root>').Load("$VHDVolume\$(Get-Item -Path $Join2Domain_Dhcp | Select-Object -ExpandProperty 'Name')")

      #        ($XmlDocument = [xml]'<root></root>').Load($UniqueUnattend)
      
      #        $XmlDocument.Save("$VHDVolume\unattend.xml")

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}

      # Password of the 'Administrator' account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -un 'Administrator')}}

      # Password of the 'BurnerAccount' local admin account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | Select-Object -ExpandProperty 'UserAccounts' | Select-Object -ExpandProperty 'LocalAccounts' | Select-Object -ExpandProperty 'LocalAccount' | Select-Object -ExpandProperty 'Password'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))}}

      # Password of the account for automatically logging on
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.AutoLogon.Password.Value) {$_.AutoLogon.Password.Value = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))}}
      
      # enable DHCP client
      $XmlDocument.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.IPv4Settings.DhcpEnabled = 'true'}}
      #       $XmlDocument.Save("$ns\xml\WTF.xml")              
      #       code "$ns\xml\WTF.xml"              

      $XmlDocument.Save("$VHDVolume\unattend.xml") # Copy UnAttended.xml into root of mounted VHDX file

      Copy-Item -Path "$lee\XmlConfigs\SetupComplete.cmd" -Destination "$VHDVolume\"
      break
    }
    'Member Server with Static IP' {
      ($xml = [xml]'<root></root>').Load($UnattendXML)

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}
  
      # IPv4 address + CIDR-based subnet mask on network adapter. Will configure IPv6 after logon
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$ht = '#text'; $_.interfaces.interface.unicastIPaddresses.ipaddress.$ht = $ip}}
  
      # Default gateway address
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = $gw}}
  
      # DNS Server address -- Statically sets IP address of the server on the network that this machine will use for DNS queries. 
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client" } | ForEach-Object { if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = $dns}}

      # Password of the 'PrimaryAdmin' local admin account
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}

      <# For another day |
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\SetupComplete.cmd" -Destination "$VHDVolume\"
        try {Get-Item -Path "$VHDVolume\Windows\Setup\Scripts" @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path "$VHDVolume\Windows\Setup\Scripts" | Out-Null}
        # Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\hostname-change.ps1" -Destination "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\hostname-change.ps1" -Force
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\hostname-change.ps1" -Destination "$VHDVolume\Windows\Setup\Scripts"
        # Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\hostname-change.ps1" -Destination "$VHDVolume\Windows\Setup\Scripts" -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        #Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\s2025\UnAttend.DJ.xml" -Destination "$VHDVolume\"
        #Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\s2022\Unattend.DJ.xml" -Destination "$hvVol\Hyper-V Prep\XML Configs\s2022" -Force
      
        # Dang, might have to reconnect NAS each time? 

        #     Set-Location "$VHDVolume\Windows\Setup\Scripts"
        #     ${C:hostname-change.ps1} -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"$($env:HashPwIddqd)" > "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        #     Set-Location -
      
        #         ${HostName Change} = Get-Content -Path "F:\Microsoft\OS\s25\Investigation 2023.1127.204958\hostname-change.ps1"
        ${HostName Change} = Get-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        $escapedLocalPwIddqd = [regex]::Escape($env:LocalPwIddqd)
        #$escapedHashPwIddqd = [regex]::Escape($env:HashPwIddqd)
        #$escapedHashPwIddqd = $env:HashPwIddqd -replace '\$','\$' 
        #$escapedHashPwIddqd = $UnencryptedHashPw -replace '\$','\$' 

        ##READ## Making mistakes is the 2nd best way to learn. The 1st is learning from the mistakes of others. ##READ##
        #On 2023-11-28 I spent appx 90 minutes uncovering why my unattended domain joins were bombing out. 
        #After much investigation, the explantion was the presence of dollar signs in my password. 
        #Unescaped dollar signs were not being interpreted as literals, so PowerShell didn't treat those dollar signs as literals, and the password was incorrect. 
        #To be clear, I wouldn't have this problem if the domain-join password was being input in a secure fashion, like a CTRL + C, CTRL + V from a password manager. 
        #Assigning clear-text passwords to an user-scoped environment variable, e.g. $env:HashPwIddqd, is shit security, even 
        #if the user of that user-scoped environment variable is a highly protected account. 
        #Correct option is a digital vault like BeyondTrust Password Safe. 

        for ($i = 0; $i -lt ${HostName Change}.Count; $i++) {
          if (
            ${HostName Change}[$i] -match 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC'
          ) {
            ${HostName Change}[$i] = ${HostName Change}[$i] -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"'$($escapedLocalPwIddqd)'"   #  "'$($env:HashPwIddqd)'"
            # shit, might have to control for non-literals
          }
        }
        ${HostName Change} | Set-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1" -Confirm:$False -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      
        ${OUPath Change} = Get-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        $escapedOUPath = [regex]::Escape($OUPath)
        for ($j = 0; $j -lt ${OUPath Change}.Count; $j++) {
          if (
            ${OUPath Change}[$j] -match '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd'
          ) {
            ${OUPath Change}[$j] = ${OUPath Change}[$j] -replace '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd',$OUPath
          }
        }
        ${OUPath Change} | Set-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1" -Confirm:$False -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      
        ($xml = [xml]'<root></root>').Load($UnattendDJXML)
        $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | % {if ($_.ComputerName) {$_.ComputerName = $Name0fGuestOS}} # Set Guest OS %HostName% equal to $Name0fGuestOS
        $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.IPv4Settings.DhcpEnabled = 'true'}}
        $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = ''}}
        $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-DNS-Client"} | % {if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = ''}}
        $xml.Save("$VHDVolume\unattend.xml") # Copy UnAttended.xml into root of mounted VHDX file
      #>

      # Copy UnAttended.xml into root of mounted VHDX file
      $xml.Save("$VHDVolume\unattend.xml")

      break
    }
    'non-domain' {
      ($xml = [xml]'<root></root>').Load($Join2Domain_Dhcp)

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}

      # Password of the 'PrimaryAdmin' local admin account
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}

      # Copy UnAttended.xml into root of mounted VHDX file
      $xml.Save("$VHDVolume\unattend.xml")

      break
    }
  }

  $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $pwsh7MSI = Get-ChildItem -Path "$env:SystemDrive\Installs\PowerShell 7" -Filter PowerShell*x64.msi -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
  Copy-Item -Path "$pwsh7MSI" -Destination "$dir"

  $dir = "$VHDVolume\Installs\OneDrive"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $OneDriveEXE = Get-Item -Path "$env:SystemDrive\Installs\OneDrive\OneDriveSetup.exe"
  Copy-Item -Path "$OneDriveEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\VS Code"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $VSCodeEXE = Get-Item -Path "$env:SystemDrive\Installs\VSCodeSetup-x64-*.exe"
  Copy-Item -Path "$VSCodeEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\Sysinternals"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  # Pull down sdelete.exe
  try {
    Invoke-WebRequest -Uri 'http://live.sysinternals.com/sdelete.exe' -OutFile "$dir\sdelete.exe" @east
  } 
  catch {
    Copy-Item -Path "$up\sysint\sdelete.exe" -Destination "$dir"
  }

  Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
  Start-VM -Name $Name0fVM | Out-Null
  return $Name0fGuestOS
}

function New-Server2025onZotacZboxMI642nano_LeveragingUnattendXml_and_4_Sloppy_Parameter_Sets { # Spins up a new Hyper-V running Server 2025 |
  [CmdletBinding(
    SupportsShouldProcess   = $True,
    ConfirmImpact           = 'low',
    DefaultParameterSetName = 'MemberServer',   # 'non-domain'
    SupportsPaging          = $true,
    HelpURI                 = 'https://www.altaro.com/hyper-v/customize-vm-powershell/',
    PositionalBinding       = $False
  )]
  [OutputType('DomainController',[string])]
  [OutputType('MemberServerStaticIP',[string])]
  [OutputType('MemberServer',[string])]
  [OutputType('non-domain',[string])]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!"
    )]
    [string]
    $Name0fVM = ('WIN-' + (([System.IO.Path]::GetRandomFileName())[0..7] -join '') + (([System.IO.Path]::GetRandomFileName())[0..2] -join '')).ToUpper(),

    [Parameter(
      Position = 1,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "placeholder"
    )]
    [ValidateSet('Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience')]
    [string]
    $Edition = 'Standard',

    [Parameter(
      Position = 2,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "placeholder"
    )]
    [ValidateSet(
      'DomainController',
      'MemberServer',
      'Member Server with Static IP',
      'non-domain'
    )]
    [string]
    $Kind = 'MemberServer',

    [Parameter(
      Position = 3,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "Supply name of an AD Computer object. Remember that domain controllers are ALSO AD Computer objects! Stated differently, the ObjectClass of a DC also 'computer'."
    )]
    [ValidateLength(1,15)]
    [ValidatePattern(
      '^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$'
    )]
    [string]
    $Name0fGuestOS = ('WIN-' + (([System.IO.Path]::GetRandomFileName())[0..7] -join '') + (([System.IO.Path]::GetRandomFileName())[0..2] -join '')).ToUpper(),

    [Parameter(
      Position = 4,
      Mandatory = $false,
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "placeholder"
    )]
    [string]
    $hvHost = "$env:ComputerName",

    [Parameter(
      Position = 5,
      Mandatory = $false,
      ParameterSetName = 'MemberServerStaticIP',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID"
    )]
    [Parameter(
      Position = 5,
      Mandatory = $false,
      ParameterSetName = 'MemberServer',
      ValueFromPipelineByPropertyName = $true,
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID.`r`nDistinguishedName of OUs in AD will match this regular expression:`r`n`t^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$`r`nGUIDs (aka UUIDs) will match this regular expression:`r`n`t^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`r`n`r`nCopy and paste these examples into PowerShell:`r`n`t'OU=Demonstration,OU=Of,DC=Regex,DC=Pattern,DC=Matching' -match '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$'`r`n`t(New-Guid).ToString() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'"
    )]
    [ValidatePattern(
      '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )]
    [string]
    $OU,

    [Parameter(
      Position = 6
    )]
    [Int32]
    $cpu = 2,

    [Parameter(
      Position = 7,
      HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM"
    )]
    [int64]
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,

    [Parameter(
      Position = 8
    )]
    [string]
    $net = "SET-enabled External vSwitch",

    [Parameter(
      Position = 9,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [Parameter(
      Position = 9,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$'
    )]
    [string]
    $ip,

    [Parameter(
      Position = 10,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [Parameter(
      Position = 10,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $gw,

    [Parameter(
      Position = 11,
      Mandatory = $True,
      ParameterSetName = 'MemberServerStaticIP'
    )]
    [Parameter(
      Position = 11,
      Mandatory = $True,
      ParameterSetName = 'DomainController'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $dns,

    [Parameter(
      Position = 12
    )]
    [ValidateSet(
      'StartIfRunning',
      'Start',
      'Nothing'
    )]
    [string]
    $ActionWhenBareMetalHostBoots = 'Start',

    [Parameter(
      Position = 13
    )]
    [ValidateSet(
      'Save',
      'TurnOff',
      'Shutdown'
    )]
    [string]
    $ActionOnBareMetalHostShutdown = 'Shutdown',

    #[Parameter(ParameterSetName = 'MemberServerStaticIP')]
    #[string]$UnattendXML = "$env:SystemDrive\Hyper-V Prep\XML Configs\s2025\UnAttend.0.xml",
    #[string]$UnattendDJXML = "$hvVol\Hyper-V Prep\XML Configs\s2025\UnAttend.DJ.xml",
    #[string]$Join2Domain_Dhcp = "$hvVol\Hyper-V Prep\XML Configs\s2025\UnAttend.1.No Static IP Config.xml",
    #[string]$UnattendedXML_DomainControllers = "$lee\XmlConfigs\s2025\Domain Controllers.xml",
    #[string]$UnattendXMLNewADForest = "$hvVol\Hyper-V Prep\XML Configs\s2025\UnAttend.00.New AD Forest.xml",

    [Parameter(
      Mandatory = $True
    )]
    [string]$xml,

    [ValidateRange(1,100)]
    [Int32]
    $Buffer = 20, 

    [ValidateSet(
      'Disabled',
      'Production',
      'ProductionOnly',
      'Standard'
    )]
    [string]
    $CheckpointType = 'Standard',

    [ValidateSet(
      'Pause',
      'None'
    )]
    [string]
    $StorageDisconnectedAction = 'Pause',

    [int32]
    $HwThreadCountPerCore = '1',

    #[ValidateRange(1,4096)][int32]$VlanID # Hopefully this won't stay a mystery for long. 

    [Parameter(
      Position = 99,
      Mandatory = $true,
      HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]
    $Notes
  )

  <# Aspirations |
    - There's gotta be a PVA or something that exits the function if the environment isn't right. Detecting Windows Home edition or absence of Hyper-V should cause the function to fail. 
  #>

  <# Trials |
    $Name0fVM = "00.18 Domain Controller"
    $Notes = "Another domain controller"
    $Edition = "StandardDesktopExperience"
    $Kind = "DomainController"
    $xml = "C:\Users\iddqd\OneDrive\IT\pwsh\lee\XmlConfigs\s2025\New Active Directory Forest-Reduced.xml"
    $xml = "$IT1\cfg\wsim\Server 2025\DCs\2\from Windowsafg.xml"
    
    $Name0fGuestOS = ('WIN-' + (([System.IO.Path]::GetRandomFileName())[0..7] -join '') + (([System.IO.Path]::GetRandomFileName())[0..2] -join '')).ToUpper()
    $hvHost = "$env:ComputerName"
    $OU = "OU=Tier 1 Servers,DC=ad,DC=kerberosnetworks,DC=com"
    $cpu = 2
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2*2MB
    $gen = 2
    $Buffer = 20
    $ip = '10.44.10.20/23'
    $gw = '10.44.10.1'
    $dns = '127.0.0.1'
    #     $net = "SET-enabled External vSwitch"
    $net = "vSwitchNAT"
    $ActionWhenBareMetalHostBoots = 'nothing'
    $ActionOnBareMetalHostShutdown = 'Shutdown'
    $CheckpointType = 'Standard'
    $StorageDisconnectedAction = 'Pause'
    $HwThreadCountPerCore = 1;    
  #>

  <# Aspiration | Format of OU is confirmed. Now verify the OU exists |
    Write-Host -ForeGroundColor 'Cyan' -Object "  Define an appropriately permissioned AD account that can read Organizational Units"
    if (
      ($Kind -eq 'MemberServer') -or ($Kind -eq 'Member Server with Static IP')
    ) {
      $NetBiosNameOfActiveDirectoryDomain = 'KNet'
      $DnsNameOfActiveDirectoryDomain = "ad.kerberosnetworks.com"
      $_Var_Name = 'OUReaderCred'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name -Value $null}
      $SamAccountName = '_ouReader0'; if (!($OUReaderCred)) {$OUReaderCred = [PSCredential]::New("$NetBiosNameOfActiveDirectoryDomain\$SamAccountName",$(ConvertTo-SecureString -String $(Get-BitwardenPassword $SamAccountName) -AsPlainText -Force))}

      $RandomSelection = New-Object -TypeName 'System.Random'
      $IPs = Resolve-DnsName $DnsNameOfActiveDirectoryDomain | Select-Object -ExpandProperty 'IPAddress'
      $Name0fDC = Resolve-DnsName -Name $IPs[$RandomSelection.Next(0,$IPs.Count)] -Type 'Ptr' | Select-Object -ExpandProperty 'NameHost'
      #$cred = @{Server = $Name0fDC; Credential = $OUReaderCred}
      ($DomainDN),(${AD DNS}) = (Get-ADDomain | Select-Object -ExpandProperty 'DistinguishedName'),(Get-ADDomain | Select-Object -ExpandProperty 'DnsRoot')
      try {${DC OUReader} = Get-PSSession -Name "$Name0fDC $SamAccountName" -ErrorAction 'Stop'} catch {${DC OUReader} = New-PSSession -CN $Name0fDC -Name "$Name0fDC $SamAccountName" @l0gin; icm -Session ${DC OUReader} @start; icm -Session ${DC OUReader} {Set-Location \; Clear-Host}}
      $adVol = icm -Session ${DC OUReader} {$adVol}

      try {Get-ADOrganizationalUnit -Identity $OU -ErrorAction 'Stop'} catch {}
    }
  #>
  
  $RedirectedError = $(${Does This VM Already Exist?} = Get-VM -Name $Name0fVM) 2>&1
  if (${Does This VM Already Exist?}) {
    Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
    break
  }

  $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
  $message01 = ".vhdx file is confirmed to be in place."
  switch ($Edition) {
    'Standard' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'Standard'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break
    }
    'StandardDesktopExperience' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'StandardDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    'Datacenter' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DataCenter'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    'DatacenterDesktopExperience' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DatacenterDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
  }

  switch ($Kind) {
    'DomainController' {
      $IsDomainController = $True
      break
    }
    default {
      $IsDomainController = $False
      break
    }
  }

  ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
  ${Current VM Version} = (Get-VMHost).SupportedVmVersions | ? {$_ -match ${Current VM Version}}

  $HT = @{
    Name               = $Name0fVM
    ComputerName       = $hvHost
    Generation         = 2
    MemoryStartupBytes = $ram
    Version            = ${Current VM Version}
  }
  try {
    ${New VM} = Get-VM -Name $HT.Name -ErrorAction 'Stop'
  }
  catch {
    ${New VM} = New-VM @HT
  }

  # Create a copy of the .vhdx file located at ${Base VHD Path}. Filename begins with name of VM and then the VM id. 
  ${Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id).vhdx"
  Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path}

  $HT = @{ # Attach VHD containing Guest OS to VM |
    VMName = $Name0fVM
    Path = ${Guest OS Disk Path}
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{
    VMName = $Name0fVM
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  ${Guest OS Disk} = Get-VMHardDiskDrive @HT
  
  $uuid1 = (New-Guid).ToString()
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$($uuid1).vhdx"
  try {${Storage1 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'} catch {${Storage1 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}

  $uuid2 = (New-Guid).ToString()
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$($uuid2).vhdx"
  try {${Storage2 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'} catch {${Storage2 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}

  ($IsDomainController) ? 
  (& {
    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'O' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "AD DS Vol" > $null
    Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null

    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
    New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'P' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk" > $null
    Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null
  }) : 
  (& {
    Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null
    ${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage1 VHDX}.Path | Get-Disk
    ${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle GPT
    ${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage1" | Out-Null
    ${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid1" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Out-Null

    Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
    ${Mounted Storage VHDX Disk} = Get-DiskImage -ImagePath ${Storage2 VHDX}.Path | Get-Disk
    ${Mounted Storage VHDX Disk #} = ${Mounted Storage VHDX Disk}.Number
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
    Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
    Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle GPT
    ${New Partition} = New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize
    #${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage2" | Out-Null
    ${New Partition} | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Storage $uuid2" | Out-Null
    Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Out-Null
  })

  $HT = @{ # Create new VHD for storage and attach to VM | 'Storage1 VHDX' |
    VMName = $Name0fVM
    Path = ${Storage1 VHDX}.Path
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '1'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{ # Create new VHD for storage and attach to VM | 'Storage2 VHDX' |
    VMName = $Name0fVM
    Path = ${Storage2 VHDX}.Path
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '2'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{ # Set memory quantity & behavior of VM |
    VMName = $Name0fVM
    DynamicMemoryEnabled = $True
    MinimumBytes = 256MB
    MaximumBytes = $ram
    Buffer = $Buffer
  }
  Set-VMMemory @HT

  $HT = @{ # VM priority when auto-launching at Hyper-V Host boot if cumulative assigned memory exhausts total physical memory |
    VMName = $Name0fVM
    Priority = '50'
  }
  Set-VMMemory @HT

  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Guest Service Interface'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Heartbeat'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Key-Value Pair Exchange'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Shutdown'
  ($Kind -eq 'non-domain') ? (Enable-VMIntegrationService -VMName $Name0fVM -Name 'Time Synchronization') : (Disable-VMIntegrationService -VMName $Name0fVM -Name 'Time Synchronization')
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'VSS'

  $HT = @{ # Quantity of vCPUs |
    VMName = $Name0fVM
    Count = $cpu
  }
  Set-VMProcessor @HT

  $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
    VMName = $Name0fVM
    Reserve = '0'
    Maximum = '100'
  }
  Set-VMProcessor @HT

  $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
    VMName = $Name0fVM
    RelativeWeight = '100'
  }
  Set-VMProcessor @HT

  $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
    VMName = $Name0fVM
    EnableHostResourceProtection = $True
  }
  Set-VMProcessor @HT

  $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false |
    VMName = $Name0fVM
    CompatibilityForMigrationEnabled = $False
  }
  Set-VMProcessor @HT

  $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
    VMName = $Name0fVM
    HwThreadCountPerCore = $HwThreadCountPerCore
  }
  Set-VMProcessor @HT

  $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
    Name = $Name0fVM
    AutomaticStartAction = $ActionWhenBareMetalHostBoots
    AutomaticStopAction = $ActionOnBareMetalHostShutdown
    AutomaticStartDelay = $(60 * ((Get-VM).Count - 1))
  }
  Set-VM @HT

  $HT = @{ # Firmware settings |
    VMName = $Name0fVM
    FirstBootDevice = ${Guest OS Disk}
    SecureBootTemplate = 'MicrosoftWindows'
    EnableSecureBoot = 'On'
  }
  Set-VMFirmware @HT

  ($Kind -eq 'DomainController') ? 
  (& { # VM Checkpoints and domain controllers don't mix |
    Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $false
  }) : 
  (& { # Automatic Checkpoints | Virtual Machine Checkpoints |
    Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $True
    Set-VM -Name $Name0fVM -CheckpointType $CheckpointType
  })

  Set-VM -VMName $Name0fVM -AutomaticCriticalErrorAction $StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120 # Automatic Response to Disconnected Storage. 

  Set-VM -VMName $Name0fVM -Notes $Notes

  ((Get-VMSwitch $net).EmbeddedTeamingEnabled) ? 
  (& {
    Get-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
    ${VM NetAdapter-SET} = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $Name0fVM
    Connect-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $Name0fVM -SwitchName $net
  }) : 
  (
    Connect-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM -SwitchName $net
  )

  Set-VMKeyProtector -VMName $Name0fVM -NewLocalKeyProtector
  Enable-VMTPM -VMName $Name0fVM

  Mount-DiskImage -ImagePath ${Guest OS Disk Path} > $null # requires elevated permissions # # Mount newly created .vhdx file if not using differencing disks. Shit, did I just find a use for sudo? 
  $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
  $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
  #$VHDVolumeName = ([string]$VHDPart.DriveLetter).trimend()
  $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

  #$_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | Format-Table -Autosize) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null
  $_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | Format-Table -Autosize) ?? (Import-Module -Name $_Module_Name) > $null
  
  <# Aspirations | 
    Switch statement directly below needs to be re-written. Only use PrimaryAdmin if the machine is creating the tree root domain or a child domain. 
    All other cases spin up a dummy local administrator like zzzDeleteMe.  Or is that even necessary in all other cases? 

    Is the injected password appearing in the .xml file in PLAIN TEXT!??! You gotta do something about that. 
    
    How do you securely delete the .xml file once deployment is complete? 
    Is there an entry in the unattend.xml file that forces a self-delete? Perhaps the supporting .cmd file can contain a line of code. 
  #>

  switch ($Kind) {
    'DomainController' {
      ($XmlDocument = [xml]'<root></root>').Load($xml)
      $XmlDocument.Save("$VHDVolume\unattend.xml")
      break
    }
    'D0mainKontro11er' {
      # Import XML document into an object instance of type XmlDocument
      ($XmlDocument = [xml]'<root></root>').Load($xml) #        $UnattendedXML_DomainControllers | Set-Clipboard

      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'generalize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.DoNotCleanTaskBar = $false}

      # Set Guest OS %HostName% equal to $Name0fGuestOS 
      #$XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) {$_.ComputerName = $Name0fGuestOS}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $Name0fGuestOS}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${Public DNS Domain}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $BitwardenOrganizationName}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.DoNotCleanTaskBar = $false}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

      # IPv4 address + CIDR-based subnet mask on network adapter. Will configure IPv6 after logon
      #$XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$ht = '#text'; $_.interfaces.interface.unicastIPaddresses.ipaddress.$ht = $ip}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.interfaces.interface.Identifier = "eth0"}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.interfaces.interface.Ipv4Settings.DhcpEnabled = $false}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $ip}
  
      # Default gateway address
      #$XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = $gw}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $gw}
  
      # DNS Server address -- Statically sets IP address of the server on the network that this machine will use for DNS queries. 
      #$XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client" } | ForEach-Object { if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = $dns}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.interfaces.interface.Identifier = "eth0"}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.'#text' = $dns}

      # Disable RDP
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TerminalServices-LocalSessionManager"} | ForEach-Object {$_.fDenyTSConnections = $true}

      # Enable all three Windows Firewall profiles
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Networking-MPSSVC-Svc"} | ForEach-Object {$_.DomainProfile_EnableFirewall = $true}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Networking-MPSSVC-Svc"} | ForEach-Object {$_.PrivateProfile_EnableFirewall = $true}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Networking-MPSSVC-Svc"} | ForEach-Object {$_.PublicProfile_EnableFirewall = $true}

      # Password of the 'Administrator' account
      #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.PlainText) {$_.UserAccounts.AdministratorPassword.PlainText = $false}}
      #${Encoded Administrator Password} = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Administrator')))
      #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = ${Encoded Administrator Password}}}
      #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.PlainText = $false}
      #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Administrator')))}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword 'Administrator')}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.AdministratorPassword.PlainText = $true}

      # Password of the 'PrimaryAdmin' local admin account
      #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.PlainText) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.PlainText = $false}}
      #($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'PrimaryAdmin')))}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword 'PrimaryAdmin')}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.UserAccounts.LocalAccounts.LocalAccount.Password.PlainText = $true}

      # Other items under the 'oobeSystem' pass
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${Public DNS Domain}}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $BitwardenOrganizationName}
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')}

      # Copy UnAttended.xml into root of mounted VHDX file
      $XmlDocument.Save("$VHDVolume\unattend.xml")
      <# Investigations |
        $AltPath = "$ns\xml\unattend $(Call-DateVar).xml"
        $XmlDocument.Save($AltPath)
        $AltPath | Set-ClipBoard
        Remove-Variable 'XmlDocument'
      #>
      break
    }
    'MemberServer' {
      Set-Location -Path "$ns\GitHub\SvenGroot\GenerateAnswerFile\src\GenerateAnswerFile\bin\Debug\net8.0"
      $UniqueUnattend = "$ns\xml\unattend $(Call-DateVar).xml"
      $HT = @{
        OutputFile = $UniqueUnattend
        Install = "Preinstalled"
        ComputerName = $Name0fGuestOS
        LocalAccount = @("Administrators:BurnerAccount,$(Get-BitwardenPassword -un 'BurnerAccount')")
        DisableServerManager = $true
        JoinDomain = ${DNS Name of the Active Directory Forest Root Domain}
        JoinDomainUser = 'PrimaryAdmin'
        TimeZone = $(Get-TimeZone | Select-Object -ExpandProperty 'StandardName')
        JoinDomainPassword = $(Get-BitwardenPassword 'PrimaryAdmin')
        OUPath = $OU
        AutoLogonUser = 'BurnerAccount'
        AutoLogonPassword = $(Get-BitwardenPassword 'BurnerAccount')
        #FirstLogonCommand = 'ipconfig.exe /registerdns && timeout /T 0 && logoff.exe'
        FirstLogonCommand = 'ipconfig.exe /registerdns && cd\ && %SystemDrive%\Installs\Sysinternals\sdelete.exe -accepteula -nobanner %SystemDrive%\unattend.xml -p 2'
      }
      ./GenerateAnswerFile.exe @HT
      ($XmlDocument = [xml]'<root></root>').Load($UniqueUnattend)
      $XmlDocument.Save("$VHDVolume\unattend.xml") # requires elevated permissions
      Set-Location $env:SystemDrive\
    }
    'Memb3rServer' {
      $path = "$VHDVolume\Windows\Setup\Scripts"; try {$path = Get-Item -Path $path -ErrorAction 'Stop'} catch {$path = New-Item -ItemType 'Directory' -Path $path}
      Copy-Item -Path "$lee\XmlConfigs\hostname-change_v2.ps1" -Destination "$path" -Force
      #      code "$path\hostname-change.ps1"
      #      $Join2Domain_Dhcp = "$lee\XmlConfigs\s2025\UnAttend 02 Domain Join with IP config via DHCP.xml"

    
      #     Set-Location "$VHDVolume\Windows\Setup\Scripts"
      #     ${C:hostname-change.ps1} -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"$($env:HashPwIddqd)" > "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      #     Set-Location -
    
      #         ${HostName Change} = Get-Content -Path "F:\Microsoft\OS\s25\Investigation 2023.1127.204958\hostname-change.ps1"
      #${HostName Change} = Get-Content -Path "$path\hostname-change_v2.ps1"

      #$escapedLocalPwIddqd = [regex]::Escape($env:LocalPwIddqd)
      #$escapedHashPwIddqd = [regex]::Escape($env:HashPwIddqd)
      #$escapedHashPwIddqd = $env:HashPwIddqd -replace '\$','\$' 
      #$escapedHashPwIddqd = $UnencryptedHashPw -replace '\$','\$' 

      ##READ## Making mistakes is the 2nd best way to learn. The 1st is learning from the mistakes of others. ##READ##
      #On 2023-11-28 I spent appx 90 minutes uncovering why my unattended domain joins were bombing out. 
      #After much investigation, the explantion was the presence of dollar signs in my password. 
      #Unescaped dollar signs were not being interpreted as literals, so PowerShell didn't treat those dollar signs as literals, and the password was incorrect. 
      #To be clear, I wouldn't have this problem if the domain-join password was being input in a secure fashion, like a CTRL + C, CTRL + V from a password manager. 
      #Assigning clear-text passwords to an user-scoped environment variable, e.g. $env:HashPwIddqd, is shit security, even 
      #if the user of that user-scoped environment variable is a highly protected account. 
      #Correct option is a digital vault like BeyondTrust Password Safe. 
      
      #${Code Block-Bytes} = [System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Join2Domain0_Tier1'))
      #${Code Block-Base64} = [System.Convert]::ToBase64String(${Code Block-Bytes})

      #[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'Join2Domain0_Tier1')))


      #for ($i = 0; $i -lt ${HostName Change}.Count; $i++) {
      #  if (
      #    ${HostName Change}[$i] -match 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC'
      #  ) {
      #    ${HostName Change}[$i] = ${HostName Change}[$i] -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"'$($escapedLocalPwIddqd)'"   #  "'$($env:HashPwIddqd)'"
      #    # shit, might have to control for non-literals
      #  }
      #}
      #${HostName Change} | Set-Content -Path "$path\hostname-change_v2.ps1" -Confirm:$False -Force
      #      code "$path\hostname-change.ps1"
    
      ${OUPath Change} = Get-Content -Path "$path\hostname-change_v2.ps1"

      #$escapedOUPath = [regex]::Escape($OU)
      for ($j = 0; $j -lt ${OUPath Change}.Count; $j++) {
        if (
          ${OUPath Change}[$j] -match '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd'
        ) {
          ${OUPath Change}[$j] = ${OUPath Change}[$j] -replace '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd',$OU
        }
      }
      ${OUPath Change} | Set-Content -Path "$path\hostname-change_v2.ps1" -Confirm:$False -Force
      #      code "$path\hostname-change_v2.ps1"
    
      
      Copy-Item -Path $Join2Domain_Dhcp -Destination "$VHDVolume\" -Force
      [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))
      ($XmlDocument = [xml]'<root></root>').Load("$VHDVolume\$(Get-Item -Path $Join2Domain_Dhcp | Select-Object -ExpandProperty 'Name')")

      #        ($XmlDocument = [xml]'<root></root>').Load($UniqueUnattend)
      
      #        $XmlDocument.Save("$VHDVolume\unattend.xml")

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $XmlDocument.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}

      # Password of the 'Administrator' account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -un 'Administrator')}}

      # Password of the 'BurnerAccount' local admin account
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | Select-Object -ExpandProperty 'UserAccounts' | Select-Object -ExpandProperty 'LocalAccounts' | Select-Object -ExpandProperty 'LocalAccount' | Select-Object -ExpandProperty 'Password'
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))}}

      # Password of the account for automatically logging on
      ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}) | Select-Object -ExpandProperty 'component' | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.AutoLogon.Password.Value) {$_.AutoLogon.Password.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($(Get-BitwardenPassword 'BurnerAccount')))}}
      
      # enable DHCP client
      $XmlDocument.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.IPv4Settings.DhcpEnabled = 'true'}}
      #       $XmlDocument.Save("$ns\xml\WTF.xml")              
      #       code "$ns\xml\WTF.xml"              

      $XmlDocument.Save("$VHDVolume\unattend.xml") # Copy UnAttended.xml into root of mounted VHDX file

      Copy-Item -Path "$lee\XmlConfigs\SetupComplete.cmd" -Destination "$VHDVolume\"
      break
    }
    'Member Server with Static IP' {
      ($xml = [xml]'<root></root>').Load($UnattendXML)

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}
  
      # IPv4 address + CIDR-based subnet mask on network adapter. Will configure IPv6 after logon
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$ht = '#text'; $_.interfaces.interface.unicastIPaddresses.ipaddress.$ht = $ip}}
  
      # Default gateway address
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = $gw}}
  
      # DNS Server address -- Statically sets IP address of the server on the network that this machine will use for DNS queries. 
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client" } | ForEach-Object { if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = $dns}}

      # Password of the 'PrimaryAdmin' local admin account
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}

      <# For another day |
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\SetupComplete.cmd" -Destination "$VHDVolume\"
        try {Get-Item -Path "$VHDVolume\Windows\Setup\Scripts" -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path "$VHDVolume\Windows\Setup\Scripts" | Out-Null}
        # Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\hostname-change.ps1" -Destination "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\hostname-change.ps1" -Force
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\hostname-change.ps1" -Destination "$VHDVolume\Windows\Setup\Scripts"
        # Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\hostname-change.ps1" -Destination "$VHDVolume\Windows\Setup\Scripts" -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        #Copy-Item -Path "C:\Users\WkSt0\OneDrive\IT\pwsh\lee\XmlConfigs\s2025\UnAttend.DJ.xml" -Destination "$VHDVolume\"
        #Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\XML Configs\s2022\Unattend.DJ.xml" -Destination "$hvVol\Hyper-V Prep\XML Configs\s2022" -Force
      
        # Dang, might have to reconnect NAS each time? 

        #     Set-Location "$VHDVolume\Windows\Setup\Scripts"
        #     ${C:hostname-change.ps1} -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"$($env:HashPwIddqd)" > "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        #     Set-Location -
      
        #         ${HostName Change} = Get-Content -Path "F:\Microsoft\OS\s25\Investigation 2023.1127.204958\hostname-change.ps1"
        ${HostName Change} = Get-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        $escapedLocalPwIddqd = [regex]::Escape($env:LocalPwIddqd)
        #$escapedHashPwIddqd = [regex]::Escape($env:HashPwIddqd)
        #$escapedHashPwIddqd = $env:HashPwIddqd -replace '\$','\$' 
        #$escapedHashPwIddqd = $UnencryptedHashPw -replace '\$','\$' 

        ##READ## Making mistakes is the 2nd best way to learn. The 1st is learning from the mistakes of others. ##READ##
        #On 2023-11-28 I spent appx 90 minutes uncovering why my unattended domain joins were bombing out. 
        #After much investigation, the explantion was the presence of dollar signs in my password. 
        #Unescaped dollar signs were not being interpreted as literals, so PowerShell didn't treat those dollar signs as literals, and the password was incorrect. 
        #To be clear, I wouldn't have this problem if the domain-join password was being input in a secure fashion, like a CTRL + C, CTRL + V from a password manager. 
        #Assigning clear-text passwords to an user-scoped environment variable, e.g. $env:HashPwIddqd, is shit security, even 
        #if the user of that user-scoped environment variable is a highly protected account. 
        #Correct option is a digital vault like BeyondTrust Password Safe. 

        for ($i = 0; $i -lt ${HostName Change}.Count; $i++) {
          if (
            ${HostName Change}[$i] -match 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC'
          ) {
            ${HostName Change}[$i] = ${HostName Change}[$i] -replace 'paMSHlKJMbjsLrB9eUF4ubWt7b1vtcdlgfCSjHb4awzZNsLocstrUW5VQLHjtCB3LrtWHx6cfUk39dpao1KXmp6UCFbGH1ABAEgvjRGS3CWf8leZdXWYaejSjgNaoXuC',"'$($escapedLocalPwIddqd)'"   #  "'$($env:HashPwIddqd)'"
            # shit, might have to control for non-literals
          }
        }
        ${HostName Change} | Set-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1" -Confirm:$False -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      
        ${OUPath Change} = Get-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
        $escapedOUPath = [regex]::Escape($OUPath)
        for ($j = 0; $j -lt ${OUPath Change}.Count; $j++) {
          if (
            ${OUPath Change}[$j] -match '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd'
          ) {
            ${OUPath Change}[$j] = ${OUPath Change}[$j] -replace '7FDhqZ7AAaPFYU8GneCFMJ7iD3kFsHbzJMjEqDg2apSumQNkuen2nvoAuhx8BAtJVvP3JDuWsqwjDsFa2VgSsud8PKNXzf6k8PDzRQRyVZhjMPJJjQUMZm7gTumHyMmd',$OUPath
          }
        }
        ${OUPath Change} | Set-Content -Path "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1" -Confirm:$False -Force
        #      code "$VHDVolume\Windows\Setup\Scripts\hostname-change.ps1"
      
        ($xml = [xml]'<root></root>').Load($UnattendDJXML)
        $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | % {if ($_.ComputerName) {$_.ComputerName = $Name0fGuestOS}} # Set Guest OS %HostName% equal to $Name0fGuestOS
        $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.IPv4Settings.DhcpEnabled = 'true'}}
        $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = ''}}
        $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-DNS-Client"} | % {if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = ''}}
        $xml.Save("$VHDVolume\unattend.xml") # Copy UnAttended.xml into root of mounted VHDX file
      #>

      # Copy UnAttended.xml into root of mounted VHDX file
      $xml.Save("$VHDVolume\unattend.xml")

      break
    }
    'non-domain' {
      ($xml = [xml]'<root></root>').Load($Join2Domain_Dhcp)

      # Set Guest OS %HostName% equal to $Name0fGuestOS
      $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}

      # Password of the 'PrimaryAdmin' local admin account
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}
      ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword -SamAccountName 'PrimaryAdmin')}}

      # Copy UnAttended.xml into root of mounted VHDX file
      $xml.Save("$VHDVolume\unattend.xml")

      break
    }
  }

  $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $pwsh7MSI = Get-ChildItem -Path "$env:SystemDrive\Installs\PowerShell 7" -Filter PowerShell*x64.msi -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
  Copy-Item -Path "$pwsh7MSI" -Destination "$dir"

  $dir = "$VHDVolume\Installs\OneDrive"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $OneDriveEXE = Get-Item -Path "$env:SystemDrive\Installs\OneDrive\OneDriveSetup.exe"
  Copy-Item -Path "$OneDriveEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\VS Code"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $VSCodeEXE = Get-Item -Path "$env:SystemDrive\Installs\VSCodeSetup-x64-*.exe"
  Copy-Item -Path "$VSCodeEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\Sysinternals"; try {Get-Item -Path $dir -ErrorAction 'Stop' | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  # Pull down sdelete.exe
  try {
    Invoke-WebRequest -Uri 'http://live.sysinternals.com/sdelete.exe' -OutFile "$dir\sdelete.exe" -ErrorAction 'Stop'
  } 
  catch {
    Copy-Item -Path "$up\sysint\sdelete.exe" -Destination "$dir"
  }

  Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
  Start-VM -Name $Name0fVM | Out-Null
  return $Name0fGuestOS

  <# Delete all children of VirtualHardDiskPath |
    Get-VM | Remove-VM -Force
    Get-ChildItem -Path (Get-VMHost).VirtualHardDiskPath -Recurse -File -Exclude "Server 2025*.vhdx" | Select-Object -ExpandProperty 'FullName' | Remove-Item -Force
    Get-ChildItem -Path (Get-VMHost).VirtualHardDiskPath -Recurse -Directory | Select-Object -ExpandProperty 'FullName' | Remove-Item -Force
  #>
}

function _PrimordialDnsServer {
  param (
    [string]$Name0fVM = "01.00 Domain Name System",
    [string]$UnattendXML = "$osVol\Hyper-V Prep\XML Configs\s2025\UnAttend.PrimordialDNS.xml",
    [ValidateSet('1','2','3','4')][string]$Ed = '1',
    [ValidatePattern('^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$')][string]$ip = '10.44.10.2/23',
    [ValidatePattern('^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$')][string]$gw = '10.44.10.1',
    [ValidatePattern('^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$')][string]$dns = '127.0.0.1',
    [string]$Notes = "Machine begins life as a standalone non-domain DNS server and is eventually joined to the domain.",

    [ValidateLength(1,15)][ValidatePattern('^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$')][string]$Name0fGuestOS = (('WIN-' + ((Get-RandomFileName)[0..7] -join '') + ((Get-RandomFileName)[0..2] -join '')).ToUpper()),
    [string]$hvHost = "$env:ComputerName",
    [Int32]$cpu = 2,
    [int64]$ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,
    [string]$net = "SET-enabled External vSwitch",
    [string]$ActionWhenBareMetalHostBoots = 'Start',
    [string]$ActionOnBareMetalHostShutdown = 'Shutdown',
    [int32]$LaunchDelayBareMetalHostBoots = $(((Get-VM).Count + 1) * 30),
    [string]$gen = '2',
    [Int32]$Buffer = 20, 
    [string]$CheckpointType = 'Standard',
    [int32]$HwThreadCountPerCore = '1'
  )

  $RedirectedError = $(${Does This VM Already Exist?} = Get-VM -Name $Name0fVM) 2>&1

  if (${Does This VM Already Exist?}) {
    Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
    break
  }

  $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
  $message01 = ".vhdx file is confirmed to be in place."
  switch ($Ed) {
    '1' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'Standard'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break
    }
    '2' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'StandardDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    '3' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DataCenter'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    '4' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DatacenterDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
  }

  ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
  ${Current VM Version} = (Get-VMHost).SupportedVmVersions | ? {$_ -match ${Current VM Version}}

  $HT = @{
    Name               = $Name0fVM
    ComputerName       = $hvHost
    Path               = $((Get-VMHost).VirtualMachinePath)
    Generation         = $gen
    MemoryStartupBytes = $ram
    Version            = ${Current VM Version}
  }
  try {${New VM} = Get-VM -Name $HT.Name @east} catch {${New VM} = New-VM @HT}

  # Don't use a differencing disk? If a differencing disk is fine, use the commented-out code
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  ${Guest OS Disk Path} = "$dir\$Name0fVM.vhdx"
  Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path}
  Set-ItemProperty -Path ${Guest OS Disk Path} -Name IsReadOnly -Value $False
  <# Differencing disk setup |
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    ${Differencing Disk Path} = Join-Path -Path $dir -ChildPath "$Name0fVM.vhdx"
    $HT = @{
      Path = ${Differencing Disk Path}
      ParentPath = ${Base VHD Path}
      Differencing = $True
    } 
    New-VHD @HT | Out-Null
    ${script:Guest OS Disk Path} = ${Differencing Disk Path}
#>

  $HT = @{
    VMName = $Name0fVM
    Path = ${Guest OS Disk Path}
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{
    VMName = $Name0fVM
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  ${Guest OS Disk} = Get-VMHardDiskDrive @HT

  $HT = @{
    VMName = $Name0fVM
    DynamicMemoryEnabled = $True
    MinimumBytes = 256MB
    MaximumBytes = $ram
    Buffer = $Buffer
  }
  Set-VMMemory @HT
 
  $HT = @{
    VMName = $Name0fVM
    Priority = '50'
  }
  Set-VMMemory @HT

  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Guest Service Interface'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Heartbeat'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Key-Value Pair Exchange'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Shutdown'
  Disable-VMIntegrationService -VMName $Name0fVM -Name 'Time Synchronization'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'VSS'

  $HT = @{
    VMName = $Name0fVM
    Count = $cpu
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    Reserve = '0'
    Maximum = '100'
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    RelativeWeight = '100'
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    EnableHostResourceProtection = $True
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    CompatibilityForMigrationEnabled = $False
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    HwThreadCountPerCore = $HwThreadCountPerCore
  }
  Set-VMProcessor @HT

  $HT = @{
    Name = $Name0fVM
    AutomaticStartAction = $ActionWhenBareMetalHostBoots
    AutomaticStopAction = $ActionOnBareMetalHostShutdown
    AutomaticStartDelay = $LaunchDelayBareMetalHostBoots
  }
  Set-VM @HT

  $HT = @{
    VMName = $Name0fVM
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '0'
  }
  ${Virtual Hard Disk} = Get-VMHardDiskDrive @HT

  ${Virtual Network Adapter} = Get-VMNetworkAdapter -VMName $Name0fVM

  $HT = @{
    VMName = $Name0fVM
    FirstBootDevice = ${Guest OS Disk}
    SecureBootTemplate = 'MicrosoftWindows'
    EnableSecureBoot = 'On'
  }
  Set-VMFirmware @HT

  Set-VM -Name $Name0fVM -CheckpointType $CheckpointType
  Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $True
  Set-VM -Name $Name0fVM -SnapshotFileLocation (Get-VMHost).VirtualMachinePath
  Set-VM -VMName $Name0fVM -Notes $Notes

  Get-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
  ${VM NetAdapter-SET} = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $Name0fVM
  Connect-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $Name0fVM -SwitchName $net

  Set-VMKeyProtector -VMName $Name0fVM -NewLocalKeyProtector
  Enable-VMTPM -VMName $Name0fVM

  Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
  $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
  $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
  $VHDVolumeName = ([string]$VHDPart.DriveLetter).trimend()
  $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

  $_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | ft -a) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null

  ($xml = [xml]'<root></root>').Load($UnattendXML)
  
  # Set Guest OS %HostName% equal to $Name0fGuestOS
  $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}
  
  # IPv4 address + CIDR-based subnet mask on network adapter. Will configure IPv6 after logon
  $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$ht = '#text'; $_.interfaces.interface.unicastIPaddresses.ipaddress.$ht = $ip}}
  
  # Default gateway address
  $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = $gw}}
  
  # DNS Server address -- Statically sets IP address of the server on the network that this machine will use for DNS queries. 
  $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client" } | ForEach-Object { if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = $dns}}
  
  # Password of the 'PrimordialDnsAdmin' local admin account
  ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -SamAccountName 'PrimordialDnsAdmin')}}
  ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword -SamAccountName 'PrimordialDnsAdmin')}}
  
  # Copy UnAttended.xml into root of mounted VHDX file
  $xml.Save("$VHDVolume\UnAttend.XML")

  $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $pwsh7MSI = Get-ChildItem -Path "$osVol\Installs\PowerShell 7" -Filter PowerShell*x64.msi -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
  Copy-Item -Path "$pwsh7MSI" -Destination "$dir"

  $dir = "$VHDVolume\Installs\OneDrive"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $OneDriveEXE = Get-Item -Path "$osVol\Installs\OneDrive\OneDriveSetup.exe"
  Copy-Item -Path "$OneDriveEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\VS Code"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $VSCodeEXE = Get-Item -Path "$osVol\Installs\VSCodeSetup-x64-*.exe"
  Copy-Item -Path "$VSCodeEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\Sysinternals"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  # Pull down sdelete.exe

  Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
  Start-VM -Name $Name0fVM | Out-Null
}

function _PrimordialDhcpServer {
  param (
    [string]$Name0fVM = "02.00 Dynamic Host Configuration Protocol",
    [string]$UnattendXML = "$osVol\Hyper-V Prep\XML Configs\s2025\UnAttend.PrimordialDHCP.xml",
    [ValidateSet('1','2','3','4')][string]$Ed = '1',
    [ValidatePattern('^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$')][string]$ip = '10.44.10.3/23',
    [ValidatePattern('^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$')][string]$gw = '10.44.10.1',
    [ValidatePattern('^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$')][string]$dns = '10.44.10.2',
    [string]$Notes = "Machine begins life as a standalone non-domain DHCP server and is eventually joined to the domain.",

    [ValidateLength(1,15)][ValidatePattern('^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$')][string]$Name0fGuestOS = (('WIN-' + ((Get-RandomFileName)[0..7] -join '') + ((Get-RandomFileName)[0..2] -join '')).ToUpper()),
    [string]$hvHost = "$env:ComputerName",
    [Int32]$cpu = 2,
    [int64]$ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,
    [string]$net = "SET-enabled External vSwitch",
    [string]$ActionWhenBareMetalHostBoots = 'Start',
    [string]$ActionOnBareMetalHostShutdown = 'Shutdown',
    [int32]$LaunchDelayBareMetalHostBoots = $(((Get-VM).Count + 1) * 30),
    [string]$gen = '2',
    [Int32]$Buffer = 20, 
    [string]$CheckpointType = 'Standard',
    [int32]$HwThreadCountPerCore = '1'
  )

  $RedirectedError = $(${Does This VM Already Exist?} = Get-VM -Name $Name0fVM) 2>&1

  if (${Does This VM Already Exist?}) {
    Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
    break
  }

  $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
  $message01 = ".vhdx file is confirmed to be in place."
  switch ($Ed) {
    '1' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'Standard'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break
    }
    '2' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'StandardDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    '3' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DataCenter'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
    '4' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      if (!(Test-Path -Path ${Base VHD Path})) {
        Write-Host -ForegroundColor 'Magenta' -Object $message00
        New-Server2025ReferenceVHDXonZotacZboxMI642nano -Edition 'DatacenterDesktopExperience'
        $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
        while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
        Remove-Variable 'VHD File-system Object'
        Write-Host -ForegroundColor 'Yellow' -Object $message01
      }
      break      
    }
  }

  ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
  ${Current VM Version} = (Get-VMHost).SupportedVmVersions | ? {$_ -match ${Current VM Version}}

  $HT = @{
    Name               = $Name0fVM
    ComputerName       = $hvHost
    Path               = $((Get-VMHost).VirtualMachinePath)
    Generation         = $gen
    MemoryStartupBytes = $ram
    Version            = ${Current VM Version}
  }
  try {${New VM} = Get-VM -Name $HT.Name @east} catch {${New VM} = New-VM @HT}

  # Don't use a differencing disk? If a differencing disk is fine, use the commented-out code
  $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  ${Guest OS Disk Path} = "$dir\$Name0fVM.vhdx"
  Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path}
  Set-ItemProperty -Path ${Guest OS Disk Path} -Name IsReadOnly -Value $False
  <# Differencing disk setup |
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
    ${Differencing Disk Path} = Join-Path -Path $dir -ChildPath "$Name0fVM.vhdx"
    $HT = @{
      Path = ${Differencing Disk Path}
      ParentPath = ${Base VHD Path}
      Differencing = $True
    } 
    New-VHD @HT | Out-Null
    ${script:Guest OS Disk Path} = ${Differencing Disk Path}
#>

  $HT = @{
    VMName = $Name0fVM
    Path = ${Guest OS Disk Path}
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  Add-VMHardDiskDrive @HT

  $HT = @{
    VMName = $Name0fVM
    ControllerType = 'SCSI'
    ControllerLocation = '0'
    ControllerNumber = '0'
  }
  ${Guest OS Disk} = Get-VMHardDiskDrive @HT

  $HT = @{
    VMName = $Name0fVM
    DynamicMemoryEnabled = $True
    MinimumBytes = 256MB
    MaximumBytes = $ram
    Buffer = $Buffer
  }
  Set-VMMemory @HT
 
  $HT = @{
    VMName = $Name0fVM
    Priority = '50'
  }
  Set-VMMemory @HT

  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Guest Service Interface'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Heartbeat'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Key-Value Pair Exchange'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'Shutdown'
  Disable-VMIntegrationService -VMName $Name0fVM -Name 'Time Synchronization'
  Enable-VMIntegrationService -VMName $Name0fVM -Name 'VSS'

  $HT = @{
    VMName = $Name0fVM
    Count = $cpu
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    Reserve = '0'
    Maximum = '100'
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    RelativeWeight = '100'
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    EnableHostResourceProtection = $True
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    CompatibilityForMigrationEnabled = $False
  }
  Set-VMProcessor @HT

  $HT = @{
    VMName = $Name0fVM
    HwThreadCountPerCore = $HwThreadCountPerCore
  }
  Set-VMProcessor @HT

  $HT = @{
    Name = $Name0fVM
    AutomaticStartAction = $ActionWhenBareMetalHostBoots
    AutomaticStopAction = $ActionOnBareMetalHostShutdown
    AutomaticStartDelay = $LaunchDelayBareMetalHostBoots
  }
  Set-VM @HT

  $HT = @{
    VMName = $Name0fVM
    ControllerType = 'SCSI'
    ControllerNumber = '0'
    ControllerLocation = '0'
  }
  ${Virtual Hard Disk} = Get-VMHardDiskDrive @HT

  ${Virtual Network Adapter} = Get-VMNetworkAdapter -VMName $Name0fVM

  $HT = @{
    VMName = $Name0fVM
    FirstBootDevice = ${Guest OS Disk}
    SecureBootTemplate = 'MicrosoftWindows'
    EnableSecureBoot = 'On'
  }
  Set-VMFirmware @HT

  Set-VM -Name $Name0fVM -CheckpointType $CheckpointType
  Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $True
  Set-VM -Name $Name0fVM -SnapshotFileLocation (Get-VMHost).VirtualMachinePath
  Set-VM -VMName $Name0fVM -Notes $Notes

  Get-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
  ${VM NetAdapter-SET} = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $Name0fVM
  Connect-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $Name0fVM -SwitchName $net

  Set-VMKeyProtector -VMName $Name0fVM -NewLocalKeyProtector
  Enable-VMTPM -VMName $Name0fVM

  Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
  $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
  $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
  $VHDVolumeName = ([string]$VHDPart.DriveLetter).trimend()
  $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

  $_Module_Name = "Secure-Automations-Toolset"; (Get-Module -Name $_Module_Name | ft -a) ?? (Import-Module -Name $_Module_Name -Scope 'Global') > $null

  ($xml = [xml]'<root></root>').Load($UnattendXML)
  # Set Guest OS %HostName% equal to $Name0fGuestOS
  $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup" } | ForEach-Object {if ($_.ComputerName) { $_.ComputerName = $Name0fGuestOS}}
  # IPv4 address + CIDR-based subnet mask on network adapter. Will configure IPv6 after logon
  $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$ht = '#text'; $_.interfaces.interface.unicastIPaddresses.ipaddress.$ht = $ip}}
  # Default gateway address
  $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = $gw}}
  # DNS Server address -- Statically sets IP address of the server on the network that this machine will use for DNS queries. 
  $xml.unattend.settings.component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client" } | ForEach-Object { if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = $dns}}
  # Password of the 'PrimordialDhcpAdmin' local admin account
  ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.AdministratorPassword.Value) {$_.UserAccounts.AdministratorPassword.Value = $(Get-BitwardenPassword -SamAccountName 'PrimordialDhcpAdmin')}}
  ($xml.unattend.settings).Where({$_.Pass -eq 'oobeSystem'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {if ($_.UserAccounts.LocalAccounts.LocalAccount.Password.Value) {$_.UserAccounts.LocalAccounts.LocalAccount.Password.Value = $(Get-BitwardenPassword -SamAccountName 'PrimordialDhcpAdmin')}}
  # Copy UnAttended.xml into root of mounted VHDX file
  $xml.Save("$VHDVolume\UnAttend.XML")

  $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $pwsh7MSI = Get-ChildItem -Path "$osVol\Installs\PowerShell 7" -Filter PowerShell*x64.msi -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
  Copy-Item -Path "$pwsh7MSI" -Destination "$dir"

  $dir = "$VHDVolume\Installs\OneDrive"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $OneDriveEXE = Get-Item -Path "$osVol\Installs\OneDrive\OneDriveSetup.exe"
  Copy-Item -Path "$OneDriveEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\VS Code"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $VSCodeEXE = Get-Item -Path "$osVol\Installs\VSCodeSetup-x64-*.exe"
  Copy-Item -Path "$VSCodeEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\Sysinternals"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  # Pull down sdelete.exe

  Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
  Start-VM -Name $Name0fVM | Out-Null
}

function New-w11onAsusZenbook {
  [CmdletBinding(
    SupportsShouldProcess   = $True,
    ConfirmImpact           = 'High',
    SupportsPaging          = $true,
    HelpURI                 = 'https://www.altaro.com/hyper-v/customize-vm-powershell/',
    PositionalBinding       = $False
  )]
  param (
    [Parameter(Position=0,Mandatory = $False,HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!",ValueFromPipelineByPropertyName = $False)][string]$Name0fVM = (('WIN-' + ((Get-RandomFileName)[0..7] -join '') + ((Get-RandomFileName)[0..2] -join '')).ToUpper()),
    [ValidateSet('1','6','10')][string]$Ed = '1',
    [Parameter(Position=1)][string]$hvHost = 'localhost',
    [Parameter(Position=2)][Int32]$cpu  = 2,
    [Parameter(Position=3)][int64]$ram  = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,
    [Parameter(Position=4)][ValidateSet('vSwitchNAT','Isolated vSwitch')][string]$net = 'Isolated vSwitch',
    [ValidateLength(1,15)]
    [ValidatePattern(
      '^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$'
    )][Parameter(
      Mandatory = $False,
      HelpMessage = "Write a value of %ComputerName% at the OS level",
      Position = 5, 
      ValueFromPipelineByPropertyName = $False
    )][string]$Name0fOSinstance = (('WIN-' + ((Get-RandomFileName)[0..7] -join '') + ((Get-RandomFileName)[0..2] -join '')).ToUpper()),
    [string]$Notes = "Always use DHCP for IP cfg on Windows 11 machines, including the PAWs.",
    [string]$UnattendXML = "$hvVol\Hyper-V Prep\XML Configs\w11_Ent\UnAttend.xml",
    [string]$UnattendDJXML = "$hvVol\Hyper-V Prep\XML Configs\w11_Ent\UnAttend.DJ.xml",
    #    [string]$UnattendDJXML = "$Lee\XmlConfigs\w11_Ent\UnAttend.DJ.xml",
    [ValidateSet('1','2')][string]$gen = '2',
    [ValidateRange(1,100)][Int32]$Buffer = 5, 
    [ValidateSet('StartIfRunning','Start','Nothing')][string]$hvHostBootAction = 'Nothing',
    [ValidateSet('Save','TurnOff','Shutdown')][string]$hvHostShutdownAction = 'Shutdown',
    [ValidateSet('Disabled','Production','ProductionOnly','Standard')][string]$CheckpointType = 'Standard',
    [ValidateSet('Pause','None')][string]$StorageDisconnectedAction = 'Pause'
  )

  ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | sort | select -Last 1
  ${Current VM Version} = (Get-VMHost).SupportedVmVersions | ? {$_ -match ${Current VM Version}}
  $HT = @{
    Name               = $Name0fVM
    ComputerName       = "$($hvHost)"
    Path               = "$((Get-VMHost).VirtualMachinePath)"
    Generation         = $gen
    MemoryStartupBytes = $ram
    Version            = "$(${Current VM Version})"
  }
  try {${New VM} = Get-VM $HT.Name @east} catch {${New VM} = New-VM @HT}

  switch ($Ed) {
    '1'  {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\w11Ent_VM_Patched_${Latest Windows 11 Enterprise}.vhdx"
    }
    '6'  {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\w11Pro.vhdx"
    }
    '10' {
      ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\w11Pro4WS.vhdx"
    }
    default {'This should never appear because the ValidateSet PVA already guards against rogue input'}
  }

  New-Item -ItemType 'Directory' -Path "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)" @easc -Force  | Out-Null
  ${Differencing Disk Path} = Join-Path -Path "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Id)" -ChildPath "$Name0fVM.vhdx"

  $HT = @{
    Path                    = ${Differencing Disk Path}
    ParentPath              = ${Base VHD Path}
    Differencing            = $True
  }
  New-VHD @HT  | Out-Null
  ${Guest OS Disk Path} = ${Differencing Disk Path} # Ternary operator not used so no controls for variable scoping needed. 

  Add-VMHardDiskDrive -VMName $Name0fVM -Path ${Guest OS Disk Path} -ControllerType SCSI -ControllerNumber '0' -ControllerLocation '0'
  ${Guest OS Disk} = Get-VMHardDiskDrive -VMName $Name0fVM -ControllerType SCSI -ControllerNumber '0' -ControllerLocation '0'

  Set-VMMemory -VMName $Name0fVM -DynamicMemoryEnabled $True -MinimumBytes 256MB -MaximumBytes $ram -Buffer $Buffer
  Set-VMMemory -VMName $Name0fVM -Priority 50

  ${All VM Integration Services} = [object[]]$('Guest Service Interface','Heartbeat','Key-Value Pair Exchange','Shutdown','Time Synchronization','VSS')
  ${All VM Integration Services} | % {Enable-VMIntegrationService -VMName "$Name0fVM" $_}

  Set-VMProcessor -VMName $Name0fVM -Count $cpu
  Set-VMProcessor -VMName $Name0fVM -Reserve 0 -Maximum 100
  Set-VMProcessor -VMName $Name0fVM -RelativeWeight 100
  Set-VMProcessor -VMName $Name0fVM -EnableHostResourceProtection $True
  Set-VMProcessor -VMName $Name0fVM -CompatibilityForMigrationEnabled $False

  Set-VM -Name $Name0fVM -AutomaticStartAction $hvHostBootAction
  Set-VM -Name $Name0fVM -AutomaticStopAction $hvHostShutdownAction

  ${Virtual Hard Disk} = Get-VMHardDiskDrive -VMName $Name0fVM -ControllerType SCSI -ControllerNumber '0' -ControllerLocation '0'
  ${Virtual Network Adapter} = Get-VMNetworkAdapter -VMName $Name0fVM
  ${Virtual DVD Drive} = Get-VMDvdDrive -VMName $Name0fVM

  $HT = @{
    VMName             = "$Name0fVM"
    FirstBootDevice    = ${Guest OS Disk}
    SecureBootTemplate = 'MicrosoftWindows'
    EnableSecureBoot   = 'On'
  }
  Set-VMFirmware @HT

  Set-VM -Name $Name0fVM -CheckpointType $CheckpointType
  Set-VM -Name $Name0fVM -AutomaticCheckpointsEnabled $True
  Set-VM -Name $Name0fVM -SnapshotFileLocation (Get-VMHost).VirtualMachinePath
  Set-VM -Name $Name0fVM -SmartPagingFilePath (Get-VMHost).VirtualMachinePath
  Set-VM -VMName $Name0fVM -AutomaticCriticalErrorAction $StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120
  Set-VM -VMName $Name0fVM -Notes $Notes

  <# MAC address spoofing. Explore another day |
    Set-VMNetworkAdapter -VMName $Name0fVM -MacAddressSpoofing On -DynamicMacAddress
    Don't set MAC address spoofing on the virtual network adapter just yet. Explore when the time comes. 
  #> 
  Connect-VMNetworkAdapter -Name "Network Adapter" -VMName $Name0fVM -SwitchName $net

  <# Complications might arise when running New-w11 on Windows 10 or an older server |
    if (${Computer Info Lite}.OSName -notmatch 'Windows 11') {
      $Guardian01 = Get-HgsGuardian -Name Guardian01
      $KeyProtector01 = New-HgsKeyProtector -Owner $Guardian01 -AllowUntrustedRoot
      Set-VMKeyProtector -VMName $Name -KeyProtector $KeyProtector01.RawData
      Enable-VMTPM -VMName $Name
    }
  #>

  Set-VMKeyProtector -VMName $Name0fVM -NewLocalKeyProtector
  Enable-VMTPM -VMName $Name0fVM

  Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
  $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
  $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
  $VHDVolumeName = ([string]$VHDPart.DriveLetter).trimend()
  $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

  <# unattend.xml mayhem |
    #($xml = [xml]'<root></root>').Load($UnattendXML)
    ($xml = [xml]'<root></root>').Load($UnattendDJXML)
    $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | % {if ($_.ComputerName) {$_.ComputerName = $Name0fOSinstance}} 
    $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.IPv4Settings.DhcpEnabled = 'true'}}
    $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-TCPIP"} | % {if ($_.Interfaces) {$_.interfaces.interface.routes.route.NextHopAddress = ''}}
    $xml.unattend.settings.component | ? {$_.Name -eq "Microsoft-Windows-DNS-Client"} | % {if ($_.Interfaces) {$ht = '#text';$_.interfaces.interface.DNSServerSearchOrder.ipaddress.$ht = ''}}
    $xml.unattend.settings.component | ? {$_.Name -eq 'Microsoft-Windows-UnattendedJoin'} | % {
      if ($_.identification) {
        $_.identification.credentials.password = $env:LocalPwIddqd # $UnencryptedLocalPw
        #$_.identification.credentials.password = $env:HashPwIddqd # $UnencryptedHashPw
      }
    }
    $xml.Save("$VHDVolume\UnAttend.XML")
    #$DateVar = Call-DateVar4
    #$xml.Save("$Lee\XmlConfigs\w11_Ent\UnAttend.DJ $($DateVar).xml")
  #>

  $dir = "$VHDVolume\Installs"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $dir = "$dir\PowerShell 7"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $pwsh7MSI = Get-ChildItem -Path "$osVol\Installs\PowerShell 7" -Filter PowerShell*x64.msi -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1
  Copy-Item -Path "$pwsh7MSI" -Destination "$dir"

  $dir = "$VHDVolume\Installs\OneDrive"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $OneDriveEXE = Get-Item -Path "$osVol\Installs\OneDrive\OneDriveSetup.exe"
  Copy-Item -Path "$OneDriveEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\VS Code"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  $VSCodeEXE = Get-Item -Path "$osVol\Installs\VSCodeSetup-x64-*.exe"
  Copy-Item -Path "$VSCodeEXE" -Destination "$dir"

  $dir = "$VHDVolume\Installs\Sysinternals"; try {Get-Item -Path $dir @east | Out-Null} catch {New-Item -ItemType 'Directory' -Path $dir | Out-Null}
  # Pull down sdelete.exe

  Dismount-DiskImage -ImagePath ${Guest OS Disk Path}  | Out-Null
  Start-VM -Name $Name0fVM  | Out-Null
  #return $Name0fOSinstance
}; Clear-Host  

function New-w11RefVHDXonAsusZenbook {
  [CmdletBinding(
    SupportsShouldProcess = $True,
    ConfirmImpact = 'High',
    HelpURI               = 'https://learn.microsoft.com/en-us/graph/overview',
    PositionalBinding     = $True
  )]
  param(
    [ValidateSet('Windows 11 Pro','Windows 11 Pro for Workstations','Windows 11 Enterprise')]
    [Parameter(
      HelpMessage = "Choose either 'Windows 11 Pro', 'Windows 11 Pro for Workstations', or 'Windows 11 Enterprise'",
      Position = 0, 
      ValueFromPipelineByPropertyName = $False
    )][string]$Edition = 'Windows 11 Enterprise'
  )
  begin {
    $StartTime = Get-Date
    $path = "$hvVol\Hyper-V Prep";                       try {Get-Item -Path $path @east | Out-Null} catch {New-Item -ItemType Directory -Path $path | Out-Null}
    $path = "$hvVol\Hyper-V Prep\Images";                try {Get-Item -Path $path @east | Out-Null} catch {New-Item -ItemType Directory -Path $path | Out-Null}
    $path = "$hvVol\Hyper-V Prep\Images\Windows 11 Pro"; try {Get-Item -Path $path @east | Out-Null} catch {New-Item -ItemType Directory -Path $path | Out-Null}

    try {Get-Item -Path "$hvVol\Hyper-V Prep\Images\${Latest Windows 11 Pro}.iso" @east | Out-Null} catch {
      if (Test-Path -Path "$FIT\Microsoft\OS\Windows 11 Pro\${Latest Windows 11 Pro}.iso") {
        Copy-Item -Path "$FIT\Microsoft\OS\Windows 11 Pro\${Latest Windows 11 Pro}.iso" -Destination "$hvVol\Hyper-V Prep\Images\Windows 11 Pro" -Force | Out-Null
      } 
      elseif (Test-Path -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\Images\${Latest Windows 11 Pro}.iso") {
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\Images\${Latest Windows 11 Pro}.iso" -Destination "$hvVol\Hyper-V Prep\Images\Windows 11 Pro" -Force | Out-Null
      }
    }

    $path = "$hvVol\Hyper-V Prep\Images\Windows 11 Enterprise"; try {Get-Item -Path $path @east | Out-Null} catch {New-Item -ItemType Directory -Path $path | Out-Null}

    try {
      Get-Item -Path "$hvVol\Hyper-V Prep\Images\Windows 11 Enterprise\${Latest Windows 11 Enterprise}.iso" @east | Out-Null
    } 
    catch {
      if (Test-Path -Path "$FIT\Microsoft\OS\Windows 11 Enterprise\${Latest Windows 11 Enterprise}.iso") {
        Copy-Item -Path "$FIT\Microsoft\OS\Windows 11 Enterprise\${Latest Windows 11 Enterprise}.iso" -Destination "$hvVol\Hyper-V Prep\Images\Windows 11 Enterprise" -Force | Out-Null
        #Copy-Item -Path "$FIT\Microsoft\OS\Windows 11 Enterprise\${Latest Windows 11 Enterprise}.iso" -Destination "$hvVol\Hyper-V Prep\Images\w11.iso" -Force | Out-Null
      }
      elseif (Test-Path -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\Images\${Latest Windows 11 Enterprise}.iso") {
        Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\Images\${Latest Windows 11 Enterprise}.iso" -Destination "$hvVol\Hyper-V Prep\Images" -Force | Out-Null
        #Copy-Item -Path "\\NAS1\Karmic_Koala\Hyper-V Prep\Images\${Latest Windows 11 Enterprise}.iso" -Destination "$hvVol\Hyper-V Prep\Images\w11.iso" -Force | Out-Null
      }
    }

    switch ($Edition) {
      'Windows 11 Pro'                  {${Iso File Path} = "$hvVol\Hyper-V Prep\Images\${Latest Windows 11 Pro}.iso"}
      'Windows 11 Pro for Workstations' {${Iso File Path} = "$hvVol\Hyper-V Prep\Images\${Latest Windows 11 Pro}.iso"}
      'Windows 11 Enterprise'           {${Iso File Path} = "$hvVol\Hyper-V Prep\Images\Windows 11 Enterprise\${Latest Windows 11 Enterprise}.iso"}
      default                           {'This should never appear because the ValidateSet PVA already guards against rogue input'}
    }

    switch ($Edition) {
      'Windows 11 Pro'                  {${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\w11Pro.vhdx"}
      'Windows 11 Pro for Workstations' {${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\w11Pro 4 WS.vhdx"}
      'Windows 11 Enterprise'           {${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\${Latest Windows 11 Enterprise}.vhdx"}
      default                           {'This should never appear because the ValidateSet PVA already guards against rogue input'}
    }


  }
  process {
    Mount-DiskImage -ImagePath ${Iso File Path} | Out-Null
    ${Mounted ISO Image} = Get-DiskImage -ImagePath ${Iso File Path} | Get-Volume
    ${Mounted Image Letter} = [string]${Mounted ISO Image}.DriveLetter + ':'
    #Get-WindowsImage -ImagePath "${Mounted Image Letter}\sources\install.wim"
    # 6  =  Windows 11 Pro
    # 10  =  Windows 11 Pro for Workstations
    ${Reference VHDX} = New-VHD -Path ${Reference VHDX Path} -SizeBytes 750GB -Dynamic
    Mount-DiskImage -ImagePath ${Reference VHDX Path}
    ${Mounted Ref VHDX Disk} = Get-DiskImage -ImagePath ${Reference VHDX Path} | Get-Disk
    ${Mounted Ref VHDX Disk #} = ${Mounted Ref VHDX Disk}.Number
    Initialize-Disk -Number ${Mounted Ref VHDX Disk #} -PartitionStyle 'MBR'

    ${Mounted Ref VHDX Drive} = New-Partition -DiskNumber ${Mounted Ref VHDX Disk #} -AssignDriveLetter -UseMaximumSize -IsActive | Format-Volume -Confirm:$False
    ${Mounted Ref VHDX Letter} = [string]${Mounted Ref VHDX Drive}.DriveLetter + ':'

    switch ($Edition) {
      'Windows 11 Pro'                  {Dism.exe /apply-Image /ImageFile:"$(${Mounted Image Letter})\Sources\install.wim" /Index:6  /ApplyDir:"${Mounted Ref VHDX Letter}\"}
      'Windows 11 Pro for Workstations' {Dism.exe /apply-Image /ImageFile:"$(${Mounted Image Letter})\Sources\install.wim" /Index:10 /ApplyDir:"$(${Mounted Ref VHDX Letter})\"}
      'Windows 11 Enterprise'           {Dism.exe /apply-Image /ImageFile:"$(${Mounted Image Letter})\Sources\install.wim" /Index:1  /ApplyDir:"$(${Mounted Ref VHDX Letter})\"}
      default                           {'This should never appear because the ValidateSet PVA already guards against rogue input'}
    }

    # NOTE: Investigate whether compatibility issues arise with our Unattend.xml file & the edition of Windows 11. 
    #Copy-Item -Path "$hvVol\Hyper-V Prep\XML Configs\w11_Ent\UnAttend.xml" -Destination "${Mounted Ref VHDX Letter}\"
    bcdboot.exe ${Mounted Ref VHDX Letter}\Windows /s ${Mounted Ref VHDX Letter} /f BIOS
    MBR2GPT.EXE /Convert /Disk:${Mounted Ref VHDX Disk #} /allowFullOs
  }
  end {
    Dismount-DiskImage -ImagePath ${Iso File Path} | Out-Null
    Dismount-DiskImage -ImagePath ${Reference VHDX Path} | Out-Null
    $EndTime = Get-Date
    write "Duration: $(($EndTime - $StartTime).Minutes)m$(($EndTime - $StartTime).Seconds)s"
  }
}

function _AutoGeneratedSecurePassword {
  param (
    [Alias('Len')]
    [Parameter(Position = 0)]
    [int32]$Length = 128
  )
  begin {
    $sequence = -join (
      [char[]](0x30..0x39) + [char[]](0x41..0x5A) + [char[]](0x61..0x7A) + [char](0x21) + [char](0x40) + [char](0x23) + [char](0x24) + [char](0x25) + [char](0x5E) + [char](0x26) + [char](0x2A)
    )

    $RandomObject = New-Object -TypeName 'System.Random'
  }
  process {
    -join $(
      foreach ($i in 0..($Length - 1)) {
        $sequence[$RandomObject.Next(0, $sequence.Length - 1)]
      }
    )
  }
}

function _PrerequisiteC0nditions_DeleteWhenTheTimeIsRight {
  # Use named matches to capture the well-known SID of the user account that owns the pwsh.exe process executing these commands.
  $WhoAmI = whoami.exe /all
  for ($i = 0; $i -lt $WhoAmI.length; $i++) {
    if (
      $WhoAmI[$i] -match '^Mandatory Label\\\D+Label\s+(?<Well_Known_SID>\S+)'
    ) {
      $Well_Known_SID = $Matches['Well_Known_SID']
    }
  }

  # Save the identity of the User's current interactive logon session into the variable ${explorer Owner} 
  $_Var_Name = 'explorer Owner'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } catch {
    New-Variable -Name $_Var_Name
  }
  ${query.exe session} = query.exe session
  for ($i = 0; $i -lt ${query.exe session}.Length; $i++) {
    if (
      ${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'
    ) {
      Set-Variable -Name $_Var_Name -Value ($Matches['explorer_Owner'])
    }
  }
  ${global:explorer Owner} = ${explorer Owner}

  # Define the variable $osVol to avoid hard-coding 'C:' into directory paths
  $_Var_Name = 'osVol'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } catch {
    New-Variable -Name $_Var_Name -Scope 'Global'
  }
  Set-Variable -Name $_Var_Name -Value ($env:SystemDrive) -Scope 'Global'
  $global:osVol = $env:SystemDrive

  # Establish folder structure in root of user profile: 
  $Folder1 = 'NoSync'
  try {
    Get-Item -Path "$osVol\Users\${explorer Owner}\$Folder1" -ErrorAction 'Stop' | Out-Null
  } 
  catch {
    New-Item -ItemType 'Directory' -Path "$osVol\Users\${explorer Owner}\$Folder1" | Out-Null
  }
  $Folder2 = 'CLIs'
  try {
    Get-Item -Path "$osVol\Users\${explorer Owner}\$Folder1\$Folder2" -ErrorAction 'Stop' | Out-Null
  } catch {
    New-Item -ItemType 'Directory' -Path "$osVol\Users\${explorer Owner}\$Folder1\$Folder2" | Out-Null
  }

  # Define variable representing "CLIs" directory
  $_Var_Name = 'CLIs'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } catch {
    New-Variable -Name $_Var_Name -Scope 'Global'
  }
  $CLIs = "$osVol\Users\${explorer Owner}\$Folder1\$Folder2"
  #Set-Variable -Name $_Var_Name -Value ("$osVol\Users\${explorer Owner}\$Folder1\$Folder2") -Scope 'Global'

  # Add CLIs directory to user-scoped $env:Path environment variable for this PowerShell session
  $env:Path = $env:Path + "$ns\CLIs;"
  
  # Confirm presence of Bitwarden Password Manager CLI (bw.exe) in $CLIs directory. Download to $CLIs if not already present.
  if (
    !(Test-Path -Path "$CLIs\bw.exe")
  ) {
    Invoke-WebRequest -Uri "https://vault.bitwarden.com/download/?app=cli&platform=windows" -OutFile "$CLIs\bw-windows.zip" -Verbose
    Expand-Archive -Path "$CLIs\bw-windows.zip" -Destination $CLIs
    Remove-Item -Path "$CLIs\bw-windows.zip" -Confirm:$false
  }

  # Confirm presence of the jq.exe JSON processor. Necessary for writing into the Bitwarden Password Manager via the Bitwarden CLI
  if (
    !(Test-Path -Path "$CLIs\jq.exe")
  ) {
    #start msedge.exe 'https://jqlang.github.io/jq/'
    #start msedge "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe"
    #Unblock-File -Path "$osVol\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe"
    #Move-Item -Path "$osVol\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe" -Destination "$osVol\Users\${explorer Owner}\NoSync\CLIs\jq.exe" -Force
    Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" -OutFile "$CLIs\jq-windows-amd64.exe" -Verbose
    while (
      Test-Path -Path "$CLIs\jq-windows-amd64.exe"
    ) {
      Start-Sleep 1
      Get-Item -Path "$CLIs\jq-windows-amd64.exe" | Rename-Item -NewName 'jq.exe'
    }
  }

  if (
    -not (
      (Get-CimInstance -ClassName Win32_Product).Where({$_.Name -match [regex]::Escape('Microsoft Visual C++ 2022 X64')})
    )
  ) {
    Write-Host -ForegroundColor 'Magenta' -Object "`r`nBitwarden Secrets Manager CLI (bws.exe) requires VCRUNTIME140.dll.`r`nDownloading & installing vc_redist.x64.exe from 'https://aka.ms/vs/17/release/vc_redist.x64.exe'`r`n`r`nReference:`r`n  https://answers.microsoft.com/en-us/windows/forum/all/vcruntime140dll-and-msvcp140dll-missing-in-windows/caf454d1-49f4-4d2b-b74a-c83fb7c38625`r`n"
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "$osVol\Users\${explorer.exe Owner}\Downloads\vc_redist.x64.exe"
    & "$osVol\Users\${explorer.exe Owner}\Downloads\vc_redist.x64.exe" /s
  }

  # Confirm presence of Bitwarden Secrets Manager CLI (bws.exe) in $CLIs directory. Download to $CLIs if not already present.
  if (
    !(Test-Path -Path "$CLIs\bws.exe")
  ) {
    # start msedge 'https://github.com/bitwarden/sdk/releases/'; start msedge 'https://github.com/bitwarden/sdk/releases/tag/bws-v1.0.0'
    $Bws_Uri = "https://github.com/bitwarden/sdk/releases/download/bws-v1.0.0/bws-x86_64-pc-windows-msvc-1.0.0.zip"
    Invoke-WebRequest -Uri $Bws_Uri -OutFile "$CLIs\bws-windows.zip" -Verbose
    Expand-Archive -Path "$CLIs\bws-windows.zip" -Destination $CLIs
    Remove-Item -Path "$CLIs\bws-windows.zip" -Confirm:$false
  }

  # Detect presence Win32 & UWP versions of the Bitwarden Password Manager desktop client
  $_Var_Name = 'Bitwarden Password Manager Win32 desktop client'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } catch {
    New-Variable -Name $_Var_Name
  }
  if (
    Test-Path -Path "$env:ProgramFiles\Bitwarden\Bitwarden.exe"
  ) {
    Set-Variable -Name 'Bitwarden Password Manager Win32 desktop client' -Value ("$env:ProgramFiles\Bitwarden\Bitwarden.exe")
  }

  $_Var_Name = 'Bitwarden Password Manager UWP desktop client'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } catch {
    New-Variable -Name $_Var_Name
  }
  if (
    Get-AppxPackage -Name '8bitSolutionsLLC.bitwardendesktop'
  ) {
    Set-Variable -Name 'Bitwarden Password Manager UWP desktop client' -Value (& {
      $app = Get-AppxPackage -Name '8bitSolutionsLLC.bitwardendesktop'
      $id = (Get-AppxPackageManifest $app).package.applications.application.id
      return "shell:AppsFolder\$($app.PackageFamilyName)!$id"
    })
  }

  # Preference of UWP version of Win32 version
  if (
    ${Bitwarden Password Manager UWP desktop client}
  ) {
    $ShortcutBwTarget = ${Bitwarden Password Manager UWP desktop client}
  } elseif (
    ${Bitwarden Password Manager Win32 desktop client}
  ) {
    $ShortcutBwTarget = ${Bitwarden Password Manager Win32 desktop client}
  } else {$ShortcutBwTarget = $null}

  # If Bitwarden desktop client is present, define a two-letter Run box shortcut 'bw' that launches the Bitwarden Password Manager desktop client
  if (
    ($ShortcutBwTarget) -and !(Test-Path -Path "$osVol\Users\${explorer Owner}\bw.lnk")
  ) {    
    $WshShell = New-Object -ComObject Wscript.shell
    $ShortcutBW = $WshShell.CreateShortcut("$osVol\Users\${explorer Owner}\bw.lnk")
    $ShortcutBw.TargetPath = $ShortcutBwTarget
    $ShortcutBw.Save()
  }

  # Globally scoped variables representing the v1.0 and beta endpoints of the Microsoft Graph API
  $global:mg = "https://graph.microsoft.com/v1.0"
  $global:mgB = "https://graph.microsoft.com/beta"

  # Code that's executed when PowerShell detects that a request to close the PowerShell host process has been submitted. 
  ${ScriptBlock to Run at PowerShell Engine Shutdown Event} = {    
    if (
      Test-Path -Path "$env:UserProfile\NoSync\CLIs\bw.exe"
    ) {
      ${Bitwarden CLI Authentication Status} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
      switch (
        ${Bitwarden CLI Authentication Status}
      )
      {
        'unauthenticated' {break}                     # Scriptblock exits if "bw.exe status" evaluates to 'unauthenticated' or 'locked'
        'locked'          {break}
        'unlocked'        {bw.exe lock | Out-Null}    # Lock the Bitwarden Password Manager CLI if "bw.exe status" evaluates to 'unlocked'
        default           {break}
      }
    }
  }

  # Register for the Event representing the PowerShell engine shutdown
  $HT = @{
    SourceIdentifier = ([System.Management.Automation.PsEngineEvent]::Exiting)
    Action = ${ScriptBlock to Run at PowerShell Engine Shutdown Event} 
  }

  <# Hold off on automatically building PowerShell Jobs for the moment (11/7/2024 1:51:45 PM) |
    Register-EngineEvent @HT | Out-Null
  #>

}

function _PrerequisiteConditions_Expedient {
  Set-StrictMode -Version 3

  # Use named matches to capture the well-known SID of the user account that owns the PowerShell process executing these commands
  $WhoAmI = whoami.exe /all
  for ($i = 0; $i -lt $WhoAmI.Length; $i++) {
    if (
      $WhoAmI[$i] -match '^Mandatory Label\\\D+Label\s+(?<Well_Known_SID>\S+)'
    ) {
      $Well_Known_SID = $Matches['Well_Known_SID']
    }
  }

  ## Exit the script if the PowerShell process is running in an elevated context. Generally speaking, avoid launching processes at IL-High or above unless absolutely necessary. 
  #if (
  #  -not (
  #    ($Well_Known_SID -eq "S-1-16-8192") -or ($Well_Known_SID -eq "S-1-16-4096")
  #  )
  #) {
  #  Write-Error -Message "`r`n  PowerShell process executing these commands is running in an elevated security context.`r`n    Launch PowerShell as non-admin and reattempt.`r`n"
  #  Pause
  #  exit
  #}

  # Confirm presence of x64 version of "Microsoft Visual C++ 2015 - 2022 Redistributable" | Invoke-WebRequest bombs out the 1st time because of no DNS resource record on the DNS server. Gotta write error-handling code. 
  # Somehow turn this into a loop that detects if the user has installed...
  while (
    -not (
      (Get-CimInstance -ClassName 'Win32_Product').Where({($_.Name -match [regex]::Escape('Microsoft Visual C++ 2022 X64 Minimum Runtime')) -or ($_.Name -match [regex]::Escape('Microsoft Visual C++ 2022 X86 Minimum Runtime'))})
    )
  ) {
    Write-Host -ForegroundColor 'Magenta' -Object "`r`nBitwarden Secrets Manager CLI (bws.exe) requires VCRUNTIME140.dll.`r`nDownload & install either...`r`n  vc_redist.x64.exe`tfrom`t'https://aka.ms/vs/17/release/vc_redist.x64.exe'`r`nor...`r`n  vc_redist.x86.exe`tfrom`t'https://aka.ms/vs/17/release/vc_redist.x86.exe'`r`nReference:`r`n  'https://answers.microsoft.com/en-us/windows/forum/all/vcruntime140dll-and-msvcp140dll-missing-in-windows/caf454d1-49f4-4d2b-b74a-c83fb7c38625'`r`n"
    Write-Host -ForegroundColor 'Yellow' -Object "Instructions: Keep this PowerShell 7 terminal up. Launch another PowerShell 7 process as Admin.`r`nRun the green lines below to download & install the 64-bit version of the C++ runtime.`r`nClose the PowerShell 7 process running as admin and re-launch as non-admin"
    @'
      ${query.exe session} = query.exe session
      for (
        $i = 0; $i -lt ${query.exe session}.Length; $i++
      )
      {
        if (
          ${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'
        )
        {
          ${explorer Owner} = $Matches['explorer_Owner']
        }
      }

      $_Var_Name = 'TempSessionVar'
      try {
        Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
      } 
      catch {
        New-Variable -Name $_Var_Name -Value $null
      }

      while (
        -not (
          $TempSessionVar
        )
      ) {
        $RedirectedError = $(
          Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" `
          -SessionVariable 'TempSessionVar' `
          -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe"
        ) 2>&1
      }
      & "$env:SystemDrive\Users\${explorer Owner}\Downloads\vc_redist.x64.exe" /quiet
      
'@ | Write-Host -ForegroundColor 'DarkGreen'
    Pause
  }

  # Confirm presence of Bitwarden Password Manager CLI (bw.exe) in a $env:Path directory. 
  $pathFolders = $env:Path -split ';'                          # Load each of the semicolon-separated directory paths into an array element
  if (
    $pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")            # If final element is the empty string of length-0...
  ) {
    $pathFolders = $pathFolders[0..($pathFolders.Length - 2)]  # Then eliminate that element from the array
  }
  while (
    -not (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "bw.exe") -ErrorAction 'SilentlyContinue') -contains $true
    )
  ) {
    Write-Host -ForegroundColor 'DarkRed' -Object "Fucking shit.  Do you see what's wrong with this code? `$pathFolders is specific to the owner of pwsh.exe but the code below establishes bw.exe  in the %path% for the Owner of explorer.exe`n`rGod dammit, how could I miss that.`r`n"
    
    Write-Host -ForegroundColor 'Magenta' -Object "Executable for the Bitwarden Password Manager CLI (bw.exe) is not among the `$env:Path directories."
    Write-Host -ForegroundColor 'Yellow' -Object "Instructions: Keep this PowerShell 7 session open and launch an additional PowerShell 7 process on a non-elevated security context.`r`nRun the green lines below to download, extract, and relocate the Bitwarden Password Manager CLI to the 1st %path% directory containing your username.`r`nReturn to this PowerShell session and hit Enter."
    @'
      ${query.exe session} = query.exe session
      for (
        $i = 0; $i -lt ${query.exe session}.Length; $i++
      )
      {
        if (
          ${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'
        )
        {
          ${explorer Owner} = $Matches['explorer_Owner']
        }
      }

      $_Var_Name = 'TempSessionVar'
      try {
        Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
      } 
      catch {
        New-Variable -Name $_Var_Name -Value $null
      }

      while (
        -not (
          $TempSessionVar
        )
      ) {
        $RedirectedError = $(
          Invoke-WebRequest -Uri "https://vault.bitwarden.com/download/?app=cli&platform=windows" `
          -SessionVariable 'TempSessionVar' `
          -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip"
        ) 2>&1
      }
      Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bw-windows.zip" `
      -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]

'@ | Write-Host -ForegroundColor 'DarkGreen'
    Pause
  }

  # Confirm presence of the jq JSON processor. Necessary for writing into the Bitwarden Password Manager via the Bitwarden CLI
  $pathFolders = $env:Path -split ';'                       # Load each of the semicolon-separated directory paths into an array element
  if (
    $pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")            # If final element is the empty string of length-0...
  ) {
    $pathFolders = $pathFolders[0..($pathFolders.Length - 2)]  # Then eliminate that element from the array
  }
  while (
    -not (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "jq-windows-amd64.exe") -ErrorAction 'SilentlyContinue') -contains $true
    )
  ) {
    Write-Host -ForegroundColor 'Magenta' -Object "Executable for jq (jq-windows-amd64.exe) is not among the `$env:Path directories."
    Write-Host -ForegroundColor 'Yellow' -Object "Instructions: Keep this PowerShell 7 session open and launch an additional PowerShell 7 process as non-admin.`r`nRun the green lines below to download and relocate the jq command-line JSON processor to the first %path% directory containing your username.`r`nReturn to this window upon completion`r`n  Reference: https://jqlang.github.io/jq/"
    @'
      ${query.exe session} = query.exe session
      for (
        $i = 0; $i -lt ${query.exe session}.Length; $i++
      )
      {
        if (
          ${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'
        )
        {
          ${explorer Owner} = $Matches['explorer_Owner']
        }
      }

      $_Var_Name = 'TempSessionVar'
      try {
        Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
      } 
      catch {
        New-Variable -Name $_Var_Name -Value $null
      }

      while (
        -not (
          $TempSessionVar
        )
      ) {
        $RedirectedError = $(
          Invoke-WebRequest -Uri "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe" `
          -SessionVariable 'TempSessionVar' `
          -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe"
        ) 2>&1
      }
      Copy-Item -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\jq-windows-amd64.exe" `
      -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]

'@ | Write-Host -ForegroundColor 'DarkGreen'
    Pause
  }
  
  # Confirm presence of Bitwarden Secrets Manager CLI (bws.exe) in a $env:Path directory. 
  $pathFolders = $env:Path -split ';'                          # Load each of the semicolon-separated directory paths into an array element
  if (
    $pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")            # If final element is the empty string of length-0..
  )
  {
    $pathFolders = $pathFolders[0..($pathFolders.Length - 2)]  # Then eliminate that element from the array
  }
  while (
    -not (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "bws.exe") -ErrorAction 'SilentlyContinue') -contains $true
    )
  ) {
    Write-Host -ForegroundColor 'Magenta' -Object "Executable for the Bitwarden Secrets Manager CLI (bws.exe) is not among the `$env:Path directories."
    Write-Host -ForegroundColor 'Yellow' -Object "Instructions: Run the green lines below to download, extract, and relocate the Bitwarden Secrets Manager CLI to the first %path% directory containing your username:"
    @'
      ${query.exe session} = query.exe session
      for (
        $i = 0; $i -lt ${query.exe session}.Length; $i++
      )
      {
        if (
          ${query.exe session}[$i] -match '^>console +(?<explorer_Owner>\S+)'
        )
        {
          ${explorer Owner} = $Matches['explorer_Owner']
        }
      }

      $_Var_Name = 'TempSessionVar'
      try {
        Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
      } 
      catch {
        New-Variable -Name $_Var_Name -Value $null
      }

      while (
        -not (
          $TempSessionVar
        )
      ) {
        $RedirectedError = $(
          Invoke-WebRequest -Uri "https://github.com/bitwarden/sdk/releases/download/bws-v1.0.0/bws-x86_64-pc-windows-msvc-1.0.0.zip" `
          -SessionVariable 'TempSessionVar' `
          -OutFile "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip"
        ) 2>&1
      }
      Expand-Archive -Path "$env:SystemDrive\Users\${explorer Owner}\Downloads\bws-windows.zip" `
      -Destination ($env:Path -split ';').Where({$_ -match [regex]::Escape("$env:SystemDrive\Users\${explorer Owner}")})[0]

'@ | Write-Host -ForegroundColor 'DarkGreen'
    Pause
  }

  # Code that's executed when PowerShell detects that a request to close the PowerShell host process has been submitted. 
  ${ScriptBlock to Run at PowerShell Engine Shutdown Event} = {
    $pathFolders = $env:Path -split ';'                          # Load each of the semicolon-separated directory paths into an array element
    if (
      $pathFolders[$pathFolders.length - 1] -notmatch [regex]::Escape("\")            # If final element is the empty string of length-0..
    )
    {
      $pathFolders = $pathFolders[0..($pathFolders.Length - 2)]  # Then eliminate that element from the array
    }
  
    if (
      (Test-Path -Path (Join-Path -Path $pathFolders -ChildPath "bw.exe") -ErrorAction 'SilentlyContinue') -contains $true
    ) {
      ${Bitwarden CLI Authentication Status} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
      switch
      (
        ${Bitwarden CLI Authentication Status}
      )
      {
        'unauthenticated' {break}                     # Scriptblock exits if "bw.exe status" evaluates to 'unauthenticated' or 'locked'
        'locked'          {break}
        'unlocked'        {bw.exe lock | Out-Null}    # Lock the Bitwarden Password Manager CLI if "bw.exe status" evaluates to 'unlocked'
        default           {break}
      }
    }
  }

  # Register for the Event representing the PowerShell engine shutdown
  $HT = @{
    SourceIdentifier = ([System.Management.Automation.PsEngineEvent]::Exiting)
    Action = ${ScriptBlock to Run at PowerShell Engine Shutdown Event} 
  }
  Register-EngineEvent @HT | Out-Null
}

function zzzGet_BitwardenPassword_AccessTokenNotSavedToEnvironmentVariable {
  [CmdletBinding(
    ConfirmImpact         = 'Low',
    SupportsShouldProcess = $True,
    SupportsPaging        = $true,
    HelpURI               = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding     = $true
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "SamAccountName of the Active Directory user account",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('un')]
    [string]$SamAccountName,

    [Parameter(
      Position = 1,
      HelpMessage = "OPTIONAL: Name of the Item in Bitwarden.`r`nKnowing the username of the AD account is enough.",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('item')]
    [string]$BitwardenItemName,

    [Parameter(
      Position = 2,
      HelpMessage = "NetBIOS name of the Active Directory domain. This is different from the Domain Name System name of the Active Directory domain.`r`n`r`nReference from Microsoft Learn:`r`n  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('dom')]
    [string]$NetBiosNameOfActiveDirectoryDomain = $NetBiosNameOfActiveDirectoryDomain,

    [Parameter(
      Position = 3,
      HelpMessage = "Name of the organization in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('org')]
    [string]$BitwardenOrganizationName = $BitwardenOrganizationName,

    [Parameter(
      Position = 4,
      HelpMessage = "Name of the collection in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('col')]
    [string]$BitwardenPwdManagerCollectionName = $BitwardenPwdManagerCollectionName,

    [Parameter(
      Position = 5,
      HelpMessage = "Name of the project in Bitwarden Secrets Manager",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('proj')]
    [string]$BitwardenSecretsManagerProjectName = $BitwardenSecretsManagerProjectName,
    
    [Parameter(
      Position = 6,
      HelpMessage = "A machine account name and an access token value are stored in the 'username' and 'password' sub-properties of the 'login' property of an 'item' in Bitwarden Password Manager. The -AT parameter accepts the NAME of the item object that corresponds to the machine account.",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$AT = ${Machine Account 01-Access Token}
  )

  Set-StrictMode -Version 3
  _PrerequisiteConditions
  $RedirectedErrors = $(${Authentication Status of the Bitwarden CLI} = (bw.exe status | ConvertFrom-Json).status) 2>&1 # Save to variable the status of bw.exe
  if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {_AuthenticateIntoBitwardenPasswordManagerCLI}      # Authenticate if status is anything aside from 'unlocked'
  
  # Initialize new variable for referencing Bitwarden Organization ID
  $_Var_Name = 'BitwardenOrganizationId' 
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Bitwarden Organization ID
  $BitwardenOrganizationId = bw.exe list organizations `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenOrganizationName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no Bitwarden Organization ID produced
  if (
    !($BitwardenOrganizationId)
  ) {
    break
  }

  # Initialize new variable for referencing the Collection ID in Bitwarden Password Manager
  $_Var_Name = 'CollectionId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Collection ID from Bitwarden Password Manager
  $CollectionId = bw.exe list --organizationid $BitwardenOrganizationId org-collections `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenPwdManagerCollectionName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no collection ID produced
  if (
    -not (
      $CollectionId
    )
  ) {
    break
  }

  $BitwardenSecretsManagerSecretId = bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json | Select-Object -ExpandProperty 'login' | Where-Object {$_.username -eq "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName"} | Select-Object -ExpandProperty 'password'

  if (
    !($BitwardenSecretsManagerSecretId)
  ) {
    Write-Error "Bitwarden does not contain an identity with those details or the local Bitwarden Password Manager CLI needs to undergo a synchronization. Execute the line below and reattempt the query:`r`n`tbw.exe sync"
    Pause
    break
  }

  #Write-Host -ForegroundColor 'Magenta' -Object "For what reason are we not automatically converting to a secure string?"
  
  bws.exe secret get --access-token $(bw.exe get password ${Machine Account 01-Access Token}) $BitwardenSecretsManagerSecretId | ConvertFrom-Json | Select-Object -ExpandProperty 'value'
}

function zzzAdd_BitwardenPassword_AccessTokenNotSavedToEnvironmentVariable {
  [CmdletBinding(
    ConfirmImpact         = 'Low',
    SupportsShouldProcess = $True,
    SupportsPaging        = $true,
    HelpURI               = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding     = $true
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "SamAccountName of the Active Directory user account",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('un')]
    [string]$SamAccountName,

    [Parameter(
      Position = 1,
      Mandatory = $true,
      HelpMessage = "Domain-level operations require an account with password length of 128 or less. Try adding a replica DC to the domain with a domain admin whose password is 129 characters-operation will fail. Joining a machine to the domain, however, will succeed.",
      ValueFromPipelineByPropertyName = $False
    )]    
    [ValidateRange(36,256)]
    [int32]$len,

    [Parameter(
      Position = 2,
      Mandatory = $false,
      HelpMessage = "OPTIONAL: Name of the Item in Bitwarden. Random GUID assigned if left blank.`r`nKnowing the username of the AD account is enough.`r`nUniqueness is only required attribute when titling an Item in Bitwarden Password Manager.",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('item')]
    [string]$BitwardenItemName = (New-Guid).ToString(),

    [Parameter(
      Position = 3,
      Mandatory = $false,
      HelpMessage = "NetBIOS name of the Active Directory domain. This is different from the Domain Name System name of the Active Directory domain.`r`n`r`nReference from Microsoft Learn:`r`n  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('dom')]
    [string]$NetBiosNameOfActiveDirectoryDomain = $NetBiosNameOfActiveDirectoryDomain,

    [Parameter(
      Position = 4,
      Mandatory = $false,
      HelpMessage = "Name of the organization in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('org')]
    [string]$BitwardenOrganizationName = $BitwardenOrganizationName,

    [Parameter(
      Position = 5,
      Mandatory = $false,
      HelpMessage = "Name of the collection in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('col')]
    [string]$BitwardenPwdManagerCollectionName = $BitwardenPwdManagerCollectionName,

    [Parameter(
      Position = 6,
      Mandatory = $false,
      HelpMessage = "Name of the project in Bitwarden Secrets Manager",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('proj')]
    [string]$BitwardenSecretsManagerProjectName = $BitwardenSecretsManagerProjectName,
    
    [Parameter(
      Position = 7,
      Mandatory = $false,
      HelpMessage = "A machine account name and an access token value are stored in the 'username' and 'password' sub-properties of the 'login' property of an 'item' in Bitwarden Password Manager. The -AT parameter accepts the NAME of the item object that corresponds to the machine account.",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$AT = ${Machine Account 01-Access Token}
  )

  Set-StrictMode -Version 3
  _PrerequisiteConditions
  $RedirectedErrors = $(${Authentication Status of the Bitwarden CLI} = (bw.exe status | ConvertFrom-Json).status) 2>&1 # Save to variable the status of bw.exe
  if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {_AuthenticateIntoBitwardenPasswordManagerCLI}      # Authenticate if status is anything aside from 'unlocked'
  
  # Verify whether the AD account already exists in the 'Active Directory Domain Services' collection of the Bitwarden organization
  
  # Initialize new variable for referencing Bitwarden Organization ID
  $_Var_Name = 'BitwardenOrganizationId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Bitwarden Organization ID
  $BitwardenOrganizationId = bw.exe list organizations `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenOrganizationName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no Bitwarden Organization ID produced
  if (
    !($BitwardenOrganizationId)
  ) {
    Write-Error -Message "Bitwarden organization name supplied did not resolve to a UUID. Confirm correct spelling of the organization's name in Kerberos Networks' Bitwarden account"
    Pause
    break
  }

  # Initialize new variable for referencing the Collection ID in Bitwarden Password Manager
  $_Var_Name = 'CollectionId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Collection ID from Bitwarden Password Manager
  $CollectionId = bw.exe list --organizationid $BitwardenOrganizationId org-collections `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenPwdManagerCollectionName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no collection ID produced
  if (
    !($CollectionId)
  ) {
    Write-Error -Message "Collection name supplied did not resolve to a UUID. No collection in Bitwarden Password Manager matches that name. Confirm correct spelling of the collection's name in Kerberos Networks' Bitwarden account"
    Pause
    break
  }

  if (
    -not $BitwardenItemName
  ) {
    # Initialize new variable for referencing an Item in Bitwarden Password Manager
    $_Var_Name = 'ItemInBitwarden'
    try {
      Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
    } 
    catch {
      New-Variable -Name $_Var_Name -Value $null
    }

    # Query the Bitwarden Organization for an item of that name. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
    $RedirectedErrors = $(
      $ItemInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId item $BitwardenItemName
    ) 2>&1

    # Destroy variable & exit function if that item is already present
    if (
      $ItemInBitwarden
    ) {
      Write-Error -Message "Bitwarden Password Manager reports that an Item already has that name.`r`n  Eliminate the '-BitwardenItemName' parameter-argument pair and reattempt."
      pause
      Remove-Variable 'ItemInBitwarden'
      break
    }
  }

  # Initialize new variable for referencing <domain>\<username>
  $_Var_Name = 'UsernameInBitwarden'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Query the Bitwarden Organization for that <domain>\<username> value. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
  $RedirectedErrors = $(
    $UsernameInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId username "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName"
  ) 2>&1

  # exit function if that username is already present
  if (
    $UsernameInBitwarden
  ) {
    Write-Warning -Message "Active Directory account with username '$UsernameInBitwarden' is already present. Attempt:`r`n`tConvertTo-SecureString -String `$(Get-BitwardenPassword -un '$SamAccountName') -AsPlainText -Force"
    break
  }

  # Can now CONFIRM that Bitwarden Password Manager does not contain any credentials that match with the parameter-argument pairs supplied to the function

  # Calling the Bitwarden Secrets Manager CLI
  
  # Save to variable Project ID from Bitwarden Secrets Manager
  $BitwardenSecretsManagerProjectId = bws.exe project list --access-token $(bw.exe get password ${Machine Account 01-Access Token}) | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenSecretsManagerProjectName} | Select-Object -ExpandProperty 'id'

  # Use bw.exe to define the secret value (generating non-locally would be ideal) and save to variable the Secret ID from Bitwarden Secrets Manager
  #$BitwardenSecretsManagerSecretId = bws.exe secret create --access-token $(bw.exe get password ${Machine Account 01-Access Token}) $BitwardenItemName "$(bw.exe generate --uppercase --lowercase --number --special --length 128)$(bw.exe generate --uppercase --lowercase --number --special --length 128)" $BitwardenSecretsManagerProjectId | ConvertFrom-Json | Select-Object -ExpandProperty 'id'
  $BitwardenSecretsManagerSecretId = bws.exe secret create --access-token $(bw.exe get password ${Machine Account 01-Access Token}) $BitwardenItemName $(_AutoGeneratedSecurePassword $len) $BitwardenSecretsManagerProjectId | ConvertFrom-Json | Select-Object -ExpandProperty 'id'

  # Save to separate variables the properties of the object that will eventually be used to define a new Item in Bitwarden Password Manager
  $EscapedUsername = "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName" -replace '\\','\\'
  ${bw item-name}           = '.name="%Bw_Item_Name%"' -replace '%Bw_Item_Name%',$BitwardenItemName
  ${bw item-login.username} = '.login.username="%Bw_Item_Login_Username%"' -replace '%Bw_Item_Login_Username%',$EscapedUsername
  ${bw item-login.password} = '.login.password="%Bw_Item_Login_Password%"' -replace '%Bw_Item_Login_Password%',$BitwardenSecretsManagerSecretId
  ${bw item-organizationId} = '.organizationId="%Id_of_Bw_Org%"' -replace '%Id_of_Bw_Org%',$BitwardenOrganizationId
  ${bw item-notes}          = '.notes="%Item_Notes%"' -replace '%Item_Notes%',""
  ${bw item-collectionId}   = '.collectionIds=["%id_of_Org_Collection%"]' -replace '%id_of_Org_Collection%',$CollectionId

  # Write into Bitwarden Password Manager (1) <dom>\<un> > 'username' sub-property, and (2) UUID of secret > 'password' sub-property. 
  bw.exe get template item | jq-windows-amd64.exe ${bw item-name} | jq-windows-amd64.exe ${bw item-login.username} | jq-windows-amd64.exe ${bw item-login.password} | jq-windows-amd64.exe ${bw item-organizationId} | jq-windows-amd64.exe ${bw item-notes} | jq-windows-amd64.exe ${bw item-collectionId} | bw.exe encode | bw.exe create item > $null

  # Force a sync and exit
  $RedirectedError = $(
    bw.exe sync
  ) 2>&1
}

function zzzUpdate_BitwardenPassword_AccessTokenNotSavedToEnvironmentVariable {
  [CmdletBinding(
    ConfirmImpact         = 'Low',
    SupportsShouldProcess = $True,
    SupportsPaging        = $true,
    HelpURI               = "https://github.com/CarlSimonIT/secure-automations-toolset",
    PositionalBinding     = $true
  )]
  param (
    [Parameter(
      Position = 0,
      Mandatory = $true,
      HelpMessage = "SamAccountName of the Active Directory user account",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('un')]
    [string]$SamAccountName,

    [Parameter(
      Position = 1,
      Mandatory = $true,
      HelpMessage = "Domain-level operations require an account with password length of 128 or less. Try adding a replica DC to the domain with a domain admin whose password is 129 characters-operation will fail. Joining a machine to the domain, however, will succeed.",
      ValueFromPipelineByPropertyName = $False
    )]    
    [ValidateRange(16,128)]
    [int32]$len,

    [Parameter(
      Position = 2,
      Mandatory = $false,
      HelpMessage = "OPTIONAL: Name of the Item in Bitwarden. Random GUID assigned if left blank.`r`nKnowing the username of the AD account is enough.`r`nUniqueness is only required attribute when titling an Item in Bitwarden Password Manager.",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('item')]
    [string]$BitwardenItemName = (New-Guid).ToString(),

    [Parameter(
      Position = 3,
      Mandatory = $false,
      HelpMessage = "NetBIOS name of the Active Directory domain. This is different from the Domain Name System name of the Active Directory domain.`r`n`r`nReference from Microsoft Learn:`r`n  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('dom')]
    [string]$NetBiosNameOfActiveDirectoryDomain = $NetBiosNameOfActiveDirectoryDomain,

    [Parameter(
      Position = 4,
      Mandatory = $false,
      HelpMessage = "Name of the organization in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('org')]
    [string]$BitwardenOrganizationName = $BitwardenOrganizationName,

    [Parameter(
      Position = 5,
      Mandatory = $false,
      HelpMessage = "Name of the collection in Bitwarden",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('col')]
    [string]$BitwardenPwdManagerCollectionName = $BitwardenPwdManagerCollectionName,

    [Parameter(
      Position = 6,
      Mandatory = $false,
      HelpMessage = "Name of the project in Bitwarden Secrets Manager",
      ValueFromPipelineByPropertyName = $False
    )]
    [Alias('proj')]
    [string]$BitwardenSecretsManagerProjectName = $BitwardenSecretsManagerProjectName,
    
    [Parameter(
      Position = 7,
      Mandatory = $false,
      HelpMessage = "A machine account name and an access token value are stored in the 'username' and 'password' sub-properties of the 'login' property of an 'item' in Bitwarden Password Manager. The -AT parameter accepts the NAME of the item object that corresponds to the machine account.",
      ValueFromPipelineByPropertyName = $False
    )]
    [string]$AT = ${Machine Account 01-Access Token}
  )

  Set-StrictMode -Version 3
  _PrerequisiteConditions
  $RedirectedErrors = $(${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status') 2>&1 # Save to variable the status of bw.exe
  if (${Authentication Status of the Bitwarden CLI} -ne 'unlocked') {_AuthenticateIntoBitwardenPasswordManagerCLI}      # Authenticate if status is anything aside from 'unlocked'
  
  # Verify whether the AD account already exists in the 'Active Directory Domain Services' collection of the Bitwarden organization
  
  # Initialize new variable for referencing Bitwarden Organization ID
  $_Var_Name = 'BitwardenOrganizationId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Bitwarden Organization ID
  $BitwardenOrganizationId = bw.exe list organizations `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenOrganizationName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no Bitwarden Organization ID produced
  if (
    !($BitwardenOrganizationId)
  ) {
    Write-Error -Message "Bitwarden organization name supplied did not resolve to a UUID. Confirm correct spelling of the organization's name in Kerberos Networks' Bitwarden account"
    Pause
    break
  }

  # Initialize new variable for referencing the Collection ID in Bitwarden Password Manager
  $_Var_Name = 'CollectionId'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Save to variable Collection ID from Bitwarden Password Manager
  $CollectionId = bw.exe list --organizationid $BitwardenOrganizationId org-collections `
  | ConvertFrom-Json `
  | Where-Object {$_.name -eq $BitwardenPwdManagerCollectionName} `
  | Select-Object -ExpandProperty 'id'

  # exit function if no collection ID produced
  if (
    !($CollectionId)
  ) {
    Write-Error -Message "Collection name supplied did not resolve to a UUID. No collection in Bitwarden Password Manager matches that name. Confirm correct spelling of the collection's name in Kerberos Networks' Bitwarden account"
    Pause
    break
  }

  # Initialize new variable for referencing an Item in Bitwarden Password Manager
  $_Var_Name = 'ItemInBitwarden'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Query the Bitwarden Organization for an item of that name. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
  $RedirectedErrors = $(
    $ItemInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId item $BitwardenItemName
  ) 2>&1

  # Destroy variable & exit function if that item is already present
  if (
    $ItemInBitwarden
  ) {
    Write-Error -Message "Bitwarden Password Manager reports that an Item already has that name.`r`n  Eliminate the '-BitwardenItemName' parameter-argument pair and reattempt."
    pause
    Remove-Variable 'ItemInBitwarden'
    break
  }

  # Initialize new variable for referencing <domain>\<username>
  $_Var_Name = 'UsernameInBitwarden'
  try {
    Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'
  } 
  catch {
    New-Variable -Name $_Var_Name -Value $null
  }

  # Query the Bitwarden Organization for that <domain>\<username> value. Conceal 'Not Found.' error message emitted from bw.exe by redirecting error stream to variable
  $RedirectedErrors = $(
    $UsernameInBitwarden = bw.exe get --organizationid $BitwardenOrganizationId username "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName"
  ) 2>&1

  # exit function if that username is not present
  if (
    -not $UsernameInBitwarden
  ) {
    Write-Warning -Message "Active Directory account with username '$UsernameInBitwarden' is not present in Bitwarden"
    break
  }

  # Can now CONFIRM that Bitwarden Password Manager does not contain any credentials that match with the parameter-argument pairs supplied to the function

  # Calling the Bitwarden Secrets Manager CLI
  
  # Save to variable Project ID from Bitwarden Secrets Manager
  #$BitwardenSecretsManagerProjectId = bws.exe project list --access-token $(bw.exe get password ${Machine Account 01-Access Token}) | ConvertFrom-Json | Where-Object {$_.name -eq $BitwardenSecretsManagerProjectName} | Select-Object -ExpandProperty 'id'

  # Migrate value of current secret to a Hidden field
  #${bw item-field-name}
  #${bw item-field-type}
  #${bw item-field-value}

  #bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json | Select-Object -ExpandProperty 'login' | Select-Object -ExpandProperty 'password'
  #bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json | Select-Object -ExpandProperty 'fields' | ConvertTo-Json
  #bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json | Select-Object -ExpandProperty 'id' | ForEach-Object {bw.exe get item $_} | ConvertFrom-Json

  #bw get item 0cca8b6b-bcf0-4bd7-b348-ac4f00d4e304 | jq '.fields+=[{"name":"custom3","value":"value3","type":0}]' | bw encode | bw edit item 0cca8b6b-bcf0-4bd7-b348-ac4f00d4e304 # see 'https://github.com/bitwarden/cli/issues/172'
  #$newField = '.fields+=[{name:"""%Field_Title%""",value:"""%Field_Value%""",type:1}]' -replace '%Field_Title%',(Call-DateVar) -replace '%Field_Value%',$(bws.exe secret get --access-token $(bw.exe get password ${Machine Account 01-Access Token}) $BitwardenSecretsManagerSecretId | ConvertFrom-Json | Select-Object -ExpandProperty 'value')
  $BitwardenSecretsManagerSecretId = bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json | Select-Object -ExpandProperty 'login' | Where-Object {$_.username -eq "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName"} | Select-Object -ExpandProperty 'password'
  $newField = '.fields+=[{name:"%Field_Title%",value:"%Field_Value%",type:1}]' -replace '%Field_Title%',(Call-DateVar) -replace '%Field_Value%',$(bws.exe secret get --access-token $(bw.exe get password ${Machine Account 01-Access Token}) $BitwardenSecretsManagerSecretId | ConvertFrom-Json | Select-Object -ExpandProperty 'value')
  $item = bw.exe list --collectionid $CollectionId items --search "$NetBIOSnameOfActiveDirectorydomain\$SamAccountName" | ConvertFrom-Json
  #$newField = '.fields+=[{"name":"%Field_Title%","value":"%Field_Value%","type":1}]' -replace '%Field_Title%',(Call-DateVar) -replace '%Field_Value%',$(bws.exe secret get --access-token $(bw.exe get password ${Machine Account 01-Access Token}) $BitwardenSecretsManagerSecretId | ConvertFrom-Json | Select-Object -ExpandProperty 'value')
  $item | ConvertTo-Json | jq-windows-amd64.exe $newField | bw.exe encode | bw.exe edit item $item.id > $null
  
  # Use bw.exe to define the secret value (generating non-locally would be ideal) and save to variable the Secret ID from Bitwarden Secrets Manager
  #$BitwardenSecretsManagerSecretId = bws.exe secret create --access-token $(bw.exe get password ${Machine Account 01-Access Token}) $BitwardenItemName "$(bw.exe generate --uppercase --lowercase --number --special --length 128)$(bw.exe generate --uppercase --lowercase --number --special --length 128)"
  
  #bws.exe secret edit --access-token $(bw.exe get password ${Machine Account 01-Access Token}) --value "$(bw.exe generate --uppercase --lowercase --number --special --length 128)$(bw.exe generate --uppercase --lowercase --number --special --length 128)" $BitwardenSecretsManagerSecretId > $null
  bws.exe secret edit --access-token $(bw.exe get password ${Machine Account 01-Access Token}) --value $(_AutoGeneratedSecurePassword $len) $BitwardenSecretsManagerSecretId > $null  
 
  #$BitwardenSecretsManagerProjectId | ConvertFrom-Json | Select-Object -ExpandProperty 'id'
  ## Save to separate variables the properties of the object that will eventually be used to define a new Item in Bitwarden Password Manager
  #$EscapedUsername = "$NetBiosNameOfActiveDirectoryDomain\$SamAccountName" -replace '\\','\\'
  #${bw item-name}           = '.name="%Bw_Item_Name%"' -replace '%Bw_Item_Name%',$BitwardenItemName
  #${bw item-login.username} = '.login.username="%Bw_Item_Login_Username%"' -replace '%Bw_Item_Login_Username%',$EscapedUsername
  #${bw item-login.password} = '.login.password="%Bw_Item_Login_Password%"' -replace '%Bw_Item_Login_Password%',$BitwardenSecretsManagerSecretId
  #${bw item-organizationId} = '.organizationId="%Id_of_Bw_Org%"' -replace '%Id_of_Bw_Org%',$BitwardenOrganizationId
  #${bw item-notes}          = '.notes="%Item_Notes%"' -replace '%Item_Notes%',""
  #${bw item-collectionId}   = '.collectionIds=["%id_of_Org_Collection%"]' -replace '%id_of_Org_Collection%',$CollectionId

  ## Write into Bitwarden Password Manager (1) <dom>\<un> > 'username' sub-property, and (2) UUID of secret > 'password' sub-property. 
  #bw.exe get template item | jq-windows-amd64.exe ${bw item-name} | jq-windows-amd64.exe ${bw item-login.username} | jq-windows-amd64.exe ${bw item-login.password} | jq-windows-amd64.exe ${bw item-organizationId} | jq-windows-amd64.exe ${bw item-notes} | jq-windows-amd64.exe ${bw item-collectionId} | bw.exe encode | bw.exe create item > $null

  # Force a sync and exit
  $RedirectedError = $(
    bw.exe sync
  ) 2>&1
}

function zzz_AuthenticateIntoBitwardenPasswordManagerCLI_AccessTokenNotSavedToEnvironmentVariable {
  Set-StrictMode -Version 3

  # the exit keyword just exits the local function, not both the local & global functions. 

  # Need to somehow get some kind of status code out of _PrerequisiteConditions 

  _PrerequisiteConditions

  # Declare a global-scope variable with name 'BW_SESSION' valued at null. 
  #$_Var_Name = 'BW_SESSION'
  #try {
  #  Clear-Variable -Name $_Var_Name -Scope 'Global' -ErrorAction 'Stop'
  #} catch {
  #  New-Variable -Name $_Var_Name -Scope 'Global' -Value $null
  #}

  # Capture status of Bitwarden Password Manager CLI. Only values of interest for our purposes are 'locked' and 'unauthenticated'
  $RedirectedErrors = $(
    ${Authentication Status of the Bitwarden CLI} = bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status'
  ) 2>&1

  # Authenticate into Bitwarden Password Manager CLI
  switch (${Authentication Status of the Bitwarden CLI}) {
    'unauthenticated' {
      $emailaddr = Read-Host -Prompt "Username of Bitwarden account"               # -MaskInput
      #${Unparsed Output} = bw.exe login $emailaddr
      [string[]]$(bw.exe login $emailaddr) | ForEach-Object {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          $env:BW_SESSION = $Matches['BW_SESSION']
          #Set-Variable -Name 'BW_SESSION' -Value ($Matches['BW_SESSION'])
        }
      }
      break
    }
    'locked' {
      #${Unparsed Output} = bw.exe unlock
      [string[]]$(bw.exe unlock) | ForEach-Object {
        if (
          $_ -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'
        ) {
          $env:BW_SESSION = $Matches['BW_SESSION']
          #Set-Variable -Name 'BW_SESSION' -Value ($Matches['BW_SESSION'])
        }
      }
      break
    }
    default {
      # somehow return to calling function without processing more lines|
      break
    }
  }

  #for ($i = 0; $i -lt ${Unparsed Output}.Count; $i++) {
  #  if (
  #    ${Unparsed Output}[$i] -match '^>\ \$env:BW_SESSION="(?<BW_SESSION>.*)"$'        # Feed 'Unparsed Output' variable into a regex that uses named matches to isolate the session token
  #  ) {
  #    Set-Variable -Name 'BW_SESSION' -Value ($Matches['BW_SESSION']) -Scope 'Global'  # save session token to global variable titled 'BW_SESSION'
  #  }
  #}

  #if (
  #  ($BW_SESSION -eq $null) -and (${Authentication Status of the Bitwarden CLI} -eq 'unlocked')
  #) {
  #  write "  Bitwarden Password Manager CLI has been locked."
  #}

  #$env:BW_SESSION = $BW_SESSION                                                        # Save the value in the 'BW_SESSION' variable to a user-scope environment variable with that same title. 

  
  #$_Var_Name = 'BW_SESSION'                                                            # Restore value in the 'BW_SESSION' variable to $null
  #try {
  #  Clear-Variable -Name $_Var_Name -Scope 'Global' -ErrorAction 'Stop'
  #} catch {
  #  New-Variable -Name $_Var_Name -Scope 'Global' -Value $null
  #}

  #Write-Host -ForegroundColor 'DarkBlue' -Object "  Status of Bitwarden Password Manager CLI is:  $($(bw.exe status | ConvertFrom-Json | Select-Object -ExpandProperty 'status').ToUpper())"
}

function zzzDeleteMe_New-Server2025onCluster {
  [CmdletBinding(DefaultParameterSetName = 'Tier 1 Member Server',ConfirmImpact = 'low',HelpURI = 'https://www.altaro.com/hyper-v/customize-vm-powershell/')]
  [OutputType('Forest Root Domain Controller')][OutputType('Replica Domain Controller')][OutputType('Tier 0 Member Server')][OutputType('Tier 1 Member Server')][OutputType('Tier 0 Member Server-Static IP Cfg')][OutputType('Tier 1 Member Server-Static IP Cfg')]

  param (
    [Parameter(Mandatory,HelpMessage = "Yes, even if work is being performed while locally logged into a Hyper-V host, a PowerShell Remoting session is still used.")]
    [Alias('sess')]
    [System.Management.Automation.Runspaces.PSSession]
    $PowerShellRemotingSession,

    [Parameter(Mandatory,ParameterSetName = 'Forest Root Domain Controller')][Parameter(Mandatory,ParameterSetName = 'Replica Domain Controller')][Parameter(Mandatory,ParameterSetName = 'Tier 0 Member Server-Static IP Cfg')][Parameter(Mandatory,ParameterSetName = 'Tier 1 Member Server-Static IP Cfg')][ValidatePattern('^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$')][string]$ip,
    [Parameter(Mandatory,ParameterSetName = 'Forest Root Domain Controller')][Parameter(Mandatory,ParameterSetName = 'Replica Domain Controller')][Parameter(Mandatory,ParameterSetName = 'Tier 0 Member Server-Static IP Cfg')][Parameter(Mandatory,ParameterSetName = 'Tier 1 Member Server-Static IP Cfg')][ValidatePattern('^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$')][string]$gw,
    [Parameter(Mandatory,ParameterSetName = 'Forest Root Domain Controller')][Parameter(Mandatory,ParameterSetName = 'Replica Domain Controller')][Parameter(Mandatory,ParameterSetName = 'Tier 0 Member Server-Static IP Cfg')][Parameter(Mandatory,ParameterSetName = 'Tier 1 Member Server-Static IP Cfg')][ValidatePattern('^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$')][string]$dns,

    [Parameter(Mandatory,ParameterSetName = 'Replica Domain Controller')]
    [Parameter(Mandatory,ParameterSetName = 'Tier 0 Member Server',
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID.`r`nDistinguishedName of OUs in AD will match this regular expression:`r`n`t^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$`r`nGUIDs (aka UUIDs) will match this regular expression:`r`n`t^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`r`n`r`nCopy and paste these examples into PowerShell:`r`n`t'OU=Demonstration,OU=Of,DC=Regex,DC=Pattern,DC=Matching' -match '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$'`r`n`t(New-Guid).ToString() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'"
    )]
    [Parameter(Mandatory,ParameterSetName = 'Tier 1 Member Server',
      HelpMessage = "The ValidateScript parameter validation attribute might be better than ValidatePattern. Binding an ObjectGUID to -OU and then converting to DistinguishedName should be possible with [ValidateScript()]"
    )]
    [Parameter(Mandatory,ParameterSetName = 'Tier 0 Member Server-Static IP Cfg')]
    [Parameter(Mandatory,ParameterSetName = 'Tier 1 Member Server-Static IP Cfg')]
    [ValidatePattern('^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]
    $OU,

    [Parameter(ParameterSetName = 'Replica Domain Controller')]
    [Parameter(ParameterSetName = 'Tier 0 Member Server')]
    [Parameter(
      ParameterSetName = 'Tier 1 Member Server',
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. 'Join2Domain0_Tier0' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [Parameter(ParameterSetName = 'Tier 0 Member Server-Static IP Cfg')]
    [Parameter(
      ParameterSetName = 'Tier 1 Member Server-Static IP Cfg',
      HelpMessage = "Verify group membership with ValidateScript PVA"
    )]
    [ValidateSet('Join2Domain0_Tier0','Join2Domain0_Tier1')]
    [string]
    $DomainJoinAccount,

    [Parameter(Mandatory,ParameterSetName = 'Replica Domain Controller')]
    [Parameter(Mandatory,ParameterSetName = 'Tier 0 Member Server')]
    [Parameter(Mandatory,ParameterSetName = 'Tier 1 Member Server')]
    [Parameter(Mandatory,ParameterSetName = 'Tier 0 Member Server-Static IP Cfg')]
    [Parameter(Mandatory,ParameterSetName = 'Tier 1 Member Server-Static IP Cfg')]
    $DomainJoinAccountPassword,

    [Parameter(HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!")][string]$Name0fVM = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),
    [Parameter(HelpMessage = "Primary differences between Datacenter and Standard is that Standard does not support Storage Spaces Direct, the Hyper-V Host Guardian, the Network Controller, or running more than 2 VMs.`r`nVM deployments of Datacenter and bare-metal deployments of Standard will be rare.`r`nComprehensive feature reference:`r`n`thttps://learn.microsoft.com/en-us/windows-server/get-started/editions-comparison?pivots=windows-server-2025")][ValidateSet('Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience')][string]$Edition = 'Standard',
    [Parameter(HelpMessage = "Supply name of an AD Computer object. Remember that domain controllers are ALSO AD Computer objects! Stated differently, the ObjectClass of a DC also 'computer'.")][ValidateLength(1,15)][ValidatePattern('^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$')][string]$Name0fGuestOS = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),
    #[Parameter(HelpMessage = "Probably not necessary since the target Hyper-V host is controlled by the PowerShell Remoting Session")][string]$hvHost = "$env:ComputerName",
    [Parameter(HelpMessage = "Two virtual CPUs should be enough")][Int32]$cpu = 2,
    [Parameter(HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM")][int64]$ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,
    [Parameter(HelpMessage = "I dont think that uniquely naming Hyper-V virtual switches (on a per-host basis) is necessary or desirable.")][ValidateSet('SET-enabled External vSwitch','vSwitchNAT')][string]$net = "SET-enabled External vSwitch",
    [Parameter(HelpMessage = "Make sure the Hyper-V host has tons of RAM")][ValidateSet('StartIfRunning','Start','Nothing')][string]$ActionWhenBareMetalHostBoots = 'Start',
    [Parameter(HelpMessage = "No need to right-click each row in Hyper-V Manager and select Shut Down.")][ValidateSet('Save','TurnOff','Shutdown')][string]$ActionOnBareMetalHostShutdown = 'Shutdown',
    [Parameter(
      Mandatory,
      HelpMessage = "I should've started using unattend.xml and autounattend.xml a long, long time ago...`r`nNote for later: Come up with a PVA that matches on a regular expression for this variable.`r`nMaybe try importing the XML file and if error results, fail the function"
    )][string]$xml,
    [ValidateRange(1,100)][Int32]$Buffer = 20,
    [Parameter(Mandatory,ParameterSetName = 'Tier 0 Member Server')]
    [Parameter(Mandatory,ParameterSetName = 'Tier 1 Member Server',HelpMessage = "Checkpoints and domain controllers do not mix")]
    [Parameter(Mandatory,ParameterSetName = 'Tier 0 Member Server-Static IP Cfg')]
    [Parameter(Mandatory,ParameterSetName = 'Tier 1 Member Server-Static IP Cfg')]
    [ValidateSet('Disabled','Production','ProductionOnly','Standard')][string]$CheckpointType = 'Standard',
    [ValidateSet('Pause','None')][string]$StorageDisconnectedAction = 'Pause',
    [int32]$HwThreadCountPerCore = '1',
    [ValidateRange(1,4096)][int32]$VlanID,    # Hopefully the $VlanID parameter won't stay a mystery for too much longer...
    [Parameter(Mandatory,HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/")][string]$Notes
  )

  Invoke-Command -Session $PowerShellRemotingSession -ScriptBlock {
    Import-Module "$env:SystemDrive\Secure-Automations-Toolset.psm1"

    $RedirectedError = $(
      ${Does This VM Already Exist?} = Get-VM -Name $using:Name0fVM
    ) 2>&1
    if (${Does This VM Already Exist?}) {
      Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
      break
    }
  
    $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
    $message01 = ".vhdx file is confirmed to be in place."
    switch ($using:Edition) {
      'Standard' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break
      }
      'StandardDesktopExperience' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
      'Datacenter' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
      'DatacenterDesktopExperience' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
    }
  
    ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
    ${Current VM Version} = (Get-VMHost).SupportedVmVersions | Where-Object {$_ -match ${Current VM Version}}
    
    $HT = @{Name = $using:Name0fVM; ComputerName = $env:ComputerName; Generation = 2; MemoryStartupBytes = $using:ram; Version = ${Current VM Version}}
    try {${New VM} = Get-VM -Name $HT.Name -ErrorAction 'Stop'} catch {${New VM} = New-VM @HT}
  
    # Create a copy of the .vhdx file located at ${Base VHD Path}. Filename begins with name of VM and then the VM id. 
    ${Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id).vhdx"
    Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path}
  
    # Attach VHD containing Guest OS to VM |
    $HT = @{VMName = $using:Name0fVM; Path = ${Guest OS Disk Path}; ControllerType = 'SCSI'; ControllerLocation = '0'; ControllerNumber = '0'}
    Add-VMHardDiskDrive @HT

    $HT = @{VMName = $using:Name0fVM; ControllerType = 'SCSI'; ControllerLocation = '0'; ControllerNumber = '0'}
    ${Guest OS Disk} = Get-VMHardDiskDrive @HT
    
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$((New-Guid).ToString()).vhdx"
    try {${Storage1 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'} catch {${Storage1 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}
  
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$((New-Guid).ToString()).vhdx"
    try {${Storage2 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'} catch {${Storage2 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic}

    switch ($using:PSCmdlet.ParameterSetName) {
      {($_ -eq 'Forest Root Domain Controller') -or ($_ -eq 'Replica Domain Controller')} {
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'O' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "AD DS Vol" > $null
        Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null
      
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'P' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 00" > $null
        Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null

        break
      }
      {($_ -eq 'Tier 0 Member Server') -or ($_ -eq 'Tier 1 Member Server') -or ($_ -eq 'Tier 0 Member Server-Static IP Cfg') -or ($_ -eq 'Tier 1 Member Server-Static IP Cfg')} {
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 00" > $null
        Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null
    
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 01" > $null
        Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null           
        
        break
      }
      default {write "avoiding the 'default' keyword in the final pattern of the switch statement because we'll probably end up further tailoring disk deployments"}
    }

    $HT = @{ # Create new VHD for storage and attach to VM | 'Storage1 VHDX' |
      VMName = $using:Name0fVM
      Path = ${Storage1 VHDX}.Path
      ControllerType = 'SCSI'
      ControllerNumber = '0'
      ControllerLocation = '1'
    }
    Add-VMHardDiskDrive @HT
    $HT = @{ # Create new VHD for storage and attach to VM | 'Storage2 VHDX' |
      VMName = $using:Name0fVM
      Path = ${Storage2 VHDX}.Path
      ControllerType = 'SCSI'
      ControllerNumber = '0'
      ControllerLocation = '2'
    }
    Add-VMHardDiskDrive @HT
    $HT = @{ # Set memory quantity & behavior of VM |
      VMName = $using:Name0fVM
      DynamicMemoryEnabled = $True
      MinimumBytes = 256MB
      MaximumBytes = $using:ram
      Buffer = $using:Buffer
    }
    Set-VMMemory @HT  
    $HT = @{ # VM priority when auto-launching at Hyper-V Host boot if cumulative assigned memory exhausts total physical memory |
      VMName = $using:Name0fVM
      Priority = '50'
    }
    Set-VMMemory @HT
  
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Guest Service Interface'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Heartbeat'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Key-Value Pair Exchange'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Shutdown'
    # Member servers in a domain should sync with a DC that does not host the PDC Emulator, and non-PDCe DCs should sync with the DC that hosts the PDC Emulator.
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Time Synchronization'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'VSS'
  
    $HT = @{ # Quantity of vCPUs |
      VMName = $using:Name0fVM
      Count = $using:cpu
    }
    Set-VMProcessor @HT  
    $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
      VMName = $using:Name0fVM
      Reserve = '0'
      Maximum = '100'
    }
    Set-VMProcessor @HT  
    $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
      VMName = $using:Name0fVM
      RelativeWeight = '100'
    }
    Set-VMProcessor @HT  
    $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
      VMName = $using:Name0fVM
      EnableHostResourceProtection = $True
    }
    Set-VMProcessor @HT  
    $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false |
      VMName = $using:Name0fVM
      CompatibilityForMigrationEnabled = $False
    }
    Set-VMProcessor @HT  
    $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
      VMName = $using:Name0fVM
      HwThreadCountPerCore = $using:HwThreadCountPerCore
    }
    Set-VMProcessor @HT  
    $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
      Name = $using:Name0fVM
      AutomaticStartAction = $using:ActionWhenBareMetalHostBoots
      AutomaticStopAction = $using:ActionOnBareMetalHostShutdown
      AutomaticStartDelay = $(60 * ((Get-VM).Count - 1))
    }
    Set-VM @HT  
    $HT = @{ # Firmware settings |
      VMName = $using:Name0fVM
      FirstBootDevice = ${Guest OS Disk}
      SecureBootTemplate = 'MicrosoftWindows'
      EnableSecureBoot = 'On'
    }
    Set-VMFirmware @HT
  
    # VM Checkpoints and domain controllers don't mix |
    (($using:PSCmdlet.ParameterSetName -eq 'Forest Root Domain Controller') -or ($using:PSCmdlet.ParameterSetName -eq 'Replica Domain Controller')) ? (Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $false) : (& {Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $True; Set-VM -Name $using:Name0fVM -CheckpointType $using:CheckpointType})
  
    Set-VM -VMName $using:Name0fVM -AutomaticCriticalErrorAction $using:StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120

    Set-VM -VMName $using:Name0fVM -Notes $using:Notes

    ((Get-VMSwitch $using:net).EmbeddedTeamingEnabled) ? 
    (& {
      Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
      ${VM NetAdapter-SET} = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $using:Name0fVM
      Connect-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $using:Name0fVM -SwitchName $using:net
      Set-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $using:Name0fVM -MacAddressSpoofing 'On'
    }) : 
    (& {
      Connect-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM -SwitchName $using:net
      Set-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM -MacAddressSpoofing 'On'
    })

    Set-VMKeyProtector -VMName $using:Name0fVM -NewLocalKeyProtector
    Enable-VMTPM -VMName $using:Name0fVM

    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
    $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
    $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

    $xml = $using:xml
    #$using:PSCmdlet.ParameterSetName
    switch ('Replica Domain Controller') {
      'Forest Root Domain Controller' {

        break
      }
      'Replica Domain Controller' {
        ($XmlDocument = [xml]'<root></root>').Load("$env:SystemDrive\$xml")
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $using:ip}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $using:gw}

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $using:dns}

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $using:DomainJoinAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $using:DomainJoinAccountPassword}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $using:OU}
        $XmlDocument.Save("$VHDVolume\unattend.xml")
      
        break
      }
      'Tier 0 Member Server' {

        break
      }
      'Tier 1 Member Server' {

        break
      }
      'Tier 0 Member Server-Static IP Cfg' {

        break
      }
      'Tier 1 Member Server-Static IP Cfg' {

        break
      }
      default {write "Keeping the possibility of more parameter sets open"}
    }
  
    Invoke-WebRequest -Uri 'http://live.sysinternals.com/sdelete.exe' -OutFile "$VHDVolume\sdelete.exe"
    Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
    Start-VM -Name $using:Name0fVM | Out-Null
  }
}

function New-Server2025onCluster {
  [CmdletBinding(
    DefaultParameterSetName = 'Tier 1 Member Server',
    ConfirmImpact = 'low',
    HelpURI = 'https://www.altaro.com/hyper-v/customize-vm-powershell/'
  )]
  
  [OutputType('Forest Root Domain Controller')]
  [OutputType('Replica Domain Controller')]
  [OutputType('Tier 0 Member Server')]
  [OutputType('Tier 1 Member Server')]
  [OutputType('Tier 0 Member Server-Static IP Cfg')]
  [OutputType('Tier 1 Member Server-Static IP Cfg')]

  param (
    [Parameter(
      Mandatory,
      HelpMessage = "Yes, even if work is being performed while locally logged into a node of a Hyper-V cluster, a PowerShell Remoting session is still required."
    )]
    [Alias('sess')]
    [System.Management.Automation.Runspaces.PSSession]
    $PowerShellRemotingSession,
    
    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 0 Member Server-Static IP Cfg'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 1 Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)/(?:\d|[12]\d|3[012])$'
    )]
    [string]
    $ip,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 0 Member Server-Static IP Cfg'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 1 Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $gw,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Forest Root Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 0 Member Server-Static IP Cfg'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 1 Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'
    )]
    [string]
    $dns,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 0 Member Server',
      HelpMessage = "The days of joining a computer to the domain without specifying an OU are over.`r`nAcceptable inputs are the Organizational Unit's DistinguishedName or ObjectGUID.`r`nDistinguishedName of OUs in AD will match this regular expression:`r`n`t^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$`r`nGUIDs (aka UUIDs) will match this regular expression:`r`n`t^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`r`n`r`nCopy and paste these examples into PowerShell:`r`n`t'OU=Demonstration,OU=Of,DC=Regex,DC=Pattern,DC=Matching' -match '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$'`r`n`t(New-Guid).ToString() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 1 Member Server',
      HelpMessage = "The ValidateScript parameter validation attribute might be better than ValidatePattern. Binding an ObjectGUID to -OU and then converting to DistinguishedName should be possible with [ValidateScript()]"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 0 Member Server-Static IP Cfg'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 1 Member Server-Static IP Cfg'
    )]
    [ValidatePattern(
      '^OU=[^,]+(?:,OU=[^,]+)*,DC=[^,]+(?:,DC=[^,]+)*$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )]
    [string]
    $OU,

    [Parameter(
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      ParameterSetName = 'Tier 0 Member Server'
    )]
    [Parameter(
      ParameterSetName = 'Tier 1 Member Server',
      HelpMessage = "Perfect opportunity to write dynamic parameters into the function definition. 'Join2Domain0_Tier0' should _NOT_ be an option if the OU's DistinguishedName property is a match for the Tier1 servers OU"
    )]
    [Parameter(
      ParameterSetName = 'Tier 0 Member Server-Static IP Cfg'
    )]
    [Parameter(
      ParameterSetName = 'Tier 1 Member Server-Static IP Cfg',
      HelpMessage = "Verify group membership with ValidateScript PVA"
    )]
    [ValidateSet(
      'Join2Domain0_Tier0',
      'Join2Domain0_Tier1'
    )]
    [string]
    $DomainJoinAccount,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Replica Domain Controller'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 0 Member Server'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 1 Member Server'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 0 Member Server-Static IP Cfg'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 1 Member Server-Static IP Cfg'
    )]
    $DomainJoinAccountPassword,

    [Parameter(
      HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!"
    )]
    [string]
    $Name0fVM = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      HelpMessage = "Primary differences between Datacenter and Standard is that Standard does not support Storage Spaces Direct, the Hyper-V Host Guardian, the Network Controller, or running more than 2 VMs.`r`nVM deployments of Datacenter and bare-metal deployments of Standard will be rare.`r`nComprehensive feature reference:`r`n`thttps://learn.microsoft.com/en-us/windows-server/get-started/editions-comparison?pivots=windows-server-2025"
    )]
    [ValidateSet(
      'Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience'
    )]
    [string]
    $Edition = 'Standard',

    [Parameter(
      HelpMessage = "Supply name of an AD Computer object. Remember that domain controllers are ALSO AD Computer objects! Stated differently, the ObjectClass of a DC also 'computer'."
    )]
    [ValidateLength(1,15)]
    [ValidatePattern(
      '^(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s25|s25desk|s25std|s25stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9]$'
    )]
    [string]
    $Name0fGuestOS = ('WIN-' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      HelpMessage = "Two virtual CPUs should be enough"
    )]
    [Int32]
    $cpu = 2,

    [Parameter(
      HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM"
    )]
    [int64]
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,
    
    [Parameter(
      HelpMessage = "I dont think that uniquely naming Hyper-V virtual switches (on a per-host basis) is necessary or desirable."
    )]
    [ValidateSet(
      'SET-enabled External vSwitch','vSwitchNAT'
    )]
    [string]
    $net = "SET-enabled External vSwitch",

    [Parameter(
      HelpMessage = "Make sure the Hyper-V host has tons of RAM"
    )]
    [ValidateSet(
      'StartIfRunning','Start','Nothing'
    )]
    [string]
    $ActionWhenBareMetalHostBoots = 'Start',
    
    [Parameter(
      HelpMessage = "No need to right-click each row in Hyper-V Manager and select Shut Down."
    )]
    [ValidateSet(
      'Save','TurnOff','Shutdown'
    )]
    [string]
    $ActionOnBareMetalHostShutdown = 'Shutdown',
    
    [Parameter(
      Mandatory,
      HelpMessage = "I should've started using unattend.xml and autounattend.xml a long, long time ago...`r`nNote for later: Come up with a PVA that matches on a regular expression for this variable.`r`nMaybe try importing the XML file and if error results, fail the function"
    )]
    [string]
    $xml,

    [ValidateRange(1,100)]
    [Int32]
    $Buffer = 20,

    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 0 Member Server'
    )]    
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 1 Member Server',
      HelpMessage = "Checkpoints and domain controllers do not mix"
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 0 Member Server-Static IP Cfg'
    )]
    [Parameter(
      Mandatory,
      ParameterSetName = 'Tier 1 Member Server-Static IP Cfg'
    )]    
    [ValidateSet(
      'Disabled','Production','ProductionOnly','Standard'
    )]
    [string]
    $CheckpointType = 'Standard',

    [ValidateSet('Pause','None')]
    [string]
    $StorageDisconnectedAction = 'Pause',

    [int32]
    $HwThreadCountPerCore = '1',

    [ValidateRange(1,4096)]
    [int32]
    $VlanID,    # Hopefully the $VlanID parameter won't stay a mystery for too much longer...

    [Parameter(
      Mandatory,
      HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/"
    )]
    [string]
    $Notes
  )

  Invoke-Command -Session $PowerShellRemotingSession -ScriptBlock {
    # Installing from the PSGalaxy hosted on a network share and then importing would work better
    Import-Module "$((Get-VMHost).VirtualMachinePath)\Secure-Automations-Toolset.psm1"

    $RedirectedError = $(
      ${Does This VM Already Exist?} = Get-VM -Name $using:Name0fVM
    ) 2>&1
    if (${Does This VM Already Exist?}) {
      Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
      break
    }
  
    $message00 = "Prerequisite .vhdx file doesn't yet exist.`r`n  Creating now..."
    $message01 = ".vhdx file is confirmed to be in place."
    switch ($using:Edition) {
      'Standard' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break
      }
      'StandardDesktopExperience' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
      'Datacenter' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
      'DatacenterDesktopExperience' {
        ${Base VHD Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
        if (!(Test-Path -Path ${Base VHD Path})) {
          Write-Host -ForegroundColor 'Magenta' -Object $message00
          New-Server2025ReferenceVHDXviaPowerShellRemoting -Edition $using:Edition
          $_Var_Name = 'VHD File-system Object'; try {Clear-Variable -Name $_Var_Name -ErrorAction 'Stop'} catch {New-Variable -Name $_Var_Name}
          while (!(${VHD File-system Object})) {${VHD File-system Object} = Get-Item -Path ${Base VHD Path}; Start-Sleep 5}
          Remove-Variable 'VHD File-system Object'
          Write-Host -ForegroundColor 'Yellow' -Object $message01
        }
        break      
      }
    }
  
    ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
    ${Current VM Version} = (Get-VMHost).SupportedVmVersions | Where-Object {$_ -match ${Current VM Version}}
    
    $HT = @{
      Name               = $using:Name0fVM
      ComputerName       = $env:ComputerName
      Generation         = 2
      MemoryStartupBytes = $using:ram
      Version            = ${Current VM Version}
    }
    try {
      ${New VM} = Get-VM -Name $HT.Name -ErrorAction 'Stop'
    } 
    catch {
      ${New VM} = New-VM @HT
    }
  
    # Create a copy of the .vhdx file located at ${Base VHD Path}. Filename begins with name of VM and then the VM id. 
    ${Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id).vhdx"
    Copy-Item -Path ${Base VHD Path} -Destination ${Guest OS Disk Path}
  
    # Attach VHD containing Guest OS to VM |
    $HT = @{
      VMName             = $using:Name0fVM
      Path               = ${Guest OS Disk Path}
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{
      VMName = $using:Name0fVM
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    ${Guest OS Disk} = Get-VMHardDiskDrive @HT
    
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$((New-Guid).ToString()).vhdx"
    try {
      ${Storage1 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'
    } 
    catch {
      ${Storage1 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic
    }
  
    $dir = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id)_$((New-Guid).ToString()).vhdx"
    try {
      ${Storage2 VHDX} = Get-VHD -Path $dir -ErrorAction 'Stop'
    } 
    catch {
      ${Storage2 VHDX} = New-VHD -Path $dir -SizeBytes 8TB -Dynamic
    }

    switch ($using:PSCmdlet.ParameterSetName) {
      {($_ -eq 'Forest Root Domain Controller') -or ($_ -eq 'Replica Domain Controller')} {
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'O' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "AD DS Vol" > $null
        Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null
      
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -DriveLetter 'P' -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 00" > $null
        Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null

        break
      }
      {($_ -eq 'Tier 0 Member Server') -or ($_ -eq 'Tier 1 Member Server') -or ($_ -eq 'Tier 0 Member Server-Static IP Cfg') -or ($_ -eq 'Tier 1 Member Server-Static IP Cfg')} {
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage1 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 00" > $null
        Dismount-DiskImage -ImagePath ${Storage1 VHDX}.Path > $null
    
        ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Storage2 VHDX}.Path | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsOffline $false
        Set-Disk -Number ${Mounted Storage VHDX Disk #} -IsReadOnly $false
        Initialize-Disk -Number ${Mounted Storage VHDX Disk #} -PartitionStyle 'GPT'
        New-Partition -DiskNumber ${Mounted Storage VHDX Disk #} -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel "Info Disk 01" > $null
        Dismount-DiskImage -ImagePath ${Storage2 VHDX}.Path > $null           
        
        break
      }
      default {write "avoiding the 'default' keyword in the final pattern of the switch statement because we'll probably end up further tailoring disk deployments"}
    }

    $HT = @{ # Create new VHD for storage and attach to VM | 'Storage1 VHDX' |
      VMName             = $using:Name0fVM
      Path               = ${Storage1 VHDX}.Path
      ControllerType     = 'SCSI'
      ControllerNumber   = '0'
      ControllerLocation = '1'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{ # Create new VHD for storage and attach to VM | 'Storage2 VHDX' |
      VMName             = $using:Name0fVM
      Path               = ${Storage2 VHDX}.Path
      ControllerType     = 'SCSI'
      ControllerNumber   = '0'
      ControllerLocation = '2'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{ # Set memory quantity & behavior of VM |
      VMName               = $using:Name0fVM
      DynamicMemoryEnabled = $True
      MinimumBytes         = 256MB
      MaximumBytes         = $using:ram
      Buffer               = $using:Buffer
    }
    Set-VMMemory @HT

    $HT = @{ # VM priority when auto-launching at Hyper-V Host boot if cumulative assigned memory exhausts total physical memory |
      VMName   = $using:Name0fVM
      Priority = '50'
    }
    Set-VMMemory @HT
  
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Guest Service Interface'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Heartbeat'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Key-Value Pair Exchange'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Shutdown'
    # Member servers in a domain should sync with a DC that does not host the PDC Emulator, and non-PDCe DCs should sync with the DC that hosts the PDC Emulator.
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Time Synchronization'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'VSS'
  
    $HT = @{ # Quantity of vCPUs |
      VMName = $using:Name0fVM
      Count  = $using:cpu
    }
    Set-VMProcessor @HT  

    $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
      VMName  = $using:Name0fVM
      Reserve = '0'
      Maximum = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
      VMName         = $using:Name0fVM
      RelativeWeight = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
      VMName                       = $using:Name0fVM
      EnableHostResourceProtection = $True
    }
    Set-VMProcessor @HT  

    $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false |
      VMName                           = $using:Name0fVM
      CompatibilityForMigrationEnabled = $False
    }
    Set-VMProcessor @HT  

    $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
      VMName               = $using:Name0fVM
      HwThreadCountPerCore = $using:HwThreadCountPerCore
    }
    Set-VMProcessor @HT  

    $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
      Name                 = $using:Name0fVM
      AutomaticStartAction = $using:ActionWhenBareMetalHostBoots
      AutomaticStopAction  = $using:ActionOnBareMetalHostShutdown
      AutomaticStartDelay  = $(60 * ((Get-VM).Count - 1))
    }
    Set-VM @HT  

    $HT = @{ # Firmware settings |
      VMName             = $using:Name0fVM
      FirstBootDevice    = ${Guest OS Disk}
      SecureBootTemplate = 'MicrosoftWindows'
      EnableSecureBoot   = 'On'
    }
    Set-VMFirmware @HT
  
    # VM Checkpoints and domain controllers don't mix |
    (($using:PSCmdlet.ParameterSetName -eq 'Forest Root Domain Controller') -or ($using:PSCmdlet.ParameterSetName -eq 'Replica Domain Controller')) ? 
    (Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $false) : 
    (& {Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $True; Set-VM -Name $using:Name0fVM -CheckpointType $using:CheckpointType})
  
    Set-VM -VMName $using:Name0fVM -AutomaticCriticalErrorAction $using:StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120

    Set-VM -VMName $using:Name0fVM -Notes $using:Notes

    ((Get-VMSwitch $using:net).EmbeddedTeamingEnabled) ? 
    (& {
      Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
      ${VM NetAdapter-SET} = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $using:Name0fVM
      Connect-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $using:Name0fVM -SwitchName $using:net
      Set-VMNetworkAdapter -Name ${VM NetAdapter-SET}.Name -VMName $using:Name0fVM -MacAddressSpoofing 'On'
    }) : 
    (& {
      Connect-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM -SwitchName $using:net
      Set-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM -MacAddressSpoofing 'On'
    })

    Set-VMKeyProtector -VMName $using:Name0fVM -NewLocalKeyProtector

    Enable-VMTPM -VMName $using:Name0fVM

    ${Mounted Storage VHDX Disk #} = Mount-DiskImage -ImagePath ${Guest OS Disk Path} | Select-Object -ExpandProperty 'ImagePath' | Get-DiskImage | Select-Object -ExpandProperty 'Number'
    $VHDDisk = Get-DiskImage -ImagePath ${Guest OS Disk Path} | Get-Disk
    $VHDPart = Get-Partition -DiskNumber $VHDDisk.Number | Select-Object -First 1
    $VHDVolume = ([string]$VHDPart.DriveLetter).trim() + ":"

    $xml = $using:xml
    #$using:PSCmdlet.ParameterSetName
    switch ('Replica Domain Controller') {
      'Forest Root Domain Controller' {break}
      'Replica Domain Controller' {
        ($XmlDocument = [xml]'<root></root>').Load("$env:SystemDrive\$xml")
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${using:Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $using:BitwardenOrganizationName}

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.UnicastIpAddresses.IpAddress.InnerText = $using:ip}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Identifier = "0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.Prefix = "0.0.0.0/0"}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-TCPIP"} | ForEach-Object {$_.Interfaces.Interface.Routes.Route.NextHopAddress = $using:gw}

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-DNS-Client"} | ForEach-Object {$_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.InnerText = $using:dns}

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $using:DomainJoinAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $using:DomainJoinAccountPassword}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $using:OU}
        $XmlDocument.Save("$VHDVolume\unattend.xml")
      
        break
      }
      'Tier 0 Member Server' {

        break
      }
      'Tier 1 Member Server' {
        $global:Join2Domain = 'Join2Domain0_Tier1'
        ($XmlDocument = [xml]'<root></root>').Load($xml)

        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.ComputerName = $using:Name0fGuestOS}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOrganization = ${Public DNS Domain}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-Shell-Setup"} | ForEach-Object {$_.RegisteredOwner = $BitwardenOrganizationName}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Domain = $((Get-ADDomain @cred).DNSRoot)}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Username = $using:DomainJoinAccount}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.Credentials.Password = $using:DomainJoinAccountPassword}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.JoinDomain = ${using:AD DNS}}
        ($XmlDocument.unattend.settings).Where({$_.Pass -eq 'specialize'}).component | Where-Object {$_.Name -eq "Microsoft-Windows-UnattendedJoin"} | ForEach-Object {$_.Identification.MachineObjectOU = $OU}

        $XmlDocument.Save("$VHDVolume\unattend.xml")
      
        break
      }
      'Tier 0 Member Server-Static IP Cfg' {

        break
      }
      'Tier 1 Member Server-Static IP Cfg' {

        break
      }
      default {write "Keeping the possibility of more parameter sets open"}
    }
  
    #   Invoke-WebRequest -Uri 'http://live.sysinternals.com/sdelete.exe' -OutFile "$ns\sdelete.exe"
    Dismount-DiskImage -ImagePath ${Guest OS Disk Path} | Out-Null
    Start-VM -Name $using:Name0fVM | Out-Null
  }
}

function New-Server2025ReferenceVHDXviaPowerShellRemoting { # Constructs a reference VHDX file of Windows Server 2025 |
  [CmdletBinding()]
  param (
    [Parameter(
      HelpMessage = "Supply 1 of the 4 editions of Windows Server: Datacenter, DatacenterDesktopExperience, Standard, or StandardDesktopExperience",
      Position = 0, 
      ValueFromPipelineByPropertyName = $False
    )]
    [ValidateSet('Standard','StandardDesktopExperience','Datacenter','DatacenterDesktopExperience')]
    [string]
    $Edition = 'Standard'
  )

  <# Trials |
    $Edition = 'Standard'
    $Edition = 'StandardDesktopExperience'
    $Edition = 'Datacenter'
    $Edition = 'DatacenterDesktopExperience'
  #>
  
  $StartTime = Get-Date

  <# There's no point to defining such a directory |
        @(
          "$((Get-VMHost).VirtualHardDiskPath)\Images",
          "$((Get-VMHost).VirtualHardDiskPath)\Images\Windows Server 2025"
        ) | ForEach-Object {
            $dir = $_ # Try replacing the $dir inside the try-catch blocks with $_... errors result. Wasted appx 2 hours on this. 
              try {
                Get-Item -Path $dir -ErrorAction 'Stop' > $null
              }
              catch {
                New-Item -Path $dir -ItemType 'Directory'
              }
            }
  #>

  <# Aspirations |
    Write a logical tree that crawls through persistent storage, removable media, and 
    network shares in search of .iso file. Dont use filenames. 
    Calculate the .iso file's SHA-256 hash. 
    If found, copy to $hvVol
    And if not found, the code should download Server 2025 from the web. 
    - How to query from Microsoft the SHA-256 has of the latest version of an OS?
    - We might have to consider Cultures outside of en-us. 

    My weak 1st attempt at the above: 
    #try {
    #  ${Iso File Path} = Get-Item -Path "$((Get-VMHost).VirtualHardDiskPath)\${Latest Server 2025}.iso" -ErrorAction 'Stop' | Select-Object -ExpandProperty 'FullName'
    #}
    #catch {
    #  try {
    #    $smb = Get-PSDrive -Name 'OS' -PSProvider 'FileSystem' -ErrorAction 'Stop'
    #  }
    #  catch {
    #    Write-Output "`r`n  Supply username & password of this PowerShell Remoting session to temporarily create the new PSDrive and download the .iso file:`r`n"
    #    $smb = New-PSDrive -Name 'OS' -PsProvider 'FileSystem' -Root "\\UcFC\OS" -Credential (Get-Credential)
    #  }
    #  Copy-Item -Path "\\UcFC\OS\${Latest Server 2025}.iso" -Destination "$((Get-VMHost).VirtualHardDiskPath)" -Force
    #  ${Iso File Path} = Get-Item -Path "$((Get-VMHost).VirtualHardDiskPath)\${Latest Server 2025}.iso" | Select-Object -ExpandProperty 'FullName'
    #}  
  #>
 
  ${Iso File Path} = Get-Item -Path "$((Get-VMHost).VirtualHardDiskPath)\${Latest Server 2025}.iso" | Select-Object -ExpandProperty 'FullName'

  switch ($Edition) {
    'Standard' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard ${Latest Server 2025}.vhdx"
      break
    }
    'StandardDesktopExperience' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Standard with Desktop Experience ${Latest Server 2025}.vhdx"
      break
    }
    'Datacenter' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter ${Latest Server 2025}.vhdx"
      break
    }
    'DatacenterDesktopExperience' {
      ${Reference VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\Server 2025 Datacenter with Desktop Experience ${Latest Server 2025}.vhdx"
      break
    }
    default {'This should never appear because the ValidateSet PVA already guards against rogue input'}
  }

  if (
    Test-Path -Path $env:WinDir\System32\MBR2GPT.exe
  ) {
    ${Mounted Image Letter} = (Mount-DiskImage -ImagePath ${Iso File Path} | Get-DiskImage | Get-Volume | Select-Object -ExpandProperty 'DriveLetter') + ':'
    #${Mounted Image Letter} = $(Mount-DiskImage -ImagePath ${Iso File Path} | Get-DiskImage | Get-Volume | Select-Object -ExpandProperty 'DriveLetter') + ':'
    # Small size deliberately chosen because _THE C: SHOULD ONLY CARRY SYSTEM FILES!!_
    New-VHD -Path ${Reference VHDX Path} -SizeBytes 50GB -Dynamic > $null
    # Would you fucking believe that the shit bombs out if you write something like 73.2GB?! 
    ${Mounted Ref VHDX Disk #} = Mount-DiskImage -ImagePath ${Reference VHDX Path} | Get-DiskImage | Get-Disk | Select-Object -ExpandProperty 'Number'
    Initialize-Disk -Number ${Mounted Ref VHDX Disk #} -PartitionStyle 'MBR'
    ${Mounted Ref VHDX Letter} = (New-Partition -DiskNumber ${Mounted Ref VHDX Disk #} -AssignDriveLetter -UseMaximumSize -IsActive | Format-Volume -FileSystem 'NTFS' -Confirm:$False | Select-Object -ExpandProperty 'DriveLetter') + ':'
  
    switch ($Edition) {
      'Standard'                    {
        Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:1 /ApplyDir:"${Mounted Ref VHDX Letter}\"     # > $null
        break
      }
      'StandardDesktopExperience'   {
        Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:2 /ApplyDir:"$(${Mounted Ref VHDX Letter})\"    # > $null
        break
      }
      'Datacenter'                  {
        Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:3 /ApplyDir:"${Mounted Ref VHDX Letter}\"     # > $null
        break
      }
      'DatacenterDesktopExperience' {
        Dism.exe /apply-Image /ImageFile:"${Mounted Image Letter}\Sources\install.wim" /Index:4 /ApplyDir:"$(${Mounted Ref VHDX Letter})\"    # > $null
        break
      }
      default                       {'This should never appear because the ValidateSet PVA already guards against rogue input'}
    }
  
    bcdboot.exe ${Mounted Ref VHDX Letter}\Windows /s ${Mounted Ref VHDX Letter} /f BIOS
    MBR2GPT.EXE /Convert /Disk:${Mounted Ref VHDX Disk #} /allowFullOs  
    Dismount-DiskImage -ImagePath ${Iso File Path} | Out-Null
    Dismount-DiskImage -ImagePath ${Reference VHDX Path} | Out-Null  
  } 
  #else {
  #  try {
  #    $smb = Get-PSDrive -Name 'OS' -PSProvider 'FileSystem' -ErrorAction 'Stop'
  #  }
  #  catch {
  #    Write-Output "`r`n  Supply username & password of this PowerShell Remoting session to temporarily create the new PSDrive and download the .vhdx file:`r`n"
  #    $smb = New-PSDrive -Name 'OS' -PsProvider 'FileSystem' -Root "\\UcFC\OS" -Credential (Get-Credential)
  #  }
  #  ${Reference VHDX} = New-Item -ItemType 'File' -Path ${Reference VHDX Path}
  #  Copy-Item -Path "\\UcFC\OS\$(${Reference VHDX}.Name)" -Destination (Get-VMHost).VirtualHardDiskPath -Force
  #}

  $EndTime = Get-Date
  write "Duration: $(($EndTime - $StartTime).Minutes)m$(($EndTime - $StartTime).Seconds)s"
}

function WTF_Was_I_Thinking_Resolve-ADComputer {
  [OutputType('Microsoft.ActiveDirectory.Management.ADComputer')]

  param (
    [PSCredential]$Credential,

    [string]$Server,

    [Parameter(Mandatory)]
    [string]
    $cname
  )

  #@{IsDomainController = ((Get-CimInstance -Query "select * from Win32_OperatingSystem where ProductType='2'") -ne $Null)} # Work Station (1) Domain Controller (2) Server (3)  
  #Get-CimInstance -Query "select * from Win32_OperatingSystem where ProductType='2'"
  #Get-CimInstance -Query "select * from Win32_OperatingSystem where ProductType='3'"
  #Get-CimInstance -Query "select * from Win32_OperatingSystem"
  #${global:Computer Info Lite} += @{PartOfDomain = (Get-CimInstance -ClassName 'Win32_ComputerSystem').PartOfDomain}

  if (${Computer Info Lite}.PartOfDomain) {
    $DnsHostName = Resolve-DnsName -Name $cname -Type 'CNAME' | Select-Object -ExpandProperty 'NameHost' | Resolve-DnsName -Type 'A' | Select-Object -ExpandProperty 'IPAddress' | Resolve-DnsName -Type 'PTR' | Select-Object -ExpandProperty 'NameHost'
    Get-ADComputer -Filter {DNSHostName -eq $DnsHostName}
  } else {}
}

function Resolve-ADComputer {
  [OutputType('Microsoft.ActiveDirectory.Management.ADComputer')]

  param (
    [Parameter(Mandatory)]
    [string]
    $cname
  )

  ${Resolved Cname} = R | Select-Object -ExpandProperty 'NameHost'

  # I hate resorting to regular expressions to isolate the %ComputerName%, but I don't see any way to get the DnsNameHost attribute of an AD Computer object from the corresponding cname 
  ${regex DNS Name of Windows Host} = [System.Text.RegularExpressions.Regex]"^(?<Host_Name>(?!(\d{1,15}|w11|w11Pro|w11Pro4WS|s22|s22desk|s22std|s22stddt|ANONYMOUS|BATCH|BUILTIN|DIALUP|DOMAIN|ENTERPRISE|INTERACTIVE|INTERNET|LOCAL|NETWORK|NULL|PROXY|RESTRICTED|SELF|SERVER|SERVICE|SYSTEM|USERS|WORLD)$)[A-Za-z0-9][A-Za-z0-9-]{1,13}[A-Za-z0-9])\.(?<AD_DNS>.+)$"
  ${Resolved Cname} -match ${regex DNS Name of Windows Host} > $null
  Get-ADComputer -Identity $Matches['Host_Name']
}

function New-LinuxVM {
  param (
    [Parameter(
      Mandatory,
      HelpMessage = "Yes, even if work is being performed while locally logged into a node of a Hyper-V cluster, a PowerShell Remoting session is still required."
    )]
    [Alias('sess')]
    [System.Management.Automation.Runspaces.PSSession]
    $PowerShellRemotingSession,

    [Parameter(
      ValueFromPipelineByPropertyName = $true
    )]
    [ValidateSet(
      'Kali','Ubuntu','SELinux'
    )]
    [string]
    $Distro = 'Kali',

    [Parameter(
      HelpMessage = "Name of the virtual machine, which does NOT need to match the name of the guest OS!"
    )]
    [string]
    $Name0fVM = ('Hyper-V VM ' + ([System.IO.Path]::GetRandomFileName()) -replace '\.','' -join '').ToUpper(),

    [Parameter(
      HelpMessage = "Two virtual CPUs should be enough"
    )]
    [Int32]
    $cpu = 2,

    [Parameter(
      HelpMessage = "Set Metasploitable Linux as a Generation 1 VM"
    )]
    [Int32]
    $gen = 2,

    [Parameter(
      HelpMessage = "Default quantity of RAM assigned to the VM is 1/8 total physical RAM, so install the maximum amount on your Hyper-V hosts!"
    )]
    [int64]
    $ram = [math]::Round(${Computer Info Lite}.RAM/(8*1024*1024)/2,0)*2MB,
    
    [Parameter(
      HelpMessage = "I suspect that uniquely naming Hyper-V virtual switches (on a per-host basis) isn't necessary or desirable... and maybe it's not even practical!"
    )]
    [ValidateSet(
      'SET-enabled External vSwitch','vSwitchNAT','VLAN-enabled External vSwitch','Isolated vSwitch'
    )]
    [string]
    $net = "SET-enabled External vSwitch",

    [Parameter(
      HelpMessage = "Make sure the Hyper-V host has tons of RAM"
    )]
    [ValidateSet(
      'StartIfRunning','Start','Nothing'
    )]
    [string]
    $ActionWhenBareMetalHostBoots = 'Nothing',
    
    [Parameter(
      HelpMessage = "No need to right-click each row in Hyper-V Manager and select Shut Down."
    )]
    [ValidateSet(
      'Save','TurnOff','Shutdown'
    )]
    [string]
    $ActionOnBareMetalHostShutdown = 'Shutdown',
    
    [ValidateRange(1,100)]
    [Int32]
    $Buffer = 20,
    
    [ValidateSet(
      'Disabled','Production','ProductionOnly','Standard'
    )]
    [string]
    $CheckpointType = 'Disabled',

    [ValidateSet(
      'Pause','None'
    )]
    [string]
    $StorageDisconnectedAction = 'Pause',

    [int32]
    $HwThreadCountPerCore = '1',

    [Parameter(
      HelpMessage = "Migration between AMD & Intel doesn't appear to be supported!"
    )]
    [Alias('LivMigCompat')]
    [boolean]
    $IsVmCompatibleAcrossDifferentProcessorSKUsOfASingleCompany = $false,

    [Parameter(
      HelpMessage = "Connect to VLAN for Workloads by default. Connecting a vNIC to the Migration (14) or Storage (16) networks doesn't make any sense."
    )]
    [ValidateSet(
      10,12
    )]
    [int32]
    $VlanID = 12,

    [Parameter(
      Mandatory,
      HelpMessage = "New policy going forward: A note is required for each VM.`r`nFor more information, visit`r`n  https://www.altaro.com/hyper-v/vm-notes-powershell/"
    )]
    [string]
    $Notes
  )

  Invoke-Command -Session $PowerShellRemotingSession -ScriptBlock {
    $RedirectedError = $(
      ${Does This VM Already Exist?} = Get-VM -Name $using:Name0fVM
    ) 2>&1
    if (${Does This VM Already Exist?}) {
      Write-Host -ForegroundColor 'DarkRed' -Object "A virtual machine of that name already exists"
      break
    }

    switch ($using:Distro) {
      'Kali' {break}
      'Ubuntu' {write-host 'Uncover how to prepare a linux vhdx file'; break}
      'SELinux' {write-host 'Uncover how to prepare a linux vhdx file'; break}
      default {exit}
    }
      
    ${Current VM Version} = [double[]](Get-VMHost).SupportedVmVersions | Sort-Object | Select-Object -Last 1
    ${Current VM Version} = (Get-VMHost).SupportedVmVersions | Where-Object {$_ -match ${Current VM Version}}
    
    $HT = @{
      Name               = $using:Name0fVM
      ComputerName       = $env:ComputerName
      Generation         = 2
      MemoryStartupBytes = $using:ram
      Version            = ${Current VM Version}
    }
    try {${New VM} = Get-VM -Name $HT.Name -ErrorAction 'Stop'} catch {${New VM} = New-VM @HT}
  
    # Create a copy of the .vhdx file located at ${Base VHD Path}. Filename begins with name of VM and then the VM id. 
    ${Base VHDX Path} = "$((Get-VMHost).VirtualHardDiskPath)\kali-linux-2024.4-hyperv-amd64.vhdx"
    ${Guest OS Disk Path} = "$((Get-VMHost).VirtualHardDiskPath)\$(${New VM}.Name) $(${New VM}.Id).vhdx"
    Copy-Item -Path ${Base VHDX Path} -Destination ${Guest OS Disk Path}

    # Attach VHD containing Guest OS to VM |
    $HT = @{
      VMName             = $using:Name0fVM
      Path               = ${Guest OS Disk Path}
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    Add-VMHardDiskDrive @HT

    $HT = @{
      VMName = $using:Name0fVM
      ControllerType     = 'SCSI'
      ControllerLocation = '0'
      ControllerNumber   = '0'
    }
    ${Hyper-V HDD-Guest OS} = Get-VMHardDiskDrive @HT

    $HT = @{ # Set memory quantity & behavior of VM |
      VMName               = $using:Name0fVM
      DynamicMemoryEnabled = $True
      MinimumBytes         = 256MB
      MaximumBytes         = $using:ram
      Buffer               = $using:Buffer
    }
    Set-VMMemory @HT

    Set-VM -Name $using:Name0fVM -EnhancedSessionTransportType 'HVSocket'
    Enable-VMIntegrationService -VMName $using:Name0fVM -Name 'Guest Service Interface'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Heartbeat'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Key-Value Pair Exchange'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Shutdown'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'Time Synchronization'
    Disable-VMIntegrationService -VMName $using:Name0fVM -Name 'VSS'
    
    $HT = @{ # Quantity of vCPUs |
      VMName = $using:Name0fVM
      Count  = $using:cpu
    }
    Set-VMProcessor @HT

    $HT = @{ # Constrain physical CPU resources available to a VM's virtual processors |
      VMName  = $using:Name0fVM
      Reserve = '0'
      Maximum = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # Prioritize access to physical CPU resources across VMs | Default value is 100. Since urgency is measured by "weight" and not "priority", a greater number reflects greater importance. |
      VMName         = $using:Name0fVM
      RelativeWeight = '100'
    }
    Set-VMProcessor @HT  

    $HT = @{ # 'Enable Auto-Throttle on a VM’s CPU Access' # Allegedly, Microsoft does not fully document what this controls |
      VMName                       = $using:Name0fVM
      EnableHostResourceProtection = $True
    }
    Set-VMProcessor @HT  

    $HT = @{ # | code "$knet\#scripts#\NuS25W11VMs\NuS25W11VMs.psm1" | Search for 'CompatibilityForMigrationEnabled' for why we set the value to false | UPDATE 2024-12-27: Migration between AMD & Intel isn't allowed by default! |
      VMName                           = $using:Name0fVM
      CompatibilityForMigrationEnabled = $using:IsVmCompatibleAcrossDifferentProcessorSKUsOfASingleCompany
    }
    Set-VMProcessor @HT  

    $HT = @{ # I think that HwThreadCountPerCore = 1 means that NUMA is not enabled _FOR THE VM_ | NUMA can still be enabled at they Hyper-V host level | HwThreadCountPerCore = 0 means to inherit the host's settings for 'hardware threads per core'
      VMName               = $using:Name0fVM
      HwThreadCountPerCore = $using:HwThreadCountPerCore
    }
    Set-VMProcessor @HT  

    $HT = @{ # Automatic Start Action | Automatic Start Delay | Automatic Stop Action |
      Name                 = $using:Name0fVM
      AutomaticStartAction = $using:ActionWhenBareMetalHostBoots
      AutomaticStopAction  = $using:ActionOnBareMetalHostShutdown
      AutomaticStartDelay  = $(60 * ((Get-VM).Count - 1))
    }
    Set-VM @HT

    $HT = @{ # Firmware settings |
      VMName           = $using:Name0fVM
      FirstBootDevice  = ${Hyper-V HDD-Guest OS}
      EnableSecureBoot = 'Off'
    }
    Set-VMFirmware @HT
  
    if ($using:CheckpointType -ne 'Disabled') {
      Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $true
      Set-VM -Name $using:Name0fVM -CheckpointType $using:CheckpointType
    } 
    else {
      Set-VM -Name $using:Name0fVM -AutomaticCheckpointsEnabled $false
      Set-VM -Name $using:Name0fVM -CheckpointType $using:CheckpointType
    }
    
    Set-VM -VMName $using:Name0fVM -AutomaticCriticalErrorAction $using:StorageDisconnectedAction -AutomaticCriticalErrorActionTimeout 120

    Set-VM -VMName $using:Name0fVM -Notes $using:Notes

    ((Get-VMSwitch $using:net).EmbeddedTeamingEnabled) ? 
    (& {
      Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM | Rename-VMNetworkAdapter -NewName "Network Adapter-SET"
      $global:vNIC = Get-VMNetworkAdapter -Name "Network Adapter-SET" -VMName $using:Name0fVM
    }) : ($global:vNIC = Get-VMNetworkAdapter -Name "Network Adapter" -VMName $using:Name0fVM)

    Connect-VMNetworkAdapter -Name $vNIC.Name -VMName $using:Name0fVM -SwitchName $using:net
    Set-VMNetworkAdapter -Name $vNIC.Name -VMName $using:Name0fVM -MacAddressSpoofing 'On'
    Set-VMNetworkAdapterVlan -VMName $using:Name0fVM -VMNetworkAdapterName $vNIC.Name -Access -VlanId $using:VlanID

    Start-VM -Name $using:Name0fVM | Out-Null
  }
}

function Safeguard-OneDrive {
  [CmdletBinding()]
  param ()

  # 256 GB Samsung FIT flash drive: 

  $SamsungFITdisk = Get-Disk | Select-Object * | ? {($_.FriendlyName -eq "Samsung Flash Drive FIT") -and ($_.UniqueId -match 'USBSTOR\\DISK&VEN_SAMSUNG&PROD_FLASH_DRIVE_FIT&REV_1100\\0330123070003679&0') -and ($_.SerialNumber -eq 'AA00000000000489')}

  if(!($SamsungFITdisk -eq $null)) {$SamsungFITpart = Get-Partition -DiskNumber $SamsungFITdisk.Number | Select-Object -First 1; $FIT = [string]$SamsungFITpart.DriveLetter + ":"}

  $dir = New-Item -ItemType Directory -Path "$FIT\od\$(Call-DateVar2)"
  
  Copy-Item -Path "$env:SystemDrive\Users\${explorer.exe Owner}\OneDrive\iddqd" -Destination "$dir" -Recurse
  Copy-Item -Path "$env:SystemDrive\Users\${explorer.exe Owner}\OneDrive\IT" -Destination "$dir" -Recurse
  Copy-Item -Path "$env:SystemDrive\Users\${explorer.exe Owner}\OneDrive\IT1" -Destination "$dir" -Recurse
  Copy-Item -Path "$env:SystemDrive\Users\${explorer.exe Owner}\OneDrive\knet" -Destination "$dir" -Recurse
}

