function Invoke-DisableInactiveAccounts {
    param (
        # Domain
        [Parameter()]
        [String]
        $Domain = "WTGTest.local",

        # Base Logging Location
        [Parameter()]
        [String]
        $BaseLocation = "C:\Scripts\Logs\",

        # Target OUs
        [Parameter()]
        [String[]]
        $TargetOUs = @('OU=Admins,DC=WTGTest,DC=local'),
        
        # Admin Inactivity Time
        [Parameter(Mandatory = $false)]
        [String]
        $AdminDuration = '1',

        # Account Exclusions
        [Parameter(Mandatory = $false)]
        [String[]]
        $Exclude = @("*svc*", "*Service*"),

        # Admin Search Terms
        [Parameter(Mandatory = $false)]
        [String[]]
        $AdminSearchTerms = @("*"),

        # Admin Search Terms
        [Parameter(Mandatory = $false)]
        [String[]]
        $DisplayNameSearchTerms,

        # AD Properties
        [Parameter(Mandatory = $false)]
        [String[]]
        $Properties = @("SamAccountName", "Enabled", "LastLogonTimestamp", "DisplayName", "DistinguishedName", "PasswordLastSet", "AccountExpirationDate", "whenCreated", "Manager"),
       
        # Destination OU
        [Parameter()]
        [String]
        $DestinationOU = "OU=Inactive,DC=WTGTest,DC=local",

        # SMTP Server
        [Parameter()]
        [String]
        $SmtpServer = "mail.smtp2go.com",

        # SMTP From
        [Parameter()]
        [String]
        $From = "PRTG@wtg.net.au",

        # SMTP To
        [Parameter()]
        [String]
        $To = "ryan@wtg.net.au",
        
        # SMTP CC
        [Parameter()]
        [String]
        $Cc = "ryan@wtg.net.au",

        # Get Accounts Only
        [Parameter(Mandatory = $false)]
        [Switch]$DryRun
    )
    if ($DryRun) {
        $Accounts = Get-InactiveAccounts -OutputPath $BaseLocation -TargetOUs $TargetOUs -Domain $Domain -AdminDuration $AdminDuration -Exclude $Exclude -AdminSearchTerms $AdminSearchTerms -DisplayNameSearchTerms $DisplayNameSearchTerms -MembershipSearchTerms $MembershipSearchTerms -Properties $Properties -Force -To $To -From $From -SMTPServer $SMTPServer
        $isNullorEmpty = ($null -eq $Accounts -or $Accounts.Count -eq 0)
        if ($isNullorEmpty) {
            Write-Host "[DRY RUN] No accounts were found that match the provided criteria." -ForegroundColor Red
            $Body = "[DRY RUN] No accounts were found that match the provided criteria."
            Send-EmailOnError -Result $isNullorEmpty -To $To -From $From -Subject "Script error" -Body $Body -SMTPServer $SmtpServer
            return
        }
        Write-Host "`n[DRY RUN] Would move the following accounts:" -ForegroundColor Yellow
        $Accounts | ForEach-Object { Write-Host $_.DistinguishedName }
    }
    elseif (!$DryRun) {
        $Accounts = Get-InactiveAccounts -OutputPath $BaseLocation -TargetOUs $TargetOUs -Domain $Domain -AdminDuration $AdminDuration -Exclude $Exclude -AdminSearchTerms $AdminSearchTerms -DisplayNameSearchTerms $DisplayNameSearchTerms -MembershipSearchTerms $MembershipSearchTerms -Properties $Properties -Force -To $To -From $From -SMTPServer $SMTPServer
        $isNullorEmpty = ($null -eq $Accounts -or $Accounts.Count -eq 0)
        if ($isNullorEmpty) {
            Write-Host "No accounts were found that match the provided criteria." -ForegroundColor Red
            $Body = "No accounts were found that match the provided criteria."
            Send-EmailOnError -Result $isNullorEmpty -To $To -From $From -Subject "Script error" -Body $Body -SMTPServer $SmtpServer
            return
        }
        $OU = Set-MoveAccounts -Accounts $Accounts -DestinationOU $DestinationOU
        Set-DisableAccounts -OU $OU
        Set-Email -Accounts $Accounts -OU $OU -SmtpServer $SmtpServer -From $From -To $To -Cc $Cc -Domain $Domain -Location $BaseLocation -AttachmentLocation $BaseLocation
    }
    Write-Host "`n=======================" -ForegroundColor Red
    Write-Host "=+= Script Complete =+=" -ForegroundColor Green
    Write-Host "=======================`n" -ForegroundColor Red


    #Remove-Item "$($BaseLocation)*.csv"
    #Stop-Transcript
}
function Get-InactiveAccounts {
    param (
        # Domain
        [Parameter(Mandatory = $false)]
        [String]
        $Domain,

        # Output Path
        [Parameter(Mandatory = $false)]
        [String]
        $OutputPath,

        # Target OUs
        [Parameter(Mandatory = $false)]
        [String[]]
        $TargetOUs,

        # Admin Inactivity Time
        [Parameter(Mandatory = $false)]
        [Int]
        $AdminDuration,

        # Account Exclusions
        [Parameter(Mandatory = $false)]
        [String[]]
        $Exclude,

        # Admin Search Terms
        [Parameter(Mandatory = $false)]
        [String[]]
        $AdminSearchTerms,

        # Admin Search Terms
        [Parameter(Mandatory = $false)]
        [String[]]
        $DisplayNameSearchTerms,

        # Group Search Terms
        [Parameter(Mandatory = $false)]
        [String[]]
        $MembershipSearchTerms,

        # AD Properties
        [Parameter(Mandatory = $false)]
        [String[]]
        $Properties,

        # Bypass Safety Prompt
        [Parameter(Mandatory = $false)]
        [Switch]$Force,
		
		# Email parameters
        [Parameter(Mandatory = $false)]
        [String]
        $To,

        [Parameter(Mandatory = $false)]
        [String]
        $From,

        [Parameter(Mandatory = $false)]
        [String]
        $SMTPServer
    )
    Write-Host "`n=================================" -ForegroundColor Cyan
    Write-Host "=+= Finding Inactive Accounts =+=" -ForegroundColor Green
    Write-Host "=================================`n" -ForegroundColor Cyan

    # Find accounts in TargetOUs
    $Accounts = @()
    Try {
        $Exclusion = ($Exclude | ForEach-Object { '(SamAccountName -notlike ' + "'$_')" }) -join ' -and '
        $Inclusion = ($AdminSearchTerms | ForEach-Object { '(SamAccountName -like ' + "'$_')" }) -join ' -and '
        $Filter = "$($Exclusion) -and $($Inclusion)"
        $InactiveAccounts = $Accounts | ForEach-Object {
            $TimeSpan = $null
            $defaultTimestamp = [DateTime]::FromFileTime(0)
            if ($null -ne $_.LastLogonTimestamp -and [DateTime]::FromFileTime($_.LastLogonTimestamp) -ne $defaultTimestamp) {
                $TimeSpan = New-TimeSpan -Start ([DateTime]::FromFileTime($_.LastLogonTimestamp)) -End (Get-Date)
            } elseif ($null -ne $_.whenCreated) {
                # if LastLogonTimestamp is null or default
                $TimeSpan = New-TimeSpan -Start $_.whenCreated -End (Get-Date)
            } else {
                Write-Host "[$($_.SamAccountName)] Skipping. Neither LastLogonTimestamp nor whenCreated are available."
                return
            }
            if ($TimeSpan.Days -gt $AdminDuration) {
                $_
            }
        }     
        If ($DisplayNameSearchTerms.Length -gt 0) {
            $DisplayNameInclusion = ($DisplayNameSearchTerms | ForEach-Object { '(DisplayName -like ' + "'$_')" }) -join ' -and '
            $Filter = "$($Filter) -and $($DisplayNameInclusion)"
        }
        Write-Host "[*] Locating Accounts`n" -ForegroundColor Cyan
        Foreach ($OU in $TargetOUs) {
            Write-Host "[*] Searching in $($OU)" -ForegroundColor Cyan
            $Accounts += Get-AdUser -Filter $Filter -SearchBase $OU -Properties $Properties | Select-Object $Properties
        }
        Write-Host "[+] Found $($Accounts.Length) Accounts" -ForegroundColor Green
    }
    Catch {
        Write-Host "[!] An Error has Occurred" -ForegroundColor Red
        Throw $_
    }

    $CurrentDate = Get-Date
    $AdminExpiry = $CurrentDate.AddDays(-$AdminDuration)
    $CreatedDeadline = $CurrentDate.AddDays(-$AdminDuration)

    # Filters accounts based on AdminSearchTerms
    Write-Host "`n[*] Filtering Accounts based on Admin Search Terms" -ForegroundColor Cyan
    $AdminSearchTerms_InactiveAdmins = @()
    ForEach ($Account in $Accounts) {
        $Timestamp = $null
        if ($null -ne $Account.LastLogonTimestamp) {
            $Timestamp = [datetime]::FromFileTime($Account.LastLogonTimestamp)
        } 
        elseif ($null -ne $Account.whenCreated) {
            # if LastLogonTimestamp is null
            $Timestamp = $Account.whenCreated
        }
        else {
            Write-Host "[$($Account.SamAccountName)] Skipping. Neither LastLogonTimestamp nor whenCreated are available.2" -ForegroundColor Yellow
            continue
        }
        If ($Timestamp -le $AdminExpiry -and $Account -notin $AdminSearchTerms_InactiveAdmins) {
            $AdminSearchTerms_InactiveAdmins += $Account
        }
    }

    Write-Host "[+] Found $($AdminSearchTerms_InactiveAdmins.Length) Inactive Admin Accounts" -ForegroundColor Green

    # Finding Groups based on MembershipSearchTerms
    Write-Host "`n[*] Finding Groups based on Membership Search Terms" -ForegroundColor Cyan
    $MembershipSearchTerms_InactiveAdmins = @()
    $Unfiltered = @()
    $Filtered = @()

    [System.Collections.ArrayList]$Groups = $MembershipSearchTerms
    $Wildcards = @()

    Foreach ($Group in $Groups) {
        If ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Group)) {
            $Wildcards += $Group
        }
    }

    Foreach ($Wildcard in $Wildcards) {
        $GroupsFound = Get-AdGroup -Filter "Name -like '$($Wildcard)'"

        Foreach ($Group in $GroupsFound) {
            $Groups += $Group.SamAccountName | Where-Object { $Group.SamAccountName -notin $Groups }
        }

        #$Groups.Remove($Wildcard)
    }

    Write-Host "[+] Found $($Groups.Count) Groups" -ForegroundColor Green

    # Find and Filter accounts based on MembershipSearchTerms
    Write-Host "`n[*] Filtering Accounts based on Membership Search Terms" -ForegroundColor Cyan

    Foreach ($Group in $Groups) {
        $Member_Accounts = @()
        $Members = Get-ADGroupMember $Group | Select-Object SamAccountName

        Foreach ($Member in $Members) {
            Try {
                $Member_Accounts += Get-AdUser $Member.SamAccountName -Properties $Properties | Select-Object $Properties
            }
            Catch {
                Write-Host "[!] Invalid Account: $($Member.SamAccountName)" -ForegroundColor Yellow
            }
        }
    }
    ForEach ($Account in $Member_Accounts) {
        $Timestamp = $null
        if ($null -ne $Account.LastLogonTimestamp) {
            $Timestamp = [datetime]::FromFileTime($Account.LastLogonTimestamp)
        } 
        elseif ($null -ne $Account.whenCreated) {
            # if LastLogonTimestamp is null
            $Timestamp = $Account.whenCreated
        }
        else {
            Write-Host "[$($Account.SamAccountName)] Skipping. Neither LastLogonTimestamp nor whenCreated are available3." -ForegroundColor Yellow
            continue
        }
        $Unfiltered += $Account | Where-Object { $Timestamp -le $AdminExpiry -and $Account -notin $Unfiltered } | Select-Object $Properties
    }

    Foreach ($Account in $Unfiltered) {
        Foreach ($Term in $AdminSearchTerms) {
            If ($Account.SamAccountName -like $Term) {
                $Filtered += $Account
                Break
            }
        }
    }

    Foreach ($Account in $Filtered) {
        $Valid = $true
        Foreach ($Term in $Exclude) {
            If ($Account.SamAccountName -like $Term) {
                $Valid = $false
                Break
            }
        }
        If ($Valid) {
            $MembershipSearchTerms_InactiveAdmins += $Account
        }
    }

    Write-Host "[+] Found $($MembershipSearchTerms_InactiveAdmins.Length) Inactive Admin Accounts" -ForegroundColor Green

    # Filter duplicates
    Write-Host "`n[*] Removing Duplicates" -ForegroundColor Cyan
    $InactiveAdmins = @()

    $InactiveAdmins += $AdminSearchTerms_InactiveAdmins

    Foreach ($Account in $MembershipSearchTerms_InactiveAdmins) {
        If ($InactiveAdmins.SamAccountName -notcontains $Account.SamAccountName) {
            $InactiveAdmins += $Account
        }
    }

    Write-Host "[+] $($InactiveAdmins.Length) Inactive Admin Accounts After Filtering" -ForegroundColor Green

    # Get group memberships
    $TotalAccounts = @()
    Write-Host "`n[*] Getting Group Memberships" -ForegroundColor Cyan

    Foreach ($Account in $InactiveAdmins) {
        $Memberships = Get-ADPrincipalGroupMembership $Account.SamAccountName | Select-Object Name

        Try {
            $Result = [PSCustomObject]@{
			SamAccountName = $Account.SamAccountName
			Enabled = $Account.Enabled
			LastLogonTimestamp = [datetime]::FromFileTime($Account.LastLogonTimestamp).ToString('g')
			Created = $Account.whenCreated
			DisplayName = $Account.DisplayName
			DistinguishedName = $Account.DistinguishedName
			PasswordLastSet = $Account.PasswordLastSet
			AccountExpirationDate = $Account.AccountExpirationDate
			Memberships = $Memberships.Name -join ', '
			Manager = $Account.Manager
}

# Check if any property is not as expected
if ($null -eq $Result.LastLogonTimestamp -or $null -eq $Result.Created) {
    Write-Host "Error creating result for account $($Account.SamAccountName): One or more properties are not as expected." -ForegroundColor Red
    Write-Host "LastLogonTimestamp: $($Result.LastLogonTimestamp)"
    Write-Host "Created: $($Result.Created)"
    Send-EmailOnError -Result $null -To $To -From $From -Subject "Error processing account" -Body "There was an error processing account $($Account.SamAccountName): One or more properties of the PSCustomObject are not as expected." -SMTPServer $SMTPServer
    return
}

$TotalAccounts += $Result
        }
        Catch {
            Write-Host "Error creating result for account $($Account.SamAccountName): $($_.Exception.Message)" -ForegroundColor Red
            Send-EmailOnError -Result $null -To $To -From $From -Subject "Error processing account" -Body "There was an error processing account $($Account.SamAccountName): $($_.Exception.Message)" -SMTPServer $SMTPServer
        }
    }		

    # Export inactive accounts
    Write-Host "`n[*] Exporting" -ForegroundColor Cyan
    Try {
        If ($TotalAccounts.Length -gt 0) {
            $TotalExportPath = "$($OutputPath)InactiveAdmins - $($Domain) - $(Get-Date -Format "dd-MM-yyyy - (hh-mm-ss)").csv"
            $TotalAccounts | Export-Csv -Path $TotalExportPath -NoTypeInformation
            Write-Host "[+] File exported to: $($TotalExportPath)" -ForegroundColor Green
        }
        else {
            Write-Host "[!] No Admin Accounts Found" -ForegroundColor Red
        }
    }
    Catch {
        Write-Host "[!] Export Error has Occurred" -ForegroundColor Red
        Throw $_
    }

    # Safety Prompt
    If ($Force -eq $false) {
        Write-Host "`n[***] DEBUG: Check Export Files Before Confirming" -ForegroundColor Yellow

        While ($true) {
            $Prompt = Read-Host -Prompt "[!] Are you sure you want to move & disable these Accounts? (Y/N)"

            If ($Prompt.ToUpper() -eq "Y") {
                Write-Host "[+] Sending Accounts to Move Function" -ForegroundColor Green
                break
            }
            elseif ($Prompt.ToUpper() -eq "N") {
                Write-Host "[!] Script Cancelled" -ForegroundColor Yellow
                Exit
            }
            else {
                Write-Host "[!] Invalid Input" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "`n[+] Sending Accounts to Move Function" -ForegroundColor Green
    }

    # Always return $TotalAccounts
    Return $TotalAccounts
}
function Send-EmailOnError {
        param (
            # Result to check
            [Parameter(Mandatory = $false)]
            $Result,

            # Email parameters
            [Parameter(Mandatory = $true)]
            [String]
            $To,
            [Parameter(Mandatory = $true)]
            [String]
            $From,
            [Parameter(Mandatory = $true)]
            [String]
            $Subject,
            [Parameter(Mandatory = $true)]
            [String]
            $Body,
            [Parameter(Mandatory = $true)]
            [String]
            $SMTPServer
        )

        if (!$Result) {
            $messageParameters = @{
                Subject    = $Subject
                Body       = $Body
                From       = $From
                To         = $To
                SmtpServer = $SMTPServer
            }

            Send-MailMessage @messageParameters
        }
    }
function Set-MoveAccounts {
        param (
            # Inactive Accounts
            [Parameter(Mandatory = $true)]
            $Accounts,

            # Destination OU
            [Parameter(Mandatory = $true)]
            [String]
            $DestinationOU
        )
        Write-Host "`n================================" -ForegroundColor Cyan
        Write-Host "=+= Moving Inactive Accounts =+=" -ForegroundColor Green
        Write-Host "================================`n" -ForegroundColor Cyan

        Write-Host "[*] Moving Accounts to $($DestinationOU)" -ForegroundColor Cyan
        Foreach ($Account in $Accounts.DistinguishedName) {
            Try {
                Move-ADObject $Account -TargetPath $DestinationOU
            }
            Catch {
                Write-Host "[!] An Error has Occurred" -ForegroundColor Red
                Throw $_
            }
        }
        Write-Host "[+] Move Complete" -ForegroundColor Green

        Write-Host "`n[+] Starting Disable Function" -ForegroundColor Green
        Return $DestinationOU
        Set-MoveAccounts -Accounts $InactiveAdmins -DestinationOU $TargetOU
    }

function Set-DisableAccounts {
    param (
        # Target OU
        [Parameter(Mandatory = $true)]
        [String]
        $OU
    )

    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host "=+= Disabling Inactive Accounts =+=" -ForegroundColor Green
    Write-Host "===================================`n" -ForegroundColor Cyan

    Write-Host "[*] Disabling Accounts in $($OU)" -ForegroundColor Cyan

    $DisabledAccounts = Get-ADUser -Filter * -SearchBase $OU

    $DisabledAccounts | ForEach-Object {
    $existingNotes = (Get-ADUser $_.SamAccountName -Properties info).info
    $newNote = "Disabled due to inactivity - $(Get-Date)"

    if ($existingNotes) {
        # Split the existing notes into an array of lines
        $existingNotesArray = $existingNotes -split "`r`n"

        # If there are already 3 lines, remove the oldest one
        if ($existingNotesArray.Count -ge 3) {
            $existingNotesArray = $existingNotesArray | Select-Object -Skip 1
        }

        # Add the new note to the array
        $existingNotesArray += $newNote

        # Join the array back into a string with line breaks
        $newNote = $existingNotesArray -join "`r`n"
    }

    Set-ADUser $_.SamAccountName -Replace @{info = $newNote}
    $_
} | Disable-ADAccount

    Write-Host "[+] Disable Complete" -ForegroundColor Green
    Write-Host "`n[+] Sending Accounts to Email Function" -ForegroundColor Green
}

function Set-Email {
        param (
            # Domain
            [Parameter(Mandatory = $true)]
            [String]
            $Domain,

            # Inactive Accounts
            [Parameter(Mandatory = $true)]
            $Accounts,

            # Log Location
            [Parameter(Mandatory = $true)]
            $Location,

            # Inactive Accounts
            [Parameter(Mandatory = $true)]
            $OU,

            # Inactive Accounts
            [Parameter(Mandatory = $true)]
            [String]
            $SmtpServer,
        
            # Inactive Accounts
            [Parameter(Mandatory = $false)]
            [Int]
            $SmtpServerPort = 2525,

            # Inactive Accounts
            [Parameter(Mandatory = $true)]
            [String]
            $From,

            # Inactive Accounts
            [Parameter(Mandatory = $true)]
            [String]
            $To,

            # Inactive Accounts
            [Parameter(Mandatory = $true)]
            [String]
            $Cc,

            # Attachment Location
            [Parameter(Mandatory = $true)]
            [String]
            $AttachmentLocation
        )
        Write-Host "`n==================================" -ForegroundColor Cyan
        Write-Host "=+= Emailing Disabled Accounts =+=" -ForegroundColor Green
        Write-Host "==================================`n" -ForegroundColor Cyan

        $Subject = "Inactive admins - 45 days - $($Domain) - $(Get-Date)" 
        $Body = @"
The following administrator accounts have been disabled:
$($Accounts | ForEach-Object { "`n$($_.SamAccountName)" })
`nPlease notify them this action has occurred and that revalidation will be required to reactivate.
"@

        $LatestCsvFile = Get-ChildItem -Path $AttachmentLocation -Filter *.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 1
		$Attachments = $LatestCsvFile.FullName

        Write-Host "Smtp Config: $($SmtpServer):$($SmtpServerPort)`n" -ForegroundColor Green
        Write-Host "To: $($To)" -ForegroundColor Cyan
        Write-Host "From: $($From)" -ForegroundColor Cyan
        Write-Host "Cc: $($Cc)" -ForegroundColor Cyan
        Write-Host "Subject: $($Subject)" -ForegroundColor Green

        Try {
            Send-MailMessage -To $To -From $From -Cc $Cc -Subject $Subject -Body $Body -SmtpServer $SmtpServer -Port $SmtpServerPort -Priority High -DeliveryNotificationOption OnSuccess, OnFailure -ErrorAction Stop -Attachments $Attachments
            Write-Host "`n[+] The Moved & Disabled accounts have been sent to $($To)" -ForegroundColor Green
        }
        Catch {
            Write-Host "[!] Email Error has Occurred" -ForegroundColor Red
            Throw $_
        }
    }
Invoke-DisableInactiveAccounts -DryRun