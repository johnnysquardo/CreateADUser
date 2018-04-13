#Import AD to your desktop PC
Import-Module ActiveDirectory

#Get Credentials to be able to use this script (Must provide Domain Admin Creds)
$cred = Get-Credential #Read credentials
 $username = $cred.username
 $password = $cred.GetNetworkCredential().password

 # Get current domain using logged-on user's credentials
 $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
 $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$UserName,$Password)

if ($domain.name -eq $null)
{
 write-host "Authentication failed - please verify your username and password."
}
else
{
 write-host "Successfully authenticated with domain $domain.name"
} 

#Test
$first = Read-Host -Prompt "Input desired First Name"
$last = Read-Host -Prompt "Input desired Last Name"

do{$account = Read-Host -Prompt "Input desired account name"
    $findaccount = get-aduser -identity $account -properties samaccountname |
       select-object -expandproperty samaccountname 
        if($findaccount -eq $account) {write-host "ERROR! Account already exists!" -foregroundcolor "red"}}
        until($findaccount -ne $account)

#Creates and checks Employee ID and Pass length
do {$EID = Read-Host -Prompt "Enter Employee ID #"
    if($EID.length -ne 6) {write-host "ERROR! Employee ID must be 6 digits!" -foregroundcolor "red"}}  
    until ($EID.length -eq 6)

do {$pass = Read-Host -Prompt "Enter new account password" -assecurestring
    if ($pass.length -lt 7) {write-host "ERROR! Password must be at least 7 characters!" -foregroundcolor "red"}}
    until ($pass.length -gt 6)
    
do {$target = Read-Host -Prompt "Enter desired target username to be copied from"
    $findtarget = Get-aduser -ldapfilter "(SAMAccountName=$target)"
    if($findtarget -eq $null) {write-host "ERROR! Account does not exist!" -foregroundcolor "red"}}
    until ($findtarget -ne $null)
    
$DN = get-aduser $target | foreach { $_.Distinguishedname}
$path = $dn -creplace '^[^,]*,', ''

#creates new user

new-ADUser -AccountPassword $pass -ChangePasswordAtLogon $true -SAMAccountName $account -DisplayName "$first $last" -enabled $true -EmployeeID $EID -givenname $first -surname $last -name "$first $last" -userprincipalname $account@pgatss.com -path $path -scriptpath login.bat

#copies all memberships to Active Directory groups

get-ADuser -Identity $target -Properties memberof |
select-object -Expandproperty memberof |
Add-ADGroupMember -Members $account

#prompt for mailbox creation

function mail{
echo "Do you want to create an email for this account?"
$answer = read-host "Enter response"

if ($answer -eq "yes" -or $answer -eq "y"){enable-mailbox -identity hgtps\$account}}

mail

write-host "---------------------------------
Account was created successfully!
---------------------------------" -foregroundcolor "green"

function menu{
echo "Do you want to create another account?"
$answer = read-host "Enter response"

if ($answer -eq "yes" -or $answer -eq "y"){c:\scripts\test.ps1}
else {write-host "-------------------
Program terminated.
-------------------" -foregroundcolor "yellow"}}

menu