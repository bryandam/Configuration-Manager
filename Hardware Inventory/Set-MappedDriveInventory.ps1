[CmdletBinding(SupportsShouldProcess=$True)]
Param
(
	[switch]
	$TriggerInventory
)

#region MAPPED DRIVES
Function Get-MappedDrives {
    Try{
        #Get HKEY_Users Registry Keys
	    [array]$UserSIDS = Get-ChildItem -Path REGISTRY::HKEY_Users | Where-Object { ($_ -notlike "*Classes*") -and ($_ -like "*S-1-5-21*") } | Select-Object -ExpandProperty Name
	    
        #Get Profiles from HKLM
	    [array]$ProfileList = Get-ChildItem -Path REGISTRY::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_ -like "*S-1-5-21*" } | Select-Object -ExpandProperty Name
    }
    Catch{
        Write-Error "Could not enumerate the user profiles.$([Environment]::NewLine)Error: $($_.Exception.Message)$([Environment]::NewLine)$($_.InvocationInfo.PositionMessage)"
        Return
    }
	
    $MappedDrives = @()

	#Iterate through each HKEY_USERS profile
	foreach ($UserSID in $UserSIDS) {
	
        Try{
    	    #GET SID only
		    [string]$UserSID = $UserSID.Split("\")[1].Trim()           
	
    	    #Find the userprofile that matches the HKEY_USERS
		    [string]$UserPROFILE = $ProfileList | Where-Object { $_ -like "*" + $UserSID + "*" }
	
    	    #Get the username associated with the SID
		    $Username = ((Get-ItemProperty -Path REGISTRY::$UserPROFILE).ProfileImagePath).Split("\")[2].trim()
            Write-Verbose "Processing $($Username)'s profile for mapped drives."
	
    	    #Define registry path to mapped drives
		    [string]$MappedDrivePath = "HKEY_USERS\" + $UserSID + "\Network"

            #Get list of the user's mapped drives
            [string[]]$MappedDriveList = Get-ChildItem REGISTRY::$MappedDrivePath | Select-Object -ExpandProperty Name
            
            If ($MappedDriveList){
                Write-Verbose "Found $($MappedDriveList.Count) mapped drive(s) for $Username."
            }
            Else{
                Write-Verbose "Found 0 mapped drives for $Username."
                Continue #Move to the next user SID.
            }
	    }
        Catch {
            Write-Error "Could not get list of the user's mapped drives.$([Environment]::NewLine)Error: $($_.Exception.Message)$([Environment]::NewLine)$($_.InvocationInfo.PositionMessage)"
            Return
        }
    
    	#Loop through mapped drives and add them to the array.
        Try{
            [array]$MappedDrives
		    foreach ($MappedDrive in $MappedDriveList) {  
                
			    $DriveLetter = Get-ItemProperty -Path REGISTRY::$MappedDrive | Select-Object -ExpandProperty PSChildName
			    $DrivePath = Get-ItemProperty -Path REGISTRY::$MappedDrive | Select-Object -ExpandProperty RemotePath
			    If ($UNCExclusions -inotcontains $DrivePath) {
				    $Drives = New-Object System.Management.Automation.PSObject
				    $Drives | Add-Member -MemberType NoteProperty -Name ComputerName -Value $env:COMPUTERNAME
				    $Drives | Add-Member -MemberType NoteProperty -Name Username -Value $Username
				    $Drives | Add-Member -MemberType NoteProperty -Name DriveLetter -Value $DriveLetter
				    $Drives | Add-Member -MemberType NoteProperty -Name DrivePath -Value $DrivePath
				    $MappedDrives += $Drives                             
                    Write-Verbose "Found drive $DriveLetter connected to $DrivePath."
			    }
		    }
        }
        Catch{
            Write-Error "Could not get mapped drive information.$([Environment]::NewLine)Error: $($_.Exception.Message)$([Environment]::NewLine)$($_.InvocationInfo.PositionMessage)"
        }
	}
	Return $MappedDrives
}


Function New-WMIClass_MappedDrives {
    [CmdletBinding(SupportsShouldProcess=$True)]
	Param
	(
		[ValidateNotNullOrEmpty()]
        [string]$Class
	)
	
    #If the class exists then delete it to clear all entries.
	$WMITest = Get-WmiObject $Class -ErrorAction SilentlyContinue
	If ($WMITest -ne $null) {
        $Output = "Deleting $Class WMI class....."
		Remove-WmiObject $Class -WhatIf:$WhatIfPreference

        #Verify that the cleass was removed.
		$WMITest = Get-WmiObject $Class -ErrorAction SilentlyContinue		
		If ($WMITest -eq $null) {
			$Output += "Success"
		} else {
			$Output += "Failed"
			Exit 1
		}
		Write-Verbose $Output
	}

    If (!$WhatIfPreference){
	    #Create the new class.
	    $newClass = New-Object System.Management.ManagementClass("root\cimv2", [String]::Empty, $null);
	    $newClass["__CLASS"] = $Class;
	    $newClass.Qualifiers.Add("Static", $true)

	    $newClass.Properties.Add("DriveLetter", [System.Management.CimType]::String, $false)
	    $newClass.Properties["DriveLetter"].Qualifiers.Add("key", $false)
	    $newClass.Properties.Add("DrivePath", [System.Management.CimType]::String, $false)
	    $newClass.Properties["DrivePath"].Qualifiers.Add("key", $false)
	    $newClass.Properties.Add("Username", [System.Management.CimType]::String, $false)
	    $newClass.Properties["Username"].Qualifiers.Add("key", $false)

	    $newClass.Put() | Out-Null
	}

    #Verify that the class was created.
    $WMITest = Get-WmiObject $Class -ErrorAction SilentlyContinue
    $Output = "Creating " + $Class + " WMI class....."
	If (($WMITest -eq $null) -or ($WhatIfPreference)) {
		$Output += "Success"
	} else {
		$Output += "Failed"
		Exit 1
	}
	Write-Verbose $Output
}

#MAIN
$ClassName = 'Custom_MappedDrives'
#Get list of mapped drives for each user
[string[]] $UNCExclusions = @("") #Enter exclusions here
[array]$MappedDrives = Get-MappedDrives
Write-Verbose "Found $($MappedDrives.Count) drives in total."

#Create the new WMI class to write the output data to
New-WMIClass_MappedDrives -Class $ClassName

#Write the output data as an instance to the WMI class
foreach ($MappedDrive in $MappedDrives) {   
    If (!$WhatIfPreference){   
	    Set-WmiInstance -Class $ClassName -Arguments @{ DriveLetter = $MappedDrive.DriveLetter; DrivePath = $MappedDrive.DrivePath; Username = $MappedDrive.Username } | Out-Null
    }
}

#Invoke a hardware inventory to send the data to SCCM
If ($TriggerInventory) {
    Try{
        $ComputerName = $env:COMPUTERNAME
	    $SMSCli = [wmiclass] "\\$ComputerName\root\ccm:SMS_Client"
	    $SMSCli.TriggerSchedule("{00000000-0000-0000-0000-000000000001}") | Out-Null
    }
    Catch{
        Write-Error "Failed to trigger hardare inventory.$([Environment]::NewLine)Error: $($_.Exception.Message)$([Environment]::NewLine)$($_.InvocationInfo.PositionMessage)"
    }
}


#Display list of mapped drives for each user
$MappedDrives | Format-Table | Out-String|% {Write-Verbose $_}

#endregion