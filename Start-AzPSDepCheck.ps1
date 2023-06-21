# local version


Connect-AzAccount

$report = @()

$subscriptions = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }

$exportTempPath = "$env:TEMP/AzPSDepCheckTemp/"
Remove-Item $exportTempPath -Force -Recurse -ErrorAction SilentlyContinue
New-Item $exportTempPath -ItemType Directory

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionObject $sub

    $autoAccounts = Get-AzAutomationAccount

    foreach ($autoAcc in $autoAccounts) {
        $runbooks = Get-AzAutomationRunbook -ResourceGroupName $autoAcc.ResourceGroupName -AutomationAccountName $autoAcc.AutomationAccountName | Where-Object {$_.RunbookType -eq "PowerShell"}

        foreach ($rb in $runbooks) {
            Export-AzAutomationRunbook -ResourceGroupName $rb.ResourceGroupName -AutomationAccountName $rb.AutomationAccountName -Name $rb.Name -OutputFolder $exportTempPath

            $content = Get-Content $exportTempPath\$($rb.Name).ps1
            if ($content -contains "Get-AutomationConnection") {
                $report += [PSCustomObject]@{
                    ItemName = "$($sub.Name)/$($rb.ResourceGroupName)/$($rb.AutomationAccountName)/$($rb.Name)"
                    Type = "Runbook"
                    Problem = "Contains Get-AutomationConnection: Recommend using Managed Identities instead."
                }
            }
            if ($content -contains "Get-AutomationVariable") {
                $report += [PSCustomObject]@{
                    ItemName = "$($sub.Name)/$($rb.ResourceGroupName)/$($rb.AutomationAccountName)/$($rb.Name)"
                    Type = "Runbook"
                    Problem = "Contains Get-AutomationVariable: Recommend using Key Vault instead."
                }
            }
        }

        $autoModules = Get-AzAutomationModule -ResourceGroupName $autoAcc.ResourceGroupName -AutomationAccountName $autoAcc.AutomationAccountName | Where-Object {$_.IsGlobal -eq $false}
        foreach ($module in $autoModules) {
            $onlineModule = Find-Module $module.Name
            if ($onlineModule.Version -ne $module.Version) {
                $report += [PSCustomObject]@{
                    ItemName = "$($sub.Name)/$($rb.ResourceGroupName)/$($rb.AutomationAccountName) Module: $($module.Name)"
                    Type = "AutomationAccountModule"
                    Problem = "Automation Account Module may be outdated. Current: $($module.Version) PSGallery: $($onlineModule.Version)"
                }
            }
        }
    }

    $azureFunctions = Get-AzFunctionApp | Where-Object {$_.Runtime -eq 'PowerShell'}

    $token = (Get-AzAccessToken).Token
    foreach ($func in $azureFunctions) {
        # Get the access token

        # Specify the header for the subsequent REST call
        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'='Bearer ' + $token
        }

        $url = "https://management.azure.com/subscriptions/$($sub.Id)/resourceGroups/$($func.ResourceGroupName)/providers/Microsoft.Web/sites/$($func.Name)/hostruntime/admin/vfs//requirements.psd1?relativePath=1&api-version=2018-11-01"
        $response = Invoke-RestMethod -Uri $url -Headers $authHeader -Method GET -UseBasicParsing
        $text = $response

        $requirements = [scriptblock]::Create($text).Invoke()
        $requirements
        foreach ($item in $requirements.Keys) {
            $value = $response[$item]
            if ($value -notcontains '*') {
                $onlineModule = Find-Module -Name $item
                if ($onlineModule.Version -notlike $value) {
                    $report += [PSCustomObject]@{
                        ItemName = "$($sub.Name)/$($func.ResourceGroupName)/$($func.Name) Module: $($item)"
                        Type = "FunctionModule"
                        Problem = "Function App Module may be outdated. Current: $($value) PSGallery: $($onlineModule.Version)"
                    }
                }
            }
        }

    }

}

$report | Format-Table
$report | Export-Csv "$(Get-Date -Format "yyyy-MM-dd-HH-mm-ss")-azure-powershell-problems.csv" -NoClobber -Force