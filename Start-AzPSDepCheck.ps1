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

    # $azureFunctions = Get-AzFunctionApp | Where-Object {$_.Runtime -eq 'PowerShell'}

    # foreach ($func in $azureFunctions) {
    #     $filePath = "/home/site/wwwroot/requirements.psd1"
    #     $publishingProfile = Get-AzWebAppPublishingProfile -ResourceGroupName $func.ResourceGroupName -Name $func.RepositorySiteName
    #     $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(($publishingProfile[0].UserName + ":" + $publishingProfile[0].UserPassword)))
    #     $apiUrl = "https://$($func.RepositorySiteName).scm.azurewebsites.net/api/vfs$filePath"

    #     $response = Invoke-RestMethod -Uri $apiUrl -Headers @{Authorization=("Basic {0}" -f $base64Auth)} -Method Get

    #     foreach ($item in $response.Keys) {
    #         $value = $response[$item]
    #         if ($value -notcontains '*') {
    #             $onlineModule = Find-Module -Name $item
    #             if ($onlineModule.Version -notlike $value) {
    #                 $report += [PSCustomObject]@{
    #                     ItemName = "$($sub.Name)/$($rb.ResourceGroupName)/$($rb.AutomationAccountName) Module: $($item)"
    #                     Type = "FunctionModule"
    #                     Problem = "Function App Module may be outdated. Current: $($value) PSGallery: $($onlineModule.Version)"
    #                 }
    #             }
    #         }
    #     }
    # }

}

$report | Format-Table
$report | Export-Csv "$(Get-Date -Format "yyyy-MM-dd-HH-mm-ss")-azure-powershell-problems.csv" -NoClobber -Force