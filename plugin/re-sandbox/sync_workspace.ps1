$ErrorActionPreference = "SilentlyContinue"

try {
    $rawInput = [Console]::In.ReadToEnd()
    if ($rawInput) {
        $payload = $rawInput | ConvertFrom-Json
        if ($payload.workspacePaths -and $payload.workspacePaths.Count -gt 0) {
            $wsPath = $payload.workspacePaths[0]
            if ($wsPath -match '^file:///') {
                $wsPath = [System.Uri]::UnescapeDataString(($wsPath -replace '^file:///', ''))
            }
            $wsPath = ($wsPath -replace '\\', '/').TrimEnd('/')
            if ($wsPath) {
                $stateDir = $PSScriptRoot
                $activeFile = Join-Path $stateDir "active_workspace.txt"
                $prevWs = ""
                if (Test-Path $activeFile) {
                    $prevWs = (Get-Content -Path $activeFile -Raw).Trim()
                }

                if ($prevWs -ne $wsPath) {
                    Set-Content -Path $activeFile -Value $wsPath -NoNewline -Encoding UTF8

                    # Trigger a live MCP reload in Antigravity so run_re_mcp.ps1 mounts the newly active project
                    if ($env:ANTIGRAVITY_LS_ADDRESS -and $env:ANTIGRAVITY_CSRF_TOKEN) {
                        $pluginDirName = Split-Path -Leaf $stateDir
                        $uri = "http://$($env:ANTIGRAVITY_LS_ADDRESS)/exa.language_server_pb.LanguageServerService/JetboxWriteState"
                        $headers = @{
                            "Content-Type"         = "application/json"
                            "x-codeium-csrf-token" = $env:ANTIGRAVITY_CSRF_TOKEN
                        }
                        $disableBody = "{`"userConfig`":{`"plugins`":{`"$pluginDirName`":{`"enabled`":false}}}}"
                        $enableBody  = "{`"userConfig`":{`"plugins`":{`"$pluginDirName`":{`"enabled`":true}}}}"
                        Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $disableBody -TimeoutSec 2 | Out-Null
                        Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $enableBody -TimeoutSec 2 | Out-Null
                    }
                }
            }
        }
    }
} catch {
    # Never block agent execution if hook parsing fails
}

[Console]::Out.Write("{}")
