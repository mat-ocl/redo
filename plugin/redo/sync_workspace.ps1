$ErrorActionPreference = "SilentlyContinue"

$isPreToolUse = $false

try {
    $rawInput = [Console]::In.ReadToEnd()
    if ($rawInput) {
        $payload = $rawInput | ConvertFrom-Json
        if ($null -ne $payload.toolCall) {
            $isPreToolUse = $true
        }

        if ($payload.workspacePaths -and $payload.workspacePaths.Count -gt 0) {
            $wsList = @()
            foreach ($rawWs in $payload.workspacePaths) {
                $wsPath = [string]$rawWs
                if ($wsPath -match '^file:///') {
                    $wsPath = [System.Uri]::UnescapeDataString(($wsPath -replace '^file:///', ''))
                }
                $wsPath = ($wsPath -replace '\\', '/').TrimEnd('/')
                if ($wsPath -and (Test-Path $wsPath)) {
                    $wsList += $wsPath
                }
            }

            if ($wsList.Count -gt 0) {
                $stateDir = $PSScriptRoot
                $wsDir = Join-Path $stateDir "workspaces"
                if (-not (Test-Path $wsDir)) {
                    New-Item -ItemType Directory -Path $wsDir -Force | Out-Null
                }

                $convId = if ($payload.conversationId) {
                    ($payload.conversationId -replace '[^a-zA-Z0-9_-]', '_')
                } else {
                    "default"
                }

                $entry = @{
                    conversationId = $convId
                    workspacePath  = $wsList[0]
                    workspacePaths = $wsList
                    updatedAtUtc   = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                }
                $entryJson = $entry | ConvertTo-Json -Compress
                Set-Content -Path (Join-Path $wsDir "$convId.json") -Value $entryJson -NoNewline -Encoding UTF8
            }
        }
    }
} catch {
    # Never block agent execution if hook parsing fails
}

if ($isPreToolUse) {
    [Console]::Out.Write('{"decision":"allow"}')
} else {
    [Console]::Out.Write('{}')
}
