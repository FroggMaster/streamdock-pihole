$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:9999/")
$listener.Start()

$logFile = "$PSScriptRoot\plugin.log"
Write-Host "Log server running. Writing to: $logFile"
Write-Host "Press Ctrl+C to stop."

try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $body = (New-Object System.IO.StreamReader($ctx.Request.InputStream)).ReadToEnd()
        $entry = "[$(Get-Date -Format 'HH:mm:ss.fff')] $body"
        Write-Host $entry
        Add-Content -Path $logFile -Value $entry
        $ctx.Response.OutputStream.Close()
    }
}
finally {
    $listener.Stop()
}
