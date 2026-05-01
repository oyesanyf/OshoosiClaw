# Opená»ŒÌ€á¹£á»Ìá»Ì€sÃ¬ Target-Side Installation Helper
# 1. Install/Update Sysmon
if (Test-Path "Sysmon64.exe") {
    echo "Installing Sysmon with security configuration..."
    .\Sysmon64.exe -i sysmonconfig-export.xml -accepteula
}
# 2. Grant permissions
echo "Ensuring administrative permissions..."
.\osoosi.exe grant-access
echo "Deployment complete. Start the agent with: .\osoosi.exe start"
