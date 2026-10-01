$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& python "$scriptDir\..\src\wikiskill\cli.py" @args
