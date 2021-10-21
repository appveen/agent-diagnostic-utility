echo "****************************************************"
echo ":: Building executables"
echo "****************************************************"

echo "env GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-windows-386.exe ./"
env GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-windows-386.exe ./

echo "env GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-windows-amd64.exe ./"
env GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-windows-amd64.exe ./

echo "env GOOS=linux GOARCH=386 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-linux-386 ./"
env GOOS=linux GOARCH=386 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-linux-386 ./

echo "env GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-linux-amd64 ./"
env GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-linux-amd64 ./ || true

echo "env GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-darwin-amd64 ./"
env GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o exec/agent-diagnostic-utility-darwin-amd64 ./ || true