# agent-diagnostic-utility
Utility to check Agent folder permission(creation, updation & deletion) and connectivity check.

Steps to run the utility on agent machine -

1. Download the compatible executable.
2. Place the executable inside the bin folder of the agent.
3. Update the values for below attributes in agent.conf file -
    a. heartbeat-frequency
    b. no-of-pings=10(add this new attribute)
4. Run the executable from commandline -
    a. windows - bin\<executable> -p %password% -c .\conf\agent.conf
    b. linux - ./bin/<executable> -p $password -c ./conf/agent.conf