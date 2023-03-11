import subprocess
import pandas as pd

nrServers = "4"
leader = "8000"

#Execute 4 servers

path = r"."
tasks = ['mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="' + nrServers + ' ' + '8000 ' + leader + '"',
        'mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="' + nrServers + ' ' + '8001 ' + leader + '"',
        'mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="' + nrServers + ' ' + '8002 ' + leader + '"',
        'mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="' + nrServers + ' ' + '8003 ' + leader + '"']
task_processes = [
    subprocess.Popen(r'%s%s' % (path, task), creationflags=subprocess.CREATE_NEW_CONSOLE)
    for task
    in tasks
]

#Execute 1 client
path = r"."
tasks = ['mvn compile exec:java -Dmainclass=pt.tecnico.SecureClient -Dexec.args="localhost 8000"']
task_processes = [
    subprocess.Popen(r'%s%s' % (path, task), creationflags=subprocess.CREATE_NEW_CONSOLE)
    for task
    in tasks
]