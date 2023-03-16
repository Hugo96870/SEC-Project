import subprocess
from subprocess import *

nrServers = "4"
leader = "8000"
process = "8000"

#subprocess.Popen('mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="4 8000 8000"', shell=True)
#subprocess.Popen('mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="4 8001 8000"', shell=True)
#subprocess.Popen('mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="4 8002 8000"', shell=True)
#subprocess.Popen('mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="4 8003 8000"', shell=True)

#subprocess.Popen('mvn compile exec:java -Dmainclass=pt.tecnico.SecureClient -Dexec.args="localhost 8000"', shell=True)

#
subprocess.call(['mvn', 'compile', 'exec:java', '-Dmainclass=pt.tecnico.SecureServer', '-Dexec.args=\"4 8000 8000 N\"'])
