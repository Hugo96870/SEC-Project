# SEC-Project

Neste projeto criamos um sistema distribuído de membros de uma blockchain que são responsáveis por manter o estado da blockchain e por, todos em conjunto, implementarem o serviço da blockchain.

Como objetivo do projeto queremos tranformar pedidos do cliente para pedidos no serviço da blockchain.

Este serviço da blockchain tem que ser tolerável a faltas e a comportamentos bizantinos, ou seja, tem que ser confiável.

Para a segunda fase, cada cliente tem a ele associado uma conta e pode fazer 3 tipos de pedido, CREATE, TRANSFER ou BALANCE
 - CREATE A
    - A: Nome associado à chave publica (Alice, Bob ou Charlie)
 - TRANSFER A B N
    - A: Conta de origem da transferencia
    - B: Conta de destino da transferencia
    - N: Quantidade a transferir
 - BALANCE A M
    - A: Nome associado à conta (Alice, Bob ou Charlie)
    - M: Modo de leitura (strong ou weak)

Este projeto foi implementado seguindo o algoritmo [The Istanbul BFT Consensus Algorithm](https://arxiv.org/pdf/2002.03613.pdf).

---

## Pressupostos do projeto

Para o design do projeto optámos por implementar uma rede distribuída com as seguintes caraterísticas:
 - Existem N = 3 * F + 1 servidores na rede, F correspondendo ao número de servidores não corretos (com comportamento bizantino).
 - Existe um servidor líder.
 - Os pedidos dos clientes são tratados em bloco, ou seja, após X pedidos, os servidores irão executar esse bloco.

 ----

 ## Estrutura do projeto
 O projeto encontra-se desenvolvido no repositório [SEC-PROJECT](https://github.com/Hugo96870/SEC-Project.git).
 
 Na diretoria raiz encontram-se duas pastas:
 - JavaCrypto: Pasta com as funções fornecidas no primerio laboratório de SEC.
 - Secure-Messages: Pasta onde foi desenvolvido todo o projeto. Dentro desta pasta encontram-se as seguintes pastas e ficheiros:
    - keys: pasta com todas as chaves geradas necessárias para a parte criptográfica do projeto.
    - src/pt/tecnico: Pasta com o código do projeto:
        - SecureClient: Código do cliente.
        - SecureServer: Código do server.
        - sendAndReceiveAck: Código de funções auxiliares a serem chamadas por threads criadas pelo servidor.
        - receiveString: Código com funções auxiliares que são chamadas por uma thread responsável por estar a receber os pedidos dos clientes.
        - auxFunctions: Código com funções de criptografia usadas durante a execução dos programas.
        - blockChain: Ficheiro toda a lógica da blockchain.
        - clientWaitResponse: Código do cliente para ficar à espera de uma maioria de respostas dos servidores.
        - IBFT_Functions: Código com as funções auxiliares para execução do algoritmo IBFT.
        - operation: Código que define os tipos de operações a serem executadas pelo cliente.
    - pom.xml: ficheiro de confiiguração do maven
 ----
 ## Funcionamento do projeto

No funcionamento do sistema distribuído, um cliente liga-se ao serviço da blockchain e envia um dos 3 possivieis tipos de pedido para todos os servidores da blockchain.

Posto isto, o serviço da blockchain segue o algoritmo [The Istanbul BFT Consensus Algorithm](https://arxiv.org/pdf/2002.03613.pdf) de maneira a assegurar o correto funcionamento do próprio.

Após o algoritmo terminar, uma maioria de servidores responde ao cliente com uma confirmação de que o seu pedido foi aceite.

---

 ## Instruções para testar / correr o projeto

Para correr o projeto será necessário ter previamente instado o [maven](https://maven.apache.org/).

Para lançar um processo servidor deverá executar o seguinte comando num terminal na diretoria que contém o ficheiro pom.xml:
```
mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="N K"
```
- Onde as variavéis tomam os seguintes valores:
    - N é o port a que o server que está a invocar se irá ligar
    - K é o estado do servidor que está a lançar, K pode ser um dos seguintes valores:
        - LEADER: para indicar que o processo é o líder
        - NORMAL: Para indicar que o processo será um processo correto, mas não o líder.
        - B_PC: para indicar que o processo terá um comportamento bizantino em que não transmite o valor correto na mensagem de PREPARE e COMMIT.
        - B_PP: para indicar que o processo terá um comportamento bizantino em que irá enviar mensagen de PREPREPARE embora não seja o líder.
        - B_PC_T: para indicar que o processo terá um comportamento bizantino em que não transmite o valor correto na mensagem de PREPARE e COMMIT e irá enviar várias mensagens de PREPARE E COMMIT fora de ordem.

Para lançar um processo cliente deverá executar o seguinte comando num terminal na diretoria que contém o ficheiro pom.xml:
```
mvn compile exec:java -Dmainclass=pt.tecnico.SecureClient -Dexec.args="localhost N Y Z"
```
Onde as variavéis tomam o seguinte valor:
- N: Nome da conta a ser lançada (Alice, Bob ou Charlie)
- Y: Número de servidores no serviço da blockchain
- Z: Porto onde o cliente se vai iniciar