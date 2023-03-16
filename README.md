# SEC-Project

## Descrição geral

Neste projeto criamos um sistema distribuído de membros de uma blockchain que são responsáveis por manter o estado da blockchain e por, todos em conjunto, implementarem o serviço da blockchain.

Como objetivo do projeto queremos tranformar pedidos do cliente para pedidos no serviço da blockchain.

Este serviço da blockchain tem que ser tolerável a faltas e a comportamentos bizantinos, ou seja, tem que ser confiável.

Para esta primeira fase, um pedido do cliente resume-se a mandar um cadeira de caracteres para ser adicionada à blockchain.

Este projeto foi implementado seguindo o algoritmo [The Istanbul BFT Consensus Algorithm](https://arxiv.org/pdf/2002.03613.pdf).

---

## Pressupostos do projeto

Para o design do projeto optamos por implementar um rede distribuída com as seguintes caracteristicas:
 - Existem N = 3 * F + 1 servidores na rede, F correspondendo ao número de servidores não corretos (com comportamento bizantino).
 - Existe um servidor líder que é sempre correto.
 - Qualquer cliente que se ligue à rede distribuída irá fazer pedidos ao servidor líder.
 - Os pedidos dos clientes são tratados de forma sequencial, ou seja, o serviço só adiciona uma cadeia de caracteres à blockchain após a última já ter sido adicionada.

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
    - src/test/java: Pasta com o Código dos testes criados em Junit.
    - pom.xml: ficheiro de confiiguração do maven
 ----
 ## Funcionamento do projeto

No funcionamento do sistema distribuído, um cliente liga-se ao serviço da blockchain (através do servidor líder) e envia uma mensagem contendo a cadeira de caracteres que deseja adicionar à blockchain.

Posto isto, o serviço do blockchain segue o algoritmo [The Istanbul BFT Consensus Algorithm](https://arxiv.org/pdf/2002.03613.pdf) de maneira a assegurar o correto funcionamento do próprio.

Após o algoritmo terminar, o servidor líder responde ao cliente com uma confirmação de que a sua cadeia de caracteres foi adicionada à blockchain e a execução termina.

---

 ## Instruções para testar / correr o projeto

Para correr o projeto será necessário ter previamente instado o [maven](https://maven.apache.org/).

Para lançar um processo servidor deverá executar o seguinte comando num terminal na diretoria que contém o ficheiro pom.xml:
```
mvn compile exec:java -Dmainclass=pt.tecnico.SecureServer -Dexec.args="N Y Z K"
```
- Onde as variavéis tomam os seguintes valores:
    - N é o tamanho da rede, obedecendo à regra N = 3F + 1
    - Y é o port a que o server que está a invocar se irá ligar
    - Z é o port do servidor lider
    - K é o estado do servidor que está a lançar, K pode ser um dos seguintes valores:
        - L: para indicar que o processo é o líder
        - N: Para indicar que o processo será um processo correto, mas não o líder.
        - B-PC: para indicar que o processo terá um comportamento bizantino em que não transmite o valor correto na mensagem de PREPARE e COMMIT.
        - B-PP: para indicar que o processo terá um comportamento bizantino em que irá enviar mensagen de PREPREPARE embora não seja o líder.
        - B-PC-T: para indicar que o processo terá um comportamento bizantino em que não transmite o valor correto na mensagem de PREPARE e COMMIT e irá enviar várias mensagens de PREPARE E COMMIT fora de ordem.

Para lançar um processo cliente deverá executar o seguinte comando num terminal na diretoria que contém o ficheiro pom.xml:
```
mvn compile exec:java -Dmainclass=pt.tecnico.SecureClient -Dexec.args="localhost X"
```
Onde a variavél toma o seguinte valor:
- N: port do processo líder.

Para correr os testes Junit tem que correr o seguinte comando num terminal na diretoria que contém o ficheiro pom.xml:
```
mvn clean test
```