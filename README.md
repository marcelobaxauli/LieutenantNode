# Lieutenant Node

Nó representando um militar subordinado ao general.

## Execução

Para executar o programa primeiramente faça o build do mesmo na raiz do projeto

~~~ sh
$ mvn clean install 
~~~

Depois rode o Jar autoexecutavel

~~~ sh
$ java -jar target/lieutenant-node-exec-1.0-SNAPSHOT.jar lieutenant1-privatekey lieutenant1 honest
~~~

Onde lieutenant1-privatekey é uma chave secreta gerada por [Keypair Generator](https://github.com/marcelobaxauli/KeypairGenerator).

lieutenant1 é o nome do nó (e que deve estar no formato: lieutenant1, lieutenant2, ...).

honest é o valor de honestidade do nó (os valores podem ser honest ou dishonest).
