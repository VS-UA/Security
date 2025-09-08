# Instruções

## Instalação

É preciso java 11.

No ubuntu usar `sudo apt install openjdk-11-jdk`

Basta baixar o repositório, mantendo a posição relativa de `auth/target/UAP.jar` e `app_auth/test.py`.

É também necessário instalar o servidor.

## Execução

1. Ligar a UAP (do terminal em `project-2---authentication-equipa_5/auth`, usar `java -jar target/UAP.jar`)
1. Desencriptar a base de dados. Para tal, indicar a sua localização e passes.
	- A base de dados não deve residir no mesmo dispositivo que a UAP
	- Para este cenário de testes, a base de dados é `db.db` e ambas as passes `!@#$MySecr3tPassw0rd`.
1. Aceder ao site e clicar em `E-CHAP` na nav.
	- Caso não funcione, aceder a `http://localhost:8080/init_auth?url=localhost`
1. Aguardar pelo pop-up que indica o estado da autenticação.
1. Quando ela for bem sucedida, na janela principal da UAP estará o session ID. Deve ser copiado para o campo relevante no site.
