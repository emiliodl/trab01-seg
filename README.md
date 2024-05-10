# Trabalho 01 – Implementação: Sistema de Gerenciamento de Chaves Públicas e Criptografia
O projeto visa desenvolver um sistema de gerenciamento de pares de chaves públicas e privadas, juntamente com funcionalidades de criptografia e descriptografia. O sistema permitirá a geração de novas chaves, armazenamento, importação/exportação das chaves, além de operações para criptografar e descriptografar de arquivos usando as chaves geradas.
- Funções implementadas:
- Geração de chaves compatível com o padrão openssl

Trecho da chaves (modo texto)

-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkMqJJLrxXQz9e
r6oMx21wkOgY3P1WFb9dvuBxK+/EUn/Jri7dsLfBv/eS2fUZBsmGyfqwSdJNYwNP
...
dFrNqgwYq00n53+f5V6sKNEhKWXN7a0OJm9yrc4YXXuyKKgzXPh5Rff7droj/xUF
-----END PRIVATE KEY-----

-----BEGIN PUBLIC KEY----- dFrNqgwYq00n53+f5V6sKNEhKWXN7a0OJm9yrc4YXXuyKKgzXPh5Rff7droj/xUF
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkMqJJLrxXQz9e
....
r6oMx21wkOgY3P1WFb9dvuBxK+/EUn/Jri7dsLfBv/eS2fUZBsmGyfqwSdJNYwNP
-----END PUBLIC KEY-----

- Desenvolver métodos para salvar/exportar as chaves em arquivos e carregar/importar as
chaves a partir destes arquivos. Deve ser possível exportar/importar o par de chaves ou
apenas a chave pública;
- Desenvolver métodos para gerenciar as chaves armazenadas, permitindo, por exemplo,
listar, pesquisar e apagar;
- Incluir métodos de proteção, permitindo proteger a chave privada usando uma senha de
modo a solicitar a mesma sempre que esse tipo de chave for usado;
- Implementar funcionalidades de criptografia e descriptografia utilizando as chaves
armazenadas
Entrada: arquivo em claro (ou criptografado)
