# Integrantes
Pedro Henrique Ferreira Xavier - 241025990
Hugo Freitas Silva - 241041302
Philipe Amâncio Reis Caetano - 241040350

# Cliente DNS

Cliente DNS desenvolvido em C para realizar consultas do tipo MX usando
UDP diretamente através da interface de sockets.

## Sistema e ambiente

- Sistema operacional de desenvolvimento: Linux (Ubuntu via WSL no Windows).
- Linguagem: C11.
- Compilador: GCC.
- Ferramentas: GNU Make e sockets POSIX.
- Porta utilizada: UDP 53.

O programa não utiliza bibliotecas externas de comunicação. A consulta DNS é
montada manualmente conforme o formato definido pelas RFCs 1034 e 1035.

## Estrutura

- `app/main.c`: coordena o fluxo completo da aplicação.
- `src/cli.c`: valida os argumentos e o endereço IPv4 do servidor.
- `src/dns_packet.c`: constrói a consulta DNS do tipo MX.
- `src/dns_name.c`: codifica e decodifica nomes DNS.
- `src/dns_client.c`: realiza a comunicação UDP e aplica o timeout.
- `src/dns_retry.c`: controla as três tentativas de consulta.
- `src/mx_lookup.c`: valida a resposta, interpreta o RCODE, extrai e ordena
  os registros MX.
- `include/`: arquivos de cabeçalho dos módulos.
- `tests/`: testes automatizados dos módulos.

## Como compilar

Na raiz do projeto, execute:

```bash
make
```

O executável `meu_cliente` será gerado na raiz do projeto.

Para remover os arquivos gerados:

```bash
make clean
```

## Como executar

```bash
./meu_cliente <dominio> <ip_servidor_dns>
```

Exemplo:

```bash
./meu_cliente google.com 8.8.8.8
```

O primeiro argumento é o domínio consultado. O segundo é o endereço IPv4 do
servidor DNS. O cliente usa a porta UDP 53, gera um transaction ID aleatório,
solicita apenas registros MX e espera até dois segundos por tentativa. Em caso
de timeout, a consulta pode ser repetida até três vezes.

## Exemplos de saída

Consulta bem-sucedida:

```text
google.com <> smtp.google.com
```

Domínio inexistente:

```text
Dominio exemplo-inexistente.invalid nao encontrado
```

Domínio sem registro MX:

```text
Dominio exemplo.com nao possui entrada MX
```

Servidor DNS sem resposta após as tentativas:

```text
Nao foi possível coletar entrada MX para exemplo.com
```

Respostas de sucesso, inclusive domínio inexistente ou sem MX, terminam com
código de saída `0`. Erros de argumentos, comunicação ou respostas inválidas
terminam com código diferente de zero.

## Testes

Para compilar e executar os testes automatizados:

```bash
make test
```

Os testes verificam:

- codificação, decodificação e compressão de nomes DNS;
- construção do cabeçalho e da pergunta MX;
- parsing de respostas válidas e malformadas;
- identificação de NXDOMAIN e ausência de registros MX;
- ordenação dos registros por prioridade;
- timeout e repetição das consultas UDP.

## Limitações conhecidas

- O cliente aceita apenas endereços IPv4 literais para o servidor DNS.
- A consulta utiliza somente UDP e limita o pacote a 512 bytes.
- Apenas consultas do tipo MX são suportadas.
- O resultado exibe o registro MX de maior prioridade, que é o primeiro após
  a ordenação dos registros encontrados.
- Firewalls ou redes que bloqueiam tráfego UDP para a porta 53 podem impedir
  consultas a servidores DNS externos.
