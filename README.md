# Nosso casamento

Controle de fornecedores, orçamento por categoria, pagamentos e fluxo de caixa.

Roda no GitHub Pages, sem servidor. Os dados ficam no branch `dados` deste
repositório, **cifrados com AES-256** usando a senha de cada pessoa
(PBKDF2-SHA256, 310 mil iterações). Quem abrir o repositório só vê texto cifrado.

## Primeiro acesso

1. Crie um token em GitHub > Settings > Developer settings > Fine-grained tokens:
   - Repository access: *Only select repositories* > `casamento`
   - Permissions > Repository > **Contents: Read and write**
   - Expiração: até depois do casamento
2. Abra o site, cole o token, escolha usuário e senha.
3. Em Ajustes > "+ Pessoa" dá acesso a mais alguém (cada um com a própria senha).

## Testar localmente

```
python3 -m http.server 8765
```

Em `localhost` o app usa o localStorage do navegador no lugar do GitHub.

Esqueceu a senha? Não há recuperação: os dados só abrem com a senha de algum
usuário cadastrado. Por isso vale baixar o backup em Ajustes de vez em quando.
