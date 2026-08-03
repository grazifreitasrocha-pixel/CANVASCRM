# CRM Contabilidade — Deploy no Railway (com login e permissões)

## O que mudou nesta versão
- **Login obrigatório**: ninguém mais acessa só com o link. Cada pessoa tem conta própria (e-mail + senha).
- **Três papéis de acesso**:
  - `admin` — acesso total: vendas, integração, precificação, relatórios e gestão da equipe
  - `comercial` — funil de vendas, integração e relatórios (não vê nem edita a estrutura de precificação)
  - `operacional` — só o funil de integração, e só pode mover a etapa dos clientes; não vê valores, comissões nem dados comerciais
- **Dados por cliente**: cada cliente agora é um registro próprio no banco (antes era um bloco único gigante) — isso permite auditoria (quem mexeu, quando) e evita que uma pessoa sobrescreva o trabalho de outra sem querer.

## Passo a passo no Railway

### 1. Subir o projeto
1. Suba esta pasta inteira (com a subpasta `public/`) para um repositório no GitHub
2. No railway.app, **New Project -> Deploy from GitHub repo** -> selecione o repositório
3. Aguarde o primeiro deploy

### 2. Adicionar o banco de dados
1. No projeto, **+ New -> Database -> Add PostgreSQL**
2. O Railway injeta a variável `DATABASE_URL` automaticamente no serviço principal

### 3. Configurar a chave de sessão (importante)
1. Clique no serviço principal (o do `server.js`) -> aba **Variables**
2. Adicione uma variável chamada `JWT_SECRET` com qualquer texto longo e aleatório (ex: gere um em https://generate-secret.vercel.app/32)
3. **Por quê**: sem essa variável, o sistema ainda funciona, mas gera uma chave nova toda vez que reinicia — e isso desloga todo mundo sozinho. Com a variável fixa, o login continua valendo entre reinícios/deploys.
4. Depois de adicionar, vá em **Settings -> Redeploy** para aplicar

### 4. Gerar a URL pública
1. **Settings -> Networking -> Generate Domain**
2. Essa é a URL que a equipe vai usar

### 5. Primeiro acesso
1. Abra a URL gerada — como ainda não existe nenhum usuário, o sistema mostra a tela **"Primeiro acesso"**
2. Preencha seu nome, e-mail e uma senha — essa conta já nasce como **administrador**
3. Depois de entrar, vá em **Equipe** (menu lateral) para criar o acesso de cada pessoa do time, escolhendo o papel certo (admin / comercial / operacional)

## Continuidade dos dados
Se você já tinha usado a versão anterior (sem login) neste mesmo banco de dados, o servidor **migra automaticamente** os clientes e a precificação que já existiam para o novo formato, na primeira vez que subir. Não precisa fazer nada manual para isso.

## Limitações que ainda existem (para próximas fases)
- Não há recuperação de senha por e-mail ainda (se alguém esquecer a senha, o admin precisa remover o acesso em Equipe e criar de novo)
- O salvamento de clientes ainda é em lote (todo o array de clientes é reenviado a cada mudança) — funciona bem para o tamanho de equipe atual, mas para dezenas de pessoas mexendo ao mesmo tempo valeria otimizar para salvar só o registro que mudou
- Não há log de auditoria detalhado ainda (sabemos quem foi o último a editar cada cliente, mas não o histórico completo de mudanças)

## Se algo der errado
- Indicador "Sem conexão com o servidor" ou "Erro ao salvar": veja os logs em **Deployments -> View Logs**
- Se todo mundo for deslogado sozinho de tempos em tempos: confirme se a variável `JWT_SECRET` foi mesmo salva nas Variables

## Integração com Google Agenda (opcional)

Cada pessoa da equipe conecta a própria conta Google — os eventos de "próxima ação" são criados na agenda pessoal de quem estiver marcado como responsável.

### 1. Criar as credenciais no Google Cloud Console
1. Acesse https://console.cloud.google.com/ e crie um projeto novo (ou use um existente)
2. No menu, vá em **APIs e serviços -> Biblioteca**, procure **Google Calendar API** e clique em **Ativar**
3. Vá em **APIs e serviços -> Tela de consentimento OAuth**
   - Tipo de usuário: **Externo** (ou Interno, se tiver Google Workspace)
   - Preencha nome do app, e-mail de suporte
   - Em "Escopos", não precisa adicionar nada manualmente aqui
   - Em "Usuários de teste" (se o app ficar em modo de teste), adicione os e-mails da equipe que vai usar
4. Vá em **APIs e serviços -> Credenciais -> Criar credenciais -> ID do cliente OAuth**
   - Tipo de aplicativo: **Aplicativo da Web**
   - Em "URIs de redirecionamento autorizados", adicione: `https://SEU-DOMINIO-RAILWAY.up.railway.app/api/google/callback`
   - Salve e copie o **Client ID** e o **Client Secret** gerados

### 2. Configurar as variáveis no Railway
No serviço principal -> **Variables**, adicione:
- `GOOGLE_CLIENT_ID` = o Client ID copiado
- `GOOGLE_CLIENT_SECRET` = o Client Secret copiado
- `GOOGLE_REDIRECT_URI` = `https://SEU-DOMINIO-RAILWAY.up.railway.app/api/google/callback` (a mesma URL cadastrada no passo anterior)

Depois de adicionar, **Redeploy** o serviço.

### 3. Usar
1. Cada pessoa, na barra lateral do CRM, clica em **"Conectar Google Agenda"** e autoriza a própria conta
2. No cadastro do cliente, ao preencher a "Próxima ação", escolha também o **Responsável** (lista de usuários do sistema)
3. Na ficha do cliente, o botão **"Adicionar ao Google Agenda"** cria o evento na agenda daquela pessoa

Se o app ainda estiver em "modo de teste" na tela de consentimento do Google, só os e-mails cadastrados como "usuários de teste" no passo 1 conseguem conectar — para liberar para qualquer pessoa, é preciso publicar o app (Google pode pedir verificação, dependendo dos escopos usados).
