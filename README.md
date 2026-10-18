# Lumi — seu iPhone leve de novo

Painel para guardar fotos, vídeos, áudios e documentos na nuvem e liberar espaço no iPhone.
Cada pessoa cria sua conta, envia os arquivos direto da galeria e depois pode apagar do celular.

## O que já vem pronto
- Cadastro e login (senha criptografada, sessão de 60 dias)
- Envio de vários arquivos de uma vez com barra de progresso (vídeos grandes também)
- Grade de fotos e vídeos, filtros (Fotos, Vídeos, Documentos, Áudios, Favoritos) e busca
- Visualizar, salvar de volta no iPhone, compartilhar, favoritar e apagar
- Seleção múltipla para baixar ou apagar em lote
- Medidor de espaço usado por pessoa (cota configurável)
- Funciona como app: Safari > Compartilhar > Adicionar à Tela de Início

## Subir no GitHub
1. Crie um repositório novo no GitHub chamado `lumi`.
2. Envie todos os arquivos desta pasta (pode arrastar no site do GitHub em "Add file > Upload files").

## Publicar no Railway
1. No Railway: **New Project > Deploy from GitHub repo** e escolha `lumi`.
2. **Crie um Volume (obrigatório)**: no serviço, clique com o botão direito > *Attach Volume*, mount path `/data`.
   Sem o volume, todos os arquivos somem a cada novo deploy.
3. Em **Variables**, adicione:
   - `JWT_SECRET` = uma senha longa e aleatória (ex: 40 letras e números misturados)
   - `NODE_ENV` = `production`
   - `QUOTA_MB` = `5120` (espaço por pessoa em MB; opcional)
   - `MAX_FILE_MB` = `2048` (tamanho máximo de cada arquivo; opcional)
   - `ALLOW_SIGNUP` = `false` se quiser fechar novos cadastros (opcional)
4. Em **Settings > Networking**, clique em **Generate Domain**. Esse é o link do seu painel.

## Custos a ter em mente
O Railway cobra pelo tamanho do volume. Se muita gente guardar vídeos, o volume cresce rápido.
Ajuste `QUOTA_MB` conforme o plano. Se o projeto crescer, o próximo passo é trocar o volume por um
armazenamento de objetos (Cloudflare R2 ou Backblaze B2), que sai bem mais barato por GB.

## Rodar no computador
```
npm install
npm start
```
Abra http://localhost:3000
