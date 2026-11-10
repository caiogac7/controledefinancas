# Documentação do Dashboard - Métricas e UI

## Métricas, KPIs e Regras de Interface

### 1. Card Fatura Consolidada (Mercado Pago - Nov 2026)
- **Valor da Fatura:** `R$ 2.936,43` (Auditado e travado de forma imutável contra recálculos indevidos de ciclo).
- **Status:** `✓ Fatura quitada` (com badge verde e `pending_amount = R$ 0,00`).
- **Total Pago:** `R$ 2.936,43` (Soma dos 5 pagamentos consolidados do mês: R$ 50,00 + R$ 15,00 + R$ 350,00 + R$ 900,00 + R$ 1.621,43).
- **Limites:** Limite total R$ 5.600,00, Usado R$ 3.979,79 (71%), Disponível R$ 1.620,21.

### 2. Ações em Lote e Seleção Múltipla (Visão Mensal & Parcelamentos)
- **Checkboxes de Seleção:** Exibidos em cada linha não paga na Visão Mensal.
- **Barra Flutuante (`batch-action-bar`):**
  - Exibe contador de títulos selecionados e **soma em tempo real** dos valores.
  - **Mudar Carteira em Massa:** Permite selecionar uma nova conta/carteira física e migrar todos os lançamentos selecionados com 1 clique.
  - **Pagar Todos & Conciliar Extrato:** Compara a soma dos títulos com movimentações de débito do extrato bancário (Pluggy) e permite quitação conjunta e conciliação imediata com o extrato.
- **Transferência de Parcelas em Massa (`batch-change-installments-bank-modal`):**
  - Botão dedicado na seção "Contratos & Compras Parceladas Ativas no Mês".
  - Permite selecionar múltiplos contratos parcelados e transferir a parcela do mês e todas as futuras para uma nova carteira bancária.

### 3. Integração Open Finance Pluggy
- **Fluxo do Primeiro Acesso:** Caso o usuário não possua nenhuma instituição conectada, o clique no botão laranja "Conectar Open Finance (Pluggy)" ou "Conectar Instituição" abre obrigatoriamente o manual guiado de conexão segura antes do widget de autenticação.
- **Botão Manual:** Acesso direto via botão "Como Conectar (Manual)".

### 4. Dual-Theme (Dark & Light)
- Blindagem total contra textos claros em fundos brancos: classes automáticas garantem contraste Slate 900 no modo claro e Slate 100/White no modo escuro.
- Paleta fintech com acentos em vermelho rubi (`#FF2E4D`) eliminando resquícios azuis indesejados.

### 5. Google Identity Services (One Tap & Popup Nativo com signInWithIdToken)
- **Eliminação de Redirecionamento Supabase:** Substituído o fluxo de redirecionamento OAuth que exibia `"Prosseguir para ncpdgcxoziekwuralwzx.supabase.co"`.
- **Fluxo Direto via ID Token:** Autenticação direta com `google.accounts.id` e `supabaseClient.auth.signInWithIdToken({ provider: 'google', token: response.credential })`.
- **Fallback Automático:** Caso o One Tap seja bloqueado ou fechado pelo usuário, fallback transparente renderiza botão do Google no container `#google-hidden-btn` e aciona a janela popup.
- **Client ID Oficial:** `812650524717-nuilae4gf0im0fl0nnjtt4jr9ovag1jl.apps.googleusercontent.com`.
- **Ícones PWA:** Atualizados para o novo padrão visual vermelho fintech (`#FF2E4D` a `#E61937`) em 192px e 512px.

### 6. Nitidez de GPU, Renderização Cristalina & Favicon Vermelho
- **Eliminação de Desfoque Subpixel:** Cartões operam com `transform-style: flat !important;`, `backface-visibility: hidden;` e `transform: translateZ(0);` com remoção de rotações 3D e `perspective: 1000px`.
- **Favicon Oficial em SVG Data URI:** Ícone da aba em SVG com gradiente `#FF2E4D` a `#E61937` e carteira branca em alta resolução.
- **Carregamento Instantâneo com Cache Local:** Resumo financeiro mantido em `financas_last_summary_${userId}` no `localStorage`, eliminando o estado de espera com `R$ 0,00` no carregamento.
- **Roteamento SPA na Vercel:** Diretivas de `rewrites` em `vercel.json` e espelhamento em `public/` garantem navegação fluida sem erro 404.

### 7. Saldo Reservado (Cofrinho / Caixinha) — Controle Estritamente Manual
- **Fim da Invasão Automática:** Eliminadas todas as extrações e heurísticas automáticas que marcavam contas como "Reservado" indevidamente. O Open Finance reportava remuneração automática de conta corrente (CDB/RDB que rende automaticamente no Itaú e InfinitePay como `automaticallyInvestedBalance`), o que indevidamente convertia o saldo livre em conta em "reserva".
- **Controle 100% nas Mãos do Usuário:** O badge "Reservado" e o campo `vault_balance` agora só existem se o próprio usuário abrir o modal de edição do banco em "Gerenciar Bancos" e preencher explicitamente um valor no campo "Dinheiro Reservado / Cofrinho".
- **Saldos em Banco Preservados:** Contas sem reserva manual permanecem limpas, exibindo exclusivamente seu saldo disponível livre sem faixas ou badges de reserva indesejados.

### 8. Estabilização de Layout, Bloqueio de Tradução Automática e Eliminação de Layout Shift

### 9. Proteção de Interface Mobile e Debounce no Open Finance
- **Trava Rígida de Clique (Anti-Double-Tap):** Bloqueio de cliques e toques repetidos no mobile através das variáveis de estado `isSyncingAllPluggyInProgress` e `activeSyncingItemIds`, desabilitando visual e funcionalmente os botões com `pointer-events: none`, `opacity: 0.5`, `cursor: not-allowed` e spinner de carregamento.

### 10. Motor Canônico de Faturas de Cartão (Espelhamento 100% SQL Supabase)
- **Fonte Canônica Exclusiva:** O valor da fatura de cartão em qualquer mês é calculado estritamente pela soma direta das despesas (`type = 'expense'`) na competência do mês (`month = :mKey`) da tabela `public.bank_statements`.
- **Fim da Mutação em Memória:** Eliminada qualquer sobrescrita destrutiva de `bankStatements` por rotinas de alocação de ciclo ou `fillInstallmentGaps` no front-end. O array `bankStatements` é a cópia fiel dos registros auditados no banco.
- **Valores Oficiais Auditados por Mês (Cartão Mercado Pago):**
  - `2026-05`: R$ 89,77 (5 transações)
  - `2026-06`: R$ 270,73 (10 transações)
  - `2026-07`: R$ 2.478,41 (72 transações)
  - `2026-08`: R$ 1.897,59 (60 transações)
  - `2026-09`: R$ 2.848,28 (82 transações)
  - `2026-10`: R$ 2.542,46 (83 transações)
  - `2026-11`: R$ 2.936,43 (49 transações)
  - `2026-12`: R$ 1.390,61 (28 transações)
  - `2027-01`: R$ 484,40 (16 transações)
  - `2027-02`: R$ 464,23 (15 transações)
  - `2027-03`: R$ 442,06 (13 transações)
  - `2027-04`: R$ 417,91 (12 transações)
  - `2027-05`: R$ 360,16 (10 transações)
  - `2027-06`: R$ 341,12 (9 transações)
  - `2027-07`: R$ 124,74 (6 transações)
  - `2027-08`: R$ 124,74 (6 transações)
  - `2027-09`: R$ 31,73 (2 transações)
- **Prevenção de Disparos Fantasmas no Touch:** Aplicação de `touch-action: manipulation;` nos botões de sincronização para eliminar o atraso tátil de 300ms e evitar que o navegador móvel dispare duplo clique acidental.
- **Cooldown no Cliente (Debounce de 3 Minutos):** Janela de segurança de 3 minutos entre sincronizações gerais de Open Finance, protegendo contra esgotamento da cota de requisições por toques repetidos.
- **Execução Sequencial com Intervalo:** Execução estritamente em fila com intervalo de respiro de 2 segundos entre conexões bancárias, impedindo bombardeamento simultâneo na API da Pluggy.
- **Proteção do LocalStorage (DOMException / QuotaExceededError):** Encapsulamento seguro via `safeLocalStorageSet` e eliminação definitiva do armazenamento de JSONs brutos de debug (`pluggy_card_raw_debug.json`) no armazenamento local do celular, mantendo o consumo de memória mobile estritamente abaixo do limite de 5MB.

### 10. Atualização Direta com a Instituição Bancária (Fluxo Oficial PATCH /items/{id})
- **Comportamento Equivalente ao Portal Meu Pluggy:** O botão "🔄 Atualizar com o Banco (Open Finance)" dispara internamente `PATCH /items/{itemId}` com corpo vazio `{}` para que a Pluggy consulte ativamente o banco emissor (Itaú, Mercado Pago, InfinitePay) e capture lançamentos e saldos em tempo real.
- **Trava Inteligente Anti-Quota (15 Minutos):** O backend verifica `item.lastUpdatedAt`. Se o banco já tiver respondido há menos de 15 minutos, pula a chamada de `PATCH` e busca direto as contas/transações mais recentes, economizando a cota da API.
- **Tratamento Gracioso de Cota:** Caso o limite de `PATCH` por hora da instituição seja atingido (HTTP 429 ou `"The quota has been exceeded"`), o backend não quebra com erro; ele prossegue com os dados mais recentes salvos na Pluggy e devolve `quotaNotice` informativo para o usuário.
- **Polling Assíncrono Seguro com Delay Inicial de 4s & Validação Estrita de Novo Snapshot:**
  - Antes de disparar o `PATCH`, o backend registra `previousUpdatedAt = itemAntes.lastUpdatedAt || itemAntes.updatedAt`.
  - Após aceitação do `PATCH`, aguarda `4000ms` (delay inicial obrigatório) para dar tempo à Pluggy de mudar o status para `UPDATING`.
  - O polling consulta a cada 3s (até 25s) e só encerra com sucesso quando: `status === 'UPDATED'` E `(lastUpdatedAt !== previousUpdatedAt || jaViuStatusUpdating === true)`.
  - O payload da resposta inclui `lastUpdatedAt`, `updatedAt`, `executionStatus` e `patchTriggered` para auditoria visual e transparente no Console do cliente.

### 11. Modos Especializados de Sincronização Open Finance e Blindagem Anti-Quota
- **⚡ Novidades (48h) [Modo Delta Incremental - Padrão Ultra Rápido]:**
  - Busca estritamente lançamentos de ontem e hoje (D-2).
  - Redução drástica de 98% no tráfego de rede (payload cai de >2MB para <10KB).
  - Resposta instantânea em ~1 a 2 segundos no mobile e desktop sem puxar o banco inteiro.
  - Elimina o envio desnecessário de objetos brutos de debug (`rawDebugPayload` condicionado a `fetchRawAll`).
- **🔄 Últimos 7 Dias:**
  - Consulta semanal para revisão e conciliação recente.
- **📦 Histórico Completo (Total):**
  - Varre todas as páginas de transações disponíveis na instituição sem limite de data.
- **Blindagem Completa Anti-Quota (Backend & Frontend):**
  - Caso a Pluggy ou o Banco reportem `The quota has been exceeded` ou `HTTP 429`, o backend responde HTTP 200 com os dados já salvos e o frontend exibe aviso informativo suave sem travar ou emitir erro fatal.
  - O `bootstrap.js` implementa versionamento anti-cache (`js/app.js?v=20261108_patch_meta_fix`), garantindo que o celular receba a versão mais atualizada imediatamente.
  - `safeLocalStorageSet` purga dados antigos e pesados de debug caso o navegador mobile atinja o teto de 5MB de armazenamento.
  - **Otimização de Salvamento em Lote:** O `CloudDB.saveUserData` é invocado uma única vez ao término da fila de sincronização (em vez de concorrente a cada banco), e o payload de extratos em `profiles.settings_json` foi limitado com proteção `try/catch` para evitar erros 500 no Supabase.
  - **Auditoria de PATCH no Objeto de Conexão:** Retorno de `patchStatus` e `patchMessage` no payload do item para rastrear exatamente se e por que o conector bancário aceitou ou rejeitou a consulta.


- **Bloqueio de Tradução Indesejada:** Inclusão de `class="notranslate" translate="no"` na tag `<html>`, meta tag `<meta name="google" content="notranslate" />` no `<head>`, e tags de blindagem em cabeçalhos, menus e botões para impedir corrupção textual ("adere de Finanças", "Pesca e Parcelas", etc.) causada pelo Google Tradutor do navegador.
- **Nomenclatura Oficial Restaurada:**
  - Sistema / Logo: `Controle de Finanças`
  - Aba de parcelamentos: `Compras Parceladas` (Desktop) / `Parcelas` (Mobile)
  - Botões de ação em cards: `Editar / Ajustar Parcelas` e `Pagar Parcela` / `✓ Parcela Paga`
- **Eliminação de Loops de Renderização e Jitter:**
  - O intervalo de polling de contas integradas/família foi elevado de 8s para 60s, com verificação de visibilidade (`!document.hidden`) e comparação por impressão digital (fingerprint) para evitar `renderAll()` redundante sem mudanças de dados.
  - Remoção de event listeners contínuos de `mousemove` que aplicavam rotação 3D (`perspective`, `rotateX`, `rotateY`, `scale`) nos cards a cada pixel movido, eliminando trepidação e distorção de fontes.
  - Proteção de CSS contra injeção de barras de tradução com `body { top: 0px !important; }` e `.skiptranslate { display: none !important; }`.

### 10. Simplificação dos Botões de Sincronização Open Finance (7 Dias & Geral)
- **Eliminação de Modais/Popups e Redundâncias:** Removidos os botões de popup e de 48h, concentrando toda a experiência de sincronização em dois fluxos claros, diretos e objetivos:
  1. **🔄 Últimos 7 Dias (`syncMode: '7d'`):** Sincronização rápida focada na última semana para conciliação contábil do dia a dia.
  2. **📦 Sincronização Geral (`syncMode: 'total'`):** Varredura completa de todo o histórico disponível na instituição bancária.
- **Limpeza Visual nos Cards de Conexão:** Cada instituição conectada exibe apenas os botões essenciais: `7 Dias`, `Geral`, `Reconectar` e `×` (Desvincular).
- **Tratamento no Backend (`/api/pluggy-sync`):** Mantido o tratamento inteligente que detecta conexões `MeuPluggy` e ignora o `PATCH /items/{id}` (bloqueado pelo provedor), garantindo que tanto a consulta de 7 dias quanto a geral sejam concluídas em poucos segundos sem falhas ou erros 400.
### 11. Refatoração UI/UX Mobile-First de Containers de Topo (Headers & Hero Sections)
- **Compactação de Altura e Paddings:**
  - Redução de padding vertical dos blocos hero de `p-5` / `p-6` para `p-3.5 sm:p-5 md:p-6` com bordas arredondadas adaptativas (`rounded-2xl md:rounded-3xl`), liberando espaço vertical essencial no celular.
  - Títulos principais redimensionados para `text-base sm:text-lg md:text-xl font-extrabold` com truncamento defensivo no mobile.
  - Parágrafos descritivos secundários configurados com `hidden sm:block`, mantendo a tela do smartphone focada estritamente nas métricas e ações sem empurrar os dados para baixo da dobra.
- **Agrupamento Inteligente de Ações (Fim da Poluição Visual):**
  - **Cabeçalho de Bancos & Conciliação:** O botão de maior prioridade (`Conectar Open Finance (Pluggy)`) recebe largura total ou destaque superior com gradiente âmbar/laranja; os outros 4 botões secundários (`Novo Banco`, `Importar OFX`, `Alinhar Saldos`, `Limpar`) organizam-se em uma grade 2x2 simétrica no mobile (`grid grid-cols-2 sm:flex sm:flex-wrap gap-2`).
  - **Painel de Conexões Automáticas:** Sincronização dividida em botões principais (`7 Dias` e `Geral`) em grade de 2 colunas, com botões utilitários compactos (`Manual`, `JSON`, `Conectar`) em linha de 3 colunas no celular.
  - **Compras Parceladas:** Ações organizadas em grade de 2 colunas (`Nova Compra` e `Conta Fixa`).
  - **Relatórios:** Exportação organizada em grade de 3 colunas compactas (`PDF`, `Mês`, `Geral`).
- **Alinhamento Flexível Responsivo (Column to Row):**
  - Containers configurados com `flex flex-col md:flex-row md:items-center md:justify-between gap-3 md:gap-4`, garantindo empilhamento limpo do título sobre os botões no mobile e alinhamento horizontal elegante no desktop.
- **Versionamento de Cache:** `bootstrap.js` atualizado para `20261108_simulador_ia_v2_1`.

### 12. Simulador de Decisão de Compra com IA v2.1 & Consultor Financeiro Pessoal v2
- **Arquivo de Patch Integrado (`simulador-ia-v2.1.patch`):** Patch consolidando aprimoramentos matemáticos e prompts estruturados do Consultor e Simulador de Compras.
- **Regras de Decisão Antifraude/Antijuros:**
  - Cálculo de Planos B realistas (`LOJA_2X`, `LOJA_3X`, etc.) mantendo a taxa de juros da loja, caso o lojista recuse negociações de desconto no balcão.
  - O campo `planoB` tornou-se obrigatório no schema do Gemini sempre que a recomendação depender da aceitação da loja.
- **Tratamento de Caixa com Virada de Cartão:** Se o mês atual já iniciou com déficit prévio, a IA não reprova compras quando a 1ª parcela só cai na fatura do mês seguinte (`impactoAtual <= 0`), informando com clareza o início do desembolso.
- **Consultor Financeiro Pessoal v2:** Histórico nativo de conversação por turnos com Gemini (`contents`), dados reais consolidados de caixa atual, projeção de 6 meses, compras parceladas ativas e cartões com virada de ciclo.
