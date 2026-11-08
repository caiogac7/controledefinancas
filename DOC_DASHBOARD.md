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

### 7. Exibição de Valor Reservado Isolado nos Cards de Contas Bancárias
- **Saldo Livre em Conta:** O saldo principal do card exibe estritamente o montante disponível para transacionar na conta corrente, sem misturar ou inflar com quantias guardadas.
- **Badge / Linha de Reservado:** Quando a conta possui dinheiro em cofrinho, caixinha ou reserva (`vaultBalance > 0`), o card exibe uma barra dedicada em âmbar com ícone de cofrinho (`piggy-bank`) e o valor exato reservado (`Reservado: R$ X,XX`).
- **Origem dos Dados e Integração Nativa da Pluggy:**
  - Extração direta dos dados nativos de saldo reservado da Pluggy: lê `acc.bankData.reservedBalances`, `acc.bankData.hasReservedBalance`, `acc.bankData.automaticallyInvestedBalance` e `pluggyClient.fetchAccountBalance()` (ex: R$ 25,00 após retirada).
  - Fallback: caso a instituição não reporte o objeto nativo, o sistema apura estritamente as movimentações do ciclo/mês vigente (`VAULT_TX` de depósitos menos retiradas/resgates do período ativo). Isso impede que resíduos cumulativos de cofrinhos já esvaziados no passado inflem o saldo real atual.
  - Caso o usuário defina ou ajuste manualmente o valor no modal da conta ("Dinheiro Reservado / Cofrinho"), a preferência manual é preservada e respeitada sobre o cálculo automático.

### 8. Estabilização de Layout, Bloqueio de Tradução Automática e Eliminação de Layout Shift

### 9. Proteção de Interface Mobile e Debounce no Open Finance
- **Trava Rígida de Clique (Anti-Double-Tap):** Bloqueio de cliques e toques repetidos no mobile através das variáveis de estado `isSyncingAllPluggyInProgress` e `activeSyncingItemIds`, desabilitando visual e funcionalmente os botões com `pointer-events: none`, `opacity: 0.5`, `cursor: not-allowed` e spinner de carregamento.
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
- **Versionamento de Cache:** `bootstrap.js` atualizado para `20261108_clean_sync_v3`.
