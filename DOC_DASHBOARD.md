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
