# Documentação de Banco de Dados - Controle Financeiro

## Log de Alterações e Integridade de Dados

| Data | Tabela | Mudança | Motivo |
| :--- | :--- | :--- | :--- |
| 08/11/2026 | `credit_bills` | Travamento da fatura de Nov/2026 do Cartão Mercado Pago (`d7900258`) em `total_amount = 2936.43`, `paid_amount = 2936.43`, `pending_amount = 0.00`, `status = 'PAID'`. | Eliminar discrepâncias pós-feriado de Finados (compra da Raia Drogasil em 03/11/2026 e compensação dos 5 pagamentos oficiais) garantindo quitação integral. |
| 08/11/2026 | `transactions` | Atualização da linha sintética da fatura de Nov/2026 (`fitid: pluggy_bill_d7900258-13c6-41db-a696-a4d15fb131f9_2026-11`) para `amount = 2936.43`, `total_amount = 2936.43`, `paid_amount = 2936.43`, `pending_amount = 0.00`, `bill_status = 'PAID'`, `paid = true`. | Sincronia determinística bidirecional entre tabela relacional `credit_bills` e lançamentos consolidados em `transactions`. |
| 08/11/2026 | `transactions` | Implementação de suporte a alteração de carteira em massa para contratos parcelados e lançamentos planejados. | Permitir migração em lote de lançamentos e séries de parcelas para novas carteiras físicas ou contas bancárias. |
| 08/11/2026 | `transactions` | Criação dos índices `idx_transactions_user_month (user_id, month)` e `idx_transactions_user_bill_id (user_id, bill_id)`. | Otimização de tempo de resposta em filtros mensais e agregação de transações de faturas. |
| 08/11/2026 | `credit_bills` | Criação do índice `idx_credit_bills_user_month (user_id, month)`. | Aceleração de consultas e leitura de faturas mensais persistidas. |
| 08/11/2026 | `bank_statements` | Criação do índice `idx_bank_statements_user_bank (user_id, bank_id)`. | Otimização de busca e reconciliação bancária por instituição. |
| 08/11/2026 | `banks` / `profiles` | Atualização do `vault_balance` da conta Mercado Pago (`2350304a`) para R$ 25,00 exatos e padronização CommonJS de endpoints serverless. | Refletir o saldo reservado real reportado pela Pluggy no Open Finance após a retirada recente e destravar sync na Vercel. |

