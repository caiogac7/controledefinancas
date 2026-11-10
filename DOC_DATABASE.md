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
| 08/11/2026 | `bank_statements` | Remoção de 5.685 parcelas sintéticas duplicadas e alinhamento do `onConflict` para `(user_id, bank_id, fitid)` com desduplicação em memória (`Map`) em lotes de 100. | Eliminar erro PostgreSQL `21000: ON CONFLICT DO UPDATE command cannot affect row a second time` e falha de constraint única. |
| 08/11/2026 | `credit_bills` / `transactions` | Recálculo das faturas futuras do Itaú Extra Mastercard Gold (Dez/2026 normalizada de R$ 14.162,71 para R$ 3.417,21) e sincronização do `settings_json`. | Restaurar integridade contábil das faturas e parcelamentos da Elisangela sem duplicações fantasmas. |
| 08/11/2026 | `profiles` | Criação da coluna `role TEXT DEFAULT 'user'` com nível `admin` para contas autorizadas. | Implementação de RBAC nativo para auditorias de sistema e controles administrativos seguros. |
| 08/11/2026 | `audit_and_recalculate_system` | Stored Procedure PL/pgSQL (`SECURITY DEFINER`) para higienização, recálculo e alinhamento contábil (individual e em massa). | Permitir auditoria e correção em milissegundos sem tráfego de rede ou risco de alucinação. |
| 08/11/2026 | `cron.job` (`pg_cron`) | Agendamento diário da rotina `auto_ajuste_diario_saldos_faturas` às 03:15 da manhã. | Manutenção preventiva e auto-correção contínua da integridade de dados de todos os clientes. |
| 08/11/2026 | `system_audit_logs` | Criação da tabela de auditoria com RLS e registro de data/hora, executor, total de faturas recalculadas e sintéticas expurgadas. | Rastreabilidade total, auditoria contábil e exibição do status ao vivo no modal de alinhamento. |
| 08/11/2026 | `system_audit_items` / `rollback_audit_item` | Criação da tabela granular de itens de auditoria e função RPC `rollback_audit_item` com snapshot completo do estado anterior. | Rastreabilidade milimétrica de alterações por cliente/cartão/mês com reversão cirúrgica de faturas com 1 clique. |
| 08/11/2026 | `bank_statements` | Correção do mês contábil da tarifa de uso do limite emergencial Mercado Pago (`id: 1794048770108`) de `2026-12` para `2026-11` conforme `billForecastDate: 2026-11` e `billPostDate: 2026-11-02`. | Corrigir divergência contábil de R$ 14,90 entre as faturas de Novembro e Dezembro/2026 do Cartão Mercado Pago. |
| 08/11/2026 | `transactions` | Adição das colunas `original_amount numeric(15,2)` e `reconciled_at timestamptz`. | Armazenar o valor planejado original para viabilizar rateio proporcional em extrato e reversão perfeita a qualquer momento. |
| 08/11/2026 | `reconcile_transactions_batch` / `undo_reconciliation_batch` | Stored Procedures transacionais ACID no PostgreSQL para quitação, conciliação e desconciliação ultra-rápidas (<30ms). | Eliminar lentidão e travamentos por upload de JSON pesado e proteger integridade contra mudança de aba/tela. |
| 10/11/2026 | `bank_statements` | Adição das colunas `bill_forecast_date (varchar(7))` e `is_advance_payment (boolean default false)`, vinculando adiantamentos pré-fechamento (`operationType = 'PAGAMENTO_FATURA'`) à competência da fatura e preenchendo o `bill_id`. | Garantir apuração contábil exata da fatura de cartão abatendo pagamentos antecipados (ex: R$ 15,00 + R$ 50,00 = R$ 65,00 em Nov/2026). |



