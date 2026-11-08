-- =============================================================================
-- MIGRAÇÃO: PERSISTÊNCIA FIXA + CLASSIFICADOR DE 5 DIMENSÕES + MOTOR DE CICLO (DATA DE VIRADA)
-- Execute este script no SQL Editor do Supabase para criar/ajustar as colunas
-- fixas e chaves únicas de Upsert sem perder nenhum dado existente.
-- =============================================================================

BEGIN;

-- 1. TABELA DE CARTÕES DE CRÉDITO (Garante colunas oficiais de Data de Virada e Vencimento)
ALTER TABLE public.credit_cards
    ADD COLUMN IF NOT EXISTS closing_day INTEGER NOT NULL DEFAULT 2,
    ADD COLUMN IF NOT EXISTS due_day INTEGER NOT NULL DEFAULT 7,
    ADD COLUMN IF NOT EXISTS pluggy_account_id TEXT;

-- 2. TABELA DE FATURAS CONSOLIDADAS FIXAS (public.credit_bills)
CREATE TABLE IF NOT EXISTS public.credit_bills (
    id TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    bank_id TEXT,
    card_id TEXT,
    card_name TEXT,
    month TEXT NOT NULL,
    due_date TEXT,
    closing_date TEXT,
    closing_day INTEGER DEFAULT 2,
    due_day INTEGER DEFAULT 7,
    total_amount NUMERIC(15, 2) NOT NULL DEFAULT 0,
    paid_amount NUMERIC(15, 2) NOT NULL DEFAULT 0,
    pending_amount NUMERIC(15, 2) NOT NULL DEFAULT 0,
    advance_paid_amount NUMERIC(15, 2) NOT NULL DEFAULT 0,
    in_cycle_refunds NUMERIC(15, 2) NOT NULL DEFAULT 0,
    post_closing_refunds NUMERIC(15, 2) NOT NULL DEFAULT 0,
    minimum_payment_amount NUMERIC(15, 2),
    status TEXT NOT NULL DEFAULT 'OPEN',
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_credit_bills_user_account_month UNIQUE (user_id, account_id, month)
);

ALTER TABLE public.credit_bills
    ADD COLUMN IF NOT EXISTS closing_day INTEGER DEFAULT 2,
    ADD COLUMN IF NOT EXISTS due_day INTEGER DEFAULT 7,
    ADD COLUMN IF NOT EXISTS advance_paid_amount NUMERIC(15, 2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS in_cycle_refunds NUMERIC(15, 2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS post_closing_refunds NUMERIC(15, 2) DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_credit_bills_user_month
    ON public.credit_bills (user_id, month);

ALTER TABLE public.credit_bills ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Usuarios gerenciam proprias faturas credit_bills" ON public.credit_bills;
CREATE POLICY "Usuarios gerenciam proprias faturas credit_bills"
    ON public.credit_bills
    FOR ALL
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- 3. COLUNAS FIXAS DE PERSISTÊNCIA EM public.transactions
ALTER TABLE public.transactions
    ADD COLUMN IF NOT EXISTS total_amount NUMERIC(15, 2),
    ADD COLUMN IF NOT EXISTS paid_amount NUMERIC(15, 2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pending_amount NUMERIC(15, 2),
    ADD COLUMN IF NOT EXISTS bill_status TEXT,
    ADD COLUMN IF NOT EXISTS closing_day INTEGER,
    ADD COLUMN IF NOT EXISTS due_day INTEGER,
    ADD COLUMN IF NOT EXISTS tx_group TEXT,
    ADD COLUMN IF NOT EXISTS show_on_home BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS is_consolidated_bill BOOLEAN DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_transactions_user_fitid
    ON public.transactions (user_id, fitid);

-- 4. COLUNAS DE CLASSIFICAÇÃO 5 DIMENSÕES E CICLO EM public.bank_statements
ALTER TABLE public.bank_statements
    ADD COLUMN IF NOT EXISTS tx_group TEXT,
    ADD COLUMN IF NOT EXISTS show_on_home BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS account_type TEXT,
    ADD COLUMN IF NOT EXISTS is_credit_card_tx BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS pluggy_category TEXT,
    ADD COLUMN IF NOT EXISTS cycle_month TEXT,
    ADD COLUMN IF NOT EXISTS settlement_phase TEXT,
    ADD COLUMN IF NOT EXISTS closing_day_used INTEGER,
    ADD COLUMN IF NOT EXISTS due_day_used INTEGER,
    ADD COLUMN IF NOT EXISTS is_synthetic_gap_fill BOOLEAN DEFAULT FALSE;

-- Remove eventuais duplicatas antigas de fitid antes de criar o índice único de Upsert
DELETE FROM public.bank_statements a
USING public.bank_statements b
WHERE a.user_id = b.user_id
  AND a.fitid IS NOT NULL
  AND a.fitid <> ''
  AND a.fitid = b.fitid
  AND a.id < b.id;

CREATE UNIQUE INDEX IF NOT EXISTS idx_bank_statements_user_fitid_unique
    ON public.bank_statements (user_id, fitid)
    WHERE fitid IS NOT NULL AND fitid <> '';

-- 5. COLUNA FIXA DE SALDO DO COFRE E CONFIGURAÇÃO DE CARTÃO EM public.banks
ALTER TABLE public.banks
    ADD COLUMN IF NOT EXISTS vault_balance NUMERIC(15, 2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pluggy_direct_balance NUMERIC(15, 2),
    ADD COLUMN IF NOT EXISTS has_card BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS card_name TEXT,
    ADD COLUMN IF NOT EXISTS card_closing_day INTEGER,
    ADD COLUMN IF NOT EXISTS card_due_day INTEGER;

COMMIT;

-- =============================================================================
-- CONSULTAS SQL (SELECT) PARA AUDITORIA DAS DESPESAS DE DEZEMBRO (2026-12)
-- =============================================================================

-- A) VISÃO MENSAL DE DEZEMBRO (Despesas Planejadas + Fatura Consolidada do Cartão):
SELECT
    t.id,
    t.month AS mes_competencia,
    t.day AS dia_vencimento,
    t.description AS descricao,
    t.category AS categoria,
    t.installment AS parcela_ou_tipo,
    COALESCE(t.total_amount, t.amount) AS valor_total_despesa,
    COALESCE(t.paid_amount, CASE WHEN t.paid THEN t.amount ELSE 0 END) AS valor_ja_pago,
    COALESCE(t.pending_amount, CASE WHEN t.paid THEN 0 ELSE t.amount END) AS valor_pendente,
    t.paid AS quitada,
    t.is_consolidated_bill AS eh_fatura_cartao,
    t.bank_id
FROM public.transactions t
WHERE t.month = '2026-12'
  AND t.type = 'expense'
ORDER BY t.day ASC, t.id ASC;

-- B) DETALHAMENTO ANALÍTICO DE TODAS AS COMPRAS E PARCELAS DO CARTÃO NA FATURA DE DEZEMBRO (2026-12):
SELECT
    bs.id,
    bs.month AS ciclo_fatura,
    bs.day AS dia_compra,
    bs.description AS estabelecimento_parcela,
    bs.amount AS valor_parcela,
    bs.pluggy_category AS categoria,
    bs.tx_group AS grupo_5_dimensoes,
    bs.fitid
FROM public.bank_statements bs
WHERE bs.month = '2026-12'
  AND bs.type = 'expense'
  AND (bs.is_credit_card_tx = TRUE OR bs.account_type = 'CREDIT' OR bs.tx_group = 'CARD_EXPENSE')
ORDER BY bs.day ASC, bs.description ASC;

