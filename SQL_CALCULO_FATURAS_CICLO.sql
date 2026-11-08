-- =========================================================================================
-- CONSULTA SQL ROBUSTA: CÁLCULO DINÂMICO DE FATURAS DE CARTÃO DE CRÉDITO
-- Banco de Dados: PostgreSQL / Supabase
-- Padrão de Fuso Horário: America/Sao_Paulo (Horário Oficial do Brasil)
-- Conformidade: Regras 1 (Ciclo & Parcelas), 2 (Status Faturas Antigas) e 3 (Abatimento)
-- =========================================================================================

-- Parâmetros da consulta:
-- :user_id      -> UUID do usuário (auth.uid())
-- :account_id   -> ID do cartão ou conta de crédito
-- :target_month -> Mês de competência alvo da fatura (formato 'YYYY-MM', ex: '2026-11')

WITH params AS (
    SELECT 
        '2026-11'::text AS target_month,
        'acc_credit_1'::text AS account_id,
        auth.uid() AS user_id
),

-- 1. Parâmetros do Cartão de Crédito (closing_day e due_day)
card_config AS (
    SELECT 
        c.id AS card_id,
        c.user_id,
        c.name AS card_name,
        COALESCE(c.closing_day, 25) AS closing_day,
        COALESCE(c.due_day, 5) AS due_day
    FROM public.credit_cards c, params p
    WHERE c.user_id = p.user_id 
      AND (c.id = p.account_id OR c.bank_id = p.account_id)
    LIMIT 1
),

-- 2. REGRA 1: Cálculo das Datas do Ciclo no Fuso Horário de São Paulo
-- Início: (closing_day + 1) do mês anterior
-- Fim: dia (closing_day) do mês alvo
cycle_dates AS (
    SELECT 
        p.target_month,
        c.card_id,
        c.card_name,
        c.closing_day,
        c.due_day,
        -- Mês anterior
        TO_CHAR((TO_DATE(p.target_month || '-01', 'YYYY-MM-DD') - INTERVAL '1 month'), 'YYYY-MM') AS prev_month,
        -- Data de Início do Ciclo
        (TO_DATE(TO_CHAR((TO_DATE(p.target_month || '-01', 'YYYY-MM-DD') - INTERVAL '1 month'), 'YYYY-MM') || '-' || 
            LPAD(LEAST(c.closing_day + 1, 28)::text, 2, '0'), 'YYYY-MM-DD'))::date AS start_cycle_date,
        -- Data de Fim do Ciclo (Dia do Fechamento)
        (TO_DATE(p.target_month || '-' || LPAD(c.closing_day::text, 2, '0'), 'YYYY-MM-DD'))::date AS end_cycle_date,
        -- Data de Vencimento da Fatura
        (TO_DATE(p.target_month || '-' || LPAD(c.due_day::text, 2, '0'), 'YYYY-MM-DD'))::date AS due_date,
        -- Data Atual em São Paulo
        (NOW() AT TIME ZONE 'America/Sao_Paulo')::date AS today_sp
    FROM params p
    CROSS JOIN card_config c
),

-- 3. Transações de Despesa do Cartão (Compras à vista no ciclo + Parcelas por competência)
card_transactions AS (
    SELECT 
        t.id,
        t.amount,
        t.type,
        t.desc,
        t.date::date AS purchase_date,
        t.credit_card_metadata,
        -- Verifica se é parcelado
        COALESCE((t.credit_card_metadata->>'totalInstallments')::int, 1) > 1 OR t.inst LIKE '%/%' AS is_installment,
        -- Competência da parcela
        COALESCE(t.credit_card_metadata->>'billForecastDate', t.month) AS competence_month
    FROM public.transactions t, cycle_dates cd, params p
    WHERE t.user_id = p.user_id
      AND (t.account_id = cd.card_id OR t.card_id = cd.card_id OR t.bank_id = cd.card_id)
      AND t.type = 'expense'
),

-- Soma do Total Bruto da Fatura (Regra 1)
invoice_gross_total AS (
    SELECT 
        COALESCE(SUM(
            CASE 
                -- REGRA 1 (Parcelas): Competência exatamente igual ao target_month
                WHEN ct.is_installment AND ct.competence_month = cd.target_month 
                    THEN ct.amount
                -- REGRA 1 (À Vista): Data de compra dentro do ciclo (start_cycle_date até end_cycle_date)
                WHEN NOT ct.is_installment AND ct.purchase_date >= cd.start_cycle_date AND ct.purchase_date <= cd.end_cycle_date 
                    THEN ct.amount
                ELSE 0
            END
        ), 0) AS total_invoice_amount
    FROM card_transactions ct
    CROSS JOIN cycle_dates cd
),

-- 4. REGRA 3: Identificação e Soma de Pagamentos de Fatura na Conta Corrente
bank_payments AS (
    SELECT 
        COALESCE(SUM(ABS(t.amount)), 0) AS total_payments_amount
    FROM public.transactions t, params p
    WHERE t.user_id = p.user_id
      AND (t.account_type = 'BANK' OR t.is_credit_card_tx = false)
      AND t.month = p.target_month
      AND (t.desc ILIKE '%pagamento%fatura%' OR t.desc ILIKE '%pgto%fatura%')
)

-- 5. RESULTADO CONSOLIDADO: Total, Pagamentos, Saldo Pendente e Status Corrigido
SELECT 
    cd.card_id AS account_id,
    cd.card_name,
    cd.target_month,
    cd.start_cycle_date,
    cd.end_cycle_date,
    cd.due_date,
    igt.total_invoice_amount AS total_amount,
    bp.total_payments_amount AS paid_amount,
    -- Saldo Pendente = Total da Fatura - Soma dos Pagamentos (sem ficar negativo)
    GREATEST(0, (igt.total_invoice_amount - bp.total_payments_amount)) AS pending_balance,
    -- REGRA 2 & 3: Definição Rigorosa do Status da Fatura
    CASE 
        -- Regra 3: Se saldo pendente zerou -> PAID
        WHEN GREATEST(0, (igt.total_invoice_amount - bp.total_payments_amount)) <= 0.009 THEN 'PAID'
        -- Regra 2: Faturas vencidas são forçadas para PAID
        WHEN cd.today_sp > cd.due_date THEN 'PAID'
        -- Fatura em aberto dentro do prazo
        ELSE 'OPEN'
    END AS status,
    cd.today_sp AS calculated_at
FROM cycle_dates cd
CROSS JOIN invoice_gross_total igt
CROSS JOIN bank_payments bp;

