-- =========================================================================================
-- BANCO DE DADOS CONSOLIDADO: ESTRUTURA, RELACIONAMENTOS (FKs), AUDITORIA E ÍNDICES
-- Executar no SQL Editor do Supabase (100% Idempotente - Seguro para rodar em produção)
-- Padrão de Fuso Horário: America/Sao_Paulo | Criptografia & RLS: OWASP Top 10
-- =========================================================================================

-- 1. FUSO HORÁRIO PADRÃO
SET timezone = 'America/Sao_Paulo';

-- 2. TABELA public.profiles (EXTENSÃO DA TABELA auth.users DO SUPABASE)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT DEFAULT '',
    photo TEXT DEFAULT '',
    terms_accepted BOOLEAN DEFAULT FALSE,
    terms_accepted_at TIMESTAMPTZ,
    terms_version TEXT DEFAULT '2026-10',
    tour_completed BOOLEAN DEFAULT FALSE,
    sharing_enabled BOOLEAN DEFAULT FALSE,
    transactions_json JSONB DEFAULT '[]'::jsonb,
    settings_json JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'profiles' AND policyname = 'users_manage_own_profile') THEN
        CREATE POLICY "users_manage_own_profile" ON public.profiles FOR ALL USING (auth.uid() = id) WITH CHECK (auth.uid() = id);
    END IF;
END $$;

-- 3. TABELA public.banks (CONTAS BANCÁRIAS E CARTEIRAS COM FK PARA PROFILES)
CREATE TABLE IF NOT EXISTS public.banks (
    id TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    emoji TEXT DEFAULT '🏦',
    type TEXT DEFAULT 'Conta Corrente',
    initial_balance NUMERIC(15,2) DEFAULT 0,
    initial_balance_date DATE DEFAULT CURRENT_DATE,
    include_in_total BOOLEAN DEFAULT TRUE,
    pluggy_item_id TEXT,
    pluggy_account_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, id)
);

ALTER TABLE public.banks ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'banks' AND policyname = 'users_manage_own_banks') THEN
        CREATE POLICY "users_manage_own_banks" ON public.banks FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_banks_user_id ON public.banks(user_id);

-- 3.1 TABELA public.credit_cards (CARTÕES DE CRÉDITO VINCULADOS A BANCOS E A PROFILES)
CREATE TABLE IF NOT EXISTS public.credit_cards (
    id TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    bank_id TEXT,
    name TEXT NOT NULL,
    closing_day INTEGER NOT NULL CHECK (closing_day >= 1 AND closing_day <= 31),
    due_day INTEGER NOT NULL CHECK (due_day >= 1 AND due_day <= 31),
    color TEXT DEFAULT '#4f46e5',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, id)
);

ALTER TABLE public.credit_cards ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'credit_cards' AND policyname = 'users_manage_own_credit_cards') THEN
        CREATE POLICY "users_manage_own_credit_cards" ON public.credit_cards FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_credit_cards_user_id ON public.credit_cards(user_id);
CREATE INDEX IF NOT EXISTS idx_credit_cards_bank_id ON public.credit_cards(user_id, bank_id);

-- 4. TABELA public.categories (CATEGORIAS DE RECEITAS E DESPESAS COM FK PARA PROFILES)
CREATE TABLE IF NOT EXISTS public.categories (
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    emoji TEXT DEFAULT '🏷️',
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, name)
);

ALTER TABLE public.categories ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'categories' AND policyname = 'users_manage_own_categories') THEN
        CREATE POLICY "users_manage_own_categories" ON public.categories FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
    END IF;
END $$;

-- 5. TABELA public.transactions (LANÇAMENTOS, PARCELAS E AJUSTES DE REGIME DE CAIXA)
CREATE TABLE IF NOT EXISTS public.transactions (
    id BIGINT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    month VARCHAR(7) NOT NULL, -- Ex: '2026-11'
    day INTEGER NOT NULL CHECK (day >= 1 AND day <= 31),
    type VARCHAR(10) NOT NULL CHECK (type IN ('income', 'expense')),
    description TEXT NOT NULL,
    amount NUMERIC(15,2) NOT NULL CHECK (amount >= 0),
    category TEXT DEFAULT 'Compras',
    installment TEXT DEFAULT 'Fixa', -- 'Fixa', 'Única' ou 'X/Y'
    bank_id TEXT DEFAULT 'bank_geral',
    card_id TEXT DEFAULT '',
    fitid TEXT DEFAULT '',
    transaction_date DATE,
    paid BOOLEAN DEFAULT FALSE,
    paid_at TIMESTAMPTZ, -- Data e horário real de quitação (Regime de Caixa)
    reconciled_with_statement BOOLEAN DEFAULT FALSE,
    reconciled_fitid TEXT, -- Fitid da movimentação real de extrato bancário conciliada
    series_id TEXT, -- ID de correlação entre parcelas da mesma compra
    alignment_batch_id TEXT, -- ID de lote de alinhamento reversível
    entry_kind VARCHAR(30) DEFAULT 'regular', -- 'regular' | 'initial_balance' | 'balance_adjustment' | 'open_finance'
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.transactions
    ADD COLUMN IF NOT EXISTS transaction_date DATE,
    ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reconciled_fitid TEXT,
    ADD COLUMN IF NOT EXISTS series_id TEXT,
    ADD COLUMN IF NOT EXISTS alignment_batch_id TEXT,
    ADD COLUMN IF NOT EXISTS entry_kind VARCHAR(30) DEFAULT 'regular',
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'transactions' AND policyname = 'users_manage_own_transactions') THEN
        CREATE POLICY "users_manage_own_transactions" ON public.transactions FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
    END IF;
END $$;

-- Índices de Alta Performance: Busca Cronológica, Regime de Caixa e Correlação
CREATE INDEX IF NOT EXISTS idx_transactions_user_cash ON public.transactions(user_id, paid, paid_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_user_month_day ON public.transactions(user_id, month, day);
CREATE INDEX IF NOT EXISTS idx_transactions_user_bank ON public.transactions(user_id, bank_id);
CREATE INDEX IF NOT EXISTS idx_transactions_user_series ON public.transactions(user_id, series_id);
CREATE INDEX IF NOT EXISTS idx_transactions_align_batch ON public.transactions(user_id, alignment_batch_id);

-- 6. TABELA public.bank_statements (EXTRATOS BANCÁRIOS IMPORTADOS .OFX / .CSV)
CREATE TABLE IF NOT EXISTS public.bank_statements (
    id BIGINT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    bank_id TEXT NOT NULL DEFAULT 'bank_geral',
    fitid TEXT DEFAULT '',
    month VARCHAR(7) NOT NULL,
    day INTEGER NOT NULL,
    type VARCHAR(10) NOT NULL CHECK (type IN ('income', 'expense')),
    description TEXT NOT NULL,
    amount NUMERIC(15,2) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.bank_statements ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'bank_statements' AND policyname = 'users_manage_own_statements') THEN
        CREATE POLICY "users_manage_own_statements" ON public.bank_statements FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_bank_statements_user_month ON public.bank_statements(user_id, month);

-- 7. TABELA public.balance_audits (LOG IMUTÁVEL DE AUDITORIA E REVERSÃO DE SALDOS)
CREATE TABLE IF NOT EXISTS public.balance_audits (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    bank_id TEXT NOT NULL,
    bank_name TEXT NOT NULL,
    month_ref VARCHAR(7) DEFAULT '2026-11',
    audit_month VARCHAR(7) DEFAULT '2026-11',
    calculated_balance NUMERIC(15,2) NOT NULL DEFAULT 0,
    informed_real_balance NUMERIC(15,2) NOT NULL DEFAULT 0,
    difference_amount NUMERIC(15,2) NOT NULL DEFAULT 0,
    adjustment_diff NUMERIC(15,2) NOT NULL DEFAULT 0,
    adjustment_tx_id BIGINT,
    batch_id TEXT,
    action_type VARCHAR(30) NOT NULL DEFAULT 'manual_align', -- 'manual_align' | 'revert' | 'ofx_balance' | 'cleanup'
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.balance_audits
    ADD COLUMN IF NOT EXISTS audit_month VARCHAR(7) DEFAULT '2026-11',
    ADD COLUMN IF NOT EXISTS month_ref VARCHAR(7) DEFAULT '2026-11',
    ADD COLUMN IF NOT EXISTS adjustment_diff NUMERIC(15,2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS difference_amount NUMERIC(15,2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS batch_id TEXT,
    ADD COLUMN IF NOT EXISTS notes TEXT;

ALTER TABLE public.balance_audits ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'balance_audits' AND policyname = 'users_manage_own_balance_audits') THEN
        CREATE POLICY "users_manage_own_balance_audits" ON public.balance_audits FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_balance_audits_user_date ON public.balance_audits(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_balance_audits_batch ON public.balance_audits(user_id, batch_id);

-- 8. TABELA public.account_links (INTEGRAÇÃO FAMILIAR: CONVITES E VISÃO CONJUNTA)
CREATE TABLE IF NOT EXISTS public.account_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    owner_name TEXT,
    owner_email TEXT NOT NULL,
    member_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    member_name TEXT,
    member_email TEXT NOT NULL,
    relationship TEXT NOT NULL DEFAULT 'Cônjuge / Familiar',
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending' | 'accepted' | 'rejected' | 'revoked'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMPTZ,
    UNIQUE(owner_id, member_email)
);

ALTER TABLE public.account_links ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'account_links' AND policyname = 'users_view_or_manage_account_links') THEN
        CREATE POLICY "users_view_or_manage_account_links"
            ON public.account_links
            FOR ALL
            USING (
                auth.uid() = owner_id
                OR auth.uid() = member_id
                OR LOWER(member_email) = LOWER(COALESCE(auth.jwt() ->> 'email', ''))
            )
            WITH CHECK (
                auth.uid() = owner_id
                OR auth.uid() = member_id
                OR LOWER(member_email) = LOWER(COALESCE(auth.jwt() ->> 'email', ''))
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_account_links_owner ON public.account_links(owner_id);
CREATE INDEX IF NOT EXISTS idx_account_links_member_email ON public.account_links(LOWER(member_email));

-- 9. POLÍTICA DE LEITURA COMPARTILHADA (FAMÍLIA COM CONVITE ACEITO)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'profiles' AND policyname = 'shared_accounts_read_profiles') THEN
        CREATE POLICY "shared_accounts_read_profiles"
            ON public.profiles
            FOR SELECT
            USING (
                auth.uid() = id
                OR EXISTS (
                    SELECT 1 FROM public.account_links al
                    WHERE al.status = 'accepted'
                      AND (
                          (al.owner_id = auth.uid() AND al.member_id = profiles.id)
                          OR (al.member_id = auth.uid() AND al.owner_id = profiles.id)
                      )
                )
            );
    END IF;
END $$;
