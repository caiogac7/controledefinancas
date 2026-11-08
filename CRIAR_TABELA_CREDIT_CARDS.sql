-- =========================================================================================
-- SCRIPT DE CRIAÇÃO DA TABELA DE CARTÕES DE CRÉDITO (public.credit_cards)
-- Executar no SQL Editor do Supabase (100% Idempotente e Seguro para Produção)
-- Padrão de Fuso Horário: America/Sao_Paulo | RLS e OWASP Top 10 Conformes
-- =========================================================================================

SET timezone = 'America/Sao_Paulo';

-- 1. TABELA public.credit_cards (VINCULADA A PROFILES E A BANKS)
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

-- 2. HABILITAR ROW LEVEL SECURITY (RLS)
ALTER TABLE public.credit_cards ENABLE ROW LEVEL SECURITY;

-- 3. POLÍTICA DE SEGURANÇA: USUÁRIO SÓ ACESSA SEUS PRÓPRIOS CARTÕES (OWASP A01)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'credit_cards' 
        AND policyname = 'users_manage_own_credit_cards'
    ) THEN
        CREATE POLICY "users_manage_own_credit_cards" 
        ON public.credit_cards 
        FOR ALL 
        USING (auth.uid() = user_id) 
        WITH CHECK (auth.uid() = user_id);
    END IF;
END $$;

-- 4. ÍNDICES DE PERFORMANCE
CREATE INDEX IF NOT EXISTS idx_credit_cards_user_id ON public.credit_cards(user_id);
CREATE INDEX IF NOT EXISTS idx_credit_cards_bank_id ON public.credit_cards(user_id, bank_id);

-- 5. CONFIRMAÇÃO DE STATUS
SELECT 'Tabela public.credit_cards e politicas RLS criadas com sucesso!' AS status;
