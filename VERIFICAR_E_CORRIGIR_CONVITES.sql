-- =========================================================================================
-- DIAGNÓSTICO E CRIAÇÃO DEFINITIVA DA TABELA account_links (CONTAS INTEGRADAS)
-- Execute no SQL Editor do Supabase (100% Idempotente e sem bloqueios)
-- =========================================================================================

-- 1. CONSULTA PARA VOCÊ VER SE O CONVITE ESTÁ GRAVADO NO BANCO:
-- SELECT * FROM public.account_links;

-- 2. CRIAÇÃO OU ATUALIZAÇÃO DA TABELA account_links
CREATE TABLE IF NOT EXISTS public.account_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    owner_name TEXT,
    owner_email TEXT NOT NULL,
    member_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    member_name TEXT,
    member_email TEXT NOT NULL,
    relationship TEXT NOT NULL DEFAULT 'Cônjuge / Familiar',
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending' | 'accepted' | 'rejected' | 'revoked'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMPTZ,
    UNIQUE(owner_id, member_email)
);

-- 3. HABILITA RLS (SEGURANÇA)
ALTER TABLE public.account_links ENABLE ROW LEVEL SECURITY;

-- 4. DROPA POLÍTICAS ANTIGAS QUE PODIAM ESTAR BLOQUEANDO O CONVITE DE APARECER
DROP POLICY IF EXISTS "users_view_or_manage_account_links" ON public.account_links;
DROP POLICY IF EXISTS "allow_all_account_links_for_authenticated" ON public.account_links;
DROP POLICY IF EXISTS "allow_owners_and_members" ON public.account_links;

-- 5. POLÍTICA PERFEITA: 
-- Permite que o dono crie/leia/atualize SEUS convites,
-- E permite que o convidado LEIA e ATUALIZE os convites destinados ao seu e-mail ou ao seu ID!
CREATE POLICY "allow_owners_and_members"
    ON public.account_links
    FOR ALL
    TO authenticated
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

-- 6. ÍNDICES DE BUSCA RÁPIDA
CREATE INDEX IF NOT EXISTS idx_account_links_owner_id ON public.account_links(owner_id);
CREATE INDEX IF NOT EXISTS idx_account_links_member_id ON public.account_links(member_id);
CREATE INDEX IF NOT EXISTS idx_account_links_member_email_lower ON public.account_links(LOWER(member_email));

-- 7. CONSULTA PARA CONFERÊNCIA IMEDIATA (RODE APÓS ENVIAR O CONVITE):
SELECT 
    id,
    owner_name,
    owner_email,
    member_email,
    relationship,
    status,
    created_at
FROM public.account_links
ORDER BY created_at DESC;
