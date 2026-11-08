-- =========================================================================================
-- CORREÇÃO DEFINITIVA DE TODAS AS POLÍTICAS (SELECT, INSERT, UPDATE, DELETE) DE account_links
-- Execute este script no SQL Editor do painel do Supabase
-- =========================================================================================

-- 1. Garante que RLS está habilitado
ALTER TABLE public.account_links ENABLE ROW LEVEL SECURITY;

-- 2. Remove políticas antigas
DROP POLICY IF EXISTS "allow_owners_and_members" ON public.account_links;
DROP POLICY IF EXISTS "users_view_or_manage_account_links" ON public.account_links;
DROP POLICY IF EXISTS "account_links_select" ON public.account_links;
DROP POLICY IF EXISTS "account_links_insert" ON public.account_links;
DROP POLICY IF EXISTS "account_links_update" ON public.account_links;
DROP POLICY IF EXISTS "account_links_delete" ON public.account_links;

-- 3. POLÍTICA DE LEITURA (SELECT): Dono ou Convidado (por ID ou E-mail)
CREATE POLICY "account_links_select"
    ON public.account_links
    FOR SELECT
    TO authenticated
    USING (
        auth.uid() = owner_id
        OR auth.uid() = member_id
        OR LOWER(member_email) = LOWER(COALESCE(auth.jwt() ->> 'email', ''))
    );

-- 4. POLÍTICA DE CRIAÇÃO (INSERT): Usuário autenticado enviando convite
CREATE POLICY "account_links_insert"
    ON public.account_links
    FOR INSERT
    TO authenticated
    WITH CHECK (
        auth.uid() = owner_id
    );

-- 5. POLÍTICA DE ATUALIZAÇÃO (UPDATE): Permite que tanto o Dono quanto o Membro atualizem o status
CREATE POLICY "account_links_update"
    ON public.account_links
    FOR UPDATE
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

-- 6. POLÍTICA DE EXCLUSÃO (DELETE - DESCONECTAR DEFINITIVAMENTE):
-- Permite que TANTO o dono do convite QUANTO o membro convidado possam DESCONECTAR e APAGAR o vínculo do banco!
CREATE POLICY "account_links_delete"
    ON public.account_links
    FOR DELETE
    TO authenticated
    USING (
        auth.uid() = owner_id
        OR auth.uid() = member_id
        OR LOWER(member_email) = LOWER(COALESCE(auth.jwt() ->> 'email', ''))
    );

-- 7. COMANDO PARA LIMPAR/ZERAR MANUALMENTE TODOS OS VÍNCULOS AGORA (SE DESEJAR):
-- DELETE FROM public.account_links;

-- 8. Visualiza os vínculos existentes atualmente:
SELECT id, owner_name, owner_email, member_name, member_email, status, created_at 
FROM public.account_links 
ORDER BY created_at DESC;
