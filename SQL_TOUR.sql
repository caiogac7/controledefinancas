-- =====================================================
-- ADICIONAR CAMPO tour_completed NA TABELA profiles
-- Execute no SQL Editor do Supabase
-- =====================================================

ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS tour_completed BOOLEAN DEFAULT FALSE;

-- Para resetar o tour de todos os usuários (re-exibir):
-- UPDATE public.profiles SET tour_completed = FALSE;

-- Para resetar o tour de um usuário específico:
-- UPDATE public.profiles SET tour_completed = FALSE WHERE id = 'UUID_DO_USUARIO';
