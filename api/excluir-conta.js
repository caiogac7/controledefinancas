const { createClient } = require('@supabase/supabase-js');

const DEFAULT_SUPABASE_URL = 'https://ncpdgcxoziekwuralwzx.supabase.co';

/**
 * POST /api/excluir-conta
 * Exclui todos os dados relacionais e a conta de autenticação (auth.users)
 * do usuário autenticado via Service Role Key no servidor (Conformidade LGPD & OWASP).
 */
module.exports = async function handler(req, res) {
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    if (req.method !== 'POST') {
        return res.status(405).json({ erro: 'Método não permitido' });
    }

    const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || DEFAULT_SUPABASE_URL;
    const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!SUPABASE_KEY) {
        return res.status(500).json({ erro: 'Configuração de servidor incompleta para exclusão de conta' });
    }

    const authHeader = req.headers.authorization || '';
    const jwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
    if (!jwt) {
        return res.status(401).json({ erro: 'Token de autenticação ausente' });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    try {
        const { data: authData, error: authError } = await supabase.auth.getUser(jwt);
        if (authError || !authData?.user) {
            return res.status(401).json({ erro: 'Sessão inválida ou expirada' });
        }

        const userId = authData.user.id;

        // 1. Exclui registros das tabelas relacionais do usuário
        await Promise.all([
            supabase.from('transactions').delete().eq('user_id', userId),
            supabase.from('bank_statements').delete().eq('user_id', userId),
            supabase.from('banks').delete().eq('user_id', userId),
            supabase.from('categories').delete().eq('user_id', userId),
            supabase.from('profiles').delete().eq('id', userId)
        ]);

        // 2. Exclui o usuário do Supabase Auth usando privilégio administrativo no back-end
        const { error: deleteUserError } = await supabase.auth.admin.deleteUser(userId);
        if (deleteUserError) {
            console.error('Erro ao excluir auth.users:', deleteUserError);
            return res.status(500).json({ erro: 'Dados removidos, mas houve falha ao encerrar credencial de acesso' });
        }

        return res.status(200).json({ sucesso: true });
    } catch (error) {
        console.error('Erro ao excluir conta:', error);
        return res.status(500).json({ erro: 'Erro interno ao processar exclusão de conta' });
    }
};
