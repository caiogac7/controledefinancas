const DEFAULT_SUPABASE_URL = 'https://ncpdgcxoziekwuralwzx.supabase.co';
const DEFAULT_SUPABASE_ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5jcGRnY3hvemlla3d1cmFsd3p4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTMwNzIzODAsImV4cCI6MjEwODY0ODM4MH0.sQ2fzs3rRbwVKjHrwa6wAP5mAugKtPIbOeSzbSpxD1Y';

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

    const rawUrl = String(process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || DEFAULT_SUPABASE_URL).trim();
    const mdMatch = rawUrl.match(/\((https?:\/\/[^)]+)\)/) || rawUrl.match(/(https?:\/\/[^\s\]"')]+)/);
    const SUPABASE_URL = (mdMatch && mdMatch[1] ? mdMatch[1] : rawUrl).replace(/\/+$/, '');
    const SUPABASE_KEY = String(process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || DEFAULT_SUPABASE_ANON).trim();

    const authHeader = req.headers.authorization || '';
    const jwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
    if (!jwt) {
        return res.status(401).json({ erro: 'Token de autenticação ausente' });
    }

    try {
        const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            headers: {
                'apikey': SUPABASE_KEY,
                'Authorization': `Bearer ${jwt}`
            }
        });
        if (!userRes.ok) {
            return res.status(401).json({ erro: 'Sessão inválida ou expirada' });
        }
        const user = await userRes.json();
        const userId = user?.id;
        if (!userId) {
            return res.status(401).json({ erro: 'Sessão inválida ou expirada' });
        }

        const bearer = process.env.SUPABASE_SERVICE_ROLE_KEY || jwt;
        const headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': `Bearer ${bearer}`,
            'Prefer': 'return=minimal'
        };

        // 1. Exclui registros das tabelas relacionais do usuário
        const tables = ['transactions', 'bank_statements', 'credit_bills', 'credit_cards', 'banks', 'categories'];
        await Promise.all([
            ...tables.map(t => fetch(`${SUPABASE_URL}/rest/v1/${t}?user_id=eq.${encodeURIComponent(userId)}`, { method: 'DELETE', headers })),
            fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}`, { method: 'DELETE', headers })
        ]);

        // 2. Exclui o usuário do Supabase Auth se a Service Role Key estiver configurada
        if (process.env.SUPABASE_SERVICE_ROLE_KEY) {
            const delUserRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${encodeURIComponent(userId)}`, {
                method: 'DELETE',
                headers: {
                    'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
                    'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`
                }
            });
            if (!delUserRes.ok) {
                console.error('Erro ao excluir auth.users:', await delUserRes.text().catch(() => ''));
            }
        }

        return res.status(200).json({ sucesso: true });
    } catch (error) {
        console.error('Erro ao excluir conta:', error);
        return res.status(500).json({ erro: 'Erro interno ao processar exclusão de conta' });
    }
};
