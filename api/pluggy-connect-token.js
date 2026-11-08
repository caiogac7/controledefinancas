import { createClient } from '@supabase/supabase-js';
import { PluggyClient } from 'pluggy-sdk';

const DEFAULT_SUPABASE_URL = 'https://ncpdgcxoziekwuralwzx.supabase.co';

/**
 * POST /api/pluggy-connect-token
 * Autentica o usuário via JWT do Supabase e gera um Connect Token oficial na Pluggy
 * usando o SDK oficial `pluggy-sdk` (PluggyClient) sem expor CLIENT_ID/CLIENT_SECRET.
 */
export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ erro: 'Método não permitido' });
    }

    const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || DEFAULT_SUPABASE_URL;
    const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    const PLUGGY_CLIENT_ID = process.env.PLUGGY_CLIENT_ID;
    const PLUGGY_CLIENT_SECRET = process.env.PLUGGY_CLIENT_SECRET;

    if (!PLUGGY_CLIENT_ID || !PLUGGY_CLIENT_SECRET) {
        return res.status(500).json({
            erro: 'Credenciais da Pluggy ausentes no servidor. Configure PLUGGY_CLIENT_ID e PLUGGY_CLIENT_SECRET nas variáveis de ambiente da Vercel.'
        });
    }

    // Validação JWT do Supabase (OWASP A01 / A07)
    const authHeader = req.headers.authorization || '';
    const jwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
    if (!jwt || !SUPABASE_KEY) {
        return res.status(401).json({ erro: 'Token de autenticação ausente' });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    try {
        const { data: authData, error: authError } = await supabase.auth.getUser(jwt);
        if (authError || !authData?.user) {
            return res.status(401).json({ erro: 'Sessão inválida ou expirada' });
        }

        const user = authData.user;
        const { itemId } = req.body || {};

        if (itemId && !/^[a-zA-Z0-9-]{10,64}$/.test(String(itemId))) {
            return res.status(400).json({ erro: 'itemId inválido' });
        }

        const pluggyClient = new PluggyClient({
            clientId: PLUGGY_CLIENT_ID,
            clientSecret: PLUGGY_CLIENT_SECRET
        });

        const tokenData = await pluggyClient.createConnectToken(
            itemId ? String(itemId) : undefined,
            { clientUserId: String(user.id) }
        );

        return res.status(200).json({
            connectToken: tokenData.accessToken
        });
    } catch (error) {
        console.error('Erro em /api/pluggy-connect-token:', error);
        return res.status(500).json({ erro: 'Erro ao gerar Connect Token na Pluggy. Verifique PLUGGY_CLIENT_ID e PLUGGY_CLIENT_SECRET.' });
    }
}
