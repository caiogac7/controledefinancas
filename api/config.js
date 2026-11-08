/**
 * GET /api/config
 * Entrega as chaves PÚBLICAS (anon key do Supabase)
 * para o frontend de forma segura via variáveis de ambiente do Vercel.
 *
 * NUNCA coloque a SUPABASE_SERVICE_ROLE_KEY aqui.
 */
module.exports = function handler(req, res) {
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    if (req.method !== 'GET') {
        return res.status(405).json({ erro: 'Método não permitido' });
    }

    const supabaseUrl  = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://ncpdgcxoziekwuralwzx.supabase.co';
    const supabaseAnon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5jcGRnY3hvemlla3d1cmFsd3p4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTMwNzIzODAsImV4cCI6MjEwODY0ODM4MH0.sQ2fzs3rRbwVKjHrwa6wAP5mAugKtPIbOeSzbSpxD1Y';

    // Cache de 1 hora — as chaves públicas mudam raramente
    res.setHeader('Cache-Control', 'public, max-age=3600');
    return res.status(200).json({
        supabaseUrl,
        supabaseAnon
    });
};
