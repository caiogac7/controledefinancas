const { createClient } = require('@supabase/supabase-js');
const { PluggyClient } = require('pluggy-sdk');

const DEFAULT_SUPABASE_URL = 'https://ncpdgcxoziekwuralwzx.supabase.co';

/**
 * Função utilitária para formatar timestamp no fuso America/Sao_Paulo
 */
function getSaoPauloTimestamp() {
    const parts = new Intl.DateTimeFormat('sv-SE', {
        timeZone: 'America/Sao_Paulo',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    }).formatToParts(new Date());

    const map = {};
    parts.forEach(p => { map[p.type] = p.value; });
    return `${map.year}-${map.month}-${map.day}T${map.hour}:${map.minute}:${map.second}-03:00`;
}

/**
 * POST /api/pluggy-webhook
 * Endpoint seguro para receber notificações de eventos da Pluggy (Open Finance)
 * Suporta: item/updated, item/created, transactions/created
 */
async function handler(req, res) {
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    if (req.method !== 'POST') {
        return res.status(405).json({ erro: 'Método não permitido' });
    }

    const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || DEFAULT_SUPABASE_URL;
    const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
    const PLUGGY_CLIENT_ID = process.env.PLUGGY_CLIENT_ID;
    const PLUGGY_CLIENT_SECRET = process.env.PLUGGY_CLIENT_SECRET;

    const { event, itemId, error: hookError } = req.body || {};

    // Validação defensiva (OWASP A01 / A03)
    if (!itemId || typeof itemId !== 'string' || !/^[a-zA-Z0-9-]{10,64}$/.test(itemId)) {
        return res.status(400).json({ erro: 'itemId ausente ou formato inválido' });
    }

    // Se o evento reportar erro no banco parceiro, apenas registra e retorna 200 para a Pluggy
    if (event === 'item/error' || hookError) {
        console.warn(`[Pluggy Webhook] Evento de erro recebido para o item ${itemId}:`, hookError);
        return res.status(200).json({ recebido: true, status: 'erro_registrado' });
    }

    // Eventos de interesse: atualização de dados ou novas transações
    const relevantEvents = ['item/updated', 'item/created', 'transactions/created'];
    if (event && !relevantEvents.includes(event)) {
        return res.status(200).json({ recebido: true, ignorado: `Evento ${event} não requer ingestão` });
    }

    if (!SUPABASE_KEY || !PLUGGY_CLIENT_ID || !PLUGGY_CLIENT_SECRET) {
        console.error('[Pluggy Webhook] Configurações de ambiente ausentes no servidor');
        return res.status(500).json({ erro: 'Configurações do servidor incompletas' });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
    const pluggyClient = new PluggyClient({
        clientId: PLUGGY_CLIENT_ID,
        clientSecret: PLUGGY_CLIENT_SECRET
    });

    try {
        // 1. Busca os metadados do item na Pluggy
        const itemData = await pluggyClient.fetchItem(itemId);
        if (!itemData) {
            return res.status(404).json({ erro: 'Item não encontrado na Pluggy' });
        }

        // 2. Identifica o usuário proprietário (clientUserId)
        let userId = itemData.clientUserId;

        // Fallback: se clientUserId não veio no item, pesquisa no banco pela conta/banco vinculado
        if (!userId) {
            const { data: bankRecord } = await supabase
                .from('banks')
                .select('user_id')
                .eq('pluggy_item_id', itemId)
                .limit(1)
                .maybeSingle();

            userId = bankRecord?.user_id;
        }

        if (!userId) {
            console.warn(`[Pluggy Webhook] Não foi possível vincular o item ${itemId} a nenhum usuário do sistema.`);
            return res.status(200).json({ recebido: true, aviso: 'Usuário não identificado para este item' });
        }

        // 3. Busca contas associadas
        const accountsResponse = await pluggyClient.fetchAccounts(itemId);
        const accounts = Array.isArray(accountsResponse?.results) ? accountsResponse.results : [];

        // 4. Atualiza saldos bancários na tabela public.banks
        const spTimestamp = getSaoPauloTimestamp();
        for (const acc of accounts) {
            if (acc.type === 'BANK') {
                const balanceVal = Number(acc.balance || 0);
                await supabase
                    .from('banks')
                    .update({
                        pluggy_direct_balance: balanceVal,
                        updated_at: spTimestamp
                    })
                    .eq('user_id', userId)
                    .eq('pluggy_account_id', String(acc.id));
            }
        }

        // 5. Busca faturas de cartão de crédito e sincroniza credit_bills
        for (const acc of accounts) {
            if (acc.type === 'CREDIT') {
                try {
                    let bills = [];
                    if (typeof pluggyClient.fetchBills === 'function') {
                        const billsResp = await pluggyClient.fetchBills(acc.id);
                        bills = Array.isArray(billsResp?.results) ? billsResp.results : [];
                    }

                    if (bills.length > 0) {
                        const billRows = bills.map(b => {
                            const tot = Number(b.totalAmount || b.total || 0);
                            const paid = Number(b.paidAmount || 0);
                            const pend = Math.max(0, tot - paid);
                            const bMonth = (b.dueDate || '').slice(0, 7) || spTimestamp.slice(0, 7);

                            return {
                                id: `bill_${String(b.id || acc.id)}`,
                                user_id: userId,
                                account_id: String(acc.id),
                                bank_id: `bank_pluggy_${String(acc.id).slice(0, 8)}`,
                                card_id: `card_${String(acc.id).slice(0, 8)}`,
                                card_name: String(acc.name || 'Cartão de Crédito'),
                                month: bMonth,
                                due_date: b.dueDate || null,
                                closing_date: b.closingDate || null,
                                total_amount: tot,
                                paid_amount: paid,
                                pending_amount: pend,
                                minimum_payment_amount: Number(b.minimumPaymentAmount || 0) || null,
                                status: pend <= 0.009 ? 'PAID' : 'OPEN',
                                updated_at: spTimestamp
                            };
                        });

                        await supabase.from('credit_bills').upsert(billRows, { onConflict: 'id' });
                    }
                } catch (bErr) {
                    console.warn(`[Pluggy Webhook] Falha ao sincronizar faturas do cartão ${acc.id}:`, bErr?.message || bErr);
                }
            }
        }

        console.log(`[Pluggy Webhook] Sucesso no processamento do evento ${event} para o usuário ${userId}`);
        return res.status(200).json({ recebido: true, processado: true, userId });
    } catch (err) {
        console.error('[Pluggy Webhook] Erro ao processar webhook:', err);
        return res.status(500).json({ erro: 'Falha interna ao processar webhook: ' + (err?.message || 'Erro inesperado') });
    }
}

module.exports = handler;
module.exports.default = handler;

