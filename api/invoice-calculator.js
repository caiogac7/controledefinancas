const { fillInstallmentGaps } = require('./pluggy-sync');
const { createClient } = require('@supabase/supabase-js');

const DEFAULT_SUPABASE_URL = 'https://ncpdgcxoziekwuralwzx.supabase.co';

/**
 * Obtém a data corrente formatada como YYYY-MM-DD no fuso horário America/Sao_Paulo
 */
function getTodayInSaoPaulo() {
    const parts = new Intl.DateTimeFormat('sv-SE', {
        timeZone: 'America/Sao_Paulo',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    }).formatToParts(new Date());

    const map = {};
    parts.forEach(p => { map[p.type] = p.value; });
    return `${map.year}-${map.month}-${map.day}`;
}

/**
 * Calcula o mês anterior no formato YYYY-MM no fuso America/Sao_Paulo
 */
function getPreviousMonthKey(yearMonth) {
    if (!/^\d{4}-\d{2}$/.test(String(yearMonth))) {
        return getTodayInSaoPaulo().slice(0, 7);
    }
    const [y, m] = yearMonth.split('-').map(Number);
    const d = new Date(Date.UTC(y, m - 2, 1));
    const prevYear = d.getUTCFullYear();
    const prevMonth = String(d.getUTCMonth() + 1).padStart(2, '0');
    return `${prevYear}-${prevMonth}`;
}

/**
 * Retorna a quantidade de dias de um determinado mês YYYY-MM
 */
function getDaysInMonth(yearMonth) {
    const [y, m] = yearMonth.split('-').map(Number);
    return new Date(Date.UTC(y, m, 0)).getUTCDate();
}

/**
 * REGRA 1: Calcula o intervalo exato do ciclo de fatura (data início e data fim)
 * Início: dia (closingDay + 1) do mês anterior
 * Fim: dia (closingDay) do mês alvo
 */
function calculateBillingCycleDates(targetMonth, closingDay) {
    const cleanClosingDay = Math.max(1, Math.min(31, Number(closingDay) || 25));
    const prevMonthKey = getPreviousMonthKey(targetMonth);

    const prevMonthDays = getDaysInMonth(prevMonthKey);
    const targetMonthDays = getDaysInMonth(targetMonth);

    const startDay = Math.min(cleanClosingDay + 1, prevMonthDays);
    const endDay = Math.min(cleanClosingDay, targetMonthDays);

    const startDateStr = `${prevMonthKey}-${String(startDay).padStart(2, '0')}`;
    const endDateStr = `${targetMonth}-${String(endDay).padStart(2, '0')}`;

    return {
        startDate: startDateStr,
        endDate: endDateStr,
        closingDay: cleanClosingDay
    };
}

/**
 * REGRA 1, 2 e 3: Função Principal de Cálculo e Consolidação da Fatura
 * 
 * @param {Object} params
 * @param {Object} params.supabase - Cliente Supabase autenticado
 * @param {string} params.userId - Identificador UUID do usuário
 * @param {string} params.accountId - Identificador da conta/cartão de crédito (Pluggy accountId ou cardId)
 * @param {string} params.targetMonth - Mês alvo da fatura no formato YYYY-MM (ex: '2026-11')
 * @param {Array} [params.memoryTransactions] - Transações em memória (opcional, para processamento direto)
 * @param {Array} [params.creditBills] - Faturas retornadas pela API Pluggy (opcional)
 */
async function calculateInvoiceDetails({
    supabase,
    userId,
    accountId,
    targetMonth,
    cardClosingDay = null,
    cardDueDay = null,
    memoryTransactions = null,
    creditBills = []
}) {
    if (!targetMonth || !/^\d{4}-\d{2}$/.test(String(targetMonth))) {
        throw new Error('Parâmetro targetMonth inválido. Formato esperado: YYYY-MM (ex: 2026-11).');
    }

    const todayInSP = getTodayInSaoPaulo();

    // 1. Busca configurações do cartão no banco de dados (closingDay e dueDay)
    let cardConfig = {
        closingDay: Number(cardClosingDay) || 25,
        dueDay: Number(cardDueDay) || 5,
        name: 'Cartão de Crédito',
        bankId: null
    };

    if (supabase && userId && (!cardClosingDay || !cardDueDay)) {
        try {
            const { data: cardRow } = await supabase
                .from('credit_cards')
                .select('id, name, closing_day, due_day, bank_id')
                .eq('user_id', userId)
                .or(`id.eq.${accountId},bank_id.eq.${accountId}`)
                .maybeSingle();

            if (cardRow) {
                cardConfig.closingDay = Number(cardRow.closing_day) || cardConfig.closingDay;
                cardConfig.dueDay = Number(cardRow.due_day) || cardConfig.dueDay;
                cardConfig.name = cardRow.name || cardConfig.name;
                cardConfig.bankId = cardRow.bank_id || null;
            }
        } catch (dbErr) {
            console.warn('Aviso ao consultar public.credit_cards:', dbErr?.message || dbErr);
        }
    }

    // Calcula as datas de início e fim do ciclo com base no closingDay
    const cycle = calculateBillingCycleDates(targetMonth, cardConfig.closingDay);

    // Data de vencimento calculada da fatura
    const targetDays = getDaysInMonth(targetMonth);
    const safeDueDay = Math.min(cardConfig.dueDay, targetDays);
    const calculatedDueDate = `${targetMonth}-${String(safeDueDay).padStart(2, '0')}`;

    // 2. Coleta de transações (do banco Supabase ou da memória)
    let allTransactions = [];

    if (Array.isArray(memoryTransactions) && memoryTransactions.length > 0) {
        allTransactions = memoryTransactions;
    } else if (supabase && userId) {
        try {
            const { data: userProfile } = await supabase
                .from('profiles')
                .select('transactions_json, bank_statements_json')
                .eq('id', userId)
                .maybeSingle();

            const txsFromProfile = Array.isArray(userProfile?.transactions_json) ? userProfile.transactions_json : [];
            const stmtsFromProfile = Array.isArray(userProfile?.bank_statements_json) ? userProfile.bank_statements_json : [];
            allTransactions = [...txsFromProfile, ...stmtsFromProfile];
        } catch (fetchErr) {
            console.warn('Aviso ao carregar transações do perfil:', fetchErr?.message || fetchErr);
        }
    }

    // 3. REGRA 1: Cálculo Dinâmico do Total da Fatura (O Algoritmo do Ciclo)
    const singleTransactionsInCycle = [];
    const installmentTransactionsForMonth = [];
    let grossTotal = 0;

    // Preenchimento Inteligente de Lacunas de Parcelas (Sem multiplicação duplicada)
    const expandedTransactions = fillInstallmentGaps(allTransactions);

    expandedTransactions.forEach(tx => {
        const amt = Number(Math.abs(Number(tx.amount || 0)).toFixed(2));
        if (amt <= 0.009) return;

        // Identifica se a transação pertence a este cartão/conta
        const isThisCard = String(tx.accountId || '') === String(accountId) ||
                           String(tx.cardId || '') === String(accountId) ||
                           String(tx.bankId || '') === String(accountId) ||
                           String(tx.cardId || '') === `card_${String(accountId).slice(0, 8)}` ||
                           Boolean(tx.isCreditCardTx);

        if (!isThisCard) return;

        // Apenas saídas/despesas compõem a fatura (exceto estornos/cashback que abatem)
        const isExpense = tx.type === 'expense' || tx.type === 'DEBIT' || (!tx.type && Number(tx.amount || 0) < 0);
        const signedAmt = isExpense ? amt : -amt;

        // Metadados de parcelamento (competência futura)
        const ccMeta = tx.creditCardMetadata || {};
        const totalInst = Number(ccMeta.totalInstallments || tx.totalInstallments || 0);
        const instLabel = String(tx.inst || '');
        const isInstallment = totalInst > 1 || /\d+\/\d+/.test(instLabel);

        // Identifica competência (mês de cobrança)
        const competenceMonth = String(ccMeta.billForecastDate || ccMeta.billPostDate || tx.installmentMonth || tx.month || '').slice(0, 7);

        // Data da compra (purchaseDate ou date)
        const rawDate = String(tx.purchaseDate || tx.date || (tx.paidAt ? tx.paidAt.slice(0, 10) : '') || '').slice(0, 10);

        if (isInstallment) {
            // REGRA 1 - B: Parcelas entram se a competência for exatamente o mês alvo
            if (competenceMonth === targetMonth) {
                installmentTransactionsForMonth.push({
                    id: tx.id,
                    desc: tx.desc || tx.description || 'Parcela de Cartão',
                    amount: amt,
                    installment: instLabel || `${ccMeta.installmentNumber || 1}/${totalInst}`,
                    date: rawDate,
                    competenceMonth
                });
                grossTotal += signedAmt;
            }
        } else {
            // REGRA 1 - A: Compras à vista entram se a data de compra cair no período do ciclo
            // Início: (closingDay + 1) do mês anterior | Fim: closingDay do mês alvo
            if (rawDate && rawDate >= cycle.startDate && rawDate <= cycle.endDate) {
                singleTransactionsInCycle.push({
                    id: tx.id,
                    desc: tx.desc || tx.description || 'Compra no Cartão',
                    amount: amt,
                    date: rawDate,
                    cycle: `${cycle.startDate} a ${cycle.endDate}`
                });
                grossTotal += signedAmt;
            }
        }
    });

    // Se houver fatura oficial fechada vinda de creditBills da Pluggy para este mês, concilia
    let officialBill = null;
    if (Array.isArray(creditBills) && creditBills.length > 0) {
        officialBill = creditBills.find(b => {
            const bDueDate = String(b.dueDate || '').slice(0, 7);
            const bAccId = String(b.accountId || '');
            return bDueDate === targetMonth && (!accountId || bAccId === String(accountId));
        });
    }

    const finalTotalAmount = Number(Math.max(0, grossTotal).toFixed(2));
    const effectiveTotal = officialBill && Number(officialBill.totalAmount || 0) > 0
        ? Number(Number(officialBill.totalAmount).toFixed(2))
        : finalTotalAmount;

    // 4. REGRA 3: Abatimento de Pagamentos e Cálculo do Saldo Pendente
    let totalPaymentsAmount = 0;
    const detectedPayments = [];
    const isBillPaymentRegex = /pagamento\s+(de\s+)?fatura|pgto\s+fatura|pagamento\s+cart[aã]o/i;

    allTransactions.forEach(tx => {
        // Transações da CONTA CORRENTE (isCreditCardTx == false ou type == 'BANK')
        const isBank = tx.accountType === 'BANK' || tx.type === 'BANK' || !tx.isCreditCardTx;
        const txMonth = String(tx.month || (tx.date ? tx.date.slice(0, 7) : '')).slice(0, 7);

        // Competência: mesmo mês da fatura
        if (isBank && txMonth === targetMonth) {
            const desc = String(tx.desc || tx.description || tx.descriptionRaw || '');
            if (isBillPaymentRegex.test(desc)) {
                const pVal = Math.abs(Number(tx.amount || 0));
                if (pVal > 0.009) {
                    detectedPayments.push({
                        id: tx.id,
                        desc,
                        amount: Number(pVal.toFixed(2)),
                        date: String(tx.date || tx.paidAt || '').slice(0, 10)
                    });
                    totalPaymentsAmount += pVal;
                }
            }
        }
    });

    totalPaymentsAmount = Number(totalPaymentsAmount.toFixed(2));
    const pendingBalance = Number(Math.max(0, effectiveTotal - totalPaymentsAmount).toFixed(2));

    // 5. REGRA 2 e 3: Definição Rigorosa do Status da Fatura
    // Compara a data de vencimento com a data atual no fuso de São Paulo
    const effectiveDueDate = officialBill?.dueDate ? String(officialBill.dueDate).slice(0, 10) : calculatedDueDate;
    const isPastDue = todayInSP > effectiveDueDate;

    let finalStatus = 'OPEN';

    if (effectiveTotal <= 0.009) {
        finalStatus = 'PAID';
    } else if (pendingBalance <= 0.009) {
        // REGRA 3: Se Saldo Pendente <= 0, muda automaticamente para PAID
        finalStatus = 'PAID';
    } else if (isPastDue) {
        // REGRA 2: Faturas vencidas são marcadas como PAID se quitadas ou OVERDUE/PAID conforme regra histórica
        finalStatus = 'PAID'; // Forçado para faturas antigas conforme solicitado na Regra 2
    } else {
        finalStatus = 'OPEN';
    }

    return {
        accountId: String(accountId),
        cardName: cardConfig.name,
        targetMonth,
        cycle: {
            closingDay: cardConfig.closingDay,
            dueDay: cardConfig.dueDay,
            startDate: cycle.startDate,
            endDate: cycle.endDate,
            dueDate: effectiveDueDate
        },
        metrics: {
            totalAmount: effectiveTotal,
            grossCalculatedAmount: finalTotalAmount,
            officialApiAmount: officialBill ? Number(officialBill.totalAmount || 0) : null,
            totalPaymentsDetected: totalPaymentsAmount,
            pendingBalance: pendingBalance,
            isFullyPaid: pendingBalance <= 0.009
        },
        status: finalStatus,
        breakdown: {
            singleTransactionsCount: singleTransactionsInCycle.length,
            singleTransactions: singleTransactionsInCycle,
            installmentTransactionsCount: installmentTransactionsForMonth.length,
            installmentTransactions: installmentTransactionsForMonth,
            paymentsCount: detectedPayments.length,
            payments: detectedPayments
        },
        calculatedAt: todayInSP
    };
}

/**
 * Handler HTTP da API Vercel Serverless (POST /api/calculate-invoice)
 */
async function handler(req, res) {
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    if (req.method !== 'POST') {
        return res.status(405).json({ erro: 'Método não permitido. Utilize POST.' });
    }

    const authHeader = req.headers.authorization || '';
    const jwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

    const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || DEFAULT_SUPABASE_URL;
    const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;

    if (!jwt || !SUPABASE_KEY) {
        return res.status(401).json({ erro: 'Token de autenticação ausente ou inválido.' });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    try {
        const { data: authData, error: authError } = await supabase.auth.getUser(jwt);
        if (authError || !authData?.user) {
            return res.status(401).json({ erro: 'Sessão inválida ou expirada.' });
        }

        const { accountId, targetMonth, creditBills, transactions } = req.body || {};

        if (!accountId) {
            return res.status(400).json({ erro: 'O parâmetro accountId é obrigatório.' });
        }

        const invoiceDetails = await calculateInvoiceDetails({
            supabase,
            userId: authData.user.id,
            accountId: String(accountId),
            targetMonth: String(targetMonth || getTodayInSaoPaulo().slice(0, 7)),
            memoryTransactions: Array.isArray(transactions) ? transactions : null,
            creditBills: Array.isArray(creditBills) ? creditBills : []
        });

        return res.status(200).json(invoiceDetails);
    } catch (err) {
        console.error('Erro em /api/calculate-invoice:', err);
        return res.status(500).json({ erro: 'Erro ao calcular detalhes da fatura: ' + (err?.message || 'Erro interno') });
    }
}

module.exports = handler;
module.exports.default = handler;
module.exports.getTodayInSaoPaulo = getTodayInSaoPaulo;
module.exports.getPreviousMonthKey = getPreviousMonthKey;
module.exports.getDaysInMonth = getDaysInMonth;
module.exports.calculateBillingCycleDates = calculateBillingCycleDates;
module.exports.calculateInvoiceDetails = calculateInvoiceDetails;
