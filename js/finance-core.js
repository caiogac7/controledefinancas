/**
 * finance-core.js
 * Núcleo isomórfico de regras financeiras do Controle de Finanças.
 * Padroniza cálculos de saldo atual/previsto, faturas consolidadas, limite de cartões,
 * impacto mensal de parcelas, normalização de categorias e classificação visual de pendentes.
 */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.FinanCore = factory();
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const round2 = (n) => Math.round((Number(n || 0) + Number.EPSILON) * 100) / 100;

    const CATEGORY_NORMALIZATION_MAP = {
        'clothing': 'Vestuário',
        'clothes': 'Vestuário',
        'vestuario': 'Vestuário',
        'vestuário': 'Vestuário',
        'food': 'Alimentação',
        'alimentacao': 'Alimentação',
        'alimentação': 'Alimentação',
        'shopping': 'Compras',
        'compras': 'Compras',
        'home': 'Casa',
        'house': 'Casa',
        'casa': 'Casa',
        'education': 'Educação',
        'educacao': 'Educação',
        'educação': 'Educação',
        'subscription': 'Assinatura',
        'subscriptions': 'Assinatura',
        'assinatura': 'Assinatura',
        'transport': 'Transporte',
        'transporte': 'Transporte',
        'health': 'Saúde',
        'saude': 'Saúde',
        'saúde': 'Saúde',
        'salary': 'Salário',
        'salario': 'Salário',
        'salário': 'Salário',
        'bonus': 'Bonificação',
        'bonificacao': 'Bonificação',
        'bonificação': 'Bonificação',
        'leisure': 'Lazer',
        'lazer': 'Lazer',
        'credit card': 'Cartão de Crédito',
        'cartao de credito': 'Cartão de Crédito',
        'cartão de crédito': 'Cartão de Crédito'
    };

    /**
     * Padroniza nomes de categorias para Português (pt-BR) mantendo compatibilidade com registros antigos.
     */
    function normalizeCategoryLabel(catName) {
        const raw = String(catName || '').trim();
        if (!raw) return 'Compras';
        const key = raw.toLowerCase();
        if (CATEGORY_NORMALIZATION_MAP[key]) {
            return CATEGORY_NORMALIZATION_MAP[key];
        }
        return raw.charAt(0).toUpperCase() + raw.slice(1);
    }

    /**
     * Mascara descrições/nomes sensíveis quando o modo privacidade está ativo.
     */
    function maskSensitiveLabel(text, isPrivate) {
        const str = String(text || '').trim();
        if (!isPrivate) return str;
        if (!str) return '••••';
        if (str.includes('@')) {
            const parts = str.split('@');
            const userPart = parts[0] || '';
            const prefix = userPart.slice(0, 2);
            return `${prefix}••••@${parts[1] || '•••'}`;
        }
        return '•••• ••••';
    }

    /**
     * Classifica o tipo visual de compromisso na lista da Visão Mensal (Fatura, Parcela, Fixa ou Única).
     */
    function classifyTransactionVisualKind(tx) {
        if (!tx) {
            return { kind: 'SINGLE', label: 'Única', shortBadge: 'Única', icon: '•' };
        }
        const fit = String(tx.fitid || '');
        const descLower = String(tx.desc || tx.description || '').toLowerCase();
        const isBill = Boolean(
            tx.isConsolidatedBill ||
            fit.startsWith('pluggy_bill_') ||
            descLower.startsWith('fatura ')
        );
        if (isBill) {
            return { kind: 'BILL', label: 'Fatura Consolidada', shortBadge: '💳 Fatura', icon: '💳' };
        }
        const instStr = String(tx.inst || '').trim();
        const instMatch = instStr.match(/^(\d+)\s*\/\s*(\d+)$/);
        if (instMatch) {
            const cur = Number(instMatch[1]);
            const tot = Number(instMatch[2]);
            return {
                kind: 'INSTALLMENT',
                label: `Parcela ${cur}/${tot}`,
                shortBadge: `📦 Parcela ${cur}/${tot}`,
                icon: '📦',
                currentInstallment: cur,
                totalInstallments: tot
            };
        }
        if (instStr.toLowerCase() === 'fixa') {
            return { kind: 'FIXED', label: 'Recorrente Fixa', shortBadge: '🔁 Fixa', icon: '🔁' };
        }
        return { kind: 'SINGLE', label: 'Lançamento Avulso', shortBadge: '⚡ Única', icon: '⚡' };
    }

    /**
     * Calcula Saldo Atual, Pendentes e Previsão de Fim de Mês para uma conta individual.
     */
    function computeBankAccountMonthSummary({
        transactions = [],
        bankId = '',
        rawBankId = '',
        monthKey = '2026-11',
        pluggyLiveBalance = null,
        lastSyncIso = '',
        isCreditCard = false,
        isLedgerEntryFn = null,
        getCashTimestampFn = null,
        isBalanceControlFn = null
    }) {
        const bId = String(bankId || '');
        const rId = String(rawBankId || bId);
        const curMonthKey = String(monthKey || '2026-11').slice(0, 7);

        const isLedger = isLedgerEntryFn || ((t) => {
            if (!t) return false;
            const tb = String(t.bankId || 'bank_geral');
            return tb === bId || tb === rId;
        });
        const isBalCtrl = isBalanceControlFn || ((t) => Boolean(
            t && (t.isInitialBalance || t.isBalanceAdjustment || t.cat === 'Saldo Inicial' || t.cat === 'Ajuste de Saldo')
        ));
        const getCashTs = getCashTimestampFn || ((t) => {
            if (!t || !t.paid) return '';
            if (t.paidAt) return String(t.paidAt);
            const m = String(t.month || curMonthKey).slice(0, 7);
            const d = String(Math.max(1, Math.min(31, Number(t.day) || 1))).padStart(2, '0');
            return `${m}-${d}T12:00:00-03:00`;
        });

        let carryIn = 0;
        let paidIncomeMonth = 0;
        let paidExpenseMonth = 0;
        let adjustmentsMonth = 0;
        let pendingIncomeMonth = 0;
        let pendingExpenseMonth = 0;

        for (let i = 0; i < transactions.length; i++) {
            const t = transactions[i];
            if (!t || !isLedger(t, bId, rId)) continue;
            const amt = Number(t.amount || 0);
            if (amt === 0) continue;
            const signed = t.type === 'income' ? amt : -amt;

            if (t.paid) {
                const cashMonth = String(getCashTs(t) || '').slice(0, 7);
                if (!cashMonth) continue;
                if (cashMonth < curMonthKey) {
                    carryIn += signed;
                } else if (cashMonth === curMonthKey) {
                    if (isBalCtrl(t)) adjustmentsMonth += signed;
                    else if (t.type === 'income') paidIncomeMonth += amt;
                    else paidExpenseMonth += amt;
                }
            } else if (String(t.month || '').slice(0, 7) === curMonthKey && !isBalCtrl(t)) {
                if (t.type === 'income') pendingIncomeMonth += amt;
                else pendingExpenseMonth += amt;
            }
        }

        const pendingNetMonth = round2(pendingIncomeMonth - pendingExpenseMonth);

        if (typeof pluggyLiveBalance === 'number' && !isCreditCard) {
            const pluggyBase = Number(pluggyLiveBalance);
            let deltaAfterSync = 0;
            for (let i = 0; i < transactions.length; i++) {
                const t = transactions[i];
                if (!t || !t.paid || !isLedger(t, bId, rId) || isBalCtrl(t)) continue;
                if (t.reconciledWithStatement) continue;
                const ts = getCashTs(t);
                if (lastSyncIso && ts && ts > lastSyncIso) {
                    deltaAfterSync += t.type === 'income' ? Number(t.amount || 0) : -Number(t.amount || 0);
                }
            }
            const currentBalance = round2(pluggyBase + deltaAfterSync);
            const projectedBalance = round2(currentBalance + pendingNetMonth);
            return {
                carryIn: round2(pluggyBase),
                paidIncomeMonth: round2(paidIncomeMonth),
                paidExpenseMonth: round2(paidExpenseMonth),
                adjustmentsMonth: 0,
                pendingIncomeMonth: round2(pendingIncomeMonth),
                pendingExpenseMonth: round2(pendingExpenseMonth),
                currentBalance,
                pendingNetMonth,
                projectedBalance
            };
        }

        const currentBalance = round2(carryIn + paidIncomeMonth - paidExpenseMonth + adjustmentsMonth);
        const projectedBalance = round2(currentBalance + pendingNetMonth);

        return {
            carryIn: round2(carryIn),
            paidIncomeMonth: round2(paidIncomeMonth),
            paidExpenseMonth: round2(paidExpenseMonth),
            adjustmentsMonth: round2(adjustmentsMonth),
            pendingIncomeMonth: round2(pendingIncomeMonth),
            pendingExpenseMonth: round2(pendingExpenseMonth),
            currentBalance,
            pendingNetMonth,
            projectedBalance
        };
    }

    /**
     * Consolida totais operacionais e previsão do mês garantindo coerência entre
     * Saldo Atual (Hoje), Receitas/Despesas Pendentes e Saldo Previsto no Mês.
     */
    function computeMonthOperationalForecast(operationalMonthTxs = [], currentRealActiveBalance = 0, options = {}) {
        const list = Array.isArray(operationalMonthTxs) ? operationalMonthTxs : [];
        const activeBankIds = options.activeBankIds instanceof Set ? options.activeBankIds : null;
        const onlyActiveForForecast = Boolean(activeBankIds && options.excludeIsolatedBanksFromForecast);

        const incomes = [];
        const expenses = [];
        let totalIncome = 0;
        let receivedIncome = 0;
        let totalExpense = 0;
        let paidExpense = 0;
        let activePendingIncome = 0;
        let activePendingExpense = 0;

        for (let i = 0; i < list.length; i++) {
            const t = list[i];
            if (!t) continue;
            const bankStr = String(t.bankId || 'bank_geral');
            const isBill = Boolean(t.isConsolidatedBill || String(t.fitid || '').startsWith('pluggy_bill_'));
            const countsInForecast = !onlyActiveForForecast || isBill || activeBankIds.has(bankStr);

            if (t.type === 'income') {
                incomes.push(t);
                const amt = Number(t.amount || 0);
                totalIncome += amt;
                if (t.paid) {
                    receivedIncome += amt;
                } else if (countsInForecast) {
                    activePendingIncome += amt;
                }
            } else {
                expenses.push(t);
                if (t.isConsolidatedBill) {
                    const bTot = Number(t.total_amount ?? t.invoiceTotal ?? t.amount ?? 0);
                    const bPaid = Math.min(bTot, Math.max(0, Number(t.paid_amount ?? t.paidAmount ?? (t.paid ? bTot : 0))));
                    const bPend = Math.max(0, Number(t.pending_amount ?? t.pendingAmount ?? (bTot - bPaid)));
                    totalExpense += bTot;
                    paidExpense += bPaid;
                    if (countsInForecast) activePendingExpense += bPend;
                } else {
                    const amt = Number(t.amount || 0);
                    totalExpense += amt;
                    if (t.paid) {
                        paidExpense += amt;
                    } else if (countsInForecast) {
                        activePendingExpense += amt;
                    }
                }
            }
        }

        const totalIncomeFixed = round2(totalIncome);
        const receivedIncomeFixed = round2(receivedIncome);
        const pendingIncome = round2(Math.max(0, totalIncomeFixed - receivedIncomeFixed));
        const totalExpenseFixed = round2(totalExpense);
        const paidExpenseFixed = round2(paidExpense);
        const pendingExpense = round2(Math.max(0, totalExpenseFixed - paidExpenseFixed));
        const paidPct = totalExpenseFixed > 0
            ? Math.round((paidExpenseFixed / totalExpenseFixed) * 100)
            : (paidExpenseFixed === 0 && receivedIncomeFixed > 0 ? 100 : 0);

        const realActiveBal = round2(currentRealActiveBalance);
        const forecastPendingNet = round2(activePendingIncome - activePendingExpense);
        const projectedEndOfMonthBalance = round2(realActiveBal + forecastPendingNet);

        return {
            incomes,
            expenses,
            totalIncome: totalIncomeFixed,
            receivedIncome: receivedIncomeFixed,
            pendingIncome,
            totalExpense: totalExpenseFixed,
            paidExpense: paidExpenseFixed,
            pendingExpense,
            paidPct,
            currentRealActiveBalance: realActiveBal,
            projectedEndOfMonthBalance
        };
    }

    /**
     * Consolida os valores de fatura e limite de um cartão de crédito, impedindo duplicação
     * de pagamentos e preservando saldo usado não faturado (Open Finance).
     */
    function computeCardLimitMetrics({ creditLimit = 0, availableCreditLimit = 0, creditLimitUsed = 0, openBillsSum = 0, currentInvoiceTotal = 0 }) {
        let total = Number(creditLimit || 0);
        let available = Number(availableCreditLimit || 0);
        let used = Number(creditLimitUsed || 0);

        if (total > 0 && available > 0 && used <= 0) {
            used = Math.max(0, round2(total - available));
        }
        if (used <= 0) {
            if (openBillsSum > 0) used = round2(openBillsSum);
            else if (currentInvoiceTotal > 0) used = round2(currentInvoiceTotal);
        }
        if (total > 0 && used > 0 && available <= 0) {
            available = Math.max(0, round2(total - used));
        } else if (total <= 0 && available > 0 && used > 0) {
            total = round2(available + used);
        }

        const hasTotalLimit = total > 0;
        const hasLimits = hasTotalLimit || available > 0 || used > 0;
        const pctUsed = hasTotalLimit ? Math.min(100, Math.max(0, Math.round((used / total) * 100))) : 0;

        return {
            total: Math.max(0, round2(total)),
            available: Math.max(0, round2(available)),
            used: Math.max(0, round2(used)),
            pctUsed,
            hasLimits,
            hasTotalLimit
        };
    }

    /**
     * Filtra exclusivamente a parcela/item pertencente ao mês vigente e calcula a soma de parcelas do mês.
     */
    function summarizeInstallmentsForMonth(transactions = [], monthKey = '2026-11') {
        const mKey = String(monthKey || '2026-11').slice(0, 7);
        const list = (Array.isArray(transactions) ? transactions : []).filter(t => {
            if (!t || String(t.month || '').slice(0, 7) !== mKey) return false;
            return /\d+\s*\/\s*\d+/.test(String(t.inst || ''));
        });
        let totalMonthInstallments = 0;
        let paidMonthInstallments = 0;
        let pendingMonthInstallments = 0;
        list.forEach(t => {
            const amt = Number(t.amount || 0);
            totalMonthInstallments += amt;
            if (t.paid) paidMonthInstallments += amt;
            else pendingMonthInstallments += amt;
        });
        return {
            items: list,
            count: list.length,
            total: round2(totalMonthInstallments),
            paid: round2(paidMonthInstallments),
            pending: round2(pendingMonthInstallments)
        };
    }

    /**
     * Filtra transações visíveis na tabela da Visão Mensal por tipo, status, modalidade (parcela/fatura/fixa), conta e busca.
     */
    function filterDashboardTransactions(monthTxs = [], filters = {}) {
        const list = Array.isArray(monthTxs) ? monthTxs : [];
        const {
            filterType = 'all',
            filterStatus = 'all',
            filterKind = 'all',
            filterBankId = 'all',
            searchQuery = '',
            banks = []
        } = filters;

        const q = String(searchQuery || '').trim().toLowerCase();
        const bankMap = new Map((Array.isArray(banks) ? banks : []).map(b => [String(b.id), b]));

        return list.filter(t => {
            if (!t) return false;
            if (filterType !== 'all' && t.type !== filterType) return false;

            const vKind = classifyTransactionVisualKind(t);
            const isBill = vKind.kind === 'BILL';
            const billPend = isBill ? Number(t.pending_amount ?? t.pendingAmount ?? (t.paid ? 0 : t.amount ?? 0)) : 0;
            const isSettled = isBill ? (Boolean(t.paid) || billPend <= 0.009) : Boolean(t.paid);

            if (filterStatus === 'pending' && isSettled) return false;
            if (filterStatus === 'paid' && !isSettled) return false;

            if (filterKind === 'installment' && vKind.kind !== 'INSTALLMENT') return false;
            if (filterKind === 'bill' && vKind.kind !== 'BILL') return false;
            if (filterKind === 'fixed_single' && vKind.kind !== 'FIXED' && vKind.kind !== 'SINGLE') return false;

            if (filterBankId !== 'all') {
                const txBId = String(t.bankId || 'bank_geral');
                if (txBId !== String(filterBankId)) return false;
            }

            if (q) {
                const bObj = bankMap.get(String(t.bankId || 'bank_geral'));
                const haystack = [
                    t.desc,
                    t.cat,
                    normalizeCategoryLabel(t.cat),
                    t.inst,
                    bObj?.name,
                    t._ownerName
                ].filter(Boolean).join(' ').toLowerCase();
                if (!haystack.includes(q)) return false;
            }

            return true;
        });
    }

    return {
        round2,
        normalizeCategoryLabel,
        maskSensitiveLabel,
        classifyTransactionVisualKind,
        computeBankAccountMonthSummary,
        computeMonthOperationalForecast,
        computeCardLimitMetrics,
        summarizeInstallmentsForMonth,
        filterDashboardTransactions
    };
}));
