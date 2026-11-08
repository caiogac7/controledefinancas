import { createClient } from '@supabase/supabase-js';
import { PluggyClient } from 'pluggy-sdk';

const DEFAULT_SUPABASE_URL = 'https://ncpdgcxoziekwuralwzx.supabase.co';

const round2 = (num) => Math.round((Number(num || 0) + Number.EPSILON) * 100) / 100;

/**
 * Formata um timestamp ISO completo no fuso America/Sao_Paulo
 */
export function getSaoPauloTimestamp() {
    try {
        const now = new Date();
        const str = now.toLocaleString('en-CA', { timeZone: 'America/Sao_Paulo', hour12: false });
        const [dPart, tPart] = str.replace(',', '').trim().split(/\s+/);
        if (dPart && tPart && /^\d{4}-\d{2}-\d{2}$/.test(dPart)) {
            return `${dPart}T${tPart.slice(0, 8)}-03:00`;
        }
    } catch (e) {}
    const spDate = new Date(Date.now() - 3 * 3600 * 1000);
    return spDate.toISOString().replace('Z', '-03:00');
}

/**
 * Formata uma data ISO para YYYY-MM e dia numérico no fuso America/Sao_Paulo
 */
export function parseDateInSaoPaulo(isoString) {
    if (!isoString) isoString = new Date().toISOString();
    let s = String(isoString).trim();
    if (/^\d{4}-\d{2}$/.test(s)) {
        const y = s.slice(0, 4);
        const m = Number(s.slice(5, 7)) || 1;
        return { year: y, monthNum: m, month: s, day: 1, isYearMonthOnly: true };
    }
    if (/^\d{4}-\d{2}-\d{2}/.test(s) && !s.includes('T')) {
        const y = s.slice(0, 4);
        const m = Number(s.slice(5, 7)) || 1;
        const d = Number(s.slice(8, 10)) || 1;
        return { year: y, monthNum: m, month: s.slice(0, 7), day: d, isYearMonthOnly: false };
    }
    try {
        const dt = new Date(s);
        if (!isNaN(dt.getTime())) {
            const locStr = dt.toLocaleString('en-CA', { timeZone: 'America/Sao_Paulo', hour12: false });
            const [dPart] = locStr.replace(',', '').trim().split(/\s+/);
            if (dPart && /^\d{4}-\d{2}-\d{2}$/.test(dPart)) {
                const y = dPart.slice(0, 4);
                const m = Number(dPart.slice(5, 7)) || 1;
                const d = Number(dPart.slice(8, 10)) || 1;
                return { year: y, monthNum: m, month: `${y}-${String(m).padStart(2, '0')}`, day: d, isYearMonthOnly: false };
            }
        }
    } catch (e) {}
    const fallbackY = s.slice(0, 4) || '2026';
    const fallbackM = Number(s.slice(5, 7)) || 11;
    const fallbackD = Number(s.slice(8, 10)) || 1;
    return { year: fallbackY, monthNum: fallbackM, month: `${fallbackY}-${String(fallbackM).padStart(2, '0')}`, day: fallbackD, isYearMonthOnly: false };
}

export function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function normalizeTextForClassification(desc) {
    if (!desc) return '';
    return String(desc)
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase()
        .replace(/\s+/g, ' ')
        .trim();
}

export function isCardBillPayment(desc) {
    if (!desc) return false;
    const clean = normalizeTextForClassification(desc);
    return clean.includes('pagamento de fatura cartao de credito') ||
           clean.includes('cartao de credito pagamento de fatura') ||
           clean.includes('pagamento cartao de credito') ||
           clean.includes('pagamento do cartao') ||
           clean.includes('pagamento de fatura') ||
           clean.includes('pagamento fatura') ||
           clean.includes('pgto fatura') ||
           clean.includes('pagamento cartao') ||
           clean.includes('pgto cartao') ||
           (clean.includes('pagamento') && clean.includes('fatura')) ||
           (clean.includes('pagamento') && clean.includes('credito'));
}

export function isCardPaymentReceivedMirror(desc) {
    if (!desc) return false;
    const clean = normalizeTextForClassification(desc);
    return clean.includes('pagamento recebido') ||
           clean.includes('pgto recebido') ||
           clean.includes('pagamento do cartao') ||
           clean.includes('pagamento de fatura') ||
           clean.includes('pagamento fatura');
}

export function isVaultTransactionDesc(desc) {
    if (!desc) return false;
    const clean = normalizeTextForClassification(desc);
    return clean.includes('reserva por gasto') ||
           clean.includes('reserva programada') ||
           clean.includes('dinheiro reservado') ||
           clean.includes('reserva autom') ||
           clean.includes('dinheiro retirado') ||
           clean.includes('dinheiro guardado') ||
           clean.includes('cofrinho') ||
           (clean.includes('reserva') && (clean.includes('carro') || clean.includes('emergencia'))) ||
           (clean.includes('retirado') && (clean.includes('carro') || clean.includes('emergencia')));
}

/**
 * Classificador Exato de 5 Dimensões na Ingestão (Pluggy Open Finance):
 * - GRUPO 1: CARD_EXPENSE (Compras do Cartão -> compõem total_amount)
 * - GRUPO 2: BILL_PAYMENT (Pagamentos de Fatura na conta BANK -> compõem paid_amount; ou espelho "Pagamento recebido" no CREDIT)
 * - GRUPO 3: CARD_REFUND (Estornos/Créditos no Cartão -> abatem de total_amount ou pós-virada)
 * - GRUPO 4: VAULT_TX (Cofre/Reservas -> atualizam vault_balance)
 * - GRUPO 5: BANK_REGULAR_TX (Movimentações Bancárias Comuns -> show_on_home = false)
 */
export function classifyPluggyTransaction(txObj) {
    if (!txObj) {
        return { tx_group: 'BANK_REGULAR_TX', show_on_home: false, paymentSource: null };
    }
    const isCredit = txObj.accountType === 'CREDIT' || Boolean(txObj.isCreditCardTx);
    const isExpense = txObj.type === 'expense';
    const desc = txObj.desc || txObj.description || '';

    if (isCredit) {
        if (isExpense) {
            return {
                tx_group: 'CARD_EXPENSE',
                show_on_home: false,
                paymentSource: null
            };
        }
        // Transação de entrada (income/CREDIT) no cartão: verifica se é espelho de pagamento recebido ou estorno de compra
        if (isCardPaymentReceivedMirror(desc)) {
            return {
                tx_group: 'BILL_PAYMENT',
                show_on_home: false,
                paymentSource: 'CREDIT_MIRROR'
            };
        }
        return {
            tx_group: 'CARD_REFUND',
            show_on_home: false,
            paymentSource: null
        };
    }

    // Conta Bancária (accountType === 'BANK', isCreditCardTx === false)
    if (isExpense && isCardBillPayment(desc)) {
        return {
            tx_group: 'BILL_PAYMENT',
            show_on_home: false,
            paymentSource: 'BANK'
        };
    }

    if (isVaultTransactionDesc(desc)) {
        return {
            tx_group: 'VAULT_TX',
            show_on_home: false,
            paymentSource: null
        };
    }

    return {
        tx_group: 'BANK_REGULAR_TX',
        show_on_home: false,
        paymentSource: null
    };
}

export function mapPluggyCategory(rawCat, desc, isExpense) {
    const c = String(rawCat || '').toLowerCase();
    const d = String(desc || '').toLowerCase();
    if (!isExpense) {
        if (c.includes('salary') || c.includes('salário') || d.includes('salario')) return 'Salário';
        return 'Bonificação';
    }
    if (c.includes('cashback')) return 'Cashback';
    if (c.includes('food') || c.includes('restaurant') || c.includes('groceries') || c.includes('aliment') || c.includes('supermarket')) return 'Alimentação';
    if (c.includes('transport') || c.includes('automotive') || c.includes('taxi') || c.includes('fuel')) return 'Transporte';
    if (c.includes('housing') || c.includes('utilities') || c.includes('rent') || c.includes('moradia')) return 'Casa';
    if (c.includes('health') || c.includes('pharmacy') || c.includes('medical') || c.includes('saúde')) return 'Saúde';
    if (c.includes('education') || c.includes('educação')) return 'Educação';
    if (c.includes('service') || c.includes('subscription') || c.includes('digital') || c.includes('telecom')) return 'Assinatura';
    return 'Compras';
}

/**
 * Normaliza descrição do estabelecimento para assinatura de compra parcelada
 */
export function getCleanMerchantSignature(desc) {
    let s = String(desc || '')
        .toUpperCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/\(••••\s*\d+\)/g, '')
        .replace(/\(\d+\/\d+\)/g, '')
        .replace(/#\w+/g, '')
        .replace(/[^A-Z0-9]/g, '');

    if (s.startsWith('MERCADOLIVRE')) return 'MERCADOLIVRE';
    if (s.startsWith('SHOPEE')) return 'SHOPEE';
    if (s.startsWith('JIMCOM')) return 'JIMCOM';
    if (s.startsWith('MPWANTEDIND')) return 'MPWANTEDIND';
    if (s.startsWith('MPMP')) return 'MPMP';
    if (s.startsWith('IFDCAVANABURGU')) return 'IFDCAVANABURGU';

    return s.slice(0, 14);
}

export function shiftMonthKey(yearMonthStr, deltaMonths) {
    if (!yearMonthStr || typeof yearMonthStr !== 'string') return yearMonthStr;
    const parts = yearMonthStr.slice(0, 7).split('-');
    if (parts.length < 2) return yearMonthStr;
    let y = parseInt(parts[0], 10);
    let m = parseInt(parts[1], 10) - 1; // 0-indexed (0=Jan, 11=Dec)
    if (isNaN(y) || isNaN(m)) return yearMonthStr;
    m += deltaMonths;
    y += Math.floor(m / 12);
    m = ((m % 12) + 12) % 12;
    return y + '-' + String(m + 1).padStart(2, '0');
}

export function getPrevMonthKey(ym) {
    return shiftMonthKey(ym, -1);
}

export function getNextMonthKey(ym) {
    return shiftMonthKey(ym, 1);
}

/**
 * Resolve a configuração oficial de ciclo do cartão (closingDay e dueDay) a partir do banco de dados
 * (public.credit_cards / public.banks / settings_json), com fallback para os metadados da conta Pluggy.
 */
export function resolveCardCycleConfig(acc, creditBills = [], dbCards = [], dbBanks = []) {
    const accIdStr = String(acc?.id || '');
    const shortId = accIdStr.slice(0, 8);
    const expectedCardId = shortId ? `card_${shortId}` : '';
    const expectedBankId = shortId ? `bank_pluggy_${shortId}` : '';
    const accNameNorm = normalizeTextForClassification(acc?.name || '');

    // 1. Prioridade absoluta: Cartão cadastrado no banco de dados (public.credit_cards / settings_json.cards)
    const matchedCard = (Array.isArray(dbCards) ? dbCards : []).find(c => {
        if (!c) return false;
        const cId = String(c.id || '');
        const cBankId = String(c.bank_id || c.bankId || '');
        const cPluggyAccId = String(c.pluggy_account_id || c.pluggyAccountId || '');
        const cNameNorm = normalizeTextForClassification(c.name || c.alias || '');
        return (accIdStr && cPluggyAccId === accIdStr) ||
               (expectedCardId && cId === expectedCardId) ||
               (expectedBankId && cBankId === expectedBankId) ||
               (accNameNorm && cNameNorm && (cNameNorm.includes(accNameNorm) || accNameNorm.includes(cNameNorm)));
    });

    // 2. Segunda prioridade: Configuração de cartão vinculada ao registro do banco (public.banks / settings_json.banks)
    const matchedBank = (Array.isArray(dbBanks) ? dbBanks : []).find(b => {
        if (!b) return false;
        const bId = String(b.id || '');
        const bPluggyAccId = String(b.pluggy_account_id || b.pluggyAccountId || '');
        return (accIdStr && bPluggyAccId === accIdStr) || (expectedBankId && bId === expectedBankId);
    });

    let closingDay = Number(
        matchedCard?.closing_day ??
        matchedCard?.closingDay ??
        matchedBank?.card_closing_day ??
        matchedBank?.cardClosingDay ??
        0
    );
    let dueDay = Number(
        matchedCard?.due_day ??
        matchedCard?.dueDay ??
        matchedBank?.card_due_day ??
        matchedBank?.cardDueDay ??
        0
    );

    // 3. Fallback: Metadados oficiais de fechamento/vencimento da própria conta/fatura na Pluggy
    if (!closingDay || closingDay < 1 || closingDay > 31) {
        if (acc?.creditData?.balanceCloseDate) {
            closingDay = parseDateInSaoPaulo(acc.creditData.balanceCloseDate).day;
        } else if (Array.isArray(creditBills) && creditBills[0]?.billClosingDate) {
            closingDay = parseDateInSaoPaulo(creditBills[0].billClosingDate).day;
        } else if (Array.isArray(creditBills) && creditBills[0]?.closingDate) {
            closingDay = parseDateInSaoPaulo(creditBills[0].closingDate).day;
        } else {
            closingDay = 2; // Padrão homologado Mercado Pago (fecha dia 02)
        }
    }

    if (!dueDay || dueDay < 1 || dueDay > 31) {
        if (acc?.creditData?.balanceDueDate) {
            dueDay = parseDateInSaoPaulo(acc.creditData.balanceDueDate).day;
        } else if (Array.isArray(creditBills) && creditBills[0]?.dueDate) {
            dueDay = parseDateInSaoPaulo(creditBills[0].dueDate).day;
        } else {
            dueDay = 7; // Padrão homologado Mercado Pago (vence dia 07)
        }
    }

    closingDay = Math.max(1, Math.min(31, closingDay));
    dueDay = Math.max(1, Math.min(31, dueDay));
    const settlementWindowEnd = dueDay >= closingDay
        ? Math.min(31, Math.max(dueDay + 3, closingDay + 1, 10))
        : Math.min(31, Math.max(dueDay + 5, 10));

    return {
        closingDay,
        dueDay,
        settlementWindowEnd,
        cardId: matchedCard?.id || expectedCardId || 'card_default',
        bankId: matchedCard?.bank_id || matchedCard?.bankId || matchedBank?.id || expectedBankId || 'bank_default'
    };
}

/**
 * MOTOR CENTRAL E INVIOLÁVEL DE ALOCAÇÃO DE CICLO POR DATA DE VIRADA DO CARTÃO
 * Regras aplicadas:
 * 1. Compras realizadas até `closingDay` pertencem ao ciclo que fecha naquele dia (M).
 * 2. Compras realizadas a partir de `closingDay + 1` pertencem à próxima fatura (M + 1).
 * 3. Considera `closingDay` e `dueDay` na classificação de compras à vista, parceladas, parcelas futuras,
 *    pagamentos, antecipações, reembolsos e estornos.
 * 4. Não aplica deslocamento duplo se a transação já estiver associada ao ciclo correto (`billId`, `isSyntheticGapFill`, `isAlreadyCycleAllocated` ou `day === 1`).
 */
export function allocateTransactionToCardCycle(tx, cardConfig = {}) {
    if (!tx) return tx;
    const closingDay = Math.max(1, Math.min(31, Number(cardConfig.closingDay ?? tx.closingDayUsed ?? 2)));
    const dueDay = Math.max(1, Math.min(31, Number(cardConfig.dueDay ?? tx.dueDayUsed ?? 7)));
    const settlementWindowEnd = cardConfig.settlementWindowEnd || (
        dueDay >= closingDay
            ? Math.min(31, Math.max(dueDay + 3, closingDay + 1, 10))
            : Math.min(31, Math.max(dueDay + 5, 10))
    );

    const cls = tx.tx_group ? {
        tx_group: tx.tx_group,
        show_on_home: Boolean(tx.show_on_home),
        paymentSource: tx.paymentSource || null
    } : classifyPluggyTransaction(tx);

    const group = cls.tx_group;
    const rawDateCandidate = String(tx.rawDate || tx.date || tx.transactionDate || '');
    const dayNum = Math.max(1, Math.min(31, Number(tx.day || (rawDateCandidate.length >= 10 ? parseInt(rawDateCandidate.slice(8, 10), 10) : 1) || 1)));
    const rawMonth = String(tx.rawMonth || tx.month || (rawDateCandidate.length >= 7 ? rawDateCandidate.slice(0, 7) : '2026-11')).slice(0, 7);
    const descNorm = normalizeTextForClassification(tx.desc || tx.description || '');
    const isSynthetic = Boolean(tx.isSyntheticGapFill || String(tx.id || '').startsWith('syn_'));
    const hasBillId = Boolean(tx.billId || tx.creditCardMetadata?.billId);
    const isPreAllocated = Boolean(
        hasBillId ||
        isSynthetic ||
        tx.isAlreadyCycleAllocated ||
        (tx.accountType === 'CREDIT' && dayNum === 1 && !tx.rawPurchaseDate)
    );

    let cycleMonth = rawMonth;
    let settlementPhase = 'IN_CYCLE';

    if (group === 'BILL_PAYMENT') {
        if (dayNum > settlementWindowEnd) {
            // Pagamento realizado após a janela de vencimento (ex: 29/09, 13/10, 31/10, 17/08) ->
            // Antecipação dentro do ciclo aberto que fechará em `closingDay` do mês seguinte (M + 1)!
            cycleMonth = shiftMonthKey(rawMonth, 1);
            settlementPhase = 'ADVANCE_BEFORE_CLOSING';
        } else if (dayNum >= closingDay + 1 && dayNum <= settlementWindowEnd) {
            // Pagamento realizado após o fechamento até o vencimento (ex: 03/11, 06/11, 06/10, 04/09, 06/08) ->
            // Quita a fatura fechada no dia `closingDay` do próprio mês (M)!
            cycleMonth = rawMonth;
            settlementPhase = 'POST_CLOSING_PAYMENT';
        } else {
            // Pago até o dia de fechamento (`dayNum <= closingDay`)
            cycleMonth = rawMonth;
            if ((tx.accountType === 'BANK' && dayNum > 1) || descNorm.includes('antecipado')) {
                settlementPhase = 'ADVANCE_BEFORE_CLOSING';
            } else {
                settlementPhase = 'POST_CLOSING_PAYMENT';
            }
        }
    } else if (group === 'CARD_REFUND') {
        if (dayNum >= closingDay + 1 && dayNum <= settlementWindowEnd) {
            // Estorno/reembolso pós-fechamento (ex: 03/08 R$ 32,34) -> abate o saldo fechado da fatura do próprio mês M
            cycleMonth = rawMonth;
            settlementPhase = 'POST_CLOSING_REFUND';
        } else {
            cycleMonth = (!isPreAllocated && dayNum > closingDay)
                ? shiftMonthKey(rawMonth, 1)
                : rawMonth;
            settlementPhase = 'IN_CYCLE_REFUND';
        }
    } else if (group === 'CARD_EXPENSE' || tx.accountType === 'CREDIT') {
        // Verifica se temos data real da compra (rawPurchaseDate) para validar se já foi deslocada para o ciclo correto
        if (tx.rawPurchaseDate && !hasBillId && !isSynthetic) {
            const parsedPurchase = parseDateInSaoPaulo(tx.rawPurchaseDate);
            const pMonth = parsedPurchase.month;
            const pDay = parsedPurchase.day;
            // Se a compra foi à vista (ou 1ª parcela) no próprio mês `rawMonth` e após `closingDay`, pertence a M + 1!
            const instMatch = String(tx.inst || '').match(/^(\d+)\s*\/\s*(\d+)$/);
            const curInst = instMatch ? parseInt(instMatch[1], 10) : 1;
            const firstInstCycle = pDay > closingDay ? shiftMonthKey(pMonth, 1) : pMonth;
            const expectedCycleByClosingDay = shiftMonthKey(firstInstCycle, Math.max(0, curInst - 1));

            // Regra 5 e 6: Se `rawMonth` ainda está no mês bruto da compra (`pMonth`) quando `pDay > closingDay`,
            // aplicamos o ciclo determinado pela virada do cartão; se a Pluggy já enviou em `expectedCycleByClosingDay`, mantemos sem deslocar 2x!
            if (rawMonth === pMonth && pDay > closingDay && curInst === 1) {
                cycleMonth = expectedCycleByClosingDay;
            } else {
                cycleMonth = rawMonth;
            }
        } else if (!isPreAllocated && dayNum > closingDay) {
            cycleMonth = shiftMonthKey(rawMonth, 1);
        } else {
            cycleMonth = rawMonth;
        }
        settlementPhase = 'IN_CYCLE';
    } else {
        // Transações de conta corrente (VAULT_TX, BANK_REGULAR_TX) mantêm sempre seu mês real de ocorrência
        cycleMonth = rawMonth;
        settlementPhase = 'IN_CYCLE';
    }

    return {
        ...tx,
        rawMonth,
        rawDay: dayNum,
        tx_group: group,
        txGroup: group,
        show_on_home: cls.show_on_home,
        showOnHome: cls.show_on_home,
        paymentSource: cls.paymentSource,
        isSyntheticGapFill: isSynthetic,
        isAlreadyCycleAllocated: true,
        cycleMonth,
        settlementPhase,
        closingDayUsed: closingDay,
        dueDayUsed: dueDay
    };
}

/**
 * Preenchimento Inteligente de Lacunas de Parcelas (Sem multiplicação duplicada)
 * Respeita obrigatoriamente a data de corte (`closingDay`) do cartão antes de projetar lacunas.
 *
 * @param {Array<Object>} txList - Lista de transações da API
 * @param {Object} cardConfig - Configuração de ciclo do cartão ({ closingDay, dueDay })
 * @returns {Array<Object>} Transações originais + apenas as parcelas sintéticas faltantes
 */
export function fillInstallmentGaps(txList, cardConfig = { closingDay: 2, dueDay: 7 }) {
    if (!Array.isArray(txList)) return [];

    const nonInstallmentTxs = [];
    const installmentGroups = [];

    txList.forEach(rawTx => {
        if (!rawTx) return;
        // Ignora sintéticas antigas caso a lista seja reprocessada
        if (rawTx.isSyntheticGapFill || String(rawTx.id || '').startsWith('syn_')) return;

        // Garante que a transação-âncora já tenha seu ciclo (`cycleMonth`) validado pela data de virada do cartão
        const t = rawTx.cycleMonth ? rawTx : allocateTransactionToCardCycle(rawTx, cardConfig);
        // Se for compra de cartão, o mês de competência da parcela é o `cycleMonth`
        const effectiveTx = (t.accountType === 'CREDIT' && (t.tx_group === 'CARD_EXPENSE' || t.type === 'expense'))
            ? { ...t, month: t.cycleMonth, isAlreadyCycleAllocated: true }
            : t;

        let cur = null;
        let tot = null;

        if (effectiveTx.inst && typeof effectiveTx.inst === 'string') {
            const m = effectiveTx.inst.trim().match(/^(\d+)\s*\/\s*(\d+)$/);
            if (m) {
                cur = parseInt(m[1], 10);
                tot = parseInt(m[2], 10);
            }
        }
        if ((!tot || tot <= 1) && effectiveTx.creditCardMetadata) {
            tot = Number(effectiveTx.creditCardMetadata.totalInstallments || 0);
            cur = Number(effectiveTx.creditCardMetadata.installmentNumber || 1);
        }

        if (!tot || tot <= 1 || !cur) {
            nonInstallmentTxs.push(effectiveTx);
            return;
        }

        const merchantKey = getCleanMerchantSignature(effectiveTx.desc || effectiveTx.description);
        const cardNum = String(effectiveTx.cardNumber || '');
        const amt = Number(Number(effectiveTx.amount || 0).toFixed(2));
        const accKey = String(effectiveTx.accountId || 'acc');

        // Agrupa tolerando diferença de centavos de arredondamento da 1ª parcela (até R$ 0,25)
        let grp = installmentGroups.find(g =>
            g.accKey === accKey &&
            g.cardNumber === cardNum &&
            g.merchantKey === merchantKey &&
            g.tot === tot &&
            Math.abs(g.sampleAmount - amt) <= 0.25 &&
            !g.known.has(cur)
        );

        if (!grp) {
            grp = installmentGroups.find(g =>
                g.accKey === accKey &&
                g.cardNumber === cardNum &&
                g.merchantKey === merchantKey &&
                g.tot === tot &&
                Math.abs(g.sampleAmount - amt) <= 0.25
            );
        }

        if (!grp) {
            const roundedAmt = Math.round(amt);
            const groupKey = `${accKey}_${cardNum}_${merchantKey}_${tot}_${roundedAmt}`;
            grp = {
                groupKey,
                accKey,
                merchantKey,
                accountId: effectiveTx.accountId,
                accountName: effectiveTx.accountName,
                accountType: effectiveTx.accountType || 'CREDIT',
                cardNumber: cardNum,
                desc: effectiveTx.desc || effectiveTx.description,
                cat: effectiveTx.pluggyCategory || effectiveTx.cat || 'Compras',
                tot,
                sampleAmount: amt,
                known: new Map() // curNumber -> tx
            };
            installmentGroups.push(grp);
        }

        if (!grp.known.has(cur)) {
            grp.known.set(cur, effectiveTx);
        }
        // Parcelas 2..N possuem o valor base recorrente exato (sem os centavos de resto da 1ª parcela)
        if (cur > 1) {
            grp.sampleAmount = amt;
        }
    });

    const result = [...nonInstallmentTxs];

    installmentGroups.forEach(grp => {
        const sortedKnownCurs = Array.from(grp.known.keys()).sort((a, b) => a - b);
        const sampleCur = sortedKnownCurs[0];
        const sampleTx = grp.known.get(sampleCur);
        const sampleMonth = sampleTx.cycleMonth || sampleTx.month || (sampleTx.creditCardMetadata?.billForecastDate ? String(sampleTx.creditCardMetadata.billForecastDate).slice(0, 7) : '2026-11');

        for (let i = 1; i <= grp.tot; i++) {
            if (grp.known.has(i)) {
                result.push(grp.known.get(i));
            } else {
                const delta = i - sampleCur;
                const targetMonth = shiftMonthKey(sampleMonth, delta);
                const syntheticId = `syn_${grp.groupKey}_p${i}`;

                result.push({
                    ...sampleTx,
                    id: syntheticId,
                    fitid: `pluggy_${syntheticId}`,
                    rawMonth: targetMonth,
                    rawDay: 1,
                    month: targetMonth,
                    cycleMonth: targetMonth,
                    day: 1,
                    inst: `${i}/${grp.tot}`,
                    amount: grp.sampleAmount,
                    desc: grp.desc,
                    isSyntheticGapFill: true,
                    isAlreadyCycleAllocated: true,
                    closingDayUsed: Number(cardConfig?.closingDay || sampleTx.closingDayUsed || 2),
                    dueDayUsed: Number(cardConfig?.dueDay || sampleTx.dueDayUsed || 7)
                });
            }
        }
    });

    return result;
}

// Retrocompatibilidade
export function processInstallments(transaction) {
    return fillInstallmentGaps([transaction]);
}

/**
 * Motor Homologado de Conciliação de Faturas por Ciclo de Virada (`dashboard_financeiro_pluggy`)
 * Calcula para cada mês de fatura:
 * - grossCardExpenses (Compras à vista + parcelas do ciclo)
 * - inCycleRefunds (Estornos antes da virada)
 * - advancePaymentsBeforeClosing (Pagamentos antecipados antes da virada)
 * - postClosingPayments (Pagamentos pós-virada entre closingDay+1 e vencimento)
 * - postClosingRefunds (Reembolsos pós-virada entre closingDay+1 e vencimento)
 * - total_amount, paid_amount, pending_amount, status
 */
export function calculateHomologatedCardBills(allTransactions, officialBills = [], cardConfig = { closingDay: 2, dueDay: 7 }, nowSp = null) {
    const currentSp = nowSp || parseDateInSaoPaulo(new Date().toISOString());
    const closingDay = Math.max(1, Math.min(31, Number(cardConfig?.closingDay || 2)));
    const dueDay = Math.max(1, Math.min(31, Number(cardConfig?.dueDay || 7)));

    const allocatedTxs = (Array.isArray(allTransactions) ? allTransactions : []).map(tx =>
        tx.cycleMonth && tx.settlementPhase ? tx : allocateTransactionToCardCycle(tx, { closingDay, dueDay })
    );

    const monthsSet = new Set();
    allocatedTxs.forEach(t => {
        if (t.accountType === 'CREDIT' && t.cycleMonth) monthsSet.add(t.cycleMonth);
        if (t.tx_group === 'BILL_PAYMENT' && t.cycleMonth) monthsSet.add(t.cycleMonth);
    });
    (Array.isArray(officialBills) ? officialBills : []).forEach(b => {
        if (b?.month) monthsSet.add(b.month);
    });

    const sortedMonths = Array.from(monthsSet).sort();
    const billsByMonth = new Map();

    sortedMonths.forEach(m => {
        const officialBill = (Array.isArray(officialBills) ? officialBills : []).find(b => b.month === m) || null;
        const cycleTxs = allocatedTxs.filter(t => t.cycleMonth === m);

        // 1. Gasto Bruto de Compras + Parcelas do Ciclo (Grupo 1)
        const grossCardExpenses = round2(
            cycleTxs
                .filter(t => t.tx_group === 'CARD_EXPENSE')
                .reduce((acc, t) => acc + Number(t.amount || 0), 0)
        );

        // 2. Estornos ocorridos ANTES do fechamento (abatidos direto na fatura antes de closingDay)
        const inCycleRefunds = round2(
            cycleTxs
                .filter(t => t.tx_group === 'CARD_REFUND' && t.settlementPhase === 'IN_CYCLE_REFUND')
                .reduce((acc, t) => acc + Number(t.amount || 0), 0)
        );

        // 3. Pagamentos Antecipados feitos ANTES do fechamento (ex: 29/09, 13/10, 31/10, 17/08)
        // Fonte primária: conta BANK (evita duplicar com espelho "Pagamento recebido" no cartão)
        const advanceBankPays = round2(
            cycleTxs
                .filter(t => t.tx_group === 'BILL_PAYMENT' && t.paymentSource === 'BANK' && t.settlementPhase === 'ADVANCE_BEFORE_CLOSING')
                .reduce((acc, t) => acc + Number(t.amount || 0), 0)
        );
        const advanceCreditPays = round2(
            cycleTxs
                .filter(t => t.tx_group === 'BILL_PAYMENT' && t.paymentSource === 'CREDIT_MIRROR' && t.settlementPhase === 'ADVANCE_BEFORE_CLOSING')
                .reduce((acc, t) => acc + Number(t.amount || 0), 0)
        );
        const advancePaymentsBeforeClosing = advanceBankPays > 0 ? advanceBankPays : advanceCreditPays;

        // 4. Pagamentos feitos APÓS o fechamento (entre closingDay+1 e janela de vencimento, ex: 03/11, 06/10, 04/09, 06/08)
        const postClosingBankPays = round2(
            cycleTxs
                .filter(t => t.tx_group === 'BILL_PAYMENT' && t.paymentSource === 'BANK' && t.settlementPhase === 'POST_CLOSING_PAYMENT')
                .reduce((acc, t) => acc + Number(t.amount || 0), 0)
        );
        const postClosingCreditPays = round2(
            cycleTxs
                .filter(t => t.tx_group === 'BILL_PAYMENT' && t.paymentSource === 'CREDIT_MIRROR' && t.settlementPhase === 'POST_CLOSING_PAYMENT')
                .reduce((acc, t) => acc + Number(t.amount || 0), 0)
        );
        const postClosingPayments = postClosingBankPays > 0 ? postClosingBankPays : postClosingCreditPays;

        // 5. Reembolsos que caíram APÓS o fechamento (ex: 03/08 R$ 32,34)
        const postClosingRefunds = round2(
            cycleTxs
                .filter(t => t.tx_group === 'CARD_REFUND' && t.settlementPhase === 'POST_CLOSING_REFUND')
                .reduce((acc, t) => acc + Number(t.amount || 0), 0)
        );

        const netExpensesAfterInCycleRefunds = round2(Math.max(0, grossCardExpenses - inCycleRefunds));
        const calculatedClosingBalance = round2(Math.max(0, netExpensesAfterInCycleRefunds - advancePaymentsBeforeClosing));
        const totalSettledAfterClosing = round2(postClosingPayments + postClosingRefunds);

        // Determinação do total_amount (Total da Fatura no Mês):
        // - Se houver fatura oficial fechada no creditBills da Pluggy (ex: Out R$ 2.198,09, Set R$ 1.871,20, Ago R$ 1.897,59),
        //   ela já reflete o saldo oficial fechado no dia da virada.
        // - Caso contrário (fatura atual/futura calculada pelas compras + parcelas do ciclo, ex: Nov R$ 2.929,08, Dez R$ 647,26, Jan R$ 484,40),
        //   usamos `netExpensesAfterInCycleRefunds`.
        const officialTotal = officialBill ? round2(Number(officialBill.totalAmount ?? officialBill.total_amount ?? 0)) : 0;
        const totalAmount = officialTotal > 0 ? officialTotal : netExpensesAfterInCycleRefunds;

        // Determinação do paid_amount (Valor Abatido / Pago na Fatura):
        // - Pagamentos pós-fechamento + reembolsos pós-fechamento (ex: R$ 1.250,00 em 03/11; R$ 2.198,09 em 06/10; R$ 1.897,59 em Ago).
        // - Se o ciclo ainda estiver aberto (sem pagamento pós-fechamento) e houver antecipação no ciclo aberto, considera a antecipação.
        const isCycleAlreadyClosed = currentSp.month > m || (currentSp.month === m && currentSp.day > closingDay);
        const rawPaidAmount = totalSettledAfterClosing > 0
            ? totalSettledAfterClosing
            : (!isCycleAlreadyClosed && !officialBill ? advancePaymentsBeforeClosing : 0);
        const paidAmount = round2(Math.min(totalAmount, rawPaidAmount));
        const pendingAmount = round2(Math.max(0, totalAmount - paidAmount));

        const isPastMonth = currentSp.month > m;
        const status = (pendingAmount <= 0.009 || isPastMonth) ? 'PAID' : 'OPEN';

        billsByMonth.set(m, {
            month: m,
            closingDay,
            dueDay,
            dueDate: officialBill?.dueDate || `${m}-${String(dueDay).padStart(2, '0')}`,
            billClosingDate: officialBill?.billClosingDate || `${m}-${String(closingDay).padStart(2, '0')}`,
            grossCardExpenses,
            inCycleRefunds,
            advancePaymentsBeforeClosing,
            calculatedClosingBalance,
            postClosingPayments,
            postClosingRefunds,
            totalSettledAfterClosing,
            total_amount: totalAmount,
            totalAmount,
            paid_amount: paidAmount,
            paidAmount,
            pending_amount: pendingAmount,
            pendingAmount,
            status
        });
    });

    return billsByMonth;
}

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
            erro: 'Credenciais da Pluggy ausentes no servidor (PLUGGY_CLIENT_ID / PLUGGY_CLIENT_SECRET).'
        });
    }

    // Validação de autenticação JWT Supabase (OWASP A01 / A07)
    const authHeader = req.headers.authorization || '';
    const jwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
    if (!jwt || !SUPABASE_KEY) {
        return res.status(401).json({ erro: 'Token de autenticação ausente' });
    }

    const { itemId, from, to, triggerUpdate } = req.body || {};
    if (!itemId || !/^[a-zA-Z0-9-]{10,64}$/.test(String(itemId))) {
        return res.status(400).json({ erro: 'Identificador de conexão (itemId) inválido' });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    try {
        const { data: authData, error: authError } = await supabase.auth.getUser(jwt);
        if (authError || !authData?.user) {
            return res.status(401).json({ erro: 'Sessão inválida ou expirada' });
        }

        const user = authData.user;

        // 0. Carrega a configuração oficial de cartões (closing_day e due_day) do banco de dados
        let dbCards = [];
        let dbBanks = [];
        try {
            const [cardsRes, banksRes, profileRes] = await Promise.all([
                supabase.from('credit_cards').select('*').eq('user_id', user.id),
                supabase.from('banks').select('*').eq('user_id', user.id),
                supabase.from('profiles').select('settings_json').eq('id', user.id).maybeSingle()
            ]);
            const relCards = Array.isArray(cardsRes?.data) ? cardsRes.data : [];
            const relBanks = Array.isArray(banksRes?.data) ? banksRes.data : [];
            const settingsJson = profileRes?.data?.settings_json || {};
            const settingsCards = Array.isArray(settingsJson.cards) ? settingsJson.cards : [];
            const settingsBanks = Array.isArray(settingsJson.banks) ? settingsJson.banks : [];

            dbCards = [...settingsCards, ...relCards];
            dbBanks = [...settingsBanks, ...relBanks];
        } catch (dbCfgErr) {
            console.warn('Aviso ao ler configuração de cartões no Supabase:', dbCfgErr?.message || dbCfgErr);
        }

        const pluggyClient = new PluggyClient({
            clientId: PLUGGY_CLIENT_ID,
            clientSecret: PLUGGY_CLIENT_SECRET
        });

        // Se solicitado pelo botão "Sincronizar Todas", dispara atualização oficial na Pluggy
        if (triggerUpdate && typeof pluggyClient.updateItem === 'function') {
            try {
                console.log(`Disparando atualização forçada de item no Pluggy: ${itemId}`);
                await pluggyClient.updateItem(String(itemId));
                await sleep(1200);
            } catch (upErr) {
                console.warn(`Aviso ao chamar updateItem(${itemId}):`, upErr?.message || upErr);
            }
        }

        // 1. Busca Metadados da Conexão (Item)
        let itemData = null;
        for (let attempt = 0; attempt < 8; attempt++) {
            itemData = await pluggyClient.fetchItem(String(itemId));
            if (!itemData) {
                return res.status(404).json({ erro: 'Conexão bancária não encontrada na Pluggy' });
            }
            if (itemData.status !== 'UPDATING' || attempt === 7) break;
            await sleep(2000);
        }

        if (itemData.clientUserId && String(itemData.clientUserId) !== String(user.id)) {
            return res.status(403).json({ erro: 'Acesso negado a esta conexão bancária' });
        }

        // 2. Busca todas as Contas (Corrente e Cartões de Crédito)
        let accounts = [];
        for (let attempt = 0; attempt < 2; attempt++) {
            const accResp = await pluggyClient.fetchAccounts(String(itemId));
            accounts = Array.isArray(accResp?.results) ? accResp.results : [];
            if (accounts.length > 0 || attempt === 1) break;
            await sleep(1500);
        }

        // Estruturas de saída especializadas
        const normalizedAccounts = [];
        const normalizedBills = [];
        const cardStatementTransactions = []; // Extrato detalhado do cartão (sem poluir Visão Mensal)
        const bankAccountTransactions = [];   // Transações de conta corrente
        const monthlyConsolidatedBills = [];  // Fatura consolidada por mês para a Visão Mensal
        const accountCycleConfigs = new Map(); // accountId -> { closingDay, dueDay, settlementWindowEnd }
        const nowSp = parseDateInSaoPaulo(new Date().toISOString());

        // Processa cada conta aplicando a REGRA 1 (Separação BANK vs CREDIT) e a DATA DE VIRADA DO CARTÃO
        await Promise.all(accounts.map(async (acc) => {
            if (!acc.id || !/^[a-zA-Z0-9-]+$/.test(String(acc.id))) return;

            const isCredit = acc.type === 'CREDIT';
            const rawBalance = Number(acc.balance || 0);

            let txResults = [];
            let creditBills = [];

            // REGRA 2: Leitura de Faturas Fechadas e Atuais (creditBills)
            if (isCredit && typeof pluggyClient.fetchCreditCardBills === 'function') {
                try {
                    const billsResp = await pluggyClient.fetchCreditCardBills(String(acc.id));
                    if (Array.isArray(billsResp?.results)) {
                        creditBills = billsResp.results;
                    }
                } catch (bErr) {
                    console.warn(`Aviso ao buscar faturas da conta ${acc.id}:`, bErr?.message || bErr);
                }
            }

            // Resolve a configuração oficial de virada (`closingDay`) e vencimento (`dueDay`) do cartão no banco de dados
            const cardCycleConfig = isCredit
                ? resolveCardCycleConfig(acc, creditBills, dbCards, dbBanks)
                : { closingDay: 2, dueDay: 7, settlementWindowEnd: 10 };
            accountCycleConfigs.set(String(acc.id), cardCycleConfig);

            const rawCreditLimit = Number(
                acc.creditData?.creditLimit ??
                acc.creditLimit ??
                acc.limit ??
                acc.creditData?.creditLimitCash ??
                0
            );
            let rawAvailableLimit = Number(
                acc.creditData?.availableCreditLimit ??
                acc.availableCreditLimit ??
                acc.availableLimit ??
                acc.creditData?.availableCreditLimitCash ??
                0
            );
            let rawCreditUsed = isCredit ? Math.abs(Number(rawBalance.toFixed(2))) : 0;
            if (Number(acc.creditData?.creditLimitUsed) > 0 && rawCreditUsed <= 0) {
                rawCreditUsed = Number(acc.creditData.creditLimitUsed);
            }
            if (rawCreditLimit > 0 && rawAvailableLimit > 0 && rawCreditUsed <= 0) {
                rawCreditUsed = Math.max(0, Number((rawCreditLimit - rawAvailableLimit).toFixed(2)));
            } else if (rawCreditLimit > 0 && rawCreditUsed > 0 && rawAvailableLimit <= 0) {
                rawAvailableLimit = Math.max(0, Number((rawCreditLimit - rawCreditUsed).toFixed(2)));
            }

            normalizedAccounts.push({
                id: String(acc.id),
                name: String(acc.name || (isCredit ? 'Cartão de Crédito' : 'Conta Corrente')),
                type: isCredit ? 'CREDIT' : 'BANK',
                subtype: String(acc.subtype || ''),
                number: String(acc.number || ''),
                balance: isCredit ? 0 : Number(rawBalance.toFixed(2)),
                creditLimitUsed: rawCreditUsed,
                creditLimit: rawCreditLimit,
                availableCreditLimit: rawAvailableLimit,
                balanceDueDate: acc.creditData?.balanceDueDate || null,
                balanceCloseDate: acc.creditData?.balanceCloseDate || null,
                closingDay: cardCycleConfig.closingDay,
                dueDay: cardCycleConfig.dueDay
            });

            // REGRA 3: Coleta exaustiva de transações e parcelas via V2 (Cursor /v2/transactions)
            const allTxsMap = new Map();
            const cursorOptions = {};
            const safeOneYearAgo = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

            if (from) {
                cursorOptions.dateFrom = String(from).slice(0, 10);
            } else if (isCredit) {
                cursorOptions.dateFrom = safeOneYearAgo;
            }
            if (to) {
                cursorOptions.dateTo = String(to).slice(0, 10);
            }

            try {
                if (typeof pluggyClient.fetchTransactionsCursor === 'function') {
                    let page = await pluggyClient.fetchTransactionsCursor(String(acc.id), cursorOptions);
                    if (Array.isArray(page?.results)) {
                        page.results.forEach(t => { if (t && t.id) allTxsMap.set(String(t.id), t); });
                    }
                    let nextUrl = page?.next;
                    let pageCount = 1;
                    while (nextUrl && pageCount < 50) {
                        try {
                            const afterParam = new URL(nextUrl, 'https://api.pluggy.ai').searchParams.get('after');
                            if (!afterParam) break;
                            page = await pluggyClient.fetchTransactionsCursor(String(acc.id), { ...cursorOptions, after: afterParam });
                            if (Array.isArray(page?.results)) {
                                page.results.forEach(t => { if (t && t.id) allTxsMap.set(String(t.id), t); });
                            }
                            nextUrl = page?.next;
                            pageCount++;
                        } catch (_) {
                            break;
                        }
                    }
                } else if (typeof pluggyClient.fetchAllTransactions === 'function') {
                    const fullList = await pluggyClient.fetchAllTransactions(String(acc.id), cursorOptions);
                    if (Array.isArray(fullList)) {
                        fullList.forEach(t => { if (t && t.id) allTxsMap.set(String(t.id), t); });
                    }
                }
            } catch (txErr) {
                console.warn(`Aviso ao coletar transações v2 para ${acc.id}:`, txErr?.message || txErr);
            }

            // Garante associação da fatura para transações que possam não ter o billId preenchido
            if (isCredit && Array.isArray(creditBills) && creditBills.length > 0) {
                creditBills.forEach(bill => {
                    if (!bill.id || !bill.dueDate) return;
                    const bMonth = String(bill.dueDate).slice(0, 7);
                    allTxsMap.forEach(t => {
                        if (!t.creditCardMetadata) t.creditCardMetadata = {};
                        if (!t.creditCardMetadata.billId && t.date && String(t.date).slice(0, 7) === bMonth) {
                            t.creditCardMetadata.billId = bill.id;
                        }
                        if (!t.creditCardMetadata.billForecastDate && bill.dueDate) {
                            t.creditCardMetadata.billForecastDate = bMonth;
                        }
                    });
                });
            }

            txResults = Array.from(allTxsMap.values());

            // Normaliza as Faturas Oficiais (creditBills) respeitando closingDay e dueDay do cartão
            creditBills.forEach((b) => {
                const totalAmt = Number(b.totalAmount || 0);
                if (totalAmt <= 0.009) return;

                const dueParsed = parseDateInSaoPaulo(b.dueDate);
                const billMonth = dueParsed.month;
                const billDay = cardCycleConfig.dueDay || dueParsed.day;
                const closeDay = cardCycleConfig.closingDay || 2;

                const dueDateStr = b.dueDate ? String(b.dueDate).slice(0, 10) : `${billMonth}-${String(billDay).padStart(2, '0')}`;
                const closeDateStr = b.billClosingDate
                    ? String(b.billClosingDate).slice(0, 10)
                    : `${billMonth}-${String(closeDay).padStart(2, '0')}`;
                const isPastDue = nowSp.month > billMonth || (nowSp.month === billMonth && nowSp.day >= billDay);

                const billEntry = {
                    id: String(b.id || `bill_${acc.id}_${billMonth}`),
                    accountId: String(acc.id),
                    cardName: String(acc.name || 'Cartão de Crédito'),
                    month: billMonth,
                    dueDate: dueDateStr,
                    dueDay: billDay,
                    closingDay: closeDay,
                    billClosingDate: closeDateStr,
                    totalAmount: Number(totalAmt.toFixed(2)),
                    minimumPaymentAmount: b.minimumPaymentAmount ? Number(Number(b.minimumPaymentAmount).toFixed(2)) : null,
                    status: isPastDue ? 'PAID' : 'OPEN',
                    raw_data: b,
                    finance_charges: b.financeCharges || null
                };
                normalizedBills.push(billEntry);
            });

            // Processa as Transações detalhadas — REGRA 3 + MOTOR DE CICLO (DATA DE VIRADA)
            const rawCardTxs = [];

            txResults.forEach((t) => {
                const rawAmt = Number(t.amount ?? t.amountInAccountCurrency ?? 0);
                if (Math.abs(rawAmt) < 0.009) return;

                const ccMeta = t.creditCardMetadata || null;
                const isExpense = t.type === 'DEBIT' || (!isCredit && rawAmt < 0);
                const hasForecastOrPost = Boolean(ccMeta?.billForecastDate || ccMeta?.billPostDate);
                const hasBillId = Boolean(ccMeta?.billId);

                let targetDateStr = t.date;
                if (isCredit) {
                    targetDateStr = ccMeta?.billForecastDate || ccMeta?.billPostDate || t.date;
                } else {
                    targetDateStr = t.date || ccMeta?.purchaseDate;
                }

                const parsedDate = parseDateInSaoPaulo(targetDateStr);
                const targetMonth = parsedDate.month;
                const targetDay = parsedDate.day;

                const totalInst = Number(ccMeta?.totalInstallments || 0);
                const curInst = Number(ccMeta?.installmentNumber || 1);
                const instLabel = totalInst > 1 ? `${Math.min(curInst, totalInst)}/${totalInst}` : 'Única';

                let baseDesc = String(t.description || t.descriptionRaw || t.merchant?.name || 'Movimentação Open Finance').trim();
                const cardSuffix = ccMeta?.cardNumber || acc.number || '';
                const shortCode = String(t.id || '').slice(0, 4);

                if (baseDesc.toUpperCase() === 'PGTO' || baseDesc.length <= 4) {
                    const parts = [baseDesc];
                    if (acc.name) parts.push(acc.name);
                    if (cardSuffix) parts.push(`•••• ${cardSuffix}`);
                    if (shortCode) parts.push(`#${shortCode}`);
                    baseDesc = parts.join(' • ');
                } else if (cardSuffix && isCredit && !baseDesc.includes(cardSuffix)) {
                    baseDesc = `${baseDesc} (•••• ${cardSuffix})`;
                }

                const catName = mapPluggyCategory(t.category, baseDesc, isExpense);
                const baseTxObj = {
                    id: String(t.id),
                    fitid: `pluggy_${t.id}`,
                    accountId: String(acc.id),
                    accountName: String(acc.name || itemData.connector?.name || 'Conta'),
                    accountType: isCredit ? 'CREDIT' : 'BANK',
                    cardNumber: String(cardSuffix),
                    month: targetMonth,
                    day: targetDay,
                    rawMonth: targetMonth,
                    rawDay: targetDay,
                    rawPurchaseDate: ccMeta?.purchaseDate || t.date || null,
                    billId: ccMeta?.billId || null,
                    isAlreadyCycleAllocated: Boolean(isCredit && (hasBillId || (hasForecastOrPost && parsedDate.isYearMonthOnly))),
                    type: isExpense ? 'expense' : 'income',
                    desc: baseDesc,
                    amount: Number(Math.abs(rawAmt).toFixed(2)),
                    inst: instLabel,
                    status: String(t.status || 'POSTED'),
                    pluggyCategory: catName,
                    isCreditCardTx: isCredit,
                    // Campos estruturados completos e payload bruto íntegro
                    raw_data: t,
                    raw_description: t.descriptionRaw || t.description || null,
                    purchase_date: ccMeta?.purchaseDate || t.date || null,
                    installment_number: ccMeta?.installmentNumber ? Number(ccMeta.installmentNumber) : (totalInst > 1 ? curInst : null),
                    total_installments: totalInst > 1 ? totalInst : null,
                    bill_id: ccMeta?.billId || null,
                    merchant_data: t.merchant || null,
                    payment_data: t.paymentData || null,
                    pluggy_status: String(t.status || 'POSTED')
                };

                const allocatedTx = allocateTransactionToCardCycle(baseTxObj, cardCycleConfig);

                if (isCredit) {
                    // Compras e estornos de cartão assumem o ciclo oficial determinado pela data de virada
                    rawCardTxs.push({
                        ...allocatedTx,
                        rawMonth: targetMonth,
                        rawDay: targetDay,
                        month: (allocatedTx.tx_group === 'CARD_EXPENSE' || allocatedTx.tx_group === 'CARD_REFUND')
                            ? allocatedTx.cycleMonth
                            : allocatedTx.month,
                        isAlreadyCycleAllocated: true
                    });
                } else {
                    bankAccountTransactions.push({
                        ...allocatedTx,
                        rawMonth: targetMonth,
                        rawDay: targetDay,
                        month: targetMonth
                    });
                }
            });

            // Preenchimento Inteligente de Lacunas de Parcelas respeitando a data de virada do cartão
            if (isCredit) {
                const filledCardTxs = fillInstallmentGaps(rawCardTxs, cardCycleConfig);
                filledCardTxs.forEach((ctx) => {
                    const allocated = ctx.cycleMonth ? ctx : allocateTransactionToCardCycle(ctx, cardCycleConfig);
                    cardStatementTransactions.push({
                        ...allocated,
                        month: allocated.cycleMonth || allocated.month,
                        isAlreadyCycleAllocated: true
                    });
                });
            }
        }));

        // Determina a configuração de ciclo primária dos cartões para alocar os pagamentos de fatura da conta BANK
        const defaultCreditConfig = Array.from(accountCycleConfigs.values()).find(c => c && c.closingDay) || {
            closingDay: 2,
            dueDay: 7,
            settlementWindowEnd: 10
        };

        // Re-aloca as transações da conta bancária (especialmente Grupo 2: BILL_PAYMENT) usando o closingDay/dueDay oficial do cartão,
        // preservando SEMPRE `month` como o mês real do extrato bancário (`rawMonth`) para nunca corromper re-sincronizações
        for (let i = 0; i < bankAccountTransactions.length; i++) {
            const btx = bankAccountTransactions[i];
            const reallocated = allocateTransactionToCardCycle({
                ...btx,
                month: btx.rawMonth || btx.month,
                day: btx.rawDay || btx.day
            }, defaultCreditConfig);
            bankAccountTransactions[i] = {
                ...reallocated,
                month: btx.rawMonth || btx.month,
                rawMonth: btx.rawMonth || btx.month,
                rawDay: btx.rawDay || btx.day
            };
        }

        // =========================================================================
        // CONSOLIDAÇÃO FIXA DETERMINÍSTICA DAS 5 DIMENSÕES + MOTOR DE VIRADA DO CARTÃO
        // 1. Saldo fixo do Cofre/Reservas (GRUPO 4 - VAULT_TX) por conta bancária
        // 2. Conciliação de Faturas por Ciclo (Compras + Parcelas - Estornos - Antecipações / Pagamentos Pós-Virada)
        // =========================================================================
        normalizedAccounts.forEach(acc => {
            if (acc.type === 'BANK') {
                let vBal = 0;
                bankAccountTransactions.forEach(btx => {
                    if (String(btx.accountId) !== String(acc.id)) return;
                    if (btx.tx_group !== 'VAULT_TX') return;
                    const cleanDesc = normalizeTextForClassification(btx.desc);
                    const isWithdrawal = cleanDesc.includes('retirado') || cleanDesc.includes('resgate') || btx.type === 'income';
                    if (isWithdrawal) vBal -= Number(btx.amount || 0);
                    else vBal += Number(btx.amount || 0);
                });
                acc.vaultBalance = Number(Math.max(0, vBal).toFixed(2));
                acc.vault_balance = acc.vaultBalance;
            } else {
                acc.vaultBalance = 0;
                acc.vault_balance = 0;
            }
        });

        // Para cada conta de cartão (CREDIT), executa o motor homologado `calculateHomologatedCardBills`
        const creditAccounts = normalizedAccounts.filter(a => a.type === 'CREDIT');
        const finalNormalizedBills = [];

        creditAccounts.forEach(cAcc => {
            const cardCfg = accountCycleConfigs.get(String(cAcc.id)) || defaultCreditConfig;
            const accCardTxs = cardStatementTransactions.filter(t => String(t.accountId) === String(cAcc.id));
            const accOfficialBills = normalizedBills.filter(b => String(b.accountId) === String(cAcc.id));

            const homologatedMap = calculateHomologatedCardBills(
                [...accCardTxs, ...bankAccountTransactions],
                accOfficialBills,
                cardCfg,
                nowSp
            );

            homologatedMap.forEach((bCalc, mKey) => {
                if (bCalc.total_amount <= 0.009) return;
                const existingOfficial = accOfficialBills.find(ob => ob.month === mKey);
                const billId = existingOfficial?.id || `bill_${cAcc.id}_${mKey}`;
                const cardSuffix = cAcc.number ? ` (•••• ${cAcc.number})` : '';
                const isForecast = !existingOfficial;

                const billEntry = {
                    id: String(billId),
                    accountId: String(cAcc.id),
                    cardName: String(cAcc.name || 'Cartão de Crédito'),
                    month: mKey,
                    dueDate: bCalc.dueDate,
                    dueDay: bCalc.dueDay,
                    closingDay: bCalc.closingDay,
                    billClosingDate: bCalc.billClosingDate,
                    totalAmount: bCalc.total_amount,
                    total_amount: bCalc.total_amount,
                    paidAmount: bCalc.paid_amount,
                    paid_amount: bCalc.paid_amount,
                    pendingAmount: bCalc.pending_amount,
                    pending_amount: bCalc.pending_amount,
                    advancePaidAmount: bCalc.advancePaymentsBeforeClosing,
                    advance_paid_amount: bCalc.advancePaymentsBeforeClosing,
                    inCycleRefunds: bCalc.inCycleRefunds,
                    in_cycle_refunds: bCalc.inCycleRefunds,
                    postClosingRefunds: bCalc.postClosingRefunds,
                    post_closing_refunds: bCalc.postClosingRefunds,
                    minimumPaymentAmount: existingOfficial?.minimumPaymentAmount || null,
                    status: bCalc.status
                };
                finalNormalizedBills.push(billEntry);

                const isPaidBool = bCalc.status === 'PAID';
                // O valor da fatura consolidada (amount) representa SEMPRE o total da fatura no mês (total_amount),
                // enquanto paid_amount e pending_amount contabilizam o que já foi pago e o que falta pagar.
                const effectiveAmount = bCalc.total_amount;

                monthlyConsolidatedBills.push({
                    id: `bill_${billId}`,
                    fitid: isForecast ? `pluggy_bill_${cAcc.id}_${mKey}` : `pluggy_bill_${billId}`,
                    accountId: String(cAcc.id),
                    accountName: String(cAcc.name || 'Cartão de Crédito'),
                    accountType: 'CREDIT',
                    month: mKey,
                    day: bCalc.dueDay,
                    closingDay: bCalc.closingDay,
                    dueDay: bCalc.dueDay,
                    type: 'expense',
                    desc: isForecast
                        ? `Fatura ${cAcc.name || 'Cartão'}${cardSuffix} (Previsão)`
                        : `Fatura ${cAcc.name || 'Cartão'}${cardSuffix}`,
                    amount: effectiveAmount,
                    total_amount: bCalc.total_amount,
                    invoiceTotal: bCalc.total_amount,
                    paid_amount: bCalc.paid_amount,
                    paidAmount: bCalc.paid_amount,
                    pending_amount: bCalc.pending_amount,
                    pendingAmount: bCalc.pending_amount,
                    advance_paid_amount: bCalc.advancePaymentsBeforeClosing,
                    bill_status: bCalc.status,
                    billStatus: bCalc.status,
                    inst: 'Fatura',
                    status: 'POSTED',
                    paid: isPaidBool,
                    pluggyCategory: 'Cartão de Crédito',
                    isConsolidatedBill: true,
                    tx_group: 'CONSOLIDATED_BILL',
                    txGroup: 'CONSOLIDATED_BILL',
                    show_on_home: true,
                    showOnHome: true
                });
            });
        });

        // Gravação direta idempotente na tabela public.credit_bills do Supabase
        const spTimestamp = getSaoPauloTimestamp();
        if (finalNormalizedBills.length > 0 && user?.id) {
            try {
                const creditBillRows = finalNormalizedBills.map(b => ({
                    id: String(b.id),
                    user_id: user.id,
                    account_id: String(b.accountId),
                    bank_id: `bank_pluggy_${String(b.accountId).slice(0, 8)}`,
                    card_id: `card_${String(b.accountId).slice(0, 8)}`,
                    card_name: String(b.cardName || 'Cartão de Crédito'),
                    month: String(b.month),
                    due_date: b.dueDate || null,
                    closing_date: b.billClosingDate || null,
                    total_amount: b.total_amount,
                    paid_amount: b.paid_amount,
                    pending_amount: b.pending_amount,
                    minimum_payment_amount: b.minimumPaymentAmount || null,
                    status: b.status,
                    raw_data: b.raw_data || null,
                    finance_charges: b.finance_charges || null,
                    updated_at: spTimestamp
                }));
                await supabase.from('credit_bills').upsert(creditBillRows, { onConflict: 'id' });
            } catch (cbErr) {
                console.warn('Aviso ao gravar credit_bills diretamente na sincronização:', cbErr?.message || cbErr);
            }
        }

        // Gravação direta idempotente na tabela public.bank_statements (todas as transações com raw_data e campos estruturados)
        const allStmtsToSave = [...cardStatementTransactions, ...bankAccountTransactions];
        if (allStmtsToSave.length > 0 && user?.id) {
            try {
                const stmtRows = allStmtsToSave.map(s => ({
                    user_id: user.id,
                    fitid: String(s.fitid || `pluggy_${s.id}`),
                    bank_id: `bank_pluggy_${String(s.accountId || '').slice(0, 8)}`,
                    month: String(s.month || '2026-11'),
                    day: Number(s.day || 1),
                    type: s.type === 'expense' ? 'expense' : 'income',
                    description: String(s.desc || s.description || 'Movimentação Open Finance'),
                    amount: Number(Number(s.amount || 0).toFixed(2)),
                    tx_group: String(s.tx_group || s.txGroup || 'BANK_REGULAR_TX'),
                    show_on_home: Boolean(s.show_on_home),
                    account_type: String(s.accountType || (s.isCreditCardTx ? 'CREDIT' : 'BANK')),
                    is_credit_card_tx: Boolean(s.isCreditCardTx),
                    pluggy_category: String(s.pluggyCategory || 'Compras'),
                    raw_data: s.raw_data || null,
                    raw_description: s.raw_description || null,
                    purchase_date: s.purchase_date || null,
                    installment_number: s.installment_number ?? null,
                    total_installments: s.total_installments ?? null,
                    bill_id: s.bill_id || null,
                    merchant_data: s.merchant_data || null,
                    payment_data: s.payment_data || null,
                    pluggy_status: s.pluggy_status || 'POSTED'
                }));

                // Inserção em lotes de 100 para alta performance e segurança
                for (let i = 0; i < stmtRows.length; i += 100) {
                    const chunk = stmtRows.slice(i, i + 100);
                    const { error: upsertErr } = await supabase
                        .from('bank_statements')
                        .upsert(chunk, { onConflict: 'user_id,fitid' });
                    if (upsertErr) {
                        console.warn('Aviso no upsert de bank_statements chunk:', upsertErr.message || upsertErr);
                    }
                }
            } catch (bsErr) {
                console.warn('Aviso ao gravar bank_statements diretamente:', bsErr?.message || bsErr);
            }
        }

        // Atualização dos saldos em public.banks
        for (const acc of normalizedAccounts) {
            try {
                const isCredit = acc.type === 'CREDIT';
                await supabase
                    .from('banks')
                    .update({
                        pluggy_direct_balance: isCredit ? 0 : Number(acc.balance || 0),
                        vault_balance: acc.vaultBalance || 0,
                        updated_at: spTimestamp
                    })
                    .eq('user_id', user.id)
                    .eq('pluggy_account_id', String(acc.id));
            } catch (bErr) {
                console.warn('Aviso ao atualizar saldo do banco:', bErr?.message);
            }
        }

        // REGRA 4: Objeto de auditoria bruta com 100% de todas as transações
        const rawDebugPayload = {
            capturedAt: spTimestamp,
            item: {
                id: String(itemData.id),
                connectorName: String(itemData.connector?.name || ''),
                status: String(itemData.status || '')
            },
            accounts: normalizedAccounts,
            creditBills: finalNormalizedBills,
            totalCardTransactions: cardStatementTransactions.length,
            totalBankTransactions: bankAccountTransactions.length,
            totalMonthlyBills: monthlyConsolidatedBills.length,
            totalAllTransactions: cardStatementTransactions.length + bankAccountTransactions.length,
            allTransactions: [...cardStatementTransactions, ...bankAccountTransactions],
            cardTransactions: cardStatementTransactions,
            bankTransactions: bankAccountTransactions
        };

        return res.status(200).json({
            item: {
                id: String(itemData.id),
                status: String(itemData.status || 'UPDATED'),
                connectorName: String(itemData.connector?.name || 'Instituição Open Finance'),
                primaryColor: String(itemData.connector?.primaryColor || '4f46e5')
            },
            accounts: normalizedAccounts,
            creditBills: finalNormalizedBills,
            monthlyTransactions: monthlyConsolidatedBills,
            cardStatementTransactions: cardStatementTransactions,
            bankStatementTransactions: bankAccountTransactions,
            rawDebugPayload: rawDebugPayload
        });
    } catch (error) {
        console.error('Erro em /api/pluggy-sync:', error);
        return res.status(500).json({ erro: 'Erro ao sincronizar dados da Pluggy: ' + (error?.message || 'Erro interno') });
    }
}
