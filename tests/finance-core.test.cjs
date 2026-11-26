'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const FinanCore = require('../js/finance-core.js');
const pluggySync = require('../api/pluggy-sync.js');

test('Saldo previsto por conta com saldo zero + entradas e saídas pendentes mantém coerência matemática', () => {
    const txs = [
        { id: 1, month: '2026-11', day: 5, type: 'income', amount: 3000, bankId: 'bank_mp', paid: false },
        { id: 2, month: '2026-11', day: 10, type: 'expense', amount: 1200, bankId: 'bank_mp', paid: false },
        { id: 3, month: '2026-11', day: 15, type: 'expense', amount: 300, bankId: 'bank_mp', paid: false }
    ];
    const metrics = FinanCore.computeBankAccountMonthSummary({
        transactions: txs,
        bankId: 'bank_mp',
        monthKey: '2026-11',
        pluggyLiveBalance: 0
    });

    assert.equal(metrics.currentBalance, 0);
    assert.equal(metrics.pendingIncomeMonth, 3000);
    assert.equal(metrics.pendingExpenseMonth, 1500);
    assert.equal(metrics.pendingNetMonth, 1500);
    assert.equal(metrics.projectedBalance, 1500);
});

test('Previsão operacional do mês soma saldo atual + receitas pendentes - despesas pendentes sem duplicar fatura paga parcialmente', () => {
    const operationalMonthTxs = [
        { id: 10, month: '2026-11', day: 5, type: 'income', amount: 4000, paid: true },
        { id: 11, month: '2026-11', day: 25, type: 'income', amount: 1000, paid: false },
        { id: 12, month: '2026-11', day: 10, type: 'expense', amount: 500, paid: false },
        {
            id: 'bill_mp_2026-11',
            month: '2026-11',
            day: 7,
            type: 'expense',
            amount: 2000,
            total_amount: 2000,
            paid_amount: 1200,
            pending_amount: 800,
            isConsolidatedBill: true,
            paid: false
        }
    ];

    const summary = FinanCore.computeMonthOperationalForecast(operationalMonthTxs, 1500);
    assert.equal(summary.totalIncome, 5000);
    assert.equal(summary.receivedIncome, 4000);
    assert.equal(summary.pendingIncome, 1000);
    assert.equal(summary.totalExpense, 2500);
    assert.equal(summary.paidExpense, 1200);
    assert.equal(summary.pendingExpense, 1300); // 500 avulsa + 800 restante da fatura
    // 1500 (atual) + 1000 (receita pendente) - 1300 (despesa pendente) = 1200
    assert.equal(summary.projectedEndOfMonthBalance, 1200);
});

test('Cartão com limite próximo ao teto calcula usado, disponível e percentual corretamente', () => {
    const limits = FinanCore.computeCardLimitMetrics({
        creditLimit: 5600,
        availableCreditLimit: 209.09,
        creditLimitUsed: 5390.91
    });
    assert.equal(limits.total, 5600);
    assert.equal(limits.available, 209.09);
    assert.equal(limits.used, 5390.91);
    assert.equal(limits.pctUsed, 96);

    // Quando o banco informa apenas total e disponível, calcula o usado por diferença
    const inferredUsed = FinanCore.computeCardLimitMetrics({
        creditLimit: 350,
        availableCreditLimit: 326,
        creditLimitUsed: 0
    });
    assert.equal(inferredUsed.used, 24);
    assert.equal(inferredUsed.pctUsed, 7);
});

test('Motor de faturas e parcelas: pagamentos parciais, antecipações, estornos e virada de ciclo', () => {
    const cardConfig = { closingDay: 2, dueDay: 7 };
    const txs = [
        // Compra antes do fechamento (dia 01/11 <= closingDay 2 -> ciclo 2026-11)
        {
            id: 'tx_spot_1',
            accountType: 'CREDIT',
            isCreditCardTx: true,
            type: 'expense',
            desc: 'Mercado Dia 1',
            amount: 500,
            rawDate: '2026-11-01',
            purchase_date: '2026-11-01'
        },
        // Compra após o fechamento (dia 05/11 > closingDay 2 -> ciclo 2026-12)
        {
            id: 'tx_spot_2',
            accountType: 'CREDIT',
            isCreditCardTx: true,
            type: 'expense',
            desc: 'Farmácia Dia 5',
            amount: 200,
            rawDate: '2026-11-05',
            purchase_date: '2026-11-05'
        },
        // Estorno dentro do ciclo de dezembro (dia 15/11 > closingDay 2 e > janela -> ciclo 2026-12)
        {
            id: 'tx_refund_1',
            accountType: 'CREDIT',
            isCreditCardTx: true,
            type: 'income',
            desc: 'Estorno Farmácia',
            amount: 50,
            rawDate: '2026-11-15',
            purchase_date: '2026-11-15'
        },
        // Pagamento parcial na conta corrente após fechamento de novembro (dia 06/11 entre closingDay+1 e vencimento)
        {
            id: 'tx_pay_nov',
            accountType: 'BANK',
            isCreditCardTx: false,
            type: 'expense',
            desc: 'Pagamento de fatura cartão',
            amount: 300,
            rawDate: '2026-11-06',
            purchase_date: '2026-11-06'
        }
    ];

    const bills = pluggySync.calculateHomologatedCardBills(
        txs,
        [],
        cardConfig,
        { year: '2026', monthNum: 11, month: '2026-11', day: 20 }
    );

    const novBill = bills.get('2026-11');
    const decBill = bills.get('2026-12');

    assert.equal(novBill.total_amount, 500);
    assert.equal(novBill.paid_amount, 300);
    assert.equal(novBill.pending_amount, 200);

    // Dezembro: 200 de compra - 50 de estorno no ciclo = 150 líquido
    assert.equal(decBill.total_amount, 150);
    assert.equal(decBill.pending_amount, 150);
});

test('Parcelamento impacta apenas a parcela referente ao mês vigente sem distorcer os próximos meses', () => {
    const txs = [
        { id: 101, month: '2026-11', day: 10, type: 'expense', desc: 'Notebook', inst: '1/3', amount: 500, paid: true },
        { id: 102, month: '2026-12', day: 10, type: 'expense', desc: 'Notebook', inst: '2/3', amount: 500, paid: false },
        { id: 103, month: '2027-01', day: 10, type: 'expense', desc: 'Notebook', inst: '3/3', amount: 500, paid: false }
    ];

    const novSummary = FinanCore.summarizeInstallmentsForMonth(txs, '2026-11');
    const decSummary = FinanCore.summarizeInstallmentsForMonth(txs, '2026-12');
    const janSummary = FinanCore.summarizeInstallmentsForMonth(txs, '2027-01');

    assert.equal(novSummary.total, 500);
    assert.equal(novSummary.pending, 0);
    assert.equal(decSummary.total, 500);
    assert.equal(decSummary.pending, 500);
    assert.equal(janSummary.total, 500);
    assert.equal(janSummary.pending, 500);
});

test('Normalização de categorias, classificação visual e filtros de Pendentes no Mês', () => {
    assert.equal(FinanCore.normalizeCategoryLabel('Clothing'), 'Vestuário');
    assert.equal(FinanCore.normalizeCategoryLabel('alimentação'), 'Alimentação');

    const sampleTxs = [
        { id: 1, type: 'expense', desc: 'Fatura Itaú', isConsolidatedBill: true, amount: 24, pending_amount: 24, paid: false, bankId: 'bank_itau', cat: 'Cartão de Crédito' },
        { id: 2, type: 'expense', desc: 'Notebook', inst: '5/10', amount: 350, paid: false, bankId: 'bank_mp', cat: 'Clothing' },
        { id: 3, type: 'expense', desc: 'Internet', inst: 'Fixa', amount: 120, paid: true, bankId: 'bank_mp', cat: 'Assinatura' },
        { id: 4, type: 'income', desc: '13º Salário', inst: 'Única', amount: 2615, paid: false, bankId: 'bank_mp', cat: 'Bonificação' }
    ];

    assert.equal(FinanCore.classifyTransactionVisualKind(sampleTxs[0]).kind, 'BILL');
    assert.equal(FinanCore.classifyTransactionVisualKind(sampleTxs[1]).kind, 'INSTALLMENT');
    assert.equal(FinanCore.classifyTransactionVisualKind(sampleTxs[2]).kind, 'FIXED');
    assert.equal(FinanCore.classifyTransactionVisualKind(sampleTxs[3]).kind, 'SINGLE');

    const onlyPendingInstallments = FinanCore.filterDashboardTransactions(sampleTxs, {
        filterStatus: 'pending',
        filterKind: 'installment'
    });
    assert.equal(onlyPendingInstallments.length, 1);
    assert.equal(onlyPendingInstallments[0].id, 2);

    const searchByPortugueseCat = FinanCore.filterDashboardTransactions(sampleTxs, {
        searchQuery: 'vestuário'
    });
    assert.equal(searchByPortugueseCat.length, 1);
    assert.equal(searchByPortugueseCat[0].id, 2);

    assert.equal(FinanCore.maskSensitiveLabel('caiogarcia2020@gmail.com', true), 'ca••••@gmail.com');
    assert.equal(FinanCore.maskSensitiveLabel('Salário', true), '•••• ••••');
});
