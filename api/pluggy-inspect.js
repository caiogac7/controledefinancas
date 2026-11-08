/**
 * GET/POST /api/pluggy-inspect
 * Endpoint de diagnóstico direto da API Pluggy v2
 */
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const clientId = process.env.PLUGGY_CLIENT_ID;
    const clientSecret = process.env.PLUGGY_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      return res.status(500).json({ error: 'Credenciais da Pluggy não encontradas' });
    }

    // 1. Autenticar na Pluggy
    const authRes = await fetch('https://api.pluggy.ai/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId, clientSecret })
    });

    if (!authRes.ok) {
      const errText = await authRes.text();
      return res.status(authRes.status).json({ error: 'Falha auth Pluggy', details: errText });
    }

    const { apiKey } = await authRes.json();
    const headers = {
      'Accept': 'application/json',
      'X-API-KEY': apiKey
    };

    const targetAccountId = req.query?.accountId || req.body?.accountId || '2350304a-9dab-4fe5-8e57-032ce5718ab9';
    const targetItemId = req.query?.itemId || req.body?.itemId || '3cb29a17-3dd9-46ba-bf8b-6b3c6d65f474';

    // 2. Buscar detalhes da conta
    const accRes = await fetch(`https://api.pluggy.ai/accounts/${targetAccountId}`, { headers });
    const accountData = accRes.ok ? await accRes.json() : { status: accRes.status, err: await accRes.text() };

    // 3. Buscar contas do item
    const allAccRes = await fetch(`https://api.pluggy.ai/accounts?itemId=${targetItemId}`, { headers });
    const allAccounts = allAccRes.ok ? await allAccRes.json() : { status: allAccRes.status };

    // 4. Buscar transações V2 direto (sem filtro)
    const txV2Res = await fetch(`https://api.pluggy.ai/v2/transactions?accountId=${targetAccountId}&pageSize=100`, { headers });
    const txV2Data = txV2Res.ok ? await txV2Res.json() : { status: txV2Res.status, err: await txV2Res.text() };

    // 5. Buscar transações V2 com data de hoje
    const today = '2026-11-08';
    const txTodayRes = await fetch(`https://api.pluggy.ai/v2/transactions?accountId=${targetAccountId}&from=${today}&pageSize=50`, { headers });
    const txTodayData = txTodayRes.ok ? await txTodayRes.json() : { status: txTodayRes.status, err: await txTodayRes.text() };

    return res.status(200).json({
      success: true,
      queryAccount: targetAccountId,
      accountData,
      allAccounts,
      txV2Total: txV2Data?.results?.length ?? 0,
      txV2First5: (txV2Data?.results || []).slice(0, 5),
      txTodayTotal: txTodayData?.results?.length ?? 0,
      txTodayResults: txTodayData?.results || [],
      txV2Full: txV2Data
    });
  } catch (error) {
    return res.status(500).json({ error: error.message, stack: error.stack });
  }
};
