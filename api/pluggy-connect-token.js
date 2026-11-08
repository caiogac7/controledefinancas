/**
 * POST /api/pluggy-connect-token
 * Gera o Connect Token na Pluggy via REST nativo (CommonJS)
 */
module.exports = async function handler(req, res) {
  // Configuração de cabeçalhos CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método não permitido', erro: 'Método não permitido' });
  }

  try {
    const clientId = process.env.PLUGGY_CLIENT_ID;
    const clientSecret = process.env.PLUGGY_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      return res.status(500).json({
        error: 'Variáveis PLUGGY_CLIENT_ID ou PLUGGY_CLIENT_SECRET não definidas na Vercel.',
        erro: 'Variáveis PLUGGY_CLIENT_ID ou PLUGGY_CLIENT_SECRET não definidas na Vercel.'
      });
    }

    // Obter API Key da Pluggy via autenticação
    const authResponse = await fetch('https://api.pluggy.ai/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId, clientSecret })
    });

    if (!authResponse.ok) {
      const authErr = await authResponse.text();
      console.error('[Pluggy Auth Error]:', authErr);
      return res.status(authResponse.status).json({
        error: 'Falha na autenticação da Pluggy',
        erro: 'Falha na autenticação da Pluggy',
        details: authErr
      });
    }

    const { apiKey } = await authResponse.json();

    // Prepara payload de criação do Connect Token
    const bodyPayload = (req.body && typeof req.body === 'object') ? { ...req.body } : {};

    // Criar o connect token
    const tokenResponse = await fetch('https://api.pluggy.ai/connect_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': apiKey
      },
      body: JSON.stringify(bodyPayload)
    });

    if (!tokenResponse.ok) {
      const tokenErr = await tokenResponse.text();
      console.error('[Pluggy Token Error]:', tokenErr);
      return res.status(tokenResponse.status).json({
        error: 'Falha ao gerar Connect Token na Pluggy',
        erro: 'Falha ao gerar Connect Token na Pluggy',
        details: tokenErr
      });
    }

    const tokenData = await tokenResponse.json();
    const finalToken = tokenData.accessToken || tokenData.connectToken;

    return res.status(200).json({
      ...tokenData,
      accessToken: finalToken,
      connectToken: finalToken
    });

  } catch (error) {
    console.error('[pluggy-connect-token crash]:', error.message);
    return res.status(500).json({
      error: error.message || 'Erro interno do servidor',
      erro: error.message || 'Erro interno do servidor'
    });
  }
};
