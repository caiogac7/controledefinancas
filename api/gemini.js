/**
 * POST /api/gemini
 * Proxy Seguro BYOK (Bring Your Own Key) para Google Gemini API v1beta (CommonJS / Node 18+ nativo).
 * Arquitetura Multi-usuário: utiliza exclusivamente a chave do usuário autenticado (header x-gemini-key),
 * validando o prefixo oficial "AIza" e operando com os modelos Gemini 2.5 / 2.0.
 */
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization, X-Gemini-Key, x-gemini-key'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Método não permitido' });
  }

  try {
    const userKeyHeader = req.headers['x-gemini-key'] || req.headers['X-Gemini-Key'];
    const apiKey = (userKeyHeader && typeof userKeyHeader === 'string') ? userKeyHeader.trim() : '';

    if (!apiKey) {
      return res.status(400).json({
        ok: false,
        code: 'API_KEY_MISSING',
        error: 'Chave de API do Gemini ausente no seu perfil. Acesse Configurações da Chave e informe sua chave de API.'
      });
    }

    const { systemInstruction, userPrompt, contents, generationConfig } = req.body || {};

    if (!userPrompt && (!contents || contents.length === 0)) {
      return res.status(400).json({ ok: false, error: 'Prompt não fornecido.' });
    }

    const candidateModels = [
      'gemini-3.5-flash-lite',
      'gemini-3.1-flash-lite',
      'gemini-flash-lite-latest',
      'gemini-3.5-flash',
      'gemini-3.6-flash',
      'gemini-flash-latest'
    ];

    const expectJson = Boolean(
      (generationConfig && generationConfig.responseMimeType === 'application/json') ||
      (systemInstruction && (String(systemInstruction).includes('SCHEMA DO JSON') || String(systemInstruction).includes('formato JSON')))
    );
    const defaultGenConfig = {
      temperature: expectJson ? 0.1 : 0.2,
      maxOutputTokens: 8192,
      ...(expectJson ? { responseMimeType: 'application/json' } : {})
    };

    let outgoingPayload;
    if (Array.isArray(contents) && contents.length > 0) {
      outgoingPayload = {
        systemInstruction: systemInstruction ? {
          parts: [{ text: String(systemInstruction) }]
        } : undefined,
        contents,
        generationConfig: { ...defaultGenConfig, ...(generationConfig || {}) }
      };
    } else {
      outgoingPayload = {
        systemInstruction: systemInstruction ? {
          parts: [{ text: String(systemInstruction) }]
        } : undefined,
        contents: [
          {
            role: 'user',
            parts: [{ text: String(userPrompt || '') }]
          }
        ],
        generationConfig: { ...defaultGenConfig, ...(generationConfig || {}) }
      };
    }

    let lastStatus = 500;
    let lastErrorMsg = 'Falha ao consultar modelos Gemini';
    let lastDetails = null;
    let lastModelTried = candidateModels[0];

    for (const model of candidateModels) {
      lastModelTried = model;
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`;

      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(outgoingPayload)
      });

      if (resp.ok) {
        const data = await resp.json();
        const candidate = data?.candidates?.[0];
        const finishReason = candidate?.finishReason || 'STOP';
        const parts = Array.isArray(candidate?.content?.parts) ? candidate.content.parts : [];
        const textParts = parts.filter(p => !p.thought && typeof p.text === 'string').map(p => p.text);
        const reply = (textParts.length > 0 ? textParts.join('') : (parts[parts.length - 1]?.text || '')).trim();

        if (finishReason === 'MAX_TOKENS' && expectJson && !reply.endsWith('}')) {
          continue;
        }

        if (reply) {
          return res.status(200).json({
            ok: true,
            model,
            finishReason,
            text: reply,
            candidates: data.candidates || []
          });
        }
      }

      const errText = await resp.text().catch(() => '');
      let errData = null;
      try {
        errData = JSON.parse(errText);
      } catch (_) {}

      const googleErrMsg = errData?.error?.message || errText || `HTTP ${resp.status}`;
      console.error(`[Gemini API Google Error] Status ${resp.status} (${model}):`, googleErrMsg);

      lastStatus = resp.status;
      lastErrorMsg = googleErrMsg;
      lastDetails = errData || errText;

      // Se a chave for inválida (400 API_KEY_INVALID) ou bloqueada por permissão/domínio (403), interrompe imediatamente sem tentar outros modelos
      const isKeyInvalid = resp.status === 400 && (
        googleErrMsg.includes('API key not valid') ||
        googleErrMsg.includes('API_KEY_INVALID') ||
        JSON.stringify(errData || {}).includes('API_KEY_INVALID')
      );
      if (isKeyInvalid || resp.status === 403) {
        return res.status(resp.status).json({
          ok: false,
          model,
          code: isKeyInvalid ? 'API_KEY_INVALID' : 'PERMISSION_DENIED',
          error: googleErrMsg,
          details: lastDetails
        });
      }
    }

    return res.status(lastStatus >= 500 ? 502 : lastStatus).json({
      ok: false,
      model: lastModelTried,
      error: lastErrorMsg,
      details: lastDetails
    });
  } catch (error) {
    console.error('[Gemini Serverless Function Error]:', error.message);
    return res.status(500).json({ ok: false, error: error.message });
  }
};
