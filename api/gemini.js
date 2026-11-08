/**
 * POST /api/gemini
 * Proxy Seguro para Google Gemini API v1beta (CommonJS / Node 18+ nativo)
 * Usa exclusivamente o modelo 'gemini-1.5-flash' estável e homologado para produção.
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
    const apiKey = (userKeyHeader && typeof userKeyHeader === 'string' && userKeyHeader.trim())
      ? userKeyHeader.trim()
      : (process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '');

    if (!apiKey) {
      return res.status(400).json({
        ok: false,
        error: 'Chave da API do Google Gemini não fornecida. Insira sua chave no painel do Consultor IA.'
      });
    }

    const { systemInstruction, userPrompt, contents, generationConfig } = req.body || {};

    if (!userPrompt && (!contents || contents.length === 0)) {
      return res.status(400).json({ ok: false, error: 'Prompt não fornecido.' });
    }

    // Modelo estável e oficial para produção
    const model = 'gemini-1.5-flash';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`;

    let outgoingPayload;
    if (Array.isArray(contents) && contents.length > 0) {
      outgoingPayload = {
        systemInstruction: systemInstruction ? {
          parts: [{ text: String(systemInstruction) }]
        } : undefined,
        contents,
        generationConfig: generationConfig || {
          temperature: 0.2,
          maxOutputTokens: 2048
        }
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
        generationConfig: generationConfig || {
          temperature: 0.2,
          maxOutputTokens: 2048
        }
      };
    }

    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(outgoingPayload)
    });

    if (resp.ok) {
      const data = await resp.json();
      const reply = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      return res.status(200).json({
        ok: true,
        model,
        text: reply ? reply.trim() : '',
        candidates: data.candidates || []
      });
    }

    // Captura e loga o corpo de erro oficial retornado pelo Google
    const errText = await resp.text().catch(() => '');
    let errData = null;
    try {
      errData = JSON.parse(errText);
    } catch (_) {}

    const googleErrMsg = errData?.error?.message || errText || `HTTP ${resp.status}`;
    console.error(`[Gemini API Google Error] Status ${resp.status} (${model}):`, googleErrMsg);

    // Se falhar por causa da systemInstruction na v1beta, tenta o payload combinado universal
    if (resp.status === 400 || resp.status === 422) {
      const fallbackPayload = {
        contents: [
          {
            role: 'user',
            parts: [{ text: `${systemInstruction || ''}\n\n---\nCONSULTA DO USUÁRIO:\n${userPrompt || ''}` }]
          }
        ],
        generationConfig: generationConfig || {
          temperature: 0.2,
          maxOutputTokens: 2048
        }
      };

      const retryResp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(fallbackPayload)
      });

      if (retryResp.ok) {
        const retryData = await retryResp.json();
        const retryReply = retryData?.candidates?.[0]?.content?.parts?.[0]?.text;
        return res.status(200).json({
          ok: true,
          model,
          text: retryReply ? retryReply.trim() : '',
          candidates: retryData.candidates || []
        });
      }

      const retryErrText = await retryResp.text().catch(() => '');
      console.error(`[Gemini API Google Retry Error] Status ${retryResp.status} (${model}):`, retryErrText);
    }

    return res.status(resp.status >= 500 ? 502 : resp.status).json({
      ok: false,
      model,
      error: googleErrMsg,
      details: errData || errText
    });
  } catch (error) {
    console.error('[Gemini Serverless Function Error]:', error.message);
    return res.status(500).json({ ok: false, error: error.message });
  }
};
