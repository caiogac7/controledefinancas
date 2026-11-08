/**
 * POST /api/gemini
 * Proxy Seguro para Google Gemini API (CommonJS / Node 18+ nativo)
 * Oculta a API Key do DevTools do navegador e elimina erros de CSP no cliente
 */
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization, X-Gemini-Key'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Método não permitido' });
  }

  try {
    const userKeyHeader = req.headers['x-gemini-key'];
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

    // Modelos oficiais suportados pela API Google AI (v1beta)
    const candidateModels = [
      'gemini-1.5-flash',
      'gemini-1.5-pro',
      'gemini-2.0-flash-exp'
    ];

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

    let lastError = null;

    for (const model of candidateModels) {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`;

      try {
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
        } else {
          const errData = await resp.json().catch(() => ({}));
          lastError = errData?.error?.message || `HTTP ${resp.status}`;
          if (resp.status === 403 || resp.status === 429) {
            break;
          }
        }
      } catch (e) {
        lastError = e.message;
      }
    }

    return res.status(502).json({
      ok: false,
      error: lastError || 'Não foi possível obter resposta dos modelos Gemini.'
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
};
