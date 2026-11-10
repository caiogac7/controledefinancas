/**
 * bootstrap.js
 * Busca as chaves públicas do servidor (/api/config) e inicializa
 * o Supabase Client com resiliência total ANTES de carregar o app.js.
 */
(async function () {
    const FALLBACK_PUBLIC_CONFIG = {
        supabaseUrl: 'https://ncpdgcxoziekwuralwzx.supabase.co',
        supabaseAnon: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5jcGRnY3hvemlla3d1cmFsd3p4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTMwNzIzODAsImV4cCI6MjEwODY0ODM4MH0.sQ2fzs3rRbwVKjHrwa6wAP5mAugKtPIbOeSzbSpxD1Y'
    };

    let cfg = FALLBACK_PUBLIC_CONFIG;

    try {
        const resp = await fetch('/api/config', {
            headers: { 'Accept': 'application/json' }
        });
        if (resp.ok) {
            const remoteCfg = await resp.json();
            if (remoteCfg?.supabaseUrl && remoteCfg?.supabaseAnon) {
                cfg = remoteCfg;
            }
        }
    } catch (_) {
        // Ambiente local sem servidor Vercel: utiliza configuração pública padrão
    }

    // 1. Garante que o SDK do Supabase está carregado antes de inicializar o client
    async function waitForSupabaseSDK(maxWaitMs = 6000) {
        const start = Date.now();
        while ((!window.supabase || typeof window.supabase.createClient !== 'function') && (Date.now() - start) < maxWaitMs) {
            await new Promise(r => setTimeout(r, 40));
        }
        if (window.supabase && typeof window.supabase.createClient === 'function') {
            return true;
        }

        // Tenta carregar fallback dinamicamente da unpkg caso o CDN do jsdelivr oscile
        try {
            await new Promise((resolve, reject) => {
                const s = document.createElement('script');
                s.src = 'https://unpkg.com/@supabase/supabase-js@2';
                s.onload = resolve;
                s.onerror = reject;
                document.head.appendChild(s);
            });
            return Boolean(window.supabase && typeof window.supabase.createClient === 'function');
        } catch (_) {
            return false;
        }
    }

    const hasSupabase = await waitForSupabaseSDK();
    if (!hasSupabase) {
        console.error('SDK do Supabase indisponível no navegador. Verifique a conexão com a CDN.');
        return;
    }

    try {
        window.__supabaseClient = window.supabase.createClient(cfg.supabaseUrl, cfg.supabaseAnon);
    } catch (err) {
        console.error('Erro crítico no bootstrap ao criar cliente Supabase:', err);
        return;
    }

    // 2. Limpeza proativa de caches legados de faturas no localStorage que causavam persistência de valores antigos
    try {
        const lastAppVer = localStorage.getItem('finan_app_version');
        const APP_CACHE_VERSION = '20261109_v6_canonical_sql_statements';
        if (lastAppVer !== APP_CACHE_VERSION) {
            for (let i = localStorage.length - 1; i >= 0; i--) {
                const k = localStorage.key(i);
                if (k && (k.startsWith('financas_credit_bills_') || k.startsWith('financas_last_summary_') || k.includes('raw_debug'))) {
                    localStorage.removeItem(k);
                }
            }
            localStorage.setItem('finan_app_version', APP_CACHE_VERSION);
        }
    } catch (_) {}

    // 3. Carrega o app principal estritamente após a criação de window.__supabaseClient com bust de cache para mobile
    const script = document.createElement('script');
    const APP_CACHE_VERSION = '20261109_v6_canonical_sql_statements';
    script.src = `js/app.js?v=${APP_CACHE_VERSION}`;
    script.defer = true;
    document.body.appendChild(script);
})();
