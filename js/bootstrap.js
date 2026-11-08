/**
 * bootstrap.js
 * Busca as chaves públicas do servidor (/api/config) e inicializa
 * o Supabase Client ANTES de carregar o app.js.
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

    try {
        window.__supabaseClient = window.supabase.createClient(cfg.supabaseUrl, cfg.supabaseAnon);
    } catch (err) {
        console.error('Erro crítico no bootstrap:', err);
        document.body.innerHTML = `
            <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;color:#fff;font-family:sans-serif;padding:2rem;text-align:center;">
                <div>
                    <p style="font-size:1.2rem;font-weight:bold;margin-bottom:.5rem;">Não foi possível iniciar o aplicativo.</p>
                    <p style="color:#94a3b8;font-size:.9rem;">Verifique sua conexão e tente novamente.</p>
                    <button id="btn-reload-bootstrap" style="margin-top:1.5rem;padding:.6rem 1.5rem;background:#4f46e5;color:#fff;border:none;border-radius:.75rem;font-weight:bold;cursor:pointer;">Tentar novamente</button>
                </div>
            </div>
        `;
        const btnReload = document.getElementById('btn-reload-bootstrap');
        if (btnReload) btnReload.addEventListener('click', () => location.reload());
        return;
    }

    // Carrega o app principal dinamicamente após inicializar os clientes
    const script = document.createElement('script');
    script.src = 'js/app.js';
    document.body.appendChild(script);
})();
