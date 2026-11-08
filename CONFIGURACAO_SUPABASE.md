# ⚙️ Configurações Necessárias no Supabase

## 🎯 Dados do Projeto

**Nome:** Controle de Finanças
**CPF:** 149.899.737-63
**URL Produção:** https://financias-alpha.vercel.app
**E-mail Contato:** contato@financias-alpha.vercel.app
**E-mail DPO:** dpo@financias-alpha.vercel.app

---

## 1. 🔗 Configurar URLs de Redirecionamento

### Acesse:
Painel Supabase → Seu Projeto → **Authentication** → **URL Configuration**

### Adicione as seguintes URLs em "Redirect URLs":

```
https://financias-alpha.vercel.app/
https://financias-alpha.vercel.app/index.html
http://localhost:5500/
http://localhost:5500/index.html
http://127.0.0.1:5500/
```

**Importante:** Clique em "Add URL" para cada uma e depois em "Save".

---

## 2. 📧 Configurar Template de E-mail de Recuperação

### Acesse:
Painel Supabase → **Authentication** → **Email Templates** → **Reset Password**

### Template Personalizado:

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redefinir Senha - Controle de Finanças</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #334155;
            margin: 0;
            padding: 0;
            background-color: #f8fafc;
        }
        .container {
            max-width: 600px;
            margin: 40px auto;
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .header {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            padding: 40px 30px;
            text-align: center;
            color: white;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 700;
        }
        .content {
            padding: 40px 30px;
        }
        .content p {
            margin: 16px 0;
            font-size: 15px;
        }
        .button {
            display: inline-block;
            background: #4f46e5;
            color: white;
            text-decoration: none;
            padding: 14px 32px;
            border-radius: 10px;
            font-weight: 600;
            margin: 24px 0;
            transition: background 0.3s;
        }
        .button:hover {
            background: #4338ca;
        }
        .alert {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 16px;
            margin: 24px 0;
            border-radius: 8px;
            font-size: 14px;
        }
        .footer {
            background: #f8fafc;
            padding: 24px 30px;
            text-align: center;
            font-size: 13px;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Redefinir Senha</h1>
        </div>
        
        <div class="content">
            <p><strong>Olá!</strong></p>
            
            <p>Recebemos uma solicitação para redefinir a senha da sua conta no <strong>Controle de Finanças</strong>.</p>
            
            <p>Clique no botão abaixo para criar uma nova senha:</p>
            
            <div style="text-align: center;">
                <a href="{{ .ConfirmationURL }}" class="button">
                    Redefinir Minha Senha
                </a>
            </div>
            
            <div class="alert">
                <strong>⏱️ Atenção:</strong> Este link é válido por <strong>60 minutos</strong> e pode ser usado apenas <strong>uma vez</strong>.
            </div>
            
            <p><strong>Não solicitou esta redefinição?</strong></p>
            <p>Se você não solicitou a alteração de senha, ignore este e-mail. Sua senha atual permanecerá ativa e segura.</p>
            
            <p>Por segurança, recomendamos:</p>
            <ul>
                <li>Nunca compartilhar sua senha</li>
                <li>Usar senhas fortes e únicas</li>
                <li>Ativar autenticação em duas etapas (em breve)</li>
            </ul>
        </div>
        
        <div class="footer">
            <p><strong>Controle de Finanças</strong></p>
            <p>https://financias-alpha.vercel.app</p>
            <p>Dúvidas? Entre em contato: <a href="mailto:contato@financias-alpha.vercel.app">contato@financias-alpha.vercel.app</a></p>
            <p style="margin-top: 16px; font-size: 12px; color: #94a3b8;">
                Este é um e-mail automático, por favor não responda.<br>
                Seus dados são protegidos conforme a LGPD.
            </p>
        </div>
    </div>
</body>
</html>
```

**Cole este template no editor e clique em "Save".**

---

## 3. 📧 Configurar Template de Confirmação de Cadastro

### Acesse:
Painel Supabase → **Authentication** → **Email Templates** → **Confirm Signup**

### Template Personalizado:

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Bem-vindo ao Controle de Finanças</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; color: #334155; background: #f8fafc; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 40px auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .header { background: linear-gradient(135deg, #059669 0%, #10b981 100%); padding: 40px 30px; text-align: center; color: white; }
        .header h1 { margin: 0; font-size: 24px; font-weight: 700; }
        .content { padding: 40px 30px; }
        .button { display: inline-block; background: #059669; color: white; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-weight: 600; margin: 24px 0; }
        .footer { background: #f8fafc; padding: 24px 30px; text-align: center; font-size: 13px; color: #64748b; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Bem-vindo!</h1>
        </div>
        <div class="content">
            <p><strong>Olá!</strong></p>
            <p>Obrigado por criar sua conta no <strong>Controle de Finanças</strong>!</p>
            <p>Para ativar sua conta, clique no botão abaixo:</p>
            <div style="text-align: center;">
                <a href="{{ .ConfirmationURL }}" class="button">Confirmar Minha Conta</a>
            </div>
            <p>Após confirmar, você poderá:</p>
            <ul>
                <li>💰 Organizar suas finanças pessoais</li>
                <li>📊 Criar relatórios e análises</li>
                <li>💳 Gerenciar cartões de crédito</li>
                <li>🏦 Controlar contas bancárias</li>
            </ul>
            <p>Bem-vindo à sua jornada de organização financeira!</p>
        </div>
        <div class="footer">
            <p><strong>Controle de Finanças</strong></p>
            <p>https://financias-alpha.vercel.app</p>
            <p>Dúvidas? <a href="mailto:contato@financias-alpha.vercel.app">contato@financias-alpha.vercel.app</a></p>
        </div>
    </div>
</body>
</html>
```

---

## 4. ⚙️ Configurações Gerais de Autenticação

### Acesse:
Painel Supabase → **Authentication** → **Settings**

### Configure:

| Configuração | Valor Recomendado |
|--------------|-------------------|
| **Enable Email Confirmations** | ✅ Ativado (recomendado) |
| **Enable Email Change Confirmations** | ✅ Ativado |
| **Enable Phone Confirmations** | ❌ Desativado (não usamos) |
| **Minimum Password Length** | 6 caracteres |
| **JWT Expiry** | 3600 (1 hora) |
| **Refresh Token Expiry** | 2592000 (30 dias) |

---

## 5. 📊 Configurar RLS (Row Level Security)

As políticas de segurança já estão implementadas no código, mas verifique se estão ativas:

### Tabelas que DEVEM ter RLS ativado:

```sql
-- Verificar status
SELECT schemaname, tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public';

-- Se não estiver ativo, ativar:
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bank_statements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.banks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.categories ENABLE ROW LEVEL SECURITY;
```

---

## 6. 🔐 Configurar SMTP (E-mail de Produção)

### Para Produção, configure SMTP personalizado:

**Opção 1: Gmail (Gratuito)**
- SMTP Host: `smtp.gmail.com`
- Port: `587`
- Username: `seu-email@gmail.com`
- Password: `senha-de-aplicativo` (não a senha normal!)
- [Como criar senha de aplicativo](https://support.google.com/accounts/answer/185833)

**Opção 2: SendGrid (Recomendado para produção)**
- SMTP Host: `smtp.sendgrid.net`
- Port: `587`
- Username: `apikey`
- Password: `sua-api-key-do-sendgrid`
- [Criar conta gratuita](https://sendgrid.com) - 100 e-mails/dia grátis

**Opção 3: AWS SES (Profissional)**
- Mais complexo mas mais confiável
- Custo baixo (US$ 0.10 por 1000 e-mails)

### Configurar no Supabase:
1. **Project Settings** → **Authentication** → **SMTP Settings**
2. Preencha os dados do provedor escolhido
3. Clique em "Save"
4. Teste enviando um e-mail de recuperação

---

## 7. 🌐 Configurar Domínio Personalizado (Opcional)

Se você tem um domínio próprio (ex: `financias.com.br`):

### No Vercel:
1. **Settings** → **Domains**
2. Adicione seu domínio
3. Configure os registros DNS conforme instruções

### No Supabase:
1. Atualize as URLs de redirecionamento
2. Substitua `financias-alpha.vercel.app` pelo seu domínio

---

## 8. 📈 Monitoramento e Logs

### Ative logs de auditoria:

```sql
-- Criar tabela de logs de autenticação
CREATE TABLE IF NOT EXISTS public.auth_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    event_type TEXT NOT NULL, -- 'login', 'logout', 'password_reset', 'account_delete'
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- RLS
ALTER TABLE public.auth_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_view_own_logs"
ON public.auth_logs
FOR SELECT
USING (auth.uid() = user_id);

-- Índice para performance
CREATE INDEX idx_auth_logs_user ON auth_logs(user_id);
CREATE INDEX idx_auth_logs_date ON auth_logs(created_at DESC);
```

---

## 9. 🎯 Checklist Final

Antes de colocar em produção, verifique:

- [ ] URLs de redirecionamento configuradas
- [ ] Templates de e-mail personalizados
- [ ] SMTP configurado (se produção)
- [ ] RLS ativado em todas as tabelas
- [ ] Políticas de segurança criadas
- [ ] Backup automático ativado (Supabase faz por padrão)
- [ ] Termos e Privacidade ajustados com dados reais
- [ ] E-mails de contato funcionando
- [ ] Testado em mobile e desktop
- [ ] Testado fluxo de recuperação de senha
- [ ] Testado fluxo de exclusão de conta

---

## 10. 🆘 Troubleshooting

### E-mail não chega
1. Verifique SPAM
2. Confira se SMTP está configurado
3. Em dev, veja os logs do Supabase: **Authentication** → **Logs**
4. Teste com outro e-mail

### Link expirado
- Links expiram em 60 minutos
- Solicite novo link de recuperação

### Erro de redirecionamento
- Verifique se a URL está na lista de Redirect URLs
- Certifique-se que não há barra final extra

### RLS bloqueando operações
```sql
-- Desabilitar temporariamente para debug (NÃO em produção!)
ALTER TABLE public.transactions DISABLE ROW LEVEL SECURITY;

-- Reabilitar depois
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;
```

---

## 📞 Suporte

**Documentação Supabase:** https://supabase.com/docs
**Documentação Vercel:** https://vercel.com/docs
**Comunidade Supabase:** https://github.com/supabase/supabase/discussions

---

**✅ Configuração completa!** Seu aplicativo está pronto para produção.
