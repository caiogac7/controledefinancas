# Política de Privacidade - Controle de Finanças

**Última atualização:** 29 de outubro de 2026

## 1. Introdução

Esta Política de Privacidade descreve como coletamos, usamos, armazenamos e protegemos seus dados pessoais ao utilizar o aplicativo "Controle de Finanças" ("Aplicativo", "nós", "nosso").

Estamos comprometidos com a proteção de sua privacidade e em conformidade com a **Lei Geral de Proteção de Dados (LGPD - Lei 13.709/2018)**.

## 2. Controlador de Dados

**Razão Social:** Controle de Finanças
**CPF:** 149.899.737-63
**Website:** https://financias-alpha.vercel.app
**E-mail:** contato@financias-alpha.vercel.app
**DPO (Encarregado):** dpo@financias-alpha.vercel.app

## 3. Dados Coletados

### 3.1 Dados Fornecidos por Você

Coletamos os seguintes dados quando você cria uma conta:

| Dado | Obrigatório | Finalidade |
|------|-------------|------------|
| Nome completo | ✅ Sim | Identificação e personalização |
| E-mail | ✅ Sim | Autenticação e comunicação |
| Senha | ✅ Sim | Autenticação e segurança |
| Telefone/WhatsApp | ❌ Não | Contato e recuperação de conta |
| Foto de perfil | ❌ Não | Personalização da experiência |

### 3.2 Dados Financeiros

Você insere voluntariamente:
- Transações financeiras (despesas e receitas)
- Contas bancárias (nome, tipo, saldo)
- Cartões de crédito (últimos 4 dígitos, bandeira)
- Categorias de gastos
- Extratos bancários (importados via OFX/CSV)

### 3.3 Dados Coletados Automaticamente

- **Logs de acesso:** Data, hora, IP, navegador
- **Dados técnicos:** Tipo de dispositivo, sistema operacional
- **Dados de uso:** Páginas visitadas, funcionalidades utilizadas
- **Cookies:** Preferências de tema (dark/light mode)

### 3.4 Dados de Terceiros

Se você optar por integrar com o Mercado Pago:
- Token de cartão de crédito
- Últimos 4 dígitos do cartão
- Bandeira do cartão

**Importante:** Não armazenamos dados completos de cartão.

## 4. Base Legal (LGPD)

Tratamos seus dados com base em:

| Base Legal | Aplicação |
|------------|-----------|
| **Consentimento** (Art. 7º, I) | Cadastro, uso do app, newsletter |
| **Execução de contrato** (Art. 7º, V) | Prestação do serviço de gestão financeira |
| **Legítimo interesse** (Art. 7º, IX) | Segurança, prevenção de fraudes, melhorias |
| **Obrigação legal** (Art. 7º, II) | Retenção de logs, atendimento a autoridades |

## 5. Finalidades do Tratamento

Utilizamos seus dados para:

### 5.1 Prestação do Serviço
- Autenticar e identificar você
- Armazenar e processar dados financeiros
- Gerar relatórios e análises
- Sincronizar dados entre dispositivos

### 5.2 Comunicação
- Enviar notificações importantes
- Responder dúvidas e suporte
- Informar sobre atualizações

### 5.3 Segurança
- Prevenir fraudes e acessos não autorizados
- Investigar atividades suspeitas
- Proteger direitos e propriedade

### 5.4 Melhorias
- Analisar uso do aplicativo
- Desenvolver novos recursos
- Corrigir bugs e problemas

## 6. Compartilhamento de Dados

### 6.1 Com Quem Compartilhamos

**Não vendemos seus dados.**

Compartilhamos apenas com:

| Terceiro | Finalidade | Dados Compartilhados |
|----------|------------|----------------------|
| **Supabase** | Infraestrutura de banco de dados | Todos os dados do app |
| **Mercado Pago** | Tokenização de cartões (opcional) | Token, últimos 4 dígitos |
| **Cloudflare** | CDN e proteção DDoS (se usar) | IP, requisições |

### 6.2 Transferência Internacional

O Supabase pode armazenar dados em servidores AWS localizados em:
- **Primário:** São Paulo, Brasil
- **Backup:** Outros data centers (conforme configuração)

Garantimos que qualquer transferência internacional segue as cláusulas contratuais padrão da LGPD.

### 6.3 Autoridades

Podemos compartilhar dados se:
- Exigido por lei, ordem judicial ou autoridade competente
- Necessário para proteger direitos, propriedade ou segurança

## 7. Armazenamento e Segurança

### 7.1 Medidas de Segurança

Implementamos:
- ✅ **Criptografia em trânsito (HTTPS/TLS)**
- ✅ **Criptografia em repouso** (banco de dados)
- ✅ **Autenticação segura** (Supabase Auth)
- ✅ **Hashing de senhas** (bcrypt)
- ✅ **Controle de acesso** (Row Level Security)
- ✅ **Logs de auditoria**
- ✅ **Backups automáticos**

### 7.2 Prazo de Armazenamento

| Tipo de Dado | Prazo de Retenção |
|--------------|-------------------|
| Dados cadastrais | Enquanto a conta estiver ativa |
| Dados financeiros | Enquanto a conta estiver ativa |
| Logs de acesso | 180 dias |
| Dados de conta excluída | 30 dias (então permanentemente deletado) |
| Logs de auditoria | 5 anos (obrigação legal) |

### 7.3 Exclusão Automática

Após solicitar exclusão de conta:
1. Conta é desativada imediatamente
2. Dados são marcados para exclusão
3. Exclusão permanente em até 30 dias
4. Logs de auditoria retidos conforme lei

## 8. Seus Direitos (LGPD - Art. 18)

Você tem direito a:

### 8.1 Confirmação e Acesso
- ✅ Confirmar se tratamos seus dados
- ✅ Acessar todos os dados que temos sobre você

**Como exercer:** Entre em contato por e-mail ou use a função "Exportar Backup JSON"

### 8.2 Correção
- ✅ Corrigir dados incompletos, inexatos ou desatualizados

**Como exercer:** Edite seus dados na aba "Configurações"

### 8.3 Anonimização, Bloqueio ou Eliminação
- ✅ Solicitar anonimização de dados desnecessários
- ✅ Bloquear temporariamente o tratamento
- ✅ Eliminar dados tratados com seu consentimento

**Como exercer:** Use o botão "Excluir Minha Conta" na aba Configurações

### 8.4 Portabilidade
- ✅ Receber seus dados em formato estruturado e legível

**Como exercer:** Use o botão "Baixar Backup JSON" na aba Configurações

### 8.5 Informação sobre Compartilhamento
- ✅ Saber com quem compartilhamos seus dados

**Como exercer:** Consulte esta política (seção 6) ou entre em contato

### 8.6 Revogação de Consentimento
- ✅ Revogar consentimento a qualquer momento

**Como exercer:** Exclua sua conta ou entre em contato

### 8.7 Oposição
- ✅ Opor-se ao tratamento em casos específicos

**Como exercer:** Entre em contato por e-mail

## 9. Cookies e Tecnologias

### 9.1 Tipos de Cookies

Utilizamos apenas cookies essenciais:

| Cookie | Tipo | Finalidade | Duração |
|--------|------|------------|---------|
| `supabase-auth-token` | Essencial | Manter você logado | 7 dias |
| `financas_theme` | Preferência | Salvar tema (dark/light) | Permanente |
| `financas_privacy` | Preferência | Modo privacidade | Sessão |

### 9.2 LocalStorage

Armazenamos no navegador:
- Backup local de transações
- Preferências de interface
- Estado de filtros e visualizações

**Você pode limpar a qualquer momento** através das configurações do navegador.

### 9.3 Não Utilizamos

❌ Cookies de rastreamento
❌ Cookies de publicidade
❌ Cookies de terceiros (analytics)
❌ Fingerprinting

## 10. Privacidade de Menores

O Aplicativo **não é destinado a menores de 18 anos**.

Se tomarmos conhecimento de que coletamos dados de menores inadvertidamente:
1. Excluiremos os dados imediatamente
2. Notificaremos os responsáveis legais

Se você é pai/mãe/responsável e acredita que seu filho forneceu dados, entre em contato conosco.

## 11. Alterações nesta Política

### 11.1 Atualizações

Podemos atualizar esta política periodicamente para:
- Refletir mudanças na legislação
- Incorporar novos recursos
- Melhorar transparência

### 11.2 Notificação

Mudanças significativas serão notificadas:
- Por e-mail
- Banner no aplicativo
- Com antecedência mínima de 15 dias

### 11.3 Aceitação

O uso continuado após mudanças implica aceitação da nova política.

## 12. Incidentes de Segurança

### 12.1 Prevenção

Tomamos todas as medidas razoáveis para prevenir incidentes de segurança.

### 12.2 Notificação

Em caso de incidente que possa gerar risco aos seus direitos:
- Notificaremos você em até 72 horas
- Informaremos a ANPD (Autoridade Nacional)
- Tomaremos medidas corretivas imediatas

## 13. Transferência de Titularidade

Em caso de venda, fusão ou aquisição:
- Seus dados podem ser transferidos ao novo controlador
- Você será notificado com antecedência
- A nova entidade deve respeitar esta política

## 14. Lei Aplicável e Foro

Esta política é regida pelas leis brasileiras, especialmente a LGPD.

Foro: Comarca do domicílio do usuário, Brasil.

## 15. Contato e Exercício de Direitos

### 15.1 Canais de Contato

**Privacidade e Proteção de Dados:**
- E-mail: contato@financias-alpha.vercel.app
- Website: https://financias-alpha.vercel.app

**Encarregado de Dados (DPO):**
- Nome: Controle de Finanças - DPO
- E-mail: dpo@financias-alpha.vercel.app
- CPF: 149.899.737-63

### 15.2 Prazo de Resposta

Responderemos sua solicitação em até:
- **15 dias corridos** para solicitações simples
- **30 dias corridos** para solicitações complexas

### 15.3 Reclamações

Se não estiver satisfeito com nossa resposta, você pode:
- Registrar reclamação junto à ANPD: https://www.gov.br/anpd/pt-br

## 16. Glossário

- **Controlador:** Quem decide sobre o tratamento de dados (nós)
- **Operador:** Quem trata dados em nome do controlador (Supabase)
- **Titular:** Você, pessoa a quem os dados se referem
- **Tratamento:** Qualquer operação com dados (coletar, armazenar, usar, etc)
- **Anonimização:** Tornar dados impossíveis de identificar você
- **Consentimento:** Sua autorização livre, informada e inequívoca

## 17. Declaração de Conformidade

Declaramos que:
- ✅ Cumprimos integralmente a LGPD (Lei 13.709/2018)
- ✅ Implementamos medidas técnicas e organizacionais adequadas
- ✅ Respeitamos todos os direitos dos titulares
- ✅ Mantemos registro das operações de tratamento
- ✅ Realizamos avaliações de impacto quando necessário

---

**Data de vigência:** 29 de outubro de 2026
**Versão:** 1.0

**Última revisão:** 29 de outubro de 2026

---

**Ao utilizar o Aplicativo, você confirma que leu e compreendeu esta Política de Privacidade.**
