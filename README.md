# VulnScanner

Scanner de vulnerabilidades web com dashboard interativo. Combina análise própria de segurança com ferramentas externas reconhecidas do mercado em uma interface unificada.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask)
![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)

## Sobre

VulnScanner realiza varreduras automatizadas em aplicações web, identificando vulnerabilidades comuns como XSS, SQL Injection, CSRF, CORS misconfiguration, headers de segurança ausentes, exposição de informações sensíveis, e muito mais. O dashboard permite acompanhar o progresso do scan em tempo real via SSE (Server-Sent Events) e consultar relatórios detalhados.

## Funcionalidades

- **Crawling inteligente** com suporte a profundidade configurável e descoberta de formulários dinâmicos (SPA)
- **Análise de vulnerabilidades**: XSS (reflected/stored), SQL Injection, Open Redirect, CSRF, IDOR, Broken Access Control
- **Verificação de headers de segurança**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
- **Análise de SSL/TLS**, cookies, JWT e CORS
- **Descoberta de recursos**: páginas, API endpoints, arquivos JS, formulários
- **Autenticação**: suporte a Bearer Token e login via formulário
- **Dashboard em tempo real** com logs via SSE
- **Relatórios** em HTML e JSON, com filtro por severidade
- **Armazenamento local** via localStorage quando o backend não está disponível

## Ferramentas Externas Integradas

O scanner integra ferramentas de segurança reconhecidas como módulos opcionais:

| Ferramenta | Descrição | Referência |
|------------|-----------|------------|
| **Nuclei** | Scanner de vulnerabilidades baseado em templates | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| **SQLMap** | Detecção e exploração automática de SQL Injection | [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) |
| **Gitleaks** | Detector de segredos e credenciais em código | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| **TruffleHog** | Scanner de segredos com verificação de credenciais | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |

As ferramentas são detectadas automaticamente se estiverem no PATH do sistema.

## Instalação

### Backend

```bash
git clone https://github.com/bellwanger/vulnscanner.git
cd vulnscanner
pip install -r requirements.txt
```

### Frontend

```bash
cd frontend
npm install
npm run build
```

### Ferramentas Externas (opcional)

Baixe os binários e adicione ao PATH do sistema:

- **Nuclei**: [Releases](https://github.com/projectdiscovery/nuclei/releases)
- **SQLMap**: `pip install sqlmap`
- **Gitleaks**: [Releases](https://github.com/gitleaks/gitleaks/releases)
- **TruffleHog**: [Releases](https://github.com/trufflesecurity/trufflehog/releases)

## Uso

### Dashboard (recomendado)

```bash
python app.py
```

Acesse `http://localhost:5000` no navegador. O dashboard permite:

1. Configurar a URL alvo e autenticação
2. Selecionar ferramentas externas disponíveis
3. Acompanhar o scan em tempo real
4. Consultar relatórios e recursos descobertos

### CLI

```bash
python scanner.py https://meusite.com
python scanner.py https://meusite.com --token "eyJhbGciOi..."
python scanner.py https://meusite.com --login-url https://meusite.com/login -u admin -p senha123
```

## Arquitetura

```
├── app.py              # Backend Flask (API REST + SSE)
├── scanner.py          # Engine de scan (crawling, análise, relatórios)
├── tools/              # Wrappers para ferramentas externas
│   ├── base.py         # Classe base abstrata
│   ├── nuclei.py       # Nuclei wrapper
│   ├── sqlmap.py       # SQLMap wrapper
│   ├── gitleaks.py     # Gitleaks wrapper
│   └── trufflehog.py   # TruffleHog wrapper
├── frontend/           # React + Vite
│   └── src/
│       ├── App.jsx
│       └── components/ # ScanPanel, ReportsTab, ReportDetail, DiscoveryTab, etc.
└── requirements.txt
```

## Disclaimer

**Uso autorizado apenas.** Esta ferramenta deve ser utilizada exclusivamente em aplicações de sua propriedade ou com permissão explícita do proprietário. O uso não autorizado pode violar leis de segurança cibernética.

## Autor

**Bernardo Ellwanger** — [LinkedIn](https://www.linkedin.com/in/bernardo-ellwanger)

## Licença

MIT
