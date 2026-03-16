# waldo-shield

## What This Is

Sistema de monitoreo de seguridad para la plataforma waldo.click. Recolecta datos de múltiples fuentes (scanner HTTP, Cloudflare API, DNS/email checks), genera informes consolidados y los envía por email periódicamente. Corre como cron job en un servidor Vultr gestionado con Laravel Forge.

## Core Value

Visibilidad continua del estado de seguridad de waldo.click — staging y producción — sin intervención manual.

## Requirements

### Validated

- ✓ Scanner HTTP modular (headers, SSL, DNS, vulnerabilidades, detección de tech) — existing
- ✓ Reportes JSON con scoring de severidad — existing
- ✓ Detección de falsos positivos (Zero Trust, Nuxt 404s) — existing

### Active

- [ ] Integración con Cloudflare API (WAF events, firewall, tráfico)
- [ ] Checks de email/DNS (SPF, DKIM, DMARC para ambos dominios)
- [ ] Generación de informe HTML consolidado
- [ ] Envío de informe por email via Mailgun
- [ ] Configuración por entorno (staging vs prod)
- [ ] Cron job compatible con Laravel Forge

### Out of Scope

- Integración Codacy — agrega fricción, requiere setup externo
- Integración Sentry — errores de prod no son estrictamente seguridad
- Dashboard web — email es suficiente para v1
- Alertas en tiempo real — el informe periódico es suficiente

## Context

**Infraestructura existente:**
- Dos servidores Vultr: prod (waldo.click) y staging (waldoclick.dev)
- Laravel Forge para gestión de servidores y cron jobs
- Mailgun para email transaccional (ya configurado para @waldo.click y @waldoclick.dev)
- Cloudflare como proxy/WAF para todos los dominios
- Zoho para email corporativo (contacto@waldo.click)

**Targets a escanear:**
- Staging: api.waldoclick.dev, dashboard.waldoclick.dev, www.waldoclick.dev
- Prod: api.waldo.click, dashboard.waldo.click, www.waldo.click

**Consideraciones:**
- dashboard.* y api.*/admin están protegidos por Cloudflare Zero Trust (302 redirects)
- El scanner actual ya maneja estos falsos positivos
- El servidor de monitoreo será un tercer servidor pequeño (~2GB RAM, ~$4/mes)

## Constraints

- **Stack**: Python puro, sin frameworks — consistente con código existente
- **Infraestructura**: Debe correr en Ubuntu con cron, compatible con Forge
- **Email**: Usar Mailgun existente, no agregar nuevos proveedores
- **Secrets**: API tokens via variables de entorno, no hardcodeados

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Servidor dedicado para monitoreo | Escanear desde afuera como un atacante real, no mezclar con servidores de app | — Pending |
| Python puro sin frameworks | Consistencia con código existente, menos dependencias | — Pending |
| Email como único canal de notificación | Simple, suficiente para v1, evita complejidad de Slack/webhooks | — Pending |

---
*Last updated: 2026-03-16 after initialization*
