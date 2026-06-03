# ADR-0002: Atomic router runtime reload для geoip/geosite policies

- Status: Accepted
- Date: 2026-06-03

## Контекст

XrayR применяет panel-managed runtime routing через hot reload Xray router:
`routing.Router.AddRule(config, false)`. Runtime policies для YouTube/Google
используют `geosite:*`, explicit IP ranges и будущие `geoip:*` selectors.

Во время YouTube incident операторские canary показали, что невалидный или
неудачно собранный geo rule может привести к остановке контейнера или
разрушению live routing state. Дополнительно live логи показали, что runtime
`domainStrategy` не применялся при hot reload, поэтому domain UDP targets вроде
`www.google.com:443` продолжали работать как `AsIs` и не участвовали в IP-based
matching.

## Проблема

`Router.ReloadRules(config, false)` был неатомарным:

- сначала закрывал webhooks и очищал текущие `rules`/`balancers`;
- затем строил новые balancers/rules;
- если build новой конфигурации падал, старые rules уже были потеряны.

Кроме того, full replace не обновлял `domainStrategy`. Это делало runtime
policies с `IPIfNonMatch`/`IPOnDemand` некорректными без полного restart Xray
core.

## Принятое Решение

Сделать `ReloadRules` two-phase:

1. Построить candidate `balancers`, `rules` и `domainStrategy` во временные
   структуры.
2. При ошибке build вернуть error без изменения текущего router state.
3. При successful full replace закрыть старые webhooks и атомарно заменить
   `domainStrategy`, `balancers`, `rules`.
4. Для append mode сохранить старое поведение по `domainStrategy`: append не
   меняет global routing strategy.

Добавлены unit tests:

- failed full replace не меняет old rules, old balancers и old
  `domainStrategy`;
- successful full replace обновляет `domainStrategy` и заменяет rules.

## Альтернативы

- Оставить как есть и компенсировать в `vpn.bot` runtime compiler. Не выбрано:
  compiler не может защитить Xray router от неатомарного internal reload.
- Запретить `geoip:*` selectors и использовать только explicit CIDR. Не
  выбрано как финальное решение: это workaround, не исправляющий crash-safety и
  `domainStrategy` hot reload.
- Всегда делать полный restart Xray core для route changes. Не выбрано:
  увеличивает downtime и blast radius runtime canaries.

## Последствия

- Bad runtime route payload больше не должен очищать live routing state.
- Runtime full replace теперь может реально менять `domainStrategy`, что
  необходимо для `geoip:*` matching domain targets после DNS resolve.
- Rollout XrayR image с этим Xray-core изменением должен идти staged: один
  canary node/process, затем малая группа, затем wider rollout после access-log
  evidence.
- `geoip:google` все равно требует отдельного canary: это изменение делает
  reload безопасным, но не доказывает качество routing path или корректность
  выбранного geo asset.

## Owner Repo

`evasionlab/Xray-core`

## Downstream Consumers

XrayR runtime route reload, `vpn.bot` runtime route policies, VPN edge nodes,
YouTube/Google routing observability in `netlogs.xrayr_events`.

## Org-Wide ADR

Не требуется на этом шаге: изменение ограничено Xray-core router runtime
semantics. Downstream rollout фиксируется отдельными `vpn.infra`/`vpn.bot` ADR
notes при выпуске и canary.
