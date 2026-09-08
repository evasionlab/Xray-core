# ADR-0001: Асинхронная shared DNS route classification для edge Xray

Статус: Accepted
Дата: 2026-09-04

## Контекст

Часть Veesp downlink-узлов не имеет устойчивого пути к российским адресам.
Глобальный `IPOnDemand` позволял выбрать `direct-ru-egress-mark` по `geoip:ru`,
но сделал DNS синхронной частью критического пути каждого нового FQDN и вызвал
общую деградацию latency.

## Проблема

Нужно выбирать RU egress для уже известных российских адресов, не блокируя
первое соединение DNS-resolve и не заставляя каждый edge повторно выполнять
одинаковую классификацию домена.

## Принятое решение

`Xray-core` получает opt-in правило `asyncDnsRoute`.

- Rule match читает только bounded локальную L1-проекцию и никогда не ждёт
  сеть.
- На miss он возвращает `false`, поэтому побеждает существующий known-good
  default/Veesp rule, и ставит запрос в bounded async очередь.
- Background workers обращаются к shared L2 classifier-cache. L2 владеет
  distributed singleflight, DNS-resolve и TTL-классификацией `RU`/`other`.
- Только fresh `RU` entry делает rule match и выбирает уже настроенный
  `direct-ru-egress-mark` outbound. Ошибка, pending и unknown — fail-open в
  default route.
- В L2 не передаются user/device identifiers; domain state хранится не дольше
  TTL. Client-facing resolver публикует в L2 только нормализованные DNS
  результаты, без access logging.

`asyncDnsRoute` выключен по умолчанию: отсутствие config message не меняет
существующий routing.

### Service authentication (2026-09-05)

Для multi-edge public HTTPS classifier core поддерживает bearer из локального
файла, путь к которому задаётся `XRAY_ASYNC_DNS_BEARER_TOKEN_FILE`. Ansible
доставляет файл с mode `0600` и read-only mount; секрет не входит в runtime
payload/БД owner, URL или логи. Файл читается при создании matcher, поэтому
ротация требует restart/reload. Настроенный, но недоступный/пустой/некорректный
файл отклоняет новый matcher, а не включает anonymous fallback. Без env
сохраняется совместимость с первоначальным canary. Token отправляется только
HTTPS endpoint без URL credentials; redirects не выполняются. Проверка файла
и HTTP не добавляются в `Apply`, который остаётся nonblocking.

IP allowlist дополняет bearer, но не заменяет service authentication при
расширении. Секрет в runtime policy или URL отклонён из-за лишнего secret
distribution surface. mTLS остаётся альтернативой при появлении PKI lifecycle.

## Альтернативы

- Глобальный `IPOnDemand`: отклонён, так как блокирует route selection DNS.
- Local-only cache на каждом edge: отклонён, так как дублирует cold resolve и
  classification по fleet.
- Remote Redis/gRPC lookup из `PickRoute`: отклонён, так как вводит сеть в
  критический путь соединения.
- Runtime policy update на каждый DNS ответ: отклонён, так как создаёт storm в
  owner delivery и не имеет TTL/lifecycle semantics.

## Последствия

- Нужны HA L2 classifier-cache и два resolver endpoints; edge использует
  public HTTPS с service authentication, их outage не влияет на established
  known-good routing. Overlay остаётся management transport.
- XrayR передаёт только статический `asyncDnsRoute` config/capability. Он не
  владеет DNS-result state и не публикует runtime policy на каждый ответ.
- Rollout: image с feature OFF, один edge, малая cohort, затем расширение
  только после outbound-tag, latency и fallback evidence.
- Rollback: удалить `asyncDnsRoute` из process config или отключить canary;
  core immediately returns to default route without cache migration.

## Owner repo

`evasionlab/Xray-core`

## Downstream consumers

`evasionlab/XrayR`, `evasionlab/vpn.bot` runtime-config compiler/delivery,
`vpn.infra` edge roles, shared resolver/classifier infrastructure and VPN
clients using the resolver listener.

## Org-wide ADR

Да. Решение меняет cross-product dataplane, shared cache/storage и DNS
delivery-flow. Локальный implementation ADR должен быть дополнен org-wide
record в `evasionlab/infra` до production canary.

## 2026-09-08: Ограниченный stale-while-revalidate и фоновые повторы

Статус дополнения: Accepted; реализация и изолированные проверки, production
пока остаётся на прежней версии. Этот раздел заменяет вышеописанное требование
«только fresh RU» исключительно для opt-in `staleGraceMillis > 0`.

L1 разделяет freshness и окончательный срок хранения. После freshness последняя
классификация может использоваться до hard deadline, пока bounded worker
обновляет её в фоне. Успешный `other` немедленно заменяет прежний RU. Ошибка,
pending и повторное чтение не продлевают hard deadline; после него действует
обычный fallback. Это осознанный риск кратковременно устаревшего маршрута,
а не обещание постоянной доступности RU-egress.

- `staleGraceMillis` по умолчанию 0; начальное значение canary — 600000 (10 минут).
  Нет изменения DNS TTL через искусственное увеличение minTTL.
- POST `/v1/classify` сохраняется; новый edge передаёт `allowStale: true` только
  при включённом grace. `ready.ttlMillis` — оставшаяся свежесть;
  `staleTtlMillis` — оставшийся **полный** срок до hard expiry, не добавочный grace.
  `stale` допустим только opt-in потребителю и имеет ttlMillis=0. Legacy endpoint
  без allowStale не отдаёт устаревшую запись как fresh ready.
- `generation` меняется только после успешного canonical DNS fill. Повторный
  ready/stale того же поколения не возобновляет локальный stale grace. При этом
  доказанная оставшаяся freshness остаётся usable; новый DNS result может дать
  новый срок. Старый producer без generation трактуется консервативно.
- L1 вычитает время HTTP-запроса и ограничивает сроки серверными remaining TTL
  и локальными caps. Старый classifier без нового поля не даёт права на stale.
- Один bounded scheduler доводит pending/error до результата с конечным
  бюджетом попыток, а также обновляет недавно использованные записи заранее.
  Нет goroutine/timer на каждый домен, неограниченной retry-map или сетевого
  ожидания в Apply. Close отменяет фоновые запросы.
- Общий L2 использует отдельный versioned подпрефикс выделенного keyspace,
  зависящий от GeoIP и resolver view. Старые данные не мигрируют и не удаляются.
  В кеш не попадают outbound tags или ручные политики.

Порядок статических правил, AsIs и raw-IP/CDN приоритеты не меняются. Public
client DNS остаётся выключенным. Transport edge→classifier — существующий
public HTTPS с allowlist+bearer; management overlay не заменяет этот путь.

Минимальные доказательства: nonblocking cold miss, autonomous pending→ready,
expiry/error до и после hard deadline, RU→other, bounded flood/Close и общий
L2 на втором edge. Затем один Gauss, малая Gauss cohort; расширение только на
согласованную группу bypass после traffic evidence. Не весь edge fleet.
Rollback: убрать staleGraceMillis, при необходимости прежний immutable XrayR
image. Старый classifier остаётся доступен через существующий blue/green owner.
Cross-product дополнение — тот же infra ADR-20260904-02, без нового owner.

## 2026-09-08: Быстрый L2 lookup при холодном L1 и длительный last-good

Статус дополнения: Accepted для реализации; production-включение не выполнено.
Этот раздел заменяет запрет любого сетевого ожидания в rule match **только**
при явном `cacheLookupWaitMillis > 0`. Owner — `evasionlab/Xray-core`; consumers —
XrayR и runtime-config compiler `vpn.bot`. Общее решение о client DNS, ёмкости,
защите resolver и rollout хранится в `evasionlab/infra`; эта правка не открывает
публичный DNS listener и не разрешает fleet expansion.

### Контекст и проблема

Тёплый общий L2 не помогает первому соединению при пустом L1: прежний edge сразу
выбирает fallback, даже если готовое решение доступно за миллисекунды. Прогрев
L2 клиентским DNS снижает число DNS miss, но не устраняет этот дефект L1. Более
долгое хранение относится к `RU/other`, а не к IP-адресу для подключения.

### Решение и границы

- `cacheLookupWaitMillis`: default 0 (старое nonblocking поведение), диапазон
  1–250 мс; начальный предлагаемый canary — 150 мс. На fresh/stale usable L1 hit
  ожидания нет. На miss/hard expiry можно дождаться **одной** уже выполняемой
  или поставленной в очередь shared HTTP-попытки. Pending/error завершают
  ожидание сразу; фоновые DNS-повторы продолжаются отдельно с прежним budget.
- HTTP по-прежнему выполняют только bounded workers. На домен один job, на его
  HTTP-попытку один completion channel; goroutine/HTTP на соединение не создаются.
  Очередь/worker count не увеличиваются. Между попытками (backoff/cooldown) edge
  не ждёт будущего таймера. Полная очередь не создаёт дополнительную waiter queue.
- На matcher максимум 1024 одновременно ожидающих вызова. При исчерпании
  admission немедленный fallback. Таймер создаётся только принятому waiter;
  mutex не удерживается во время ожидания. Close и отмена контекста соединения
  освобождают waiter, не отменяя shared job из-за одного ушедшего клиента.
- Один абсолютный budget на route selection: следующие правила и повторный
  проход IPIfNonMatch не начинают срок заново. Он появляется только при
  достижении opt-in правила; дешёвый process matcher стоит раньше async matcher.
  Optional `GetContext()` сохраняет отмену в session/DNS wrappers без изменения
  обязательного `routing.Context` interface. Для внешнего контекста без этого
  метода остаются ограничение времени и Close, но нет caller cancellation.
- `ready`/пригодный `stale` возвращает актуальный результат RU/other; timeout,
  unusable response, pending/error и admission overflow сохраняют fallback.
  Ни lookup, ни reload не возобновляют hard deadline/generation/retry budget.
  Reload наследует только value state; completion channels принадлежат старым
  workers, старые waiters освобождаются через Close.
- Верхняя граница `staleGraceMillis` увеличена с 1 часа до 7 суток (604800000 мс),
  default по-прежнему 0. Это разрешённый ceiling, а не автоматическое включение.
  Fresh TTL, authoritative server hard lifetime, generation/tombstone semantics
  остаются прежними. Бессрочного хранения или stale IP подключения нет.
- Низкокардинальные counters: lookup waits/hits/timeouts/pending/rejected/canceled
  и текущие waiters; без domain/user labels. Worker errors, queueDrops и retry
  exhaustion остаются отдельными метриками. Hit включает RU и other.

### Альтернативы, последствия, rollout

Увеличить только L2: не исправляет первый L1 miss. Ждать весь DNS-resolve/retry
budget: слишком длинная задержка и риск удержания соединений. Прямой HTTP на
каждое соединение: лишняя нагрузка/неограниченная конкуренция. Бессрочный кеш:
не выбран из-за неограниченного устаревания; длительный last-good имеет явный
hard срок и фоновое обновление.

Проверки: RU/other/stale/pending/error первой попытки, L1 hit без ожидания,
жёсткий wait timeout, concurrent dedupe/cancel, Close/admission/reload, общий
budget через несколько правил и DNS wrapper, default 0 и семисуточный ceiling;
`go test -race` для focused router/config tests. Production canary должен
доказать первый L1 miss при тёплом L2, bounded latency при L2 outage и трафик по
ожидаемому outbound; клиентская DNS нагрузка проверяется отдельно её owner.
Rollback ожидания — `cacheLookupWaitMillis: 0`; rollback retention — прежнее
значение grace через runtime owner. Параметры включаются только scoped canary,
не автоматически при доставке binary. Проверка cleanup/review — до расширения
за пределы первой canary cohort.
