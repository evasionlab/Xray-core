# ADR-0008: Country mark guard фактического TCP IPv4 socket

- Status: Proposed
- Date: 2026-10-14
- Repo-owner: `evasionlab/Xray-core`
- Downstream consumers: `evasionlab/XrayR`, `evasionlab/vpn.bot`, `evasionlab/infra`
- Org-wide ADR required: Yes; org-owner готовит связанное решение.
- Implementation status: source candidate, serving metadata и images не меняются.

## Контекст и проблема

На cdn10 YouTube TCP через существующий `core-services → direct` не возвращает
HTTP-ответ клиенту, а проверенный primary egress работает. Исправление должно
сохранить весь RU трафик на RU egress. DNS classifier и фактический dial имеют
разные resolver views. Положительная классификация всех ответов classifier как
non-RU не доказывает страну IP, который OS DNS выберет для соединения.

На cdn10 RU mark 41060 и primary mark 41014 имеют подтверждённые IPv4 IPIP
таблицы. Присвоение mark IPv6 socket не доказывает корректный IPv6 маршрут:
новый механизм обязан закрыть IPv6 до connect. Существующие freedom finalRules
могут блокировать фактический IP, но не переводят его на нужный RU mark.

## Решение

Добавить явный `sockopt.countryMarkGuard`:

```json
{
  "ruMark": 41060,
  "nonRuMark": 41014,
  "geoipFile": "geoip.dat",
  "geoipSHA256": "<approved-lowercase-sha256>"
}
```

Поле предназначено для отдельного direct/freedom TCP IPv4 outbound. Оно
не меняет resolver и global domainStrategy. Отсутствие поля сохраняет прежние
socket options и поведение UDP. С полем non-Linux, non-TCP, IPv6, dialerProxy,
interface binding и альтернативный system dialer отвергаются.

Обычный GoDialer передаёт своему Control callback фактический literal IP:port
каждого socket candidate до connect. Guard проверяет именно этот адрес заново
на каждой попытке, включая DNS retry/fallback. PRIVATE/reserved и unknown
отвергаются; положительно известный RU получает ruMark, положительно известная
non-RU страна — nonRuMark. RU membership имеет приоритет при пересечениях.
Наличие адреса вне RU не служит доказательством non-RU.

Положительное покрытие допускает только явный набор 249 действующих назначенных
ISO3166-1 alpha-2 кодов. Псевдокоды ZZ/XX, XK, historical/provider/group entries
не дают географического доказательства. Reverse country/private entries,
невалидный asset/prefix, отсутствие RU или положительного non-RU покрытия
отвергаются. PRIVATE, специальные IPv4/IPv6 диапазоны и отсутствие country
coverage никогда не открывают foreign route.

Chosen mark применяется последним после обычных socket options. Ошибка
обычных options, внешнего RawConn.Control или внутреннего SO_MARK возвращается
до connect; guard не наследует прежний log-and-continue для ошибок mark.
Новый socket protobuf field 24 переносит policy без потери обязательного pin.

## Ресурсы и совместимость

Asset ограничен 32MiB и обязательным SHA256. Wire scan проверяет число CIDR
до protobuf object graph allocation; допускается не более 2,000,000 prefixes.
Декодирование идёт по одному GeoIP entry. Compact immutable indexes занимают
не более 16MiB на pin, single-entry cache не растёт с числом outbound configs.
Context budget загрузки/ожидания составляет 5 секунд; истёкший результат не
публикуется. Обычный hot socket callback читает готовый index без DNS или I/O.

Измерение public serving asset cdn10: 23,080,744 bytes,
SHA256 c67bd077eb102cec74fab759b73d17f99275f56af10a87c14d9fd983508f5ce1,
1,372,014 принятых prefixes, примерно 605ms startup, 248MB peak Go heap,
1,508,640 bytes retained index на локальной машине. Это source sizing;
реальная задержка/память canary проверяются отдельно.

Старый SocketConfig parser игнорирует неизвестные поля. Поэтому нельзя считать
mixed-version config безопасным: owner preflight обязан подтвердить точный
новый serving image и принятую guard policy до присвоения profile. Затем
проверяются compile/apply/ACK, реальные client HTTP-over-tunnel проверки и
IPv4 RU route/foreign route; known IPv6 и unknown должны быть закрыты.
Сначала rollback owner profile, затем старый image. Новая capability автоматически
не рекламируется этим PR. Classifier-only proposal остаётся отдельным и не
заменяет actual socket guard.

Корректность mark→routing-table является отдельной обязательной предпосылкой:
owner проверяет живые IPv4 rules/routes для обоих marks и отсутствие более
позднего перезаписывания mark. SO_MARK сам по себе не доказывает страну egress.

## Проверка

Focused tests проверяют actual candidate против другой DNS view, RU/foreign
пересечение, private/pseudo/unknown/IPv6 rejection, mark-last и retry,
RawConn/inner mark errors, preconnect запрет через настоящий GoDialer, прежний
unguarded localhost dial, proxy/custom dialer bypass, JSON/protobuf и budget
реального asset. Linux kernel proof запускается отдельно в существующем CI
через скомпилированный QA test binary под уже доступным sudo: настоящий
неподключённый socket получает SO_MARK, getsockopt подтверждает RU/foreign,
реальные EBADF и закрытый RawConn не игнорируются. Без этого CI proof не
объявляется полученным; local macOS тесты его не заменяют.

## Альтернативы и последствия

- DNS view equality без привязки адреса: не гарантирует выбранный dial IP.
- Инверсия RU/other classifier: открывает unknown и смешанные ответы.
- Global domainStrategy change: изменяет другие маршруты и DNS поведение.
- Existing finalRules block: containment, но не RU rerouting.
- Kernel country set для всей системы: существенно шире одного outbound.

Guard ограничивает новый outbound, сохраняет RU socket routing даже при
несовпадении DNS view и закрывает неизвестность. IPv6 для этого outbound
временно недоступен; UseIPv4 улучшает доступность, но security опирается на
проверку actual socket, а не на preference. Отключение — возврат прежнего
node-scoped profile без guard/outbound через owner API.
