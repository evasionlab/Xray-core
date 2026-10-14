# ADR-0006: Явное подтверждение свежей классификации non-RU

- Status: Proposed
- Date: 2026-10-14
- Repo-owner: `evasionlab/Xray-core`
- Downstream consumers: `evasionlab/dns-route-cache`, `evasionlab/XrayR`, `evasionlab/vpn.bot`, `evasionlab/infra`
- Org-wide ADR required: Yes; org-owner готовит связанное решение.
- Implementation status: source candidate; production metadata и образы этим PR не изменяются.

## Контекст и проблема

На cdn10 реальные клиентские YouTube TCP проверки завершаются без HTTP-ответа,
при этом gstatic через primary egress работает. Owner compile и completion logs
показывают YouTube через существующий `core-services → direct`. Проверенный
primary egress возвращает YouTube HTTP 204. Общая policy остаётся принятой;
исправление должно ограничиваться физическим процессом cdn10, узлы 61 и 176,
и сохранять маршрутизацию RU.

`asyncDnsRoute` сейчас сопоставляет RU и опционально сохранённый stale RU.
Инверсия этого результата небезопасна: cache miss, pending и ошибки также
возвращают false. Более того, classifier `route=other` означает наличие хотя бы
одного адреса вне RU, включая смешанные RU/non-RU ответы; старые ответы и
снимки не содержат отдельного положительного доказательства non-RU.

## Решение

Добавить конфигурацию `matchDecision` со значениями `ru` и `non_ru`.
Отсутствие поля сохраняет прежний RU matcher, включая настроенный stale grace.
Иные значения отвергаются при сборке JSON config и создании matcher.
Новый protobuf field 13 сохраняет решение при передаче конфигурации.

В режиме `non_ru` совпадение допускается только для свежего `route=other`
с явным `nonRuConfirmed=true`. Classifier-owner устанавливает это отдельное
доказательство только после успешного непустого DNS fill, когда каждый
валидный адрес положительно покрыт известной non-RU страной в загруженном
GeoIP asset и ни один адрес не покрыт RU. Смешанные RU/non-RU ответы,
неизвестная страна, служебные наборы GeoIP, invalid/empty DNS, ошибка и
legacy cache не выдают подтверждения. Исходная классификация `route` не меняется.
Classifier implementation и её память/CPU должны иметь отдельное source evidence.

Core сохраняет явное подтверждение в L1 и в защищённом checksum snapshot.
Отсутствие нового поля в ответе или старом snapshot означает false;
`ru=false` никогда не становится доказательством. Snapshot с одновременно
RU и non-RU подтверждением отвергается. Новая свежая классификация без
подтверждения немедленно снимает прежнее подтверждение. После fresh TTL
совпадение non-RU запрещено даже внутри допустимого stale grace. Ошибка
refresh не продлевает срок ранее полученного свежего подтверждения.

Это доказательство DNS answer-set конкретного resolver/view/GeoIP namespace
на время authoritative TTL, а не абсолютное доказательство IP последующего
отдельного dial resolution. Использование другого DNS view, геобазы или
смешанного/изменившегося набора адресов требует отдельного решения.
`domainStrategy`, глобальные правила и правила UDP этим изменением не меняются.

## Совместимость и применение

Действующий старый core декодирует classifier response через `json.Unmarshal`
и игнорирует новое response поле. Старый config parser использует
`DisallowUnknownFields` для `asyncDnsRoute` и отвергнет новый `matchDecision`:
сначала нужны проверенный classifier proof и новый CI image core/XrayR,
затем owner compile и canary profile только на новом image.

Canary требует положительного свежего proof, сохранения mandatory guards,
прежних RU правил и неизменности UDP/остальных routing rules. Проверка включает
owner apply/ACK и настоящий клиентский HTTP-over-tunnel YouTube плюс RU smoke.
До этого новый profile не активируется. При откате сначала вернуть прежний
owner profile, затем прежний image. Нельзя подавать новое config поле старому
engine или заменять отсутствие доказательства здоровым результатом.

## Альтернативы

- Инвертировать RU matcher: отвергнуто, неизвестность открывает foreign route.
- Считать любой `other` non-RU: отвергнуто, смешанные ответы включают RU.
- `geoip:!ru` с изменением global `domainStrategy`: затрагивает остальные правила
  и DNS поведение; не входит в canary scope.
- Изменить общий `core-services`: затрагивает другие процессы и принятую policy.
- Kernel country guard: на cdn10 полный независимый RU guard не подтверждён.

## Последствия и проверка

Новый режим остаётся закрытым без положительного доказательства. Legacy RU
поведение и его L1/SWR deadlines сохраняются. Legacy snapshots требуют нового
fill до non-RU совпадения. Размер snapshot увеличивается одним optional bool
на подтверждённую запись; очередь, число workers и route wait не меняются.

Focused tests покрывают новые/legacy ответы, смешанный или неизвестный proof,
RU, pending, HTTP/decode errors, expiration in transit, границу fresh TTL,
отзыв доказательства новым fill, snapshot restore/противоречие, JSON validation
и protobuf roundtrip. Действующий AsyncDNS regression suite проверяет прежние
RU/SWR/HA/TTL и bounded worker contracts. Required CI и production canary
являются отдельными этапами; source tests не объявляют инцидент исправленным.
