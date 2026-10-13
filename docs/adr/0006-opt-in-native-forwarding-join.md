# ADR-0006: Opt-in join native forwarding одного Core instance

- Status: Proposed
- Date: 2026-10-13
- Repo-owner: `evasionlab/Xray-core`
- Consumers: будущая отдельная интеграция XrayR; обычные Core callers не переключены
- Implementation scope: SOURCE-only; без image/release, runtime flags, live traffic и gRPC

## Контекст и проблема

`task.Run` может вернуть ошибку или cancellation до окончания соседней copy.
Trojan UDP-over-TCP дополнительно владеет `udp.handleInput`, response callback
и downstream freedom copies; закрытый inbound socket сам по себе не доказывает
их завершение. Listener TCP также запускает transport delivery goroutine до
controller callback. Старый `Instance.Close` закрывает features, но не является
доказательством завершения всех forwarding owners. Process exit не доказывает
финальный accounting drain и может потерять ещё не staged counters.

Нужна минимальная same-instance foundation, которую можно честно проверить
до отдельной интеграции XrayR. Существующие constructor и глобальный `task.Run`
сохраняют прежнее поведение.

## Решение

`core.NewWithForwardingDrain(ctx, config, ForwardingDrainConfig)` сначала
клонирует и валидирует полный compiled graph, затем создаёт один private owner.
Возвращаемый `*ForwardingDrain` относится только к этому `*Instance`.
`CloseAndJoin(ctx)` публикует terminal admission closure и ожидает реальные
owners. При deadline/error возвращается нулевой result, instance остаётся
sealed; повторное ожидание относится к тому же owner и cleanup batch.

Первый поддержанный graph: 1–2 уникальных inbound tags, каждый — Trojan/TCP
с одной валидной inline static TLS certificate/key pair (`OneTimeLoading`,
без OCSP/renewal/issuer/path/ECH), без fallback/sniffing/masks; builtin
DefaultDispatcher и один simple freedom outbound, IP destinations. Optional
fixed policy/stats/log допустимы. Router/DNS apps, custom dispatcher,
extensions, mux/XUDP, TimeoutOnly, proxy chaining, transport masks, destination
rewrite, fragmentation/noises/PROXY protocol не поддержаны. Unknown fields,
включая nested typed account/TLS/config, отвергаются. Local configured freedom
final rules сохраняются; loopback test allowance не меняет default policy.

После init поздние `AddFeature`, manager `AddHandler`/`RemoveHandler` запрещены
на этом instance до Start, во время работы и после closure. Guards используют
constructor-captured instance context, а не выбранный caller context. Dispatcher
также требует exact owner и уже зарегистрированный native-parent lineage до
allocations/dispatch. Прямой native outbound handler Dispatch также получает
actual child admission до Process/dial; Dial требует private marker именно этого
живого admitted Dispatch. Caller owner-carrying context без marker не заменяет
его authority. Cleanup links происходит до Done. Обычные nil-owner
managers/dispatchers/handlers не меняются.

Listener loop, accepted transport delivery, native parent, dispatch worker и
каждая выбранная copy регистрируются **до go/Start effect**. Startup token
регистрируется до lifecycle lock. Seal не ожидает этот lock; начатый startup
входит в join, а дальнейшие Start effects отвергаются. Parent completion ждёт
всех зарегистрированных descendants. Opt-in transport callback вызывает
native worker синхронно в уже owned goroutine, не создавая второго скрытого fork.

Selected Trojan/freedom branches используют local `RunJoined`; глобальный
`task.Run` не изменён. При error/cancellation принадлежащие endpoints
interrupt/close, затем обе реальные copies заканчивают cleanup до возврата.
Opt-in activity timers закрываются на завершении Process. UDP dispatcher
закрывает rays и ждёт `handleInput` вместе с его callback вне dispatcher mutex;
UDP parent не считается завершённым раньше этого ожидания. Mux worker не
создаётся в declared graph.

Terminal interruption — один owned batch, не goroutine на каждый resource.
Cancellation всех captured tokens публикуется до potentially held native
Close/Interrupt. `Join` ждёт и batch, и forwarding tokens; ctx ограничивает
**ожидание**, не выдаёт выдуманное completion и не бросает cleanup ownership.
CapturedParents/Tasks относятся к активным forwarding tokens при seal;
joined control cleanup worker не добавляется к forwarding census. Уже
завершённые до seal owners в этом volatile capture отсутствуют.

## Граница результата

`PhysicalJoin="completed"` означает только окончание captured selected native
forwarding owners и interruption batch этого instance. Это не OS-success count,
не remote delivery, не stats freeze, counter census, финальная финансовая
terminality, durable restart closure или бизнес handoff. `FinalAccounting`
всегда `not_proven`. Feature metadata/logging shutdown и освобождение всего
Core instance остаются обязанностью обычного `Instance.Close`; join handle
не заявляет завершение непередающих telemetry/background features.

Текущий CDN owner catalog содержит marked freedom и VLESS/TCP mux; эта
foundation **не** доказывает совместимость полного live CDN graph. XrayR
custom dispatcher, signed policy/static Core ABI, image pin и before-go
controller bridge потребуют отдельного решения и проверки. Никаких downstream
pins, protobuf, production flags или release workflows этот batch не меняет.

## Проверка

Genuine Core fixture использует два Trojan TLS/TCP inbound, actual TCP echo и
Trojan UDP-over-TCP response; successful join сопровождается native socket EOF
и запретом restart. Отдельные actual TCP request/response copy barriers и
actual Core/freedom UDP response callback удерживают native completion:
deadline даёт zero result, release позволяет реальный join. Startup barrier
удерживает существующий lifecycle lock; late Start не выполняет effects после
seal. Held native Close подтверждает отдельное ожидание interruption batch.

Unsupported extension/fallback/plaintext/nil transport/nil port/nested unknown/
reload certificate, unowned/foreign dispatcher и late feature/manager mutations
отвергаются до listener/forwarding effects. Capacity admission проверяется до
fork. Race detector включён, TLS verification не отключена. Старые default
UDP fixture и outbound tags-cache races фиксируются отдельно как limitations;
эта работа их не исправляет и не выдаёт за original incident RCA.

## Альтернативы и последствия

Глобальный rewrite `task.Run`, process-wide goroutine census и process exit
отвергнуты: меняют default semantics и не дают scoped accounting authority.
Broad graph support отложен; строгий отказ лучше неполного утверждения о join.
Registry volatile и bounded; ownership не переживает process restart. Если
native resource не завершает Close/Interrupt, caller может перестать ждать,
но positive physical result отсутствует до actual completion.
