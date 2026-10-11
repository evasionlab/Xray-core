# Per-instance admission hooks для native runtime

Статус: outer wrapper реализован в PR #30; расширение stream lifecycle — Proposed,
проверяется только в candidate. Это не включение native runtime на VPN-узлах.
Owner: `evasionlab/Xray-core`. Consumer: `evasionlab/vpn-node-runtime`.
Общий контракт owner exit хранится в runtime
`docs/contracts/owner-exit-config-parity.md`; инфраструктурное включение отдельно
принадлежит `evasionlab/infra`.

## Контекст и проблема

Обычный Core сохраняет собственные dispatcher, mux и proxy semantics. Native
runtime добавляет account/tag admission и управляемое закрытие сеансов на одном
Core instance. Уже существующий `routing.InboundDispatcherWrapper` оборачивает
inbound dispatcher до mux interception: VLESS/mux parent проходит локальное
admission, а дети возвращаются в установленный dispatcher.

Trojan TCP и UDP-over-TCP используют `Dispatch`, а не внешний `DispatchLink`.
Время жизни отдельного child ray не равно времени жизни authenticated TCP parent.
Регистрировать parent на каждый destination, удерживать его в orphan map или
угадывать завершение по таймеру нельзя: revoke и device accounting стали бы
неполными, а cleanup — неограниченным.

## Решение candidate

Optional `routing.InboundSessionLifecycle` имеет метод
`BeginInboundSession(context.Context) (context.Context, func())`.

TCP и UNIX worker вызывают Begin после установки `session.Inbound{Tag, Conn}` и
sniffing content, до `proxy.Process`. Authentication в этот момент ещё не
произошла. Возвращённый context должен сохранять исходное состояние Core;
cleanup вызывается через defer при завершении Process, включая error и panic.
Nonnil context и cleanup обязательны: некорректный hook останавливается до
Process. Без optional feature вызывается прежний Process с прежним context.
Native datagram worker не входит в это расширение.

Lifecycle берётся из установленного dispatcher конкретного Core instance, а
не из mux/outer wrapper, который не обязан пересылать optional interfaces.
Другие instance и стандартный dispatcher не получают hook автоматически.

Runtime consumer лениво регистрирует authenticated parent на первом dispatch,
проверяет текущий account/tag и epoch под admission lock. Context scope ограничен
одним живым stream; его terminal fence нельзя сбросить при re-grant. Завершение
Process освобождает scope и принадлежащие ему children; поздняя регистрация child
повторно проверяет scope. Revoke закрывает реальный inbound Conn. VLESS использует
существующий parent, не создавая второй. Core hook сам по себе не разрешает доступ.

До поддержки Trojan listener runtime требует signed manifest capability
`tracked_dispatch_parent/v1`, наряду с `outer_admission/v1`; наличие только
outer wrapper не доказывает Trojan parity. Manifest validation принадлежит
access/runtime consumer, а не библиотеке Core. Авторизация нескольких tags
должна быть подтверждена отдельно; этот hook её не расширяет.

## Альтернативы и последствия

Per-Dispatch parent и cleanup по idle timer отвергнуты: UDP child churn не
заканчивает TCP parent. Глобальный hook отвергнут: менял бы обычный Core и другие
instance. Регистрация до authentication отвергнута: Begin не устанавливает user.

Расширение добавляет один optional вызов на stream только для consumer с feature;
не добавляет goroutine, background timer, глобальные maps, credential wire или
production flag. Rollback библиотеки — прежний immutable Core pin; runtime с
обязательной новой capability должен отказаться запускаться с несовместимым pin.

Минимальная проверка Core: реальные TCP/UNIX callbacks, cleanup при success,
error, cancellation и panic, отказ некорректному hook, прежний путь без feature.
Следующая consumer проверка: authenticated Trojan TCP и UDP-over-TCP, child churn,
rotation/revoke, отсутствие orphan после Process end и один VLESS/mux parent.
Core tests не являются доказательством production или двухпортовой авторизации.
