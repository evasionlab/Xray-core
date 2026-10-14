# 0006. Типизированное наблюдение отказа validator для accounting-safe probes

Статус: Accepted для разработки и изолированного QA; production OFF.

## Контекст и проблема

Source/runtime/XrayR мониторинг grant/revoke требует отличать настоящую проверку
старого credential от TLS/network/protocol ошибок. Текущий lifecycle Begin/cleanup
связывает accepted connection, но отсутствие User после Process не доказывает
отказ аутентификации. Разбор текста ошибок/logs недостоверен и раскрывает данные.

## Решение

Optional per-instance `routing.InboundAuthenticationObserver` получает callback
только при конкретном validator.Get == nil: VLESS после чтения UUID/version,
Trojan после canonical lowercase SHA224 hex56 и CRLF. Ошибки чтения, version,
handshake, malformed prefix и прочие protocol ошибки не становятся verdict.
VLESS использует per-Process wrapper, без context в общем validator; все остальные
методы delegated unchanged. Callback не изменяет результат validator или fallback.
Без observer существующие wire/dispatch/accounting paths сохраняются.

Callback содержит protocol и SHA256 private domain-separated authenticator:
`vpn.runtime.authenticator.v1`, protocol и canonical authenticator hex. VLESS
нормализует route bytes6/7 точно как настоящий ProcessUUID; Trojan использует wire
SHA224 password. Нет plaintext credential, UUID, password или subscription state.
Digest запрещён в logs/events/metrics и остаётся в bound private capability.

Native/XrayR adapters передают verdict только в заранее bound lease exact accepted
socket, сравнивают protocol/wire digest/boot/TTL и дают `authentication_rejected`.
Wrong digest/scope/expired/unbound остаются classification_failed/unknown. Hook
не принимает expected grant/deny и не разрешает authentication. Active/stale Core
credential продолжает аутентифицироваться и должен пропускать probe HTTP, обнаруживая
failed revoke. Lease accounting exemption и identity lineage — отдельные owners.

## Альтернативы

Парсинг строк, User==nil после cleanup и любая отрицательная HTTP попытка отвергнуты:
они маскируют protocol/network outages под успешный revoke. Глобальный auth bypass
или observer-driven deny нарушил бы реальную проверку. Hook только наблюдает решение
того же validator, которое уже произошло.

## Доказательство и последствия

Actual VLESS DecodeRequestHeader и Trojan Server.Process проверены для unknown
credential, known credential и malformed/truncated/version/CRLF случаев; race tests
проверяют per-request context. Management SDK и Core unit tests не заменяют joined
network QA stock Xray + accounting-safe runtime + healthy same-entry control.
Before canary нужны этот joined proof и конкретный diff/план пользователя.

## Owners и consumers

Owner hook — evasionlab/Xray-core. Adapters — vpn-node-runtime и XrayR;
общий lease SDK/ADR — vpn.access `docs/adr/0020-accounting-safe-runtime-probes.md`.
Protected prior credential lineage — vpn.bot; orchestration/coverage — evasionlab/infra.
Org-wide решение будет сохранено у evasionlab/infra перед canary. Отдельный Core flag
не нужен: default dispatcher не имеет observer, runtime adapter default OFF.
Rollback: отключить adapter без изменения обычного validator/credential/billing.
