# 0007. Приватный образ форка Xray-core

Статус: Accepted
Дата: 2026-10-15
Owner: evasionlab/Xray-core

## Контекст и проблема

Существующий Docker publisher форка указывал GHCR. Организационный контракт
CI требует `registry.team.evasionlab.ru` и собственные Linux runners.
При ограничении публичного runner pool точными workflow refs на main прямой
`release` event с tag ref также перестал проходить guard publisher.

Путь `vpn/xray-core` уже принадлежит upstream vendor image XTLS: существующий
writer находится в `evasionlab/XrayR`, а infra access probes используют его
immutable version/digest. Этот образ не является образом нашего форка.

## Решение

Существующий `.github/workflows/docker.yml` публикует форк в
`registry.team.evasionlab.ru/vpn/xray-core-fork`. Owner source и publisher —
`evasionlab/Xray-core`. Обычные GitOps consumers этого пути сейчас отсутствуют:
consumer delta равен нулю. Vendor path `vpn/xray-core`, writer XrayR и его
текущие infra pins сохраняют ownership.

Существующий release router вызывает Docker publisher как reusable workflow
на `@main`. Job определён в разрешённом runner group workflow на main,
проверяет source repository и published event, затем checkout делает точный
release tag. Ручная сборка на main сохраняет явный image tag и необязательные
aliases. Ни release router, ни ручной запуск не меняют GitOps consumers.

Исторический tag до миграции с публичными Docker definitions отклоняется
до сборки с явной ошибкой. Его product source/Dockerfile не подменяются
другой ревизией. Обычный путь — tag/revision, содержащий эту миграцию.

Образы собирает только GitHub Actions на собственном Linux runner. Build и
runtime base images берутся из существующего приватного platform catalog
по immutable digest. Go crosscompile выполняется на build platform; ARM variant передаётся в GOARM. Два фиксированных staging
tags `build-main`/`build-additional` используются только для сборки финального
index по returned digests; единый publisher concurrency с `queue: max` сохраняет
до100 ожидающих публикаций, не заменяя предыдущий pending run.
Native
Windows/macOS hosts для Docker publisher не требуются. Автоматические Docker
build records в GitHub artifacts отключены.

## Альтернативы

- Продолжить GHCR: противоречит принятому приватному registry контракту.
- Использовать `vpn/xray-core`: смешивает независимых writers и vendor/fork
  identity, создаёт риск подмены существующих access probe consumers.
- Разрешить весь публичный репозиторий в Default runner group: расширяет доступ
  к приватным runners; сохраняется отдельная группа с точными main refs.

## Последствия и проверка

Fork image имеет отдельную identity и может проверяться без production rollout.
Подключение нового GitOps consumer требует отдельного явного решения writer.
Проверяются release/main guards, точный checkout tag, приватные image refs,
успешный CI publisher и manifest/digest readback. Нативные Linux Go tests и
runtime interface race checks остаются в существующем `test.yml`.

Связанный организационный контракт: `evasionlab/infra`,
`docs/adr/ADR-20261015-01-ci-artifacts-private-registry.md`.
