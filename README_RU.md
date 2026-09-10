# A53 PPR patcher

[English](README.md) | **Русский**

Проект собирает профильный A53 patcher с двумя независимыми функциями:

- динамический selector PPR-PFS чтений `NATIVE` / `PLAINTEXT_NOAUTH`,
  выбирающий путь для каждого запроса;
- опциональное расширение KMB-диапазона ExtFs/opcode `0x53` encryption.

Selector заменяет только криптографическую часть помеченных 64-КиБ
package-чтений. Native-запросы продолжают вызывать исходный A53 helper с
неизменёнными аргументами. Глобального plaintext-режима нет: после одной
установки native и помеченные plaintext mount могут чередоваться.

> **Безопасность:** для любого изменения A53-кода требуется `--idle`. Этот
> флаг подтверждает, что оператор уже дождался завершения всех PPR read/mount,
> APR bind и unmount; payload не может проверить это условие самостоятельно.

Подробный разбор caller и очередей находится в
[`PPR_READ_PATHS_RU.md`](../PPR_READ_PATHS_RU.md). Английская версия —
[`PPR_READ_PATHS.md`](../PPR_READ_PATHS.md).

## Состав проекта

- небольшой DECI5S transport через `/dev/mp4/dump`;
- state machine точных профилей с отказом на неизвестном layout или
  инструкции;
- AArch64 runtime/plaintext wrapper, генерируемые из одного общего шаблона;
- вывод каждой полной строки в консоль и `/dev/notification0`;
- host-тесты state machine и статическая проверка профилей/wrapper.

## Сборка

Из WSL с заданным `PS5_PAYLOAD_SDK`:

```sh
cd ppr-patcher
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make -j2
```

Target проверки ожидает по одному A53 ELF для каждого профиля, включённого в
`ppr_patch.c`. Пути по умолчанию и переменные для их переопределения находятся
в `Makefile`.

Артефакты записываются в `build/`:

- `a53_ppr_patcher.elf` — payload status/control с аргументами;
- `a53_ppr_install.elf` — установка с проверенными batch и persistent
  transport;
- `a53_ppr_install_fast.elf` — установка со всеми проверенными ускорениями;
- `a53_ppr_plaintext.elf` — install alias для launcher без аргументов;
- `a53_ppr_native.elf` — stock-restore alias для launcher без аргументов;
- `a53_ppr_uninstall.elf` — восстановление точных stock entry instructions;
- `a53_kmb_range_install.elf` — расширение ExtFs allocator и обход отдельного
  whitelist AES-индексов opcode `0x53`;
- `a53_kmb_range_uninstall.elf` — восстановление трёх точных stock-инструкций.

## Точные профили вместо предположений о прошивке

Каждый бинарник читает полный A53 suffix `releases/XX.XX` и выбирает точный
профиль. Resolver проверяет live-записи сегментов IO и DRAM-IO, преобразует
исполняемые SRAM/G6 адреса и сравнивает каждую подключаемую точку патча с её
ожидаемым stock/current word. Неизвестные release, layout, инструкция или
подключённый trampoline приводят к отказу до первой записи.

Адреса принадлежат профилю и не являются предположениями алгоритма. Только как
пример: в профиле 9.40 общий package decrypt/auth helper находится по адресу
`0x04e5a6bc`. Для другого образа нужен собственный полностью проверенный
профиль.

Перед записью transport также сравнивает scalar read с batch из двух команд и
проверяет две последовательные транзакции через одну пару fd/kqueue.
Неподдерживаемые ускорения отключаются, а проверенные fallback остаются
доступны. Смешанные пакеты write/readback применяются только после проверки
batch ABI.

## Командная строка

```text
--status
--install --idle
--uninstall --idle
--mode native --idle
--mode plaintext-noauth --idle
--kmb-range-install --idle
--kmb-range-uninstall --idle
--fast --persistent --batch --mixed-io
--conservative
```

Для `--idle` также поддерживается alias `--i-know-ppr-idle`.

`--install` устанавливает динамический selector; `--uninstall` возвращает
точные stock entry instructions. Обе команды `--mode` являются compatibility
alias: `plaintext-noauth` устанавливает тот же динамический selector, а
`native` удаляет его. Они не задают постоянный глобальный режим.

`--status` выполняет только чтение. Он показывает состояние selector,
разрешённые адреса cave, независимое состояние KMB range и счётчики transport.
Команда успешна только для полного stock/installed образа selector и известной
stock/extended инструкции KMB range.

## Покрытие путей чтения

Десять прямых caller общего helper
`zcnDriverAddCommandsPackageDecryptToZcnBufferAndVerifySign` перенаправляются в
один runtime wrapper:

| № | Функциональный путь | ZCN-буфер |
| ---: | --- | --- |
| 1 | `FlashReadPackage1Block` | input |
| 2 | `FlashReadPackage2Block` | input |
| 3 | `FlashReadDecryptAndVerifySha` | input |
| 4 | `ExtFs_UnpackPackage1Block` | input |
| 5–6 | обе ветви `ExtFs_UnpackPackage2Block` | input |
| 7 | `ExtFs_DecryptAndVerifySha` | output |
| 8 | `NSID2_FlashAppendFromDeltaSource` | input |
| 9–10 | обе ветви `NSID2_FlashReadPackageFile` | input |

Перехват общего helper сохраняет выбор буфера, dependency, PASID, состояние
очередей и терминальное уведомление каждого caller. При неполном перехвате
часть ExtFs/NSID2 запросов попала бы в native crypto с plaintext sentinel.

## Selector для каждого запроса

Wrapper читает `kmbIdxKeyAes` из `[sp+0x18]`:

- любой выделяемый AES index без изменений уходит в исходный helper;
- приватный невалидный AES index `0xff` выбирает `PLAINTEXT_NOAUTH` и
  превращается во внутренний encryption type `0x7f`.

Подписанный outer PFS обычно передаёт `SHA=0xfe, AES=0xff`, а unsigned inner
PFS может не передавать SHA key и сохранить только AES sentinel. Поэтому
dispatch зависит от `AES == 0xff`, а не от точной пары `fe/ff`. Штатный путь не
может принять `0xff`: helper сразу формирует `IdmaDecrypt`, и IOC отклоняет
невыделяемый индекс с `ILLEGAL_KMB_ACCESS`.

Sentinel должен устанавливаться соответствующей kernel-side mount-логикой
только для проверенного plaintext mount. Добавление A53-профиля само по себе не
добавляет и не разрешает kernel-side marker.

## Контракт очередей

Штатная native-цепочка:

```text
WaitForBufferFree
  -> IDMA + AES-XTS, queue 0, промежуточное notify
  -> SHA3-CMAC, queue 1, терминальное notify
  -> caller-specific consumer
```

Для `PLAINTEXT_NOAUTH` wrapper сохраняет штатные wait, проверку ёмкости
SHA-очереди, выбранный input/output buffer, dependency, PASID, prediction state
и оба completion event. Он также отклоняет package source без ненулевого
BFS/LVD LPAR в физическом адресе до добавления descriptor.

```text
IdmaPt(passthrough unit 1, queue 0, native IDMA/AES notify)
  -> WaitForIdmaAes(queue 1, native terminal SHA notify)
  -> сохранить max(lastSha, IdmaPt) + 0x19a и buffer watermarks
  -> submit queue 1
  -> submit queue 0
```

Для помеченного чтения команды AES-XTS и SHA3-CMAC не создаются. Queue 1
активируется до короткого producer в queue 0, поэтому waiter видим до
завершения IDMA. Passthrough unit 1 — штатный engine для направления MP4
physical source -> ZCN buffer; его номер нельзя путать с номером очереди.

## Независимое расширение KMB range

`--kmb-range-install` меняет два независимых валидатора. В
`ExtFs_EncryptAndCalculateSha` patched instruction выбирает полную 9-битную
hardware aperture с исключительной верхней границей 512. В
`FlashWriteEncryptAndCalculateSha` (opcode `0x53`) обе ветви отказа whitelist
AES-индексов перенаправляются в штатный success block. В opcode `0x53`
AES/SHA-поля остаются 8-битными: допустимы слоты 0..255 и XTS base не выше
254.

Эта операция не устанавливает и не удаляет read selector. Она разрешена,
только если все три текущие инструкции точно совпадают с известными stock или
patched words, а каждая запись проверяется readback. Старая установка только
ExtFs распознаётся как восстанавливаемое частичное состояние.
`--kmb-range-uninstall` восстанавливает все три профильные stock-инструкции.

## Безопасность состояния патча

При установке сначала записывается неподключённый cave-код, затем подключаются
две внутренние точки helper и последними перенаправляются десять публичных
caller. При удалении публичные caller отключаются до восстановления внутренних
точек. Каждая запись проверяется чтением, после чего заново читается полное
итоговое состояние.

Прерванную транзакцию можно восстановить, только если оба текущих trampoline
полны, а каждый entry word точно равен stock/current значению. Неизвестные
подключённые байты никогда не исправляются предположительно. Для трёх
инструкций KMB range действует та же политика exact stock/patched, но их
состояние остаётся независимым.

## Проверка

```sh
make verify
make host-test
```

`make verify` проверяет переданные A53 ELF, размеры и flags сегментов, все
двенадцать patch site и branch target, ABI helper/IdmaPt/submit, порядок и
уведомления plaintext-очередей, KMB allocator guard, свободный executable tail
и побайтовое совпадение wrapper, сгенерированных C и assembler.

`make host-test` проверяет status, обязательный `--idle`, install,
восстановление прерванного состояния, uninstall, независимые KMB
install/uninstall, отказ при неизвестной инструкции и отказ для
неподдерживаемого профиля на mock A53 layout.

На консоли после перезагрузки и полного drain очередей сначала проверьте
`--status`. До помеченного plaintext package запустите заведомо исправный
native package, затем повторите mount/unmount для ExtFs, inner PFS, APR и
NSID2/delta. Ожидаемое поведение очередей и разбор ошибок приведены в подробном
документе о путях чтения.

## Установка проверенным fast payload

```sh
make deploy-install-fast PS5_HOST=192.168.1.2 PS5_PORT=9021
```

Deploy target намеренно отделён от `all`: обычная сборка ничего не записывает
на консоль.
