# A53 PPR patcher

[English](README.md) | **Русский**

Проект собирает два профильных инструмента для A53:

- динамический selector PPR-PFS чтений `NATIVE` / `PLAINTEXT_NOAUTH`,
  выбирающий путь для каждого запроса;
- отдельный опциональный обход KMB whitelist encryption-команды opcode `0x53`.

У KMB-инструмента собственные main, state machine, таблица профилей, verifier
и тесты. Он не линкуется ни в один `a53_ppr_*` payload, поэтому установка и
status selector не разрешают, не читают, не классифицируют и не меняют
инструкцию FsWrite.

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
- вывод в консоль и `/dev/notification0`; payload объединяет лог в одно
  финальное popup вместо отдельного syscall для каждой строки;
- host-тесты state machine и статическая проверка профилей/wrapper.

## Сборка

Из WSL с заданным `PS5_PAYLOAD_SDK`:

```sh
cd ppr-patcher
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make -j2
```

В `ppr_profiles.inc` записаны все 54 архивных MP4-релиза от 1.00 до 11.40.
В отдельном `kmb_range_profiles.inc` находятся 31 проверенный KMB layout от
4.00 до 10.60. `make profiles` пересобирает обе таблицы из `PPR_FULL_ROOT`
(`../../MP4_1.00-12.00` по умолчанию), используя `PPR_DRAM_ROOT`
(`/mnt/j/PS5Dev/mp4`) как резервный источник. `make verify` независимо
извлекает и проверяет каждый профиль по этим ELF. Имя источника принимается
только при совпадении release-маркера внутри embedded AArch64 ELF, поэтому
ошибочно названный full image не может перекрыть правильный DRAM fallback.
Имеющиеся образы `6.00.01`, `7.01.01` и `8.20.02` проверяются как точные aliases
`6.00`, `7.01` и `8.20`; у них те же runtime firmware ID, поэтому дубли строк
профилей не создаются.

Артефакты записываются в `build/`:

- `a53_ppr_patcher.elf` — payload status/control с аргументами;
- `a53_ppr_install.elf` — установка с проверенным pair-only fast transport;
- `a53_ppr_install_fast.elf` — alias с совместимым именем, тем же действием и
  теми же transport defaults;
- `a53_ppr_plaintext.elf` — install alias для launcher без аргументов;
- `a53_ppr_native.elf` — stock-restore alias для launcher без аргументов;
- `a53_ppr_uninstall.elf` — восстановление точных stock entry instructions;
- `a53_kmb_range_install.elf` — отдельный fixed-action payload обхода
  whitelist AES-индексов opcode `0x53`;
- `a53_kmb_range_uninstall.elf` — отдельный fixed-action payload
  восстановления точной stock-инструкции.

Для запуска используйте только эти файлы из `build/`. Скопированные ранее
ELF в корне репозитория могут содержать старую реализацию; повторно их
использовать нельзя.

## Точные профили вместо предположений о прошивке

Каждый бинарник читает полный A53 suffix `releases/XX.XX` и выбирает точный
профиль. Для 1.x используется объединённый DEV text layout, для 2.x/3.x —
ранний split ABI, для 4.x–10.x — текущий ABI, для 11.x — поздний ABI. Resolver
проверяет соответствующие live-записи сегментов, преобразует исполняемые
SRAM/G6 адреса и сравнивает каждую подключаемую точку патча с её ожидаемым
stock/current word. Неизвестные release, layout, инструкция или подключённый
trampoline приводят к отказу до первой записи.

Адреса принадлежат профилю и не являются предположениями алгоритма. Только как
пример: в профиле 9.40 общий package decrypt/auth helper находится по адресу
`0x04e5a6bc`. Для другого образа нужен собственный полностью проверенный
профиль.

Перед записью transport сравнивает scalar read с read-only batch из 16 команд
и проверяет две последовательные транзакции через одну пару fd/kqueue.
Максимальный read envelope покрывает preflight из 15 команд без синтетической
записи в A53. Production-мутации намеренно ограничены формой packet,
подтверждённой рабочим fast path: две записи, затем два их точных readback.
Новая группировка восьми записей state machine не предоставляется.
Неподдерживаемые ускорения отключаются, а проверенные fallback остаются
доступны. Каждый ответ ограничен целым DECI5S/SDBGP envelope и обязан вернуть
sequence текущего запроса; старый result от более длинного предыдущего packet
отвергается.

Для чистой установки fixed-action payload GET_CONF занимает одну транзакцию,
успешная проверка возможностей — ещё две транзакции и одно открытие, дескриптор
которого сохраняется. Чистая установка использует ещё одиннадцать транзакций:
snapshot layout, точный preflight 15 sites, парный write/readback caves, три
транзакции для трёх внутренних hooks (одна пара и один scalar write/readback) и
пять парных транзакций для десяти публичных caller. Итого нормальный путь
выполняет четырнадцать DECI5S-запросов плюс однократный handshake поиска
mailbox. Ни одно из этих чтений или записей не содержит FsWrite/KMB.

## Командная строка

```text
--status
--install --idle
--uninstall --idle
--mode native --idle
--mode plaintext-noauth --idle
--fast --persistent --batch --mixed-io
--conservative
```

Для `--idle` также поддерживается alias `--i-know-ppr-idle`.

`--install` устанавливает динамический selector; `--uninstall` возвращает
точные stock entry instructions. Обе команды `--mode` являются compatibility
alias: `plaintext-noauth` устанавливает тот же динамический selector, а
`native` удаляет его. Они не задают постоянный глобальный режим. Mutating
actions в payload с аргументами также по умолчанию включают все проверяемые
ускорения; `--conservative` явно отключает их.

`--status` выполняет только чтение. Он показывает только состояние selector,
разрешённые адреса cave и счётчики transport. Команда успешна для полного
stock/installed образа selector.

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

Wrapper загружает полные 32-битные аргументы `kmbIdxKeyAes` и
`kmbIdxKeySha` из `[sp+0x18]` и `[sp+0x20]`. `PLAINTEXT_NOAUTH` выбирается
только для точной пары, опубликованной ядром:
`AES=0x000000ff, SHA=0x000000fe`. Любой другой запрос без изменений уходит в
исходный helper.

Поля индексов в A53 девятибитные. Сравнение только младшего байта объединяет
разные реальные значения, а проверка одного AES также перехватывает native
запросы. Kernel builders и outer, и inner NAPS-чтения сохраняют полную пару,
поэтому unsigned inner PFS не требует ослабленного selector. После точного
совпадения пара заменяется приватными маркерами `0x7ff` / `0x7fe`. Они лежат
вне штатного девятибитного диапазона KMB и поглощаются внутренними hooks до
кодирования аппаратного дескриптора.

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

Для `PLAINTEXT_NOAUTH` исходные common helper и native dispatch сохраняют
управление выбором буфера, проверками ёмкости, continuation, completion-таблицами,
clocks и публикацией queue 0. Два AES-builder hook заменяют только помеченный
AES data descriptor штатным physical-to-ZCN plaintext descriptor этой прошивки.

```text
штатные common helper / native dispatch
  -> setup descriptor queue 0, completion a4
  -> IdmaPt(engine 5 / unit 0, queue 0, completion a5)
  -> штатный bookkeeping и submit queue 0
  -> штатный WaitForIdmaAes queue 1, completion a4
  -> терминальный WaitForIdmaAes, completion a6
  -> публикация per-buffer q1 release id и low-24 dependency mask
  -> submit queue 1
```

Помеченные AES-XTS и SHA3-CMAC descriptors не достигают hardware. `a5` и `a6`
нельзя объединять: `a5` завершает NVM internal-buffer command, а `a6` является
терминальным уведомлением чтения. Q1 release entry и mask не дают следующему
queue-0 reuse обогнать терминальный wait.

## Независимое расширение KMB range

`a53_kmb_range_install.elf` меняет только
`FlashWriteEncryptAndCalculateSha` (opcode `0x53`): точная ветвь отказа `b.hi`
в профильном site заменяется безусловным переходом на `site+0x24`. Тем самым
эта классификация диапазона/bitmask пропускается и для каждого запроса
выбирается её штатный разрешённый путь. Меняется только одна инструкция; весь
код и проверки после разрешённого пути остаются stock. AES base по-прежнему
извлекается как 8-битное поле: допустимы слоты 0..255 и XTS base не выше 254.

Ни один selector payload `a53_ppr_*` не читает, не меняет и не восстанавливает
эту инструкцию FsWrite; её касаются только два отдельных payload
`a53_kmb_range_*`.

Эта операция не устанавливает и не удаляет read selector; её бинарник не
линкует `ppr_patch.c`. Он проверяет один точный snapshot DEV layout, выполняет
одно чтение состояния инструкции, а при необходимом изменении — одну запись и
один readback. Текущее слово обязано точно совпасть с профильным stock или
patched значением. `a53_kmb_range_uninstall.elf` восстанавливает точную
профильную stock-инструкцию. Отдельная таблица покрывает все 31 архивный
профиль 4.00–10.60; на 1.x–3.x и 11.x операция завершается как unsupported до
любой записи, не ограничивая поддержку read selector.
Если readback после изменения не проходит, payload пытается точно вернуть
предыдущую инструкцию и проверяет этот rollback перед возвратом ошибки.
Неопределённый timeout отдельного патча также сверяется новым чтением; если
restore подтвердить нельзя, выдаётся `KMB_ROLLBACK_REBOOT_REQUIRED`.

## Безопасность состояния патча

При установке сначала записывается неподключённый cave-код, затем подключаются
три внутренние точки helper и последними перенаправляются десять публичных
caller. При удалении публичные caller отключаются до восстановления внутренних
точек. Каждая мутация немедленно проверяется точным readback. Timeout
транспорта не доказывает, что A53 пропустил запись, поэтому error path сначала
делает новое точное чтение и принимает уже установленное нужное значение.
Rollback выполняется по фазам и проверяется; если публичные caller нельзя
подтвердить как stock, внутренние hooks намеренно остаются целыми и payload
сообщает `ROLLBACK_REBOOT_REQUIRED`. Быстрый preflight
операции читает все тринадцать текущих и две старые entry words одним пакетом
из 15 команд. При чистой stock-установке старые байты caves не читаются, потому
что будут перезаписаны; caves читаются только для классификации точного
текущего hooked/mixed состояния. После успешных проверенных записей лишний
полный снимок состояния повторно не запрашивается.

Проверка состояния также читает старые точки precheck и dispatch, которые
использовало предыдущее поколение патча. Состояние считается текущим stock или
installed только при точных stock words в обеих старых точках. Точные старые
branch targets выводятся как `LEGACY_REBOOT_REQUIRED`; и install, и uninstall
завершаются до первой записи. Текущий payload никогда не исправляет, не
мигрирует и не перезаписывает эти старые точки. Перед применением текущего
патча нужно перезагрузить заведомо stock A53 image (либо использовать
соответствующий старый uninstaller в проверенной для него среде). Неизвестное
слово в любой старой точке также приводит к fail-closed отказу.

Прерванную текущую транзакцию можно восстановить, только если оба текущих
trampoline полны, каждый текущий entry word точно равен stock/current значению,
а обе старые точки точно stock. Неизвестные подключённые байты никогда не
исправляются предположительно. Состояние FsWrite KMB не входит в эту state
machine и обрабатывается только отдельными payload.

## Проверка

```sh
make verify
make host-test
```

`make verify` проверяет все 54 A53 ELF, три patch-version alias, тринадцать site
selector и branch target,
native AES и штатный plaintext descriptor builder, terminal SHA release/submit
layout, размещение в свободном executable tail, точную семантику FE/FF selector
и побайтовое совпадение wrapper, сгенерированных C и assembler. Отдельный KMB
verifier проверяет точный 20-word контекст FsWrite, DEV layout, site, stock word
и заменяющую ветвь для всех 31 KMB-профилей.

`make host-test` проверяет status, обязательный `--idle`, install,
восстановление прерванного состояния, uninstall, отказ при неизвестной
инструкции и отказ для неподдерживаемого профиля selector. Отдельный тест
проверяет KMB install/uninstall, отказ на неточном layout и неизвестном слове,
а также ошибку readback.

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
