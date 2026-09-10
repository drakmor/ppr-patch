# Пути чтения PPR-PFS на A53

[English](PPR_READ_PATHS.md) | **Русский**

Этот документ описывает контракт динамического патча `NATIVE` /
`PLAINTEXT_NOAUTH`. Описание не зависит от конкретной прошивки: адреса и
машинные слова находятся в точном профиле выбранного A53-образа. В качестве
примера ниже приведён только профиль 9.40.

Цель патча — заменить криптографическую часть одного 64-КиБ package-чтения,
не меняя выбор и время жизни ZCN-буфера, зависимости очередей и уведомления
вызывающего пути.

## Общая точка перехвата

Десять путей вызывают общий helper
`zcnDriverAddCommandsPackageDecryptToZcnBufferAndVerifySign`. Существенные
аргументы его ABI одинаковы во всех поддерживаемых профилях:

| ABI | Значение |
| --- | --- |
| `a4` / `w3` | source промежуточной dependency-команды |
| `a5` / `w4` | уведомление завершения IDMA/AES-стадии |
| `a6` / `w5` | терминальное уведомление SHA/CMAC-стадии |
| `a7` / `x6` | физический MP4 source-адрес |
| `a8` / `w7` | PASID |
| `[sp+0x10]` | тип шифрования |
| `[sp+0x18]` | AES key index |
| `[sp+0x20]` | SHA key index |

Статическая проверка профиля подтверждает сигнатуру helper, сохранение
терминального SHA-уведомления и все десять прямых `BL`. Профиль также фиксирует
две внутренние точки helper: проверку ёмкости SHA-очереди и native dispatch.

## Десять входов

| № | Функциональный путь | ZCN-буфер |
| ---: | --- | --- |
| 1 | `FlashReadPackage1Block` | input |
| 2 | `FlashReadPackage2Block` | input |
| 3 | `FlashReadDecryptAndVerifySha` | input |
| 4 | `ExtFs_UnpackPackage1Block` | input |
| 5 | `ExtFs_UnpackPackage2Block`, ветвь A | input |
| 6 | `ExtFs_UnpackPackage2Block`, ветвь B | input |
| 7 | `ExtFs_DecryptAndVerifySha` | output |
| 8 | `NSID2_FlashAppendFromDeltaSource` | input |
| 9 | `NSID2_FlashReadPackageFile`, ветвь A | input |
| 10 | `NSID2_FlashReadPackageFile`, ветвь B | input |

Первые три пути читают package/NVM-данные в ZCN input. ExtFs использует тот же
физический MP4 source, но один decrypt-путь выбирает output buffer. После
чтения NSID2/delta продолжает собственную цепочку decompression/PT/ODMA.
Поэтому общий helper — минимальная точка переключения: перехват отдельных
верхнеуровневых функций оставил бы несколько несовместимых реализаций.

### Единственный пример адресов: профиль 9.40

В этом профиле общий helper находится по адресу `0x04e5a6bc`, а прямые вызовы
расположены так:

| № | Адрес `BL` |
| ---: | ---: |
| 1 | `0x04e4879c` |
| 2 | `0x04e49048` |
| 3 | `0x06414f1c` |
| 4 | `0x06416118` |
| 5 | `0x064163a8` |
| 6 | `0x0641663c` |
| 7 | `0x06417c50` |
| 8 | `0x0642313c` |
| 9 | `0x064251dc` |
| 10 | `0x064278d0` |

Эти значения служат только примером. Для установки патча payload читает
release A53, выбирает точный профиль, проверяет live layout и ожидаемые
инструкции и отказывается от записи при любом расхождении.

## Штатная цепочка `NATIVE`

Упрощённо native-запрос выполняется так:

```text
caller
  -> общий helper и WaitForBufferFree(выбранный ZCN buffer)
  -> dependency / проверка места в очередях
  -> IDMA + AES-XTS, queue 0, notify=a5
  -> SHA3-CMAC, queue 1, notify=a6
  -> следующий ExtFs/NSID2/Package consumer
```

`WaitForBufferFree` учитывает последние SHA-, PT/ODMA- и ZDE-команды для
выбранного буфера. Выбор input/output buffer и prediction state происходит в
штатном helper до dispatch. SHA-очередь не читает те же байты параллельно: она
зависит от результата AES/IDMA и публикует терминальное событие операции.

Готовый `zcnDriverAddCommandsCopyBuffer` не подходит как замена: он строит
полную DRAM-to-DRAM цепочку `IDMA-PT + ODMA`, тогда как рассматриваемые пути
должны оставить данные в уже выбранном ZCN input/output buffer.

## Выбор режима на каждый запрос

Wrapper проверяет только `kmbIdxKeyAes == 0xff`:

- `AES != 0xff` без изменений уходит в исходный helper;
- `AES == 0xff` выбирает `PLAINTEXT_NOAUTH` и заменяет внутренний encryption
  type на `0x7f`.

Подписанный outer PFS обычно передаёт пару `SHA=0xfe, AES=0xff`, но unsigned
inner PFS может не иметь SHA-ключа и всё равно сохраняет AES sentinel. Поэтому
точная пара `fe/ff` больше не является условием dispatch. `0xff` не может быть
отложенным native-ключом: это невыделяемый индекс KMB, а штатный helper сразу
формирует `IdmaDecrypt`; IOC отклоняет такой запрос с `ILLEGAL_KMB_ACCESS`.

Селектор не хранит глобальный режим или latch. После единственной установки
native и помеченные plaintext-запросы могут чередоваться без повторного патча
A53. Kernel-side код должен устанавливать sentinel только для проверенного
plaintext mount; один A53-профиль сам по себе этого не делает.

## Цепочка `PLAINTEXT_NOAUTH`

Plaintext continuation сохраняет штатные wait, dependency, выбор буфера и
проверку ёмкости SHA-очереди. До добавления descriptor она также требует
полный package-backed source с ненулевым BFS/LVD LPAR в старшем слове
физического адреса. Index-only source отклоняется до запуска IDMA.

После проверок выполняется:

```text
IdmaPt(source physical -> выбранный ZCN buffer,
       passthrough unit 1, queue 0, commandInfo=native a5)
  -> WaitForIdmaAes(queue 1, commandInfo=native a6)
  -> prediction = max(lastSha, IdmaPt) + 0x19a
  -> обновление lastSha и watermarks выбранного ZCN buffer
  -> submit queue 1
  -> submit queue 0
  -> общий success return
```

SHA3-CMAC и AES-XTS не создаются, но обе стадии завершения сохраняются:
`IdmaPt` несёт промежуточное уведомление `a5`, а queue-1 wait — терминальное
`a6`. Штатный plaintext producer строит обе очереди до публикации batch.
Standalone wrapper поэтому сначала активирует queue 1 с waiter и только потом
запускает короткий PT producer в queue 0: waiter гарантированно видим до
completion. Резервирование `0x19a` не позволяет переиспользовать ZCN-буфер
раньше времени.

Passthrough unit 1 выбран намеренно: это тот же engine, который использует
единственный штатный `IdmaPt` caller направления MP4 physical source -> ZCN
buffer. Номер passthrough unit не следует путать с номером очереди: команда
по-прежнему исполняется в queue 0.

## Отдельный патч диапазона KMB

Расширение диапазона KMB не является частью read-path selector и управляется
отдельно. `--kmb-range-install` заменяет только выбор верхней границы в
`ExtFs_EncryptAndCalculateSha`: вместо ограничения request class выбирается
полная 9-битная аппаратная апертура с исключительной верхней границей 512
(допустимые индексы до 511). Нижняя граница, проверка размера XTS-пары и
диапазона CMAC остаются штатными. `--kmb-range-uninstall` восстанавливает
точную исходную инструкцию.

Операция разрешена только при точном совпадении текущей инструкции со stock
или с известным patched word. Её состояние показывается в `--status` и не
меняется при установке или удалении динамического selector.

## Инварианты совместимости

1. Native-запрос никогда не входит в plaintext continuation и вызывает
   исходный helper с неизменёнными аргументами.
2. Режим выбирается отдельно для каждого запроса по AES sentinel `0xff`;
   наличие SHA sentinel не обязательно.
3. Перехватываются все десять прямых caller, иначе часть ExtFs/NSID2 ушла бы в
   native crypto-путь с невыделяемым индексом.
4. Сохраняются `WaitForBufferFree`, выбранный input/output buffer, dependency,
   PASID, обе prediction state и публикация обеих очередей.
5. `IdmaPt` получает native `a5`, а queue-1 wait — native `a6`, сохраняя
   caller-specific completion contract.
6. Package-backed source без LPAR отклоняется до добавления IDMA descriptor.
7. Неизвестный layout, код или состояние приводит к отказу до записи.
   Прерванная транзакция восстанавливается только при полном текущем
   trampoline и точной смеси stock/current entry words.
8. Установка и удаление выполняются только после полного drain PPR/APR
   очередей; `--idle` является явным подтверждением этого условия, а не
   автоматической проверкой.

## План проверки

1. Выполнить `make -C ppr-patcher verify`: проверяются ELF всех переданных
   профилей, ABI, двенадцать patch sites, wrapper и KMB guard.
2. Выполнить `make -C ppr-patcher host-test`, затем собрать payload командой
   `make -C ppr-patcher`.
3. После перезагрузки и полного drain очередей запустить `--status`. Ожидаются
   точный профиль, состояние `STOCK` или точный текущий образ и известное
   состояние KMB range.
4. Установить selector и сначала запустить заведомо валидную native-игру. Она
   должна пройти исходный helper, обе native PPR-PFS mount-стадии и APR bind.
5. Только после native regression смонтировать тестовый plaintext package.
   Для sentinel-запроса ожидаются одна passthrough IDMA-команда в queue 0,
   терминальный wait в queue 1, отсутствие AES/SHA-команд и успешное чтение
   outer metadata.
6. Повторить mount/unmount и проверить ExtFs, inner PFS, APR и NSID2/delta.
   IOC dump или зависание после IDMA обычно указывает на порядок
   submit/completion либо lifetime буфера; ошибка inode/L2P — на формат
   тестового образа, а не на dispatch wrapper.
7. Если нужен расширенный KMB range, проверить его отдельными
   install/status/uninstall циклами и убедиться, что состояние selector при
   этом не меняется.
