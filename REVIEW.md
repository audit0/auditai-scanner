# REVIEW: обработка ошибок в auditai-scanner

Обзор всех `.ts`-файлов в `packages/*/src` (кроме `*.test.ts`), `scripts/bundle.mjs` и
`evals/harness`. `evals/fixtures/**` в обзор не входят — это специально уязвимые/безопасные
примеры для тестирования правил, а не код самого сканера.

## Общий вывод

Кодовая база написана дисциплинированно: почти каждый `JSON.parse`/`readFileSync`/`realpathSync`
обёрнут в `try/catch` с содержательным сообщением. В исходном коде сканера (вне тестов и фикстур)
нет `async`-функций, `fetch`, `child_process.exec*`, `as any` или non-null assertion (`!`) —
сканер полностью синхронный и не делает сеть/сабпроцессы. Пустых `catch {}` без объяснения не
найдено; ни один `catch` не трактует ошибку парсинга как «значит, всё безопасно».

Главный содержательный риск — не единичный баг, а **системный архитектурный паттерн**: ошибка на
уровне правила, файла или директории намеренно превращается в `warning` вместо явного сбоя, а
`warnings` не влияют на итоговый exit code сканера. Для security-инструмента это создаёт риск
тихого false negative — отчёт выглядит «чисто», хотя часть проверок не выполнилась.

---

## 1. `packages/rules/src/rule.ts:52-59` — ВЫСОКАЯ серьёзность

```ts
for (const rule of rules) {
  try {
    findings.push(...rule.evaluate({ model, graph, now, nextId }));
  } catch (e) {
    // A broken rule must never take the whole scan down; surface it as a model warning instead.
    model.warnings.push(`rule ${rule.id} failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}
```

Если любое правило (`supabase-authorization`, `supabase-sql-policies`, `supabase-storage-rpc`,
`sql-functions` и т.д.) бросает исключение — например, из-за неожиданной формы графа или бага в
самом правиле — **все находки этого правила молча исчезают**. Единственный след — строка в
`model.warnings`.

Проверено (`packages/scanner/src/fail-on.ts:21`, `packages/scanner/src/scan.ts:151`): `blocking`
считается только по `findings.some(isBlocking)`, `warnings` в этой логике не участвуют. То есть
CI может получить `exit 0` ("No blocking findings"), хотя, скажем, правило проверки
авторизации упало и не проверило проект вообще. В текстовом отчёте (`format.ts:142,175`)
предупреждения выводятся последними строками, после "No findings."/"No blocking findings." —
их легко пропустить в логах CI.

**Рекомендация**: считать сканирование неполным (не «чистым») при непустых `warnings`, либо
добавить флаг вида `--fail-on-warnings`, а также поднять предупреждения выше в отчёте / в начало.

## 2. `packages/parser/src/discover.ts:257-280` — СРЕДНЯЯ серьёзность

```ts
try {
  entries = readdirSync(dir);
} catch (e) {
  const rel = relative(root, dir).split(sep).join("/") || ".";
  warnings.push(`could not read directory ${rel}: ${errorCode(e)}`);
  return;
}
...
try {
  const st = lstatSync(full);
  ...
} catch (e) {
  warnings.push(`could not stat ${relative(root, full)}: ${errorCode(e)}`);
  continue;
}
```

Недоступная директория (нет прав, гонка при удалении во время обхода) **целиком выпадает из
скана**, без исключения — только warning. Если в такой директории лежат API-роуты или SQL-миграции,
проверки для них никогда не запустятся; итог выглядит как обычный скан с чуть меньшим числом файлов.

## 3. `packages/parser/src/parse-project.ts:2957-3037` — СРЕДНЯЯ серьёзность

Тот же паттерн на уровне отдельных файлов — чтение исходников, `.prisma`-схем, SQL-миграций с
RLS-политиками и анализ модулей:

```ts
try {
  sources.set(rel, parseSource(rel, readFileSync(join(root, rel), "utf8")));
} catch (e) {
  warnings.push(`could not read ${rel}: ...`);
}
...
try {
  registry.set(rel, analyzeModule(rel, sf));
} catch (e) {
  sources.delete(rel);
  warnings.push(`could not analyse ${rel}: ...`);
}
...
try {
  parseSqlForRls(rel, readFileSync(resolve(root, rel), "utf8"), tables);
} catch (e) { warnings.push(...); }
...
try {
  analyzeFile(project, rel, sf, ..., { routes, exposures, fileIgnores });
} catch (e) {
  warnings.push(`could not analyse ${rel}: ...`);
}
```

Файл, который не удалось прочитать/распарсить/проанализировать, **выпадает из модели проекта
целиком** — его маршруты/таблицы/политики никогда не попадут в граф и в правила. Комментарии в
коде признают это как осознанный выбор ("never throws on malformed input", "the rest of the
project is still scanned"), но именно такой fail-open может маскировать уязвимость в файле,
который не смог распарситься из-за бага самого парсера или экзотического синтаксиса.

## 4. `packages/scanner/src/config.ts:124-130` — НИЗКАЯ/СРЕДНЯЯ серьёзность

```ts
let realBase: string;
try {
  realBase = realpathSync(base);
} catch (e) {
  for (const entry of entries) drop(entry, `project root unreadable: ${errorCode(e)}`);
  return { dirs, warnings };
}
```

Если сам корень проекта недоступен через `realpathSync`, все пользовательские
`migrations`-директории из `audit.config.json` тихо отбрасываются. SQL-миграции — основной
источник данных о состоянии RLS, так что при этом сбое состояние RLS для всех таблиц станет
"unknown" вместо явной ошибки сканирования.

## 5. Небезопасные приведения типов через `unknown` — НИЗКАЯ серьёзность

- `packages/rules/src/packs/supabase-authorization.ts:147,166`
- `packages/rules/src/packs/supabase-storage-rpc.ts:32,42`

```ts
const data = handler.data as unknown as HandlerNodeData;
data: query.data as unknown as QueryNodeData,
```

`GraphNode.data` типизирован как `Record<string, unknown>`
(`packages/graph/src/graph.ts:38`), эти места приводят его к конкретным типам узлов без
runtime-проверки. Риск невысокий, поскольку приведение идёт сразу после
`graph.nodesOfKind("Handler"/"Query")`, что по построению графа гарантирует нужную форму данных —
но это неявный инвариант, а не проверенный факт. Если граф когда-нибудь создаст узел с неполными
данными, обращение к отсутствующему полю даст `undefined`, а брошенное дальше исключение будет
молча поглощено находкой №1, и правило целиком пропадёт из отчёта без явного сигнала.

## 6. `scripts/bundle.mjs` — ИНФОРМАЦИОННО

```js
await build({
  entryPoints: [resolve(root, "packages/scanner/src/bin.ts")],
  ...
});
chmodSync(outfile, 0o755);
```

Верхнеуровневый `await build(...)` не обёрнут в `try/catch`. Для build-скрипта поведение Node по
умолчанию (unhandled rejection → ненулевой exit code и трассировка) приемлемо, но нет собственного
осмысленного сообщения об ошибке сборки.

## 7. `packages/scanner/src/bin.ts:61-67` — ОЧЕНЬ НИЗКАЯ серьёзность (TOCTOU)

```ts
if (snapshotFile !== "-" && !existsSync(snapshotFile)) {
  process.stderr.write(`error: ${snapshotFile} does not exist\n`);
  return 2;
}
const text = readFileSync(snapshotFile === "-" ? 0 : snapshotFile, "utf8");
```

Между `existsSync` и `readFileSync` есть окно гонки (файл могли удалить/подменить между
проверками). Некритично для локального CLI; исключение из `readFileSync` всё равно перехватывается
внешним `try/catch` в `main()` (строки 94-99) и превращается в управляемый `exit 2`.

---

## Что проверено и не найдено

- **`JSON.parse` без try/catch**: все вызовы (`config.ts:50`, `scan-snapshot.ts:124`,
  `live-snapshot.ts:505`, `resolve.ts:106`) обёрнуты в try/catch с содержательной обработкой.
- **Промисы без `.catch()` / fire-and-forget async**: в `packages/*/src` нет ни одной `async
  function` и ни одного `.then(` вне тестов — сканер полностью синхронный, сети и сабпроцессов не
  делает.
- **Пустые `catch {}`**: все «пустые на вид» catch-блоки (`supabase-authorization.ts:80`,
  `parse-project.ts:2792`, `scan-snapshot.ts:146`) содержат объясняющий комментарий и
  консервативный fallback, а не подавление finding.
- **`catch`, считающий что-то «безопасным» при ошибке**: не найдено — при неизвестном состоянии
  RLS сканер явно помечает его как "unknown" (fail-closed в отчётности), а не как "safe".
- **`child_process.exec/execSync/spawn`**: не используется.
- **`process.env` без проверки**: реальных обращений к `process.env` в коде сканера нет (только в
  комментариях/JSDoc, описывающих паттерны, которые сканер ищет в чужом коде).
- **`as any` / non-null assertion (`!`)**: не встречаются в `packages/*/src` (только в тестовых
  фикстурах).

## Итоговая рекомендация

Пункты 1–4 — не независимые баги, а один и тот же паттерн "ошибка → warning, exit code не
меняется". Стоит рассмотреть:

1. Явно отражать наличие `warnings` в статусе скана (например, отдельный exit code или
   `--fail-on-warnings`), чтобы «упавшее правило» не выглядело как «чистый скан».
2. Выводить warnings в начале отчёта, а не после "No findings."/"No blocking findings.", чтобы они
   не терялись в CI-логах.
