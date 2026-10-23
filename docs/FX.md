# FX: анализ Firefox fingerprint и снижение аллокаций Necko

Ветка `fx` развивает два направления: обнаружение устойчивых отличий от
Firefox и снижение нагрузки на память при передаче через Necko. Это не новый
сетевой протокол и не гарантированный обход DPI.

## 1. Контроль fingerprint (опциональный строгий gate)

Из существующих тестов сохраняются независимые отчёты:
- `compare_necko_firefox.py`: FoxTunnel против Firefox CONNECT;
- `analyze_firefox_self.py`: контроль Firefox против Firefox на том же runtime;
- `evaluate_fx_fingerprint.py`: классификация отличий с учётом вариативности
  Firefox. Неодинаковые поля **никогда** не нормализуются до «равно».

Пример после получения штатных замеров:

```sh
python3 scripts/evaluate_fx_fingerprint.py \
  --candidate necko-fingerprint/comparison.json \
  --control necko-fingerprint/firefox-self.json \
  --out necko-fingerprint/fx-audit.json
```

`--enforce` делает устойчивые различия ошибкой (exit 1). На данном этапе CI
публикует отчёт без `--enforce`: ранее зафиксированные несовпадения H2
могут потребовать осознанного исправления до включения строгого gate.
Контроль Firefox самого с собой может показывать как случайный порядок
расширений, так и другие вариации. Их статус — **inconclusive**, не pass.
Тесты не измеряют обычную навигацию неизменённого Firefox, IP/TCP сигнатуры,
эффекты мобильной сети и эффективность против ТСПУ.

## 2. Память / горячий путь Necko

Ранее `AsyncIO.read()` создавал новый `Uint8Array` на каждый чтение
пакета (не более 32 КиБ). Теперь два независимых `pumpBuffered` создают
по одному 32-КиБ scratch-буферу на активное направление и используют его
до EOF или ошибки. Следующее чтение начинается **после** завершения
записи предыдущего чанка, поэтому данные не перезаписываются. При окончании
передачи буфер освобождается вместе с async pump. SOCKS setup по-прежнему
использует отдельные маленькие буферы.

Это снижение количества аллокаций на горячем пути, а не обещание снижения
пикового RSS или CPU: основная память Necko/Gecko остаётся нативной.
Проверка регрессий включает бинарные данные, backpressure, half-close,
ошибку записи и штатные native H2/H3 тесты.

## Проверка

```sh
node --test experiments/firefox-necko/client_test.cjs
python3 -m unittest discover -s scripts -p 'test_evaluate_fx_fingerprint.py' -v
# На Linux amd64 с тем же закреплённым libxul:
FOXTUNNEL_XPCSHELL=/path/to/runtime/xpcshell \
  go test -race ./experiments/firefox-necko -run '^TestGecko' -v
```

Workflow `necko-runtime-test.yml` теперь запускается при push в `fx`
и сохраняет `fx-audit.json` рядом с исходными wire-измерениями.
До получения новых native результатов нельзя количественно утверждать,
что FoxTunnel стал быстрее, экономнее или менее отличимым от Firefox.
