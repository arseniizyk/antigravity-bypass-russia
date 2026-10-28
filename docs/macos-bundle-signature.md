# Подпись приложения на macOS

macOS подписывает приложение целиком. В `Antigravity.app/Contents/CodeResources`
хранится печать (seal) — хеши всех файлов бандла, — а в самом исполняемом файле
указано, что приложение запущено с hardened runtime и защитой целостности
бандла.

## Почему появляется «Antigravity повреждён»

Любое изменение файла внутри подписанного бандла ломает печать:

```text
$ codesign --verify --deep --strict /Applications/Antigravity.app
/Applications/Antigravity.app: a sealed resource is missing or invalid
file added:     .../Resources/bin/language_server.ag-backups/5b1a....bin
file added:     .../Resources/bin/language_server.ag-backups/current.json
file modified:  .../Resources/bin/language_server
```

Дальше ядро macOS убивает процесс при запуске (процесс завершается с
`SIGKILL`, код 137), а система показывает «Antigravity повреждён и не может
быть открыт». Это происходит и при изменении самого файла, и при добавлении
рядом с ним резервной копии.

## Что делает утилита

1. **Резервные копии хранятся вне бандла.** Для файлов внутри `*.app` журнал и
   копии переносятся в
   `~/Library/Application Support/AntigravityBypass/backups/<бандл>/<файл>.ag-backups`.
   Старый журнал, оставшийся внутри бандла, переносится автоматически
   (`journal::migrate_legacy_directory`).
2. **После правки бандл переподписывается локально** (`system::bundle::reseal`).
   Порядок действий:
   - читаются entitlements вложенного кода (helper-приложения, фреймворки,
     `chrome_crashpad_handler`);
   - бандл подписывается целиком (`codesign --force --deep --sign -`) с
     entitlements главного исполняемого файла;
   - вложенный код подписывается отдельно, со своими entitlements;
   - бандл перепечатывается заново, уже с новыми подписями вложенного кода;
   - результат проверяется `codesign --verify --deep --strict`.
3. **Главному исполняемому файлу и helper-приложениям добавляется**
   `com.apple.security.cs.disable-library-validation`. После локальной
   подписи у главного файла и у Electron Framework нет общего идентификатора
   разработчика, и `dyld` отказывается загружать фреймворк:

   ```text
   dyld: Library not loaded: @rpath/Electron Framework.framework/Electron Framework
   Reason: ... mapping process and mapped file (non-platform) have different Team IDs
   ```

## Восстановление подписи вручную

```bash
sudo antigravity-bypass-russia reseal              # все установленные приложения
sudo antigravity-bypass-russia reseal /Applications/Antigravity.app
```

Проверка состояния:

```bash
codesign --verify --deep --strict /Applications/Antigravity.app
```

## Ограничения

- После локальной переподписи бандл больше не подписан Developer ID
  Google: `spctl -a` возвращает `rejected`. Приложение запускается, но
  автообновление Squirrel может отказаться ставить новую версию, потому что
  она подписана другим идентификатором. В этом случае приложение
  обновляется вручную.
- Подпись каталога `Contents/_CodeSignature` не восстанавливается: у
  утилиты нет ключа Google. Откат возвращает оригинальные байты файлов и
  оставляет рабочую локальную подпись.
