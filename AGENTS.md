# Repository Guidelines

## Project Structure & Module Organization
- `src/` — Library code under the `Nyra\\Jwt\\` namespace (PSR-4).
- `tests/` — PHPUnit tests under `Nyra\\Jwt\\Tests\\` (PSR-4).
- `vendor/` — Composer-managed dependencies. Do not edit; regenerate via Composer.
- `composer.json` — Autoload, scripts, and metadata. Run `composer dump-autoload` after adding/moving classes.

## Build, Test, and Development Commands
- `composer install` — Install dependencies.
- `composer test` — Run the PHPUnit suite.
- `vendor/bin/phpunit --filter ClassOrMethod` — Run specific tests.
- `composer dump-autoload -o` — Rebuild optimized autoloader after structural changes.

## Coding Style & Naming Conventions
- Follow PSR-12: 4-space indentation, meaningful line length, and consistent brace style.
- Add `declare(strict_types=1);` at the top of PHP files.
- PSR-4 namespaces mirror folders (e.g., `src/Jwt.php` → `Nyra\\Jwt\\Jwt`).
- Class names: StudlyCaps; methods/properties: camelCase. Exceptions end with `Exception`.

## Testing Guidelines
- Framework: PHPUnit 12. Place tests in `tests/` mirroring `src/` structure.
- File names end with `*Test.php`; test methods use `test*`/`it*` naming.
- Cover success and failure paths; prefer data providers for matrix cases.
- Examples: `vendor/bin/phpunit --filter SchemaTest` or a single method `--filter 'JwtTest::test_decode_invalid'`.

## Commit & Pull Request Guidelines
- Commits: short, imperative subject (“Add schema parser”, “Fix nullable handling”).
- Reference issues where applicable (e.g., `Fixes #123`).
- PRs must include: clear description, rationale, API changes, and tests. Update README/examples if behavior changes.
- Keep PRs focused and small; avoid unrelated refactors.

## Security & Configuration Tips
- Never commit secrets or edit `vendor/` manually. Use `composer update` when needed.
- Run `composer validate` and ensure the test suite passes before opening a PR.
- Target maintained PHP versions compatible with the dependency set (use latest stable 8.x during development).

## Agent-Specific Instructions
- Do not modify `vendor/` or `composer.lock` unless updating dependencies intentionally.
- When adding namespaces or moving files, ensure PSR-4 paths align and run `composer dump-autoload`.
- Keep changes minimal and localized; always add/adjust tests alongside code changes.

