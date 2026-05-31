<?php
declare(strict_types=1);
session_start();

$app = require __DIR__ . '/../config/config.php';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(24));
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function flash(string $type, string $message): void
{
    $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
}

function flashes(): array
{
    $items = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $items;
}

function require_csrf(): void
{
    $sent = $_POST['csrf_token'] ?? '';
    $expected = $_SESSION['csrf_token'] ?? '';
    if (!is_string($sent) || !hash_equals($expected, $sent)) {
        http_response_code(403);
        exit('Invalid CSRF token');
    }
}

function parse_waf_config(string $path): array
{
    $result = ['values' => [], 'lines' => []];
    if (!is_readable($path)) {
        return $result;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return $result;
    }

    foreach ($lines as $line) {
        $entry = ['raw' => $line, 'key' => null, 'value' => null];
        $trimmed = trim($line);
        if ($trimmed !== '' && $trimmed[0] !== '#' && str_contains($line, '=')) {
            [$key, $value] = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            $entry['key'] = $key;
            $entry['value'] = $value;
            $result['values'][$key] = $value;
        }
        $result['lines'][] = $entry;
    }

    return $result;
}

function atomic_write(string $path, string $content): bool
{
    $dir = dirname($path);
    if (!is_dir($dir) || !is_writable($dir)) {
        return false;
    }

    $tmp = tempnam($dir, '.wafdash_');
    if ($tmp === false) {
        return false;
    }

    $ok = file_put_contents($tmp, $content, LOCK_EX) !== false;
    if (!$ok) {
        @unlink($tmp);
        return false;
    }

    return rename($tmp, $path);
}

function write_waf_config(string $path, array $oldLines, array $newValues, array $allowedKeys): bool
{
    $allowed = array_flip($allowedKeys);
    $seen = [];
    $out = [];

    foreach ($oldLines as $entry) {
        $key = $entry['key'];
        if ($key !== null && isset($allowed[$key]) && array_key_exists($key, $newValues)) {
            $out[] = $key . '=' . trim((string)$newValues[$key]);
            $seen[$key] = true;
        } else {
            $out[] = $entry['raw'];
        }
    }

    foreach ($allowedKeys as $key) {
        if (array_key_exists($key, $newValues) && !isset($seen[$key])) {
            $out[] = $key . '=' . trim((string)$newValues[$key]);
        }
    }

    return atomic_write($path, implode(PHP_EOL, $out) . PHP_EOL);
}

function resolve_engine_path(string $configuredPath, string $fallback, array $app): string
{
    $configuredPath = trim($configuredPath);
    if ($configuredPath === '') {
        $configuredPath = $fallback;
    }

    if ($configuredPath[0] === '/') {
        $candidate = $configuredPath;
    } else {
        // The C engine is normally launched from engine/, so relative paths in waf.conf are resolved from engine/.
        $candidate = $app['engine_root'] . '/' . $configuredPath;
    }

    $dir = realpath(is_dir($candidate) ? $candidate : dirname($candidate));
    $root = realpath($app['waf_root']);
    if ($dir === false || $root === false) {
        return $fallback;
    }

    $full = $dir . DIRECTORY_SEPARATOR . basename($candidate);
    if (str_starts_with($full, $root . DIRECTORY_SEPARATOR) || $full === $root) {
        return $full;
    }

    return $fallback;
}

function parse_rules(string $path): array
{
    if (!is_readable($path)) {
        return [];
    }

    $rules = [];
    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return [];
    }

    foreach ($lines as $lineNo => $line) {
        $trimmed = trim($line);
        if ($trimmed === '') {
            continue;
        }

        $enabled = true;
        $payload = $line;

        if (preg_match('/^\s*#\s*DISABLED\|(.*)$/', $line, $m)) {
            $enabled = false;
            $payload = $m[1];
        } elseif ($trimmed[0] === '#') {
            continue;
        }

        $parts = explode('|', $payload, 4);
        if (count($parts) !== 4) {
            continue;
        }

        $rules[] = [
            'line_no' => $lineNo + 1,
            'enabled' => $enabled,
            'id' => trim($parts[0]),
            'score' => trim($parts[1]),
            'zone' => trim($parts[2]),
            'match' => $parts[3],
        ];
    }

    return $rules;
}

function serialize_rules(array $rules): string
{
    $lines = [];
    foreach ($rules as $rule) {
        $id = trim((string)($rule['id'] ?? ''));
        $score = trim((string)($rule['score'] ?? ''));
        $zone = trim((string)($rule['zone'] ?? ''));
        $match = (string)($rule['match'] ?? '');

        if ($id === '' || $score === '' || $zone === '' || $match === '') {
            continue;
        }

        $line = $id . '|' . $score . '|' . $zone . '|' . str_replace(["\r", "\n"], '', $match);
        if (empty($rule['enabled'])) {
            $line = '#DISABLED|' . $line;
        }
        $lines[] = $line;
    }

    return implode(PHP_EOL, $lines) . PHP_EOL;
}

function find_rule_index(array $rules, string $id): ?int
{
    foreach ($rules as $i => $rule) {
        if ((string)$rule['id'] === $id) {
            return $i;
        }
    }
    return null;
}

function tail_file(string $path, int $maxLines): array
{
    if (!is_readable($path) || $maxLines <= 0) {
        return [];
    }

    $file = new SplFileObject($path, 'r');
    $file->seek(PHP_INT_MAX);
    $lastLine = $file->key();
    $start = max(0, $lastLine - $maxLines + 1);
    $lines = [];

    $file->seek($start);
    while (!$file->eof()) {
        $line = rtrim((string)$file->fgets(), "\r\n");
        if ($line !== '') {
            $lines[] = $line;
        }
    }

    return array_slice($lines, -$maxLines);
}

function summarize_logs(array $lines): array
{
    $summary = [
        'events' => count($lines),
        'drops' => 0,
        'bad_req' => 0,
        'sqli' => 0,
        'xss' => 0,
        'ac' => 0,
        'last_reason' => 'none',
    ];

    foreach ($lines as $line) {
        if (str_contains($line, 'DROP')) {
            $summary['drops']++;
        }
        if (str_contains($line, 'BAD_REQ')) {
            $summary['bad_req']++;
        }
        if (stripos($line, 'SQLI') !== false) {
            $summary['sqli']++;
        }
        if (stripos($line, 'XSS') !== false || stripos($line, 'JS_DFA') !== false) {
            $summary['xss']++;
        }
        if (str_contains($line, 'AC_SCORE_THRESHOLD')) {
            $summary['ac']++;
        }
        if (preg_match('/reason=([^\s]+)/', $line, $m)) {
            $summary['last_reason'] = $m[1];
        }
    }

    return $summary;
}

function bytes_human(int $bytes): string
{
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1024 * 1024) return number_format($bytes / 1024, 1) . ' KB';
    return number_format($bytes / (1024 * 1024), 1) . ' MB';
}

$configData = parse_waf_config($app['waf_config_file']);
$values = $configData['values'];
$rulesFile = resolve_engine_path($values['rules_file'] ?? '', $app['fallback_rules_file'], $app);
$logFile = resolve_engine_path($values['log_file'] ?? '', $app['fallback_log_file'], $app);

if (isset($_GET['ajax']) && $_GET['ajax'] === 'logs') {
    $logLines = tail_file($logFile, (int)$app['max_log_lines']);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'ok' => true,
        'lines' => $logLines,
        'summary' => summarize_logs($logLines),
        'path' => $logFile,
        'readable' => is_readable($logFile),
        'mtime' => is_readable($logFile) ? date('H:i:s', (int)filemtime($logFile)) : null,
        'size' => is_readable($logFile) ? bytes_human((int)filesize($logFile)) : '0 B',
        'server_time' => date('H:i:s'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'save_config') {
        $newValues = [];
        foreach ($app['allowed_config_keys'] as $key) {
            if (in_array($key, ['enable_sql_dfa', 'enable_xss_dfa', 'log_allow'], true)) {
                $newValues[$key] = isset($_POST[$key]) ? '1' : '0';
            } else {
                $newValues[$key] = trim((string)($_POST[$key] ?? ($values[$key] ?? '')));
            }
        }

        if (write_waf_config($app['waf_config_file'], $configData['lines'], $newValues, $app['allowed_config_keys'])) {
            flash('success', 'Configuration saved. Restart the C engine for these settings to affect runtime detection.');
        } else {
            flash('error', 'Could not write config file. Check filesystem permissions.');
        }
    } elseif ($action === 'save_rules_raw') {
        $raw = (string)($_POST['rules_raw'] ?? '');
        if (atomic_write($rulesFile, rtrim($raw) . PHP_EOL)) {
            flash('success', 'Rules file saved. Restart the C engine to rebuild the Aho-Corasick trie.');
        } else {
            flash('error', 'Could not write rules file. Check permissions.');
        }
    } elseif ($action === 'add_rule') {
        $rules = parse_rules($rulesFile);
        $id = trim((string)($_POST['id'] ?? ''));
        $score = trim((string)($_POST['score'] ?? '100'));
        $zone = trim((string)($_POST['zone'] ?? 'URI'));
        $match = trim((string)($_POST['match'] ?? ''));
        if ($id === '' || $score === '' || $match === '') {
            flash('error', 'Rule id, score, and match string are required.');
        } elseif (find_rule_index($rules, $id) !== null) {
            flash('error', 'Rule id already exists. Choose another id.');
        } else {
            $rules[] = [
                'enabled' => isset($_POST['enabled']),
                'id' => $id,
                'score' => $score,
                'zone' => $zone,
                'match' => $match,
            ];
            if (atomic_write($rulesFile, serialize_rules($rules))) {
                flash('success', 'Rule added. Restart the C engine before testing it.');
            } else {
                flash('error', 'Could not write rules file.');
            }
        }
    } elseif ($action === 'toggle_rule' || $action === 'delete_rule') {
        $rules = parse_rules($rulesFile);
        $id = trim((string)($_POST['id'] ?? ''));
        $idx = find_rule_index($rules, $id);
        if ($idx === null) {
            flash('error', 'Rule not found.');
        } else {
            if ($action === 'toggle_rule') {
                $rules[$idx]['enabled'] = isset($_POST['enabled']);
                $msg = 'Rule status updated. Restart the C engine before relying on this change.';
            } else {
                array_splice($rules, $idx, 1);
                $msg = 'Rule removed. Restart the C engine to unload it.';
            }
            if (atomic_write($rulesFile, serialize_rules($rules))) {
                flash('success', $msg);
            } else {
                flash('error', 'Could not write rules file.');
            }
        }
    }

    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

$configData = parse_waf_config($app['waf_config_file']);
$values = $configData['values'];
$rulesFile = resolve_engine_path($values['rules_file'] ?? '', $app['fallback_rules_file'], $app);
$logFile = resolve_engine_path($values['log_file'] ?? '', $app['fallback_log_file'], $app);
$rules = parse_rules($rulesFile);
$rulesRaw = is_readable($rulesFile) ? (string)file_get_contents($rulesFile) : '';
$logLines = tail_file($logFile, (int)$app['max_log_lines']);
$logSummary = summarize_logs($logLines);
$token = $_SESSION['csrf_token'];
$enabledRules = count(array_filter($rules, static fn(array $r): bool => !empty($r['enabled'])));
$disabledRules = count($rules) - $enabledRules;
$sqlEnabled = (($values['enable_sql_dfa'] ?? '0') === '1');
$xssEnabled = (($values['enable_xss_dfa'] ?? '0') === '1');
$logReadable = is_readable($logFile);
$configWritable = is_writable($app['waf_config_file']);
$rulesWritable = is_writable($rulesFile);
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>C WAF Command Center</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<div class="shell">
    <aside class="sidebar">
        <div class="brand">
            <div class="brand-mark">W</div>
            <div>
                <strong>C-WAF</strong>
                <span>Layer-7 proxy</span>
            </div>
        </div>
        <nav class="nav">
            <a href="#overview">Overview</a>
            <a href="#engines">DFA Engines</a>
            <a href="#rules">AC Rules</a>
            <a href="#logs">Live Logs</a>
            <a href="#raw">Raw Editor</a>
        </nav>
        <div class="sidebar-card">
            <span>Runtime note</span>
            <p>The dashboard writes files. The C engine must be restarted to rebuild rules/config loaded at startup.</p>
        </div>
    </aside>

    <main class="workspace">
        <header class="hero" id="overview">
            <div>
                <p class="kicker">High-performance Web Application Firewall</p>
                <h1>WAF Command Center</h1>
                <p class="hero-text">Control AC signatures, DFA modules, and telemetry from a vanilla PHP dashboard.</p>
            </div>
            <div class="hero-actions">
                <button type="button" class="ghost" id="reload-page">Reload files</button>
                <button type="button" class="primary" id="manual-log-refresh">Refresh logs</button>
            </div>
        </header>

        <?php foreach (flashes() as $item): ?>
            <div class="flash <?= e($item['type']) ?>"><?= e($item['message']) ?></div>
        <?php endforeach; ?>

        <section class="status-grid">
            <article class="metric hot">
                <span>DROP events</span>
                <strong id="metric-drops"><?= e((string)$logSummary['drops']) ?></strong>
                <small>tail window</small>
            </article>
            <article class="metric">
                <span>Active rules</span>
                <strong><?= e((string)$enabledRules) ?></strong>
                <small><?= e((string)$disabledRules) ?> disabled</small>
            </article>
            <article class="metric <?= $sqlEnabled ? 'ok' : 'muted' ?>">
                <span>SQLi DFA</span>
                <strong><?= $sqlEnabled ? 'ON' : 'OFF' ?></strong>
                <small>enable_sql_dfa</small>
            </article>
            <article class="metric <?= $xssEnabled ? 'ok' : 'muted' ?>">
                <span>XSS DFA</span>
                <strong><?= $xssEnabled ? 'ON' : 'OFF' ?></strong>
                <small>enable_xss_dfa</small>
            </article>
        </section>

        <section class="file-strip">
            <div><span>Config</span><code><?= e($app['waf_config_file']) ?></code><b class="dot <?= $configWritable ? 'green' : 'red' ?>"></b></div>
            <div><span>Rules</span><code><?= e($rulesFile) ?></code><b class="dot <?= $rulesWritable ? 'green' : 'red' ?>"></b></div>
            <div><span>Logs</span><code><?= e($logFile) ?></code><b class="dot <?= $logReadable ? 'green' : 'red' ?>"></b></div>
        </section>

        <section class="panel" id="engines">
            <div class="panel-head">
                <div>
                    <p class="kicker">Engine configuration</p>
                    <h2>waf.conf</h2>
                </div>
                <span class="chip">restart required after save</span>
            </div>

            <form method="post" class="config-form">
                <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
                <input type="hidden" name="action" value="save_config">

                <div class="toggle-board">
                    <label class="switch-card">
                        <input type="checkbox" name="enable_sql_dfa" <?= $sqlEnabled ? 'checked' : '' ?>>
                        <span class="switch-ui"></span>
                        <strong>SQL Injection DFA</strong>
                        <small>Lexer/DFA detection for SQLi grammar features.</small>
                    </label>
                    <label class="switch-card">
                        <input type="checkbox" name="enable_xss_dfa" <?= $xssEnabled ? 'checked' : '' ?>>
                        <span class="switch-ui"></span>
                        <strong>XSS / JavaScript DFA</strong>
                        <small>Detects script-like payload patterns.</small>
                    </label>
                    <label class="switch-card">
                        <input type="checkbox" name="log_allow" <?= (($values['log_allow'] ?? '0') === '1') ? 'checked' : '' ?>>
                        <span class="switch-ui"></span>
                        <strong>Log allowed requests</strong>
                        <small>Useful for debugging; noisy during load tests.</small>
                    </label>
                </div>

                <div class="form-grid">
                    <?php foreach (['listen_port','backend_host','backend_port','rules_file','block_threshold','log_file','max_request_size','max_body_size','max_headers'] as $key): ?>
                        <label class="field">
                            <span><?= e($key) ?></span>
                            <input name="<?= e($key) ?>" value="<?= e($values[$key] ?? '') ?>">
                        </label>
                    <?php endforeach; ?>
                </div>

                <div class="form-actions">
                    <button type="submit" class="primary">Save configuration</button>
                    <p>Writes to disk immediately, but your current C process will not reload until restarted.</p>
                </div>
            </form>
        </section>

        <section class="panel" id="rules">
            <div class="panel-head">
                <div>
                    <p class="kicker">Aho-Corasick pre-filter</p>
                    <h2>Signature Rules</h2>
                </div>
                <span class="chip"><?= e((string)count($rules)) ?> total</span>
            </div>

            <form method="post" class="add-rule">
                <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
                <input type="hidden" name="action" value="add_rule">
                <label class="field"><span>ID</span><input name="id" placeholder="9075"></label>
                <label class="field"><span>Score</span><input name="score" value="100"></label>
                <label class="field"><span>Zone</span>
                    <select name="zone">
                        <option>URI</option>
                        <option>BODY</option>
                        <option>HEADER</option>
                        <option>HEADER:User-Agent</option>
                        <option>HEADER:Content-Type</option>
                        <option>ANY</option>
                    </select>
                </label>
                <label class="field wide"><span>Match string</span><input name="match" placeholder="UNION SELECT"></label>
                <label class="mini-check"><input type="checkbox" name="enabled" checked><span>Enabled</span></label>
                <button type="submit" class="primary">Add rule</button>
            </form>

            <div class="toolbar">
                <input id="rule-search" placeholder="Filter by id, zone, or payload...">
                <span>Toggle status directly from the table.</span>
            </div>

            <div class="table-wrap">
                <table id="rules-table">
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>ID</th>
                            <th>Score</th>
                            <th>Zone</th>
                            <th>Match</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!$rules): ?>
                            <tr><td colspan="6" class="empty">No rules found.</td></tr>
                        <?php endif; ?>
                        <?php foreach ($rules as $rule): ?>
                            <tr data-rule-row>
                                <td>
                                    <form method="post" class="inline-form">
                                        <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
                                        <input type="hidden" name="action" value="toggle_rule">
                                        <input type="hidden" name="id" value="<?= e($rule['id']) ?>">
                                        <label class="row-switch" title="Enable/disable rule">
                                            <input type="checkbox" name="enabled" <?= $rule['enabled'] ? 'checked' : '' ?> onchange="this.form.submit()">
                                            <span></span>
                                        </label>
                                    </form>
                                </td>
                                <td><code><?= e($rule['id']) ?></code></td>
                                <td><?= e($rule['score']) ?></td>
                                <td><span class="zone"><?= e($rule['zone']) ?></span></td>
                                <td class="match"><code><?= e($rule['match']) ?></code></td>
                                <td>
                                    <form method="post" onsubmit="return confirm('Remove rule <?= e($rule['id']) ?>?')">
                                        <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
                                        <input type="hidden" name="action" value="delete_rule">
                                        <input type="hidden" name="id" value="<?= e($rule['id']) ?>">
                                        <button class="danger" type="submit">Remove</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="panel logs-panel" id="logs">
            <div class="panel-head">
                <div>
                    <p class="kicker">Blocking telemetry</p>
                    <h2>Live log tail</h2>
                </div>
                <div class="log-controls">
                    <label class="mini-check"><input type="checkbox" id="auto-refresh" checked><span>Auto-refresh</span></label>
                    <label class="mini-check"><input type="checkbox" id="auto-scroll" checked><span>Auto-scroll</span></label>
                    <button type="button" class="ghost" id="clear-view">Clear view</button>
                </div>
            </div>

            <div class="log-metrics">
                <div><span>Events</span><strong id="metric-events"><?= e((string)$logSummary['events']) ?></strong></div>
                <div><span>SQLi</span><strong id="metric-sqli"><?= e((string)$logSummary['sqli']) ?></strong></div>
                <div><span>XSS</span><strong id="metric-xss"><?= e((string)$logSummary['xss']) ?></strong></div>
                <div><span>AC threshold</span><strong id="metric-ac"><?= e((string)$logSummary['ac']) ?></strong></div>
                <div><span>Last reason</span><strong id="metric-reason"><?= e((string)$logSummary['last_reason']) ?></strong></div>
            </div>

            <div class="console-head">
                <span id="log-status">Ready</span>
                <span id="log-meta"><?= $logReadable ? 'Loaded from disk' : 'Log file is not readable' ?></span>
            </div>
            <pre id="log-tail" class="logs" data-ajax-url="<?= e(strtok($_SERVER['REQUEST_URI'], '?') ?: '/') ?>?ajax=logs"><?= e(implode(PHP_EOL, $logLines)) ?></pre>
        </section>

        <section class="panel" id="raw">
            <div class="panel-head">
                <div>
                    <p class="kicker">Raw file mode</p>
                    <h2>Rules editor</h2>
                </div>
                <span class="chip">format: id|score|zone|match</span>
            </div>
            <form method="post" class="raw-editor">
                <input type="hidden" name="csrf_token" value="<?= e($token) ?>">
                <input type="hidden" name="action" value="save_rules_raw">
                <textarea name="rules_raw" spellcheck="false"><?= e($rulesRaw) ?></textarea>
                <div class="form-actions">
                    <button type="submit" class="primary">Save raw rules</button>
                    <p>Disabled rules use <code>#DISABLED|...</code>, which the C loader ignores because it skips comments.</p>
                </div>
            </form>
        </section>
    </main>
</div>

<script src="assets/js/app.js"></script>
</body>
</html>
