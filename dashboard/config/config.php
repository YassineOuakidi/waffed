<?php
/**
 * Lightweight WAF dashboard configuration.
 * Keep this file outside public/ when serving with PHP's built-in server:
 *   php -S 127.0.0.1:8081 -t dashboard/public
 */
declare(strict_types=1);

$wafRoot = realpath(__DIR__ . '/../..');
if ($wafRoot === false) {
    $wafRoot = dirname(__DIR__, 2);
}

return [
    'waf_root' => $wafRoot,
    'engine_root' => $wafRoot . '/engine',
    'waf_config_file' => $wafRoot . '/config/waf.conf',
    'fallback_rules_file' => $wafRoot . '/rules/disabled/experimental.rules',
    'fallback_log_file' => $wafRoot . '/logs/waf.log',
    'max_log_lines' => 200,
    'allowed_config_keys' => [
        'listen_port',
        'backend_host',
        'backend_port',
        'rules_file',
        'block_threshold',
        'enable_sql_dfa',
        'enable_xss_dfa',
        'log_file',
        'log_allow',
        'max_request_size',
        'max_body_size',
        'max_headers',
    ],
];
