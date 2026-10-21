<?php
session_start();
echo 'PHP ' . PHP_VERSION . ' SAPI=' . php_sapi_name()
    . ' upload_progress.cleanup=' . (int) ini_get('session.upload_progress.cleanup')
    . ' use_only_cookies=' . (int) ini_get('session.use_only_cookies') . "\n";
