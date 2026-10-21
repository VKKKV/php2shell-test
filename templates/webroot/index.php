<?php
// Endpoint for the 109618 lab (mod_php). Nothing here matters: the trigger is
// the multipart body parsed during request startup.
echo 'ok pid=', getmypid(), ' php=', PHP_VERSION,
    ' memory_limit=', ini_get('memory_limit'),
    ' post_max_size=', ini_get('post_max_size'), "\n";
