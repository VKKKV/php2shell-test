<?php
// Producer for the FPM variant of 109619.
//
// The OOM has to happen *inside* serialize() during normal application
// execution, after RINIT. The bailout skips php_var_serialize_destroy(), so
// BG(serialize).level stays 1 with a context that request shutdown then frees.
// The next request's upload-progress encode runs before RINIT and reuses it.
//
// Under php-fpm an application fatal does not kill the child (unlike a startup
// fatal), so the same worker handles the fire request.
$payload = str_repeat("A", 4 * 1024 * 1024);
echo "producing\n";
serialize([$payload]);
echo "not reached\n";
