<?php
// Inert endpoint for the 109619 lab. The bug fires during request startup,
// before this file is compiled; keep it trivial.
echo 'ok pid=', getmypid(), ' php=', PHP_VERSION, "\n";
