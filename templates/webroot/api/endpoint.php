<?php
// Demo gadget: proves the injected object was really instantiated, not just
// that a "failed to decode" warning appeared.
class Gadget {
    public string $proof = 'object-instantiated';

    public function __destruct() {
        @file_put_contents('/tmp/gadget-hit', $this->proof . "\n");
    }
}

session_start();
echo 'read-endpoint (php handler)' . "\n";
