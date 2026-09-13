<?php
// BLOB FORGE :: preference cache objects.
//
// The front-end posts a base64 blob of "preferences" and the shop hands it back
// to us on every request in the `prefs` cookie. We decode it with the legacy
// serializer so old backups keep working. See index.php.

class PreferenceCache
{
    public string $path    = '/tmp/prefs.cache'; // where the cache lands
    public string $content = '';                 // cache body
    public int    $ttl     = 3600;               // seconds; 0 means "no repopulate"

    public function __construct(string $path = '/tmp/prefs.cache', string $content = '', int $ttl = 3600)
    {
        $this->path    = $path;
        $this->content = $content;
        $this->ttl     = $ttl;
    }

    // Persist the cache when the request finishes.
    public function __destruct()
    {
        // Nothing to write? Nothing to do.
        if (strlen($this->content) === 0) {
            return;
        }
        // ttl of 0 is the "purge, do not repopulate" sentinel the cron job uses.
        if ($this->ttl === 0) {
            return;
        }
        @file_put_contents($this->path, $this->content);
    }
}

class GhostSession
{
    public string $id = '';

    public function __construct(string $id = '')
    {
        $this->id = $id;
    }

    public function __toString(): string
    {
        return $this->id;
    }
}
