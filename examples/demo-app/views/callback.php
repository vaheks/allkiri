<?php
/**
 * The page the Smart-ID app opens after a sign-in on the same phone. It opens in
 * a new tab, so it says how things ended and leads back to the demo.
 *
 * @var array{name: string, identity: string}|null $signedIn
 * @var string|null                                $problem
 */
$e = static fn(string $text): string => htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>allkiri demo</title>
<style>
  :root { color-scheme: light dark; --line: #8884; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  section { border: 1px solid var(--line); border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; }
  .bad { color: #c00; }
  .note { font-size: .85rem; opacity: .75; }
</style>
</head>
<body>

<h1>allkiri demo</h1>

<section>
<?php if ($signedIn !== null) { ?>
  <strong>Signed in with Smart-ID</strong>
  <p>Signed in as <?= $e($signedIn['name']) ?> (<?= $e($signedIn['identity']) ?>).</p>
  <p class="note">The Smart-ID app opened this page in a new tab. The tab you started in says the same, and you can close it.</p>
<?php } else { ?>
  <strong>Not signed in</strong>
  <p class="bad"><?= $e((string) $problem) ?></p>
<?php } ?>
  <p><a href="/">Back to the demo</a></p>
</section>

</body>
</html>
