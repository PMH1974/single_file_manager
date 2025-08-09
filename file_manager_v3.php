<?php
/**
 * Secure PHP File Manager (PHP 7+)
 * - Light/Dark theme (set THEME)
 * - Recursive search (depth-limited)
 * - Sorting (name/size/modified, asc/desc)
 * - Drag & drop uploads (+ safe allowlist)
 * - Image previews (inline, size-limited)
 * - Browse, breadcrumbs, mkdir, rename, download, delete
 * Security: BASE_PATH scope, traversal blocked, CSRF, strict allowlist, hide/block dangerous types
 */

session_start();

/* =========================
   Debug (OFF in production)
========================= */
const DEBUG = false;
if (DEBUG) {
    ini_set('display_errors', '1');
    ini_set('log_errors', '1');
    ini_set('error_log', __DIR__ . '/file_manager_error.log');
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', '0');
    error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED);
}

/* =========================
   Developer Options
========================= */
define('THEME', 'light'); // 'dark' or 'light'
define('BASE_PATH', __DIR__);                // lock scope
define('PAGE_TITLE', 'PMH File Manager');

define('ALLOW_UPLOADS',   true);
define('ALLOW_DELETE',    true);
define('ALLOW_RENAME',    true);
define('ALLOW_CREATE_DIR',true);

define('MAX_UPLOAD_BYTES', 50 * 1024 * 1024); // 50 MB

// Allow only clearly safe document/image/archive types
define('ALLOWED_UPLOAD_EXTS', [
  'jpg','jpeg','png','gif','webp',
  'pdf','txt','csv',
  'zip','7z','tar','gz',
  'doc','docx','xls','xlsx','ppt','pptx'
]);

// Hide and block these from listing / upload / download / rename-targets
define('DANGEROUS_EXTS', [
  'php','phtml','php3','php4','php5','php7','php8','phps','phar',
  'cgi','pl','asp','aspx','jsp',
  'js','mjs','ts',
  'sh','bash','zsh','ksh','ps1','bat','cmd',
  'exe','dll','com','msi','scr'
]);

define('HIDE_DOTFILES', true);
define('HIDE_PATTERNS', ['.htaccess','.env','.env.local','.git','.gitignore','.DS_Store']);

// Search/Preview knobs
define('RECURSIVE_SEARCH', true);
define('SEARCH_MAX_DEPTH', 4); // depth from current folder
define('PREVIEW_MAX_BYTES', 8 * 1024 * 1024); // 8MB inline preview limit
define('PREVIEW_IMAGE_EXTS', ['jpg','jpeg','png','gif','webp']);

/* =========================
   PHP 7 polyfills
========================= */
if (!function_exists('str_starts_with')) {
    function str_starts_with($haystack, $needle) {
        $haystack = (string)$haystack; $needle = (string)$needle;
        return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}
if (!function_exists('mime_content_type')) {
    function mime_content_type($filename) { return 'application/octet-stream'; }
}

/* =========================
   Helpers
========================= */
function csrf_token() {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function check_csrf() {
    if (($_POST['csrf'] ?? '') !== ($_SESSION['csrf'] ?? null)) { http_response_code(400); exit('Bad CSRF token'); }
}
function clean_seg($seg) {
    $seg = str_replace(["\0", '\\'], ['', '/'], (string)$seg);
    return trim($seg);
}
function resolve_path($relative) {
    $relative  = clean_seg($relative);
    $relative  = ltrim($relative, '/');
    $candidate = rtrim(BASE_PATH, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $relative;
    $realBase  = realpath(BASE_PATH);
    if ($realBase === false) { http_response_code(500); exit('BASE_PATH invalid'); }
    $realCand  = realpath($candidate);
    if ($realCand === false) { $realCand = str_replace('\\','/',$candidate); }
    else { $realCand = str_replace('\\','/',$realCand); }
    $realBase = rtrim(str_replace('\\','/',$realBase), '/');
    if (strpos($realCand, $realBase) !== 0) { http_response_code(403); exit('Forbidden path'); }
    return [$realBase, $realCand, $relative];
}
function format_bytes($bytes) {
    $bytes = (int)$bytes; $units = ['B','KB','MB','GB','TB']; $i=0;
    while ($bytes >= 1024 && $i < count($units)-1) { $bytes /= 1024; $i++; }
    return ($bytes >= 10 || $bytes == floor($bytes)) ? round($bytes) . ' ' . $units[$i] : number_format($bytes,1) . ' ' . $units[$i];
}
function file_ext($name) { return strtolower(pathinfo((string)$name, PATHINFO_EXTENSION)); }
function is_dangerous_ext($name) { $ext = file_ext($name); return $ext !== '' && in_array($ext, DANGEROUS_EXTS, true); }
function ext_allowed($filename) { $ext = file_ext($filename); return $ext !== '' && in_array($ext, ALLOWED_UPLOAD_EXTS, true); }
function is_image_previewable($name, $size) {
    $ext = file_ext($name);
    return in_array($ext, PREVIEW_IMAGE_EXTS, true) && $size <= PREVIEW_MAX_BYTES;
}
function is_hidden($name) {
    $name = (string)$name;
    if (HIDE_DOTFILES && isset($name[0]) && $name[0] === '.') return true;
    foreach (HIDE_PATTERNS as $pat) { if (strcasecmp($name, $pat) === 0) return true; }
    if (is_dangerous_ext($name)) return true;
    return false;
}
function rrmdir($dir) {
    if (!is_dir($dir)) return false;
    $items = scandir($dir); if ($items === false) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) { if (!rrmdir($path)) return false; }
        else { if (!@unlink($path)) return false; }
    }
    return @rmdir($dir);
}
function breadcrumb($relative) {
    $crumbs = [];
    if ($relative === '' || $relative === '/') return $crumbs;
    $parts = explode('/', trim($relative, '/'));
    $accum = '';
    foreach ($parts as $p) { $accum .= ($accum ? '/' : '') . $p; $crumbs[] = [$p, $accum]; }
    return $crumbs;
}
function respond_download($absPath, $name) {
    if (is_dangerous_ext($name)) { http_response_code(403); exit('Download blocked.'); }
    if (!is_file($absPath) || !is_readable($absPath)) { http_response_code(404); exit('File not found'); }
    $mime = @mime_content_type($absPath); if (!$mime) $mime = 'application/octet-stream';
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . (string)filesize($absPath));
    header('Content-Disposition: attachment; filename="' . rawurlencode($name) . '"');
    header('X-Content-Type-Options: nosniff');
    $fp = fopen($absPath, 'rb'); if ($fp) { fpassthru($fp); } else { readfile($absPath); }
    exit;
}
function respond_preview_image($absPath, $name) {
    // inline image preview with strict checks
    $size = @filesize($absPath); if ($size === false) { http_response_code(404); exit('File not found'); }
    if (!is_image_previewable($name, $size)) { http_response_code(403); exit('Preview not allowed'); }
    $mime = @mime_content_type($absPath);
    if (!$mime || stripos($mime, 'image/') !== 0) $mime = 'image/*';
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . (string)$size);
    header('Content-Disposition: inline; filename="' . rawurlencode($name) . '"');
    header('Cache-Control: private, max-age=3600');
    $fp = fopen($absPath, 'rb'); if ($fp) { fpassthru($fp); } else { readfile($absPath); }
    exit;
}
function safe_filename($name) {
    $name = preg_replace('/[\\x00-\\x1F\\x7F\\/\\\\]/', '_', (string)$name);
    $name = trim((string)$name);
    if ($name === '' || $name === '.' || $name === '..') { http_response_code(400); exit('Invalid name'); }
    return $name;
}
// NEW: base name without extension (used to lock file extensions during rename)
function filename_base(string $name): string {
    $base = pathinfo($name, PATHINFO_FILENAME);
    return safe_filename($base);
}
function link_here($params = []) {
    $base = $_GET;
    foreach ($params as $k=>$v) { if ($v === null) unset($base[$k]); else $base[$k] = $v; }
    $qs = http_build_query($base);
    $self = $_SERVER['PHP_SELF'] ?? 'file_manager.php';
    return htmlspecialchars($self . ($qs ? ('?' . $qs) : ''));
}

/* =========================
   Directory scan / search
========================= */
function collect_items($absDir, $relDir, $needle, $recursive, $depth, &$dirs, &$files) {
    $items = @scandir($absDir);
    if ($items === false) return;
    $hasNeedle = ($needle !== '');
    foreach ($items as $it) {
        if ($it === '.' || $it === '..') continue;
        if (is_hidden($it)) continue;

        $p = $absDir . DIRECTORY_SEPARATOR . $it;
        $isDir = is_dir($p);
        $mtime = @filemtime($p) ?: time();

        // If searching, filter by name (case-insensitive); still descend into dirs for recursive search
        $matches = !$hasNeedle || (mb_stripos($it, $needle, 0, 'UTF-8') !== false);

        if ($isDir) {
            if ($matches) $dirs[] = ['name'=>$it,'mtime'=>$mtime,'rel'=>$relDir];
            if ($recursive && $depth > 0) {
                $childRel = ltrim(trim($relDir . '/' . $it, '/'), '/');
                collect_items($p, $childRel, $needle, true, $depth-1, $dirs, $files);
            }
        } else {
            if (is_dangerous_ext($it)) continue;
            if ($matches) {
                $size = @filesize($p); if ($size === false) $size = 0;
                $files[] = ['name'=>$it,'mtime'=>$mtime,'size'=>$size,'rel'=>$relDir];
            }
        }
    }
}
function sort_items(&$dirs, &$files, $sort, $order) {
    $dirCmp = function($a,$b) use($sort,$order){
        $res = 0;
        if ($sort === 'mtime') $res = $a['mtime'] <=> $b['mtime'];
        else $res = strnatcasecmp($a['name'],$b['name']);
        return $order === 'desc' ? -$res : $res;
    };
    $fileCmp = function($a,$b) use($sort,$order){
        if ($sort === 'size') { $res = ($a['size'] <=> $b['size']); }
        elseif ($sort === 'mtime') { $res = ($a['mtime'] <=> $b['mtime']); }
        else { $res = strnatcasecmp($a['name'],$b['name']); }
        return $order === 'desc' ? -$res : $res;
    };
    usort($dirs, $dirCmp);
    usort($files, $fileCmp);
}

/* =========================
   Inputs
========================= */
$dir   = clean_seg($_GET['dir'] ?? '');
$q     = trim((string)($_GET['q'] ?? ''));
$sort  = in_array(($s = ($_GET['sort'] ?? 'name')), ['name','size','mtime'], true) ? $s : 'name';
$order = in_array(($o = ($_GET['order'] ?? 'asc')), ['asc','desc'], true) ? $o : 'asc';

$act   = $_REQUEST['action'] ?? '';
$name  = $_REQUEST['name'] ?? '';
$new   = $_REQUEST['new']  ?? '';

list($realBase, $absDir, $relDir) = resolve_path($dir);
if (!is_dir($absDir)) { $absDir = $realBase; $relDir = ''; }

/* =========================
   Actions
========================= */
if ($act === 'download') {
    $file = safe_filename((string)$name);
    $target = $absDir . DIRECTORY_SEPARATOR . $file;
    respond_download($target, $file);
}
if ($act === 'preview') {
    $file = safe_filename((string)$name);
    $target = $absDir . DIRECTORY_SEPARATOR . $file;
    respond_preview_image($target, $file);
}

$flash = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();

    if ($act === 'upload' && ALLOW_UPLOADS) {
        $errs = []; $count = 0;
        if (!isset($_FILES['files'])) { $flash = ['err','No files uploaded.']; }
        else {
            if (!is_writable($absDir)) { $errs[] = 'Directory not writable.'; }
            $names  = $_FILES['files']['name'] ?? [];
            $sizes  = $_FILES['files']['size'] ?? [];
            $tmps   = $_FILES['files']['tmp_name'] ?? [];
            $errors = $_FILES['files']['error'] ?? [];
            foreach ($names as $i => $filename) {
                if ($filename === '') continue;
                $filename = safe_filename($filename);

                if (is_dangerous_ext($filename)) { $errs[] = "$filename: dangerous extension blocked"; continue; }
                if (!ext_allowed($filename))     { $errs[] = "$filename: extension not allowed"; continue; }

                $size  = (int)($sizes[$i] ?? 0);
                if ($size > MAX_UPLOAD_BYTES) { $errs[] = "$filename: exceeds size limit"; continue; }
                $tmp   = $tmps[$i] ?? '';
                $err   = (int)($errors[$i] ?? UPLOAD_ERR_OK);
                if ($err !== UPLOAD_ERR_OK) { $errs[] = "$filename: upload error $err"; continue; }
                if (!is_uploaded_file($tmp)) { $errs[] = "$filename: invalid temp file"; continue; }

                if (function_exists('finfo_open')) {
                    $fi = finfo_open(FILEINFO_MIME_TYPE);
                    if ($fi) {
                        $mime = finfo_file($fi, $tmp) ?: '';
                        finfo_close($fi);
                        $badMimeStarts = ['application/x-php','text/x-php','application/x-sh','text/x-shellscript'];
                        foreach ($badMimeStarts as $bad) { if (stripos($mime, $bad) === 0) { $errs[] = "$filename: mime not allowed"; continue 2; } }
                    }
                }

                $dest = $absDir . DIRECTORY_SEPARATOR . $filename;
                if (!@move_uploaded_file($tmp, $dest)) { $errs[] = "$filename: move failed"; continue; }
                $count++;
            }
            $flash = $errs ? ['err', implode('<br>', $errs)] : ['ok', "Uploaded $count file(s)."];
        }
    }

    if ($act === 'mkdir' && ALLOW_CREATE_DIR) {
        $folder = safe_filename((string)($_POST['folder'] ?? ''));
        if ($folder === '') { $flash = ['err','Folder name required.']; }
        else {
            $target = $absDir . DIRECTORY_SEPARATOR . $folder;
            if (is_dir($target)) $flash = ['err','Folder already exists.'];
            else $flash = @mkdir($target, 0775) ? ['ok','Folder created.'] : ['err','Failed to create folder.'];
        }
    }

    if ($act === 'delete' && ALLOW_DELETE) {
        $targetName = safe_filename((string)$name);
        $target = $absDir . DIRECTORY_SEPARATOR . $targetName;
        if (!file_exists($target))       $flash = ['err','Item not found.'];
        elseif (is_dir($target))         $flash = rrmdir($target) ? ['ok','Folder deleted.'] : ['err','Delete failed.'];
        else                              $flash = @unlink($target) ? ['ok','File deleted.'] : ['err','Delete failed.'];
    }

    /* ======== MOVE: move file/folder to another folder (root-relative path) ======== */
    if ($act === 'move') {
        $itemName  = safe_filename((string)$name);
        $targetRel = clean_seg((string)($_POST['target'] ?? '')); // e.g., "photos/2025"
        $srcPath   = $absDir . DIRECTORY_SEPARATOR . $itemName;

        if (!file_exists($srcPath)) {
            $flash = ['err','Item not found.'];
        } elseif ($targetRel === '') {
            $flash = ['err','Target folder required.'];
        } else {
            list($realBase2, $absTargetDir, $relTargetDir) = resolve_path($targetRel);
            if (!is_dir($absTargetDir)) {
                $flash = ['err','Target folder does not exist.'];
            } else {
                $srcReal = realpath($srcPath);
                $dstPath = $absTargetDir . DIRECTORY_SEPARATOR . basename($itemName);
                $dstRealParent = realpath($absTargetDir);

                // prevent moving folder into itself/descendant
                if ($srcReal !== false && is_dir($srcPath)) {
                    if (strpos($dstRealParent . DIRECTORY_SEPARATOR, $srcReal . DIRECTORY_SEPARATOR) === 0) {
                        $flash = ['err','Cannot move a folder into itself or its subfolder.'];
                        goto MOVE_END;
                    }
                }

                if (file_exists($dstPath)) {
                    $flash = ['err','An item with the same name already exists in target.'];
                } else {
                    $ok = @rename($srcPath, $dstPath);
                    $flash = $ok ? ['ok','Moved.'] : ['err','Move failed.'];
                }
            }
        }
        MOVE_END:;
    }
    /* ============================================================================== */

    /* ======== RENAME: keeps file extension; folders rename freely ======== */
    if ($act === 'rename' && ALLOW_RENAME) {
        $old     = safe_filename((string)$name);
        $newRaw  = (string)$new;
        $src     = $absDir . DIRECTORY_SEPARATOR . $old;

        if (!file_exists($src)) {
            $flash = ['err','Item not found.'];
        } else {
            if (is_dir($src)) {
                // Folder: rename to sanitized input (no extension concept)
                $newName = filename_base($newRaw);
                if ($newName === '') {
                    $flash = ['err','Folder name required.'];
                } else {
                    $dst = $absDir . DIRECTORY_SEPARATOR . $newName;
                    if (file_exists($dst)) $flash = ['err','Target name exists.'];
                    else $flash = @rename($src, $dst) ? ['ok','Renamed.'] : ['err','Rename failed.'];
                }
            } else {
                // File: lock the original extension
                $origExt = file_ext($old);                 // '' if none
                $newBase = filename_base($newRaw);         // strip any typed extension
                if ($newBase === '') {
                    $flash = ['err','File name required.'];
                } else {
                    $newName = $origExt !== '' ? ($newBase . '.' . $origExt) : $newBase;
                    if (is_dangerous_ext($newName)) {
                        $flash = ['err','Target name not allowed.'];
                    } else {
                        $dst = $absDir . DIRECTORY_SEPARATOR . $newName;
                        if (file_exists($dst)) $flash = ['err','Target name exists.'];
                        else $flash = @rename($src, $dst) ? ['ok','Renamed.'] : ['err','Rename failed.'];
                    }
                }
            }
        }
    }
    /* ==================================================================== */
}

/* =========================
   Listing (+ recursive search)
========================= */
$dirs = []; $files = [];
$needle = $q !== '' ? mb_strtolower($q, 'UTF-8') : '';
$doRecursive = (RECURSIVE_SEARCH && $q !== '');

collect_items($absDir, $relDir, $needle, $doRecursive, SEARCH_MAX_DEPTH, $dirs, $files);
sort_items($dirs, $files, $sort, $order);

$totalShown = count($dirs) + count($files);
$crumbs = breadcrumb($relDir);
$parentRel = '';
if ($relDir !== '' && $relDir !== '/') { $bits = explode('/', trim($relDir,'/')); array_pop($bits); $parentRel = implode('/', $bits); }

/* =========================
   Theme vars
========================= */
$themeVars = THEME === 'light'
    ? [
        '--bg'     => '#f5f5f5',
        '--card'   => '#ffffff',
        '--muted'  => '#555',
        '--text'   => '#0a0a0a',
        '--accent' => '#1a73e8',
        '--ok'     => '#0f9d58',
        '--err'    => '#d93025',
      ]
    : [
        '--bg'     => '#0b0c10',
        '--card'   => '#111218',
        '--muted'  => '#9aa0a6',
        '--text'   => '#e8eaed',
        '--accent' => '#8ab4f8',
        '--ok'     => '#34a853',
        '--err'    => '#ea4335',
      ];

?><!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?php echo htmlspecialchars(PAGE_TITLE); ?></title>
<style>
:root {
<?php foreach ($themeVars as $k=>$v) echo $k.':'.$v.';'; ?>
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.4 system-ui,Segoe UI,Roboto,Arial}
h1{margin:0;font-size:16px}
.wrap{max-width:1100px;margin:0 auto;padding:16px}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;margin:8px 0 16px}
.crumbs a{color:var(--accent);text-decoration:none}
.crumbs span{color:var(--muted)}
.tools form, .controls form{display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap}
input[type=text], input[type=file], select{
  background:#0e1015;border:1px solid #2a2c36;color:var(--text);padding:8px;border-radius:10px
}
<?php if (THEME === 'light'): ?>
input[type=text], input[type=file], select{
  background:#fff;border:1px solid #d0d7de;color:#111
}
<?php endif; ?>
button{
  background:#202437;border:1px solid #2a2c36;color:var(--text);
  padding:8px 12px;border-radius:12px;cursor:pointer
}
button:hover{filter:brightness(1.08)}
a.btn{
  display:inline-block;padding:8px 12px;border-radius:12px;
  border:1px solid #2a2c36;background:#202437;color:var(--text);
  text-decoration:none
}
<?php if (THEME === 'light'): ?>
button,a.btn{
  background:#f6f8fa;border:1px solid #d0d7de;color:#111;
}
button:hover,a.btn:hover{
  background:#eef1f4;
}
<?php endif; ?>
.grid{display:grid;grid-template-columns:1fr;gap:10px} /* single-column */
.card{
  background:var(--card);border:1px solid #1f2026;border-radius:16px;
  padding:12px;display:flex;justify-content:space-between;align-items:center
}
<?php if (THEME === 'light'): ?>
.card{border-color:#e5e7eb}
<?php endif; ?>
.meta{color:var(--muted);font-size:12px}
.name{font-weight:600;word-break:break-word}
.row{display:flex;align-items:center;gap:10px;min-width:0}
.icon{font-size:18px}
.actions form{display:inline}
.flash{padding:10px;border-radius:12px;margin-bottom:12px}
.ok{
  background:rgba(52,168,83,.15);border:1px solid rgba(52,168,83,.4)
}
.err{
  background:rgba(234,67,53,.15);border:1px solid rgba(234,67,53,.4)
}
<?php if (THEME === 'light'): ?>
.ok{background:#e9f7ef;border:1px solid #b6e3c5}
.err{background:#fde8e6;border:1px solid #f2b8b5}
<?php endif; ?>
.muted{color:var(--muted)}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
#dropzone{
  border:2px dashed #2a2c36;border-radius:14px;padding:14px;
  display:flex;gap:10px;align-items:center;justify-content:space-between;
  background:#0e1015;margin-bottom:12px
}
<?php if (THEME === 'light'): ?>
#dropzone{background:#fff;border-color:#d0d7de}
<?php endif; ?>
#dropzone.drag{
  border-color:var(--accent);box-shadow:0 0 0 2px rgba(138,180,248,.25) inset
}
.hint{color:var(--muted);font-size:12px}
.preview{
  max-height:100px;max-width:160px;border-radius:8px;
  border:1px solid #2a2c36;display:block
}
<?php if (THEME === 'light'): ?>
.preview{border-color:#e5e7eb}
<?php endif; ?>
.pathcrumb{font-size:12px;color:var(--muted)}
</style>

</head>
<body>
<div class="wrap">
  <?php if (isset($flash) && $flash): ?>
    <div class="flash <?php echo $flash[0]==='ok'?'ok':'err'; ?>"><?php echo $flash[1]; ?></div>
  <?php endif; ?>

  <div class="bar">
    <div class="crumbs">
      <a href="<?php echo link_here(['dir'=>'', 'action'=>null, 'name'=>null, 'new'=>null, 'q'=>null]); ?>">🏠 root</a>
      <?php foreach ($crumbs as $c): ?>
        <span> / </span>
        <a href="<?php echo link_here(['dir'=>$c[1], 'action'=>null, 'name'=>null, 'new'=>null, 'q'=>null]); ?>">
          <?php echo htmlspecialchars($c[0]); ?>
        </a>
      <?php endforeach; ?>
    
      <?php if ($relDir !== ''): // show Up whenever not at root ?>
        <span class="muted"> — </span>
        <a class="btn" href="<?php echo link_here(['dir'=>$parentRel, 'action'=>null, 'name'=>null, 'new'=>null, 'q'=>null]); ?>">⬆️ Up</a>
      <?php endif; ?>
    </div>

    <div class="controls">
      <!-- Search + Sorting -->
      <form method="get" class="inline" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] ?? 'file_manager.php'); ?>">
        <input type="hidden" name="dir" value="<?php echo htmlspecialchars($relDir); ?>">
        <input type="text" name="q" value="<?php echo htmlspecialchars($q); ?>" placeholder="Search this folder<?php echo RECURSIVE_SEARCH ? ' (recursively)' : ''; ?>…">
        <select name="sort">
          <option value="name"<?php if($sort==='name') echo ' selected'; ?>>Sort: Name</option>
          <option value="size"<?php if($sort==='size') echo ' selected'; ?>>Sort: Size</option>
          <option value="mtime"<?php if($sort==='mtime') echo ' selected'; ?>>Sort: Modified</option>
        </select>
        <select name="order">
          <option value="asc"<?php if($order==='asc') echo ' selected'; ?>>Asc</option>
          <option value="desc"<?php if($order==='desc') echo ' selected'; ?>>Desc</option>
        </select>
        <button type="submit">🔎 Apply</button>
        <?php if ($q !== '' || $sort!=='name' || $order!=='asc'): ?>
          <a class="btn" href="<?php echo link_here(['q'=>null,'sort'=>null,'order'=>null]); ?>">✖ Clear</a>
        <?php endif; ?>
      </form>

      <?php if (ALLOW_CREATE_DIR): ?>
      <form method="post" class="inline" action="<?php echo link_here(['action'=>'mkdir','q'=>null]); ?>">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>">
        <input type="text" name="folder" placeholder="New folder name" required>
        <button type="submit">📁 Create</button>
      </form>
      <?php endif; ?>
    </div>
  </div>

  <!-- Drag & Drop Upload Zone -->
  <?php if (ALLOW_UPLOADS): ?>
  <div id="dropzone">
    <div class="hint">Drag & drop files here to upload, or use the button →</div>
    <form id="uploadForm" method="post" enctype="multipart/form-data" class="inline" action="<?php echo link_here(['action'=>'upload']); ?>">
      <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>">
      <input id="filesInput" type="file" name="files[]" multiple style="display:none">
      <button type="button" id="pickBtn">⬆️ Select files</button>
      <button type="submit" id="submitBtn" style="display:none">Upload</button>
    </form>
  </div>
  <?php endif; ?>

  <?php if ($relDir !== ''): ?>
    <div class="muted" style="margin:10px 0 0">Current: <code><?php echo htmlspecialchars('/'.$relDir); ?></code></div>
  <?php endif; ?>

  <?php if ($dirs): ?>
  <h3>Folders <?php if($q!==''){ echo '<span class="muted">('.count($dirs).' match'.(count($dirs)===1?'':'es').')</span>'; } ?></h3>
  <div class="grid">
    <?php foreach ($dirs as $d): $dRel = $d['rel']; $fullRel = ltrim($dRel, '/'); ?>
      <div class="card">
        <div class="row">
          <div class="icon">📁</div>
          <div>
            <div class="name">
              <a class="btn" href="<?php echo link_here(['dir'=>($dRel? $dRel.'/':'').$d['name'], 'q'=>null]); ?>">
                <?php echo htmlspecialchars($d['name']); ?>
              </a>
            </div>
            <div class="meta">Modified: <?php echo date('Y-m-d H:i', $d['mtime']); ?></div>
            <?php if($q!==''): ?>
              <div class="pathcrumb">in /<?php echo htmlspecialchars($dRel === '' ? '.' : $dRel); ?></div>
            <?php endif; ?>
          </div>
        </div>
        <div class="actions">
          <?php if (ALLOW_RENAME): ?>
          <form method="post" class="inline" action="<?php echo link_here(['dir'=>$dRel,'action'=>'rename','name'=>$d['name']]); ?>">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>">
            <input type="text" name="new" placeholder="Rename to" required>
            <button>✏️</button>
          </form>
          <?php endif; ?>
          <?php if (ALLOW_DELETE): ?>
          <form method="post" class="inline" onsubmit="return confirm('Delete folder and all contents?')" action="<?php echo link_here(['dir'=>$dRel,'action'=>'delete','name'=>$d['name']]); ?>">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>">
            <button>🗑️</button>
          </form>
          <?php endif; ?>
          <!-- MOVE folder -->
          <form method="post" class="inline" action="<?php echo link_here(['dir'=>$dRel,'action'=>'move','name'=>$d['name']]); ?>">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>">
            <input type="text" name="target" placeholder="Move to (e.g. photos/2025)" required>
            <button title="Move">↪️</button>
          </form>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

  <h3 style="margin-top:18px;">Files <?php if($totalShown > 0 && $q!==''){ echo '<span class="muted">('.count($files).' match'.(count($files)===1?'':'es').')</span>'; } ?></h3>
  <?php if (!$files): ?>
    <div class="muted"><?php echo $q!=='' ? 'No file matches.' : 'No files in this folder.'; ?></div>
  <?php else: ?>
  <div class="grid">
    <?php foreach ($files as $f): $fRel = $f['rel']; $pathForLinks = $fRel; ?>
      <div class="card">
        <div class="row">
          <div class="icon">📄</div>
          <div>
            <div class="name">
              <?php if ($q !== ''): ?>
                <a class="btn" href="<?php echo link_here(['dir'=>$fRel, 'q'=>null, 'sort'=>null, 'order'=>null]); ?>">
                  <?php echo htmlspecialchars($f['name']); ?>
                </a>
              <?php else: ?>
                <?php echo htmlspecialchars($f['name']); ?>
              <?php endif; ?>
            </div>
            <div class="meta"><?php echo format_bytes((int)$f['size']); ?> • Modified: <?php echo date('Y-m-d H:i', $f['mtime']); ?></div>
            <?php if (is_image_previewable($f['name'], (int)$f['size'])): ?>
              <img class="preview" alt="" src="<?php echo link_here(['dir'=>$pathForLinks,'action'=>'preview','name'=>$f['name']]); ?>">
            <?php endif; ?>
            <?php if($q!==''): ?>
              <div class="pathcrumb">in /<?php echo htmlspecialchars($fRel === '' ? '.' : $fRel); ?></div>
            <?php endif; ?>
          </div>
        </div>
        <div class="actions">
          <a class="btn" href="<?php echo link_here(['dir'=>$pathForLinks,'action'=>'download','name'=>$f['name']]); ?>">⬇️ Download</a>
          <?php if (ALLOW_RENAME): ?>
          <form method="post" class="inline" action="<?php echo link_here(['dir'=>$pathForLinks,'action'=>'rename','name'=>$f['name']]); ?>">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>">
            <input type="text" name="new" placeholder="Rename to" required>
            <button>✏️</button>
          </form>
          <?php endif; ?>
          <?php if (ALLOW_DELETE): ?>
          <form method="post" class="inline" onsubmit="return confirm('Delete file?')" action="<?php echo link_here(['dir'=>$pathForLinks,'action'=>'delete','name'=>$f['name']]); ?>">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>">
            <button>🗑️</button>
          </form>
          <?php endif; ?>
          <!-- MOVE file -->
          <form method="post" class="inline" action="<?php echo link_here(['dir'=>$pathForLinks,'action'=>'move','name'=>$f['name']]); ?>">
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>">
            <input type="text" name="target" placeholder="Move to (e.g. folder/sub)" required>
            <button title="Move">↪️</button>
          </form>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

  <p class="muted" style="margin-top:20px">
    Scoped to: <code><?php echo htmlspecialchars($realBase); ?></code><br>
    <?php if (ALLOW_UPLOADS): ?>Max upload size: <?php echo format_bytes((int)MAX_UPLOAD_BYTES); ?><?php endif; ?>
  </p>
</div>

<?php if (ALLOW_UPLOADS): ?>
<script>
(function(){
  const drop = document.getElementById('dropzone');
  const form = document.getElementById('uploadForm');
  const input = document.getElementById('filesInput');
  const pickBtn = document.getElementById('pickBtn');
  if (!drop) return;
  function prevent(e){ e.preventDefault(); e.stopPropagation(); }
  ['dragenter','dragover','dragleave','drop'].forEach(ev => drop.addEventListener(ev, prevent, false));
  ['dragenter','dragover'].forEach(ev => drop.addEventListener(ev, () => drop.classList.add('drag'), false));
  ['dragleave','drop'].forEach(ev => drop.addEventListener(ev, () => drop.classList.remove('drag'), false));
  drop.addEventListener('drop', async (e) => {
    const files = e.dataTransfer.files;
    if (!files || !files.length) return;
    const fd = new FormData(form);
    for (let i = 0; i < files.length; i++) { fd.append('files[]', files[i], files[i].name); }
    try { await fetch(form.action, { method: 'POST', body: fd, credentials: 'same-origin' }); window.location.reload(); }
    catch { alert('Upload failed.'); }
  });
  pickBtn.addEventListener('click', () => input.click());
  input.addEventListener('change', () => {
    const fd = new FormData(form);
    for (let i = 0; i < input.files.length; i++) { fd.append('files[]', input.files[i], input.files[i].name); }
    fetch(form.action, { method: 'POST', body: fd, credentials: 'same-origin' })
      .then(() => window.location.reload())
      .catch(() => alert('Upload failed.'));
  });
})();
</script>
<?php endif; ?>
</body></html>