<?php
function isImage($file) {
    $imageTypes = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'];
    $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    return in_array($extension, $imageTypes);
}

function getCurrentDir() {
    $currentDir = isset($_GET['dir']) ? $_GET['dir'] : '';
    $currentDir = rtrim($currentDir, '/');
    return $currentDir ? $currentDir . '/' : '';
}

$uploadDir = __DIR__ . '/' . getCurrentDir();

$notAllowed = ['.php', '.htaccess', '.git', '.exe', '.bat', '.cmd', '.com', '.sh', '.bin', '.cgi', '.pl', '.py', '.rb', '.jar', '.asp', '.aspx', '.jsp', '.jspx', '.war', '.ear', '.zip', '.tar', '.gz', '.rar', '.7z', '.pif', '.scr', '.vb', '.vbs', '.wsf', '.ps1', '.psm1', '.inf', '.reg', '.msi', '.msp', '.mst', '.dll', '.sys', '.drv', '.cpl', '.ocx', '.sct', '.ade', '.adp', '.bas', '.chm', '.cmd', '.cpl', '.crt', '.csh', '.der', '.fxp', '.gadget', '.hlp', '.hta', '.ins', '.isp', '.jse', '.ksh', '.lnk', '.msc', '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml', '.ops', '.prg', '.reg', '.scf', '.shb', '.shs', '.u3p', '.vb', '.vbe', '.vbs', '.vsmacros', '.vsw', '.ws', '.wsc', '.wsf', '.wsh'];

function isNotAllowed($file) {
    global $notAllowed;
    foreach ($notAllowed as $ext) {
        if (strpos($file, $ext) !== false) {
            return true;
        }
    }
    return false;
}

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $filename = basename($_FILES['file']['name']);
    if (isNotAllowed($filename)) {
        echo json_encode(['status' => 'error', 'message' => 'File type not allowed.']);
        exit;
    }
    if (file_exists($uploadDir . $filename)) {
        if (!isset($_POST['overwrite'])) {
            echo json_encode(['status' => 'overwrite', 'message' => 'File with the same name already exists. Do you want to overwrite it?']);
            exit;
        }
    }
    if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadDir . $filename)) {
        echo json_encode(['status' => 'success', 'message' => 'File uploaded successfully.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'File upload failed.']);
    }
    exit;
}

// Handle file rename
if (isset($_POST['rename'])) {
    $oldName = basename($_POST['oldName']);
    $extension = pathinfo($oldName, PATHINFO_EXTENSION);
    $newBaseName = basename($_POST['newName'], ".$extension");
    $newName = $newBaseName . '.' . $extension;

    if (file_exists($uploadDir . $newName)) {
        echo json_encode(['status' => 'error', 'message' => 'A file with the new name already exists.']);
        exit;
    }

    if (!isNotAllowed($newName) && rename($uploadDir . $oldName, $uploadDir . $newName)) {
        echo json_encode(['status' => 'success', 'message' => 'File renamed successfully.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'File rename failed.']);
    }
    exit;
}

// Handle file delete
if (isset($_POST['delete'])) {
    $file = $uploadDir . basename($_POST['file']);
    if (unlink($file)) {
        echo json_encode(['status' => 'success', 'message' => 'File deleted successfully.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'File delete failed.']);
    }
    exit;
}

// Handle file download
if (isset($_GET['download'])) {
    $file = $uploadDir . basename($_GET['file']);
    if (file_exists($file)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename=' . basename($file));
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    }
}

// Handle folder creation
if (isset($_POST['createFolder'])) {
    $folderName = basename($_POST['folderName']);
    $newFolder = $uploadDir . $folderName;
    if (!file_exists($newFolder)) {
        if (mkdir($newFolder)) {
            echo json_encode(['status' => 'success', 'message' => 'Folder created successfully.']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Failed to create folder.']);
        }
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Folder already exists.']);
    }
    exit;
}

// Handle folder rename
if (isset($_POST['renameFolder'])) {
    $oldName = basename($_POST['oldName']);
    $newName = basename($_POST['newName']);
    $oldPath = $uploadDir . $oldName;
    $newPath = $uploadDir . $newName;

    if (file_exists($newPath)) {
        echo json_encode(['status' => 'error', 'message' => 'A folder with the new name already exists.']);
        exit;
    }

    if (rename($oldPath, $newPath)) {
        echo json_encode(['status' => 'success', 'message' => 'Folder renamed successfully.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Failed to rename folder.']);
    }
    exit;
}

// Handle folder delete
if (isset($_POST['deleteFolder'])) {
    $folderName = basename($_POST['folder']);
    $folderPath = $uploadDir . $folderName;

    function deleteDir($dirPath) {
        if (!is_dir($dirPath)) {
            return;
        }
        $files = array_diff(scandir($dirPath), array('.', '..'));
        foreach ($files as $file) {
            $path = $dirPath . '/' . $file;
            is_dir($path) ? deleteDir($path) : unlink($path);
        }
        return rmdir($dirPath);
    }

    if (deleteDir($folderPath)) {
        echo json_encode(['status' => 'success', 'message' => 'Folder deleted successfully.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Failed to delete folder.']);
    }
    exit;
}

// Handle file move
if (isset($_POST['moveFile'])) {
    $fileName = basename($_POST['fileName']);
    $destinationFolder = trim($_POST['destinationFolder'], '/');
    $currentDir = getCurrentDir();
    $sourcePath = $uploadDir . $fileName;
    
    // Prevent moving to parent directories
    if (strpos($destinationFolder, '..') !== false) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid destination path.']);
        exit;
    }
    
    // Ensure the destination is within the allowed directory structure
    $destPath = realpath(__DIR__) . '/' . $destinationFolder . '/' . $fileName;
    if (strpos($destPath, realpath(__DIR__)) !== 0) {
        echo json_encode(['status' => 'error', 'message' => 'Destination is outside of allowed directory.']);
        exit;
    }
    
    // Create destination directory if it doesn't exist
    if (!file_exists(dirname($destPath))) {
        mkdir(dirname($destPath), 0777, true);
    }

    if (rename($sourcePath, $destPath)) {
        echo json_encode(['status' => 'success', 'message' => 'File moved successfully.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Failed to move file.']);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File Manager</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 800px;
            margin: auto;
            padding: 10px;
        }
        .file-list {
            margin-top: 5px;
        }
        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 5px;
            border-bottom: 1px solid #ddd;
        }
        .file-item:last-child { border-bottom: none; }
        .file-item span { flex: 1; }
        .file-item div { flex-shrink: 0; }
        .file-item button {
            margin-left: 5px;
            padding: 3px 4px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 10px;
            font-weight: bold;
            width: 30px;
        }
        .file-item button.delete {
            background-color: darkred;
            color: #fff;
        }
        .file-item button.rename {
            background-color: gray;
            color: #fff;
        }
        .navBtns {
            background-color: gray;
            color: #fff;
            padding: 4px 8px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 10px;
            font-weight: bold;
            width: 100px;
        }
        .file-item button {
            background-color: #19212D;
            color: #fff;
        }
        #file-input label:hover, .file-item button.rename:hover, .file-item button.delete:hover, .file-item button:hover, .navBtns:hover {
            filter: brightness(50%);
        }
        #drop-area {
    border: 2px dashed #ccc;
    padding: 20px;
    text-align: center;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.3s ease;
}
#drop-area:hover {
    border: 2px dashed #19212D;
    background-color: hsl(120, 100%, 98%);
}
        
        #file-input {
            margin-top: 5px;
        }
        #file-input input { display: none; }
        #file-input label {
            display: inline-block;
            padding: 10px 20px;
            background-color: #19212D;
            color: #fff;
            border-radius: 4px;
            cursor: pointer;
        }
        .file-name {
            overflow: hidden;
            white-space: nowrap;
            text-overflow: ellipsis;
        }
        h3 {
            border-bottom: 1px solid #19212D;
            padding-bottom: 3px;
            margin-bottom: 0px;
        }
        #image-overlay { cursor: pointer; }
        
        .breadcrumb a {
    color: #19212D;
    text-decoration: none;
}
.breadcrumb a:hover {
    text-decoration: underline;
}
    </style>
</head>
<body>
    <div class="container">
        <div id="drop-area">
    Drop files here or click to upload
    <input type="file" id="file-upload-input" multiple style="display: none;">
</div>
        <div style="display: flex; justify-content: space-between;margin-top: 5px">
            <button id="backButton" onclick="goBack()" class="navBtns">&#9664; BACK</button>
            <button onclick="createFolder()" class="navBtns">&#128449; CREATE</button>
        </div>
        <div class="file-list">
            <?php
            $currentDir = getCurrentDir();
            echo "<div class='breadcrumb'><h3>";
$paths = explode('/', trim($currentDir, '/'));
$fullPath = '';
echo "<a href='file_manager.php'>Home</a>";
foreach ($paths as $index => $path) {
    $fullPath .= '/' . $path;
    echo " / <a href='file_manager.php?dir=" . urlencode(trim($fullPath, '/')) . "'>" . htmlspecialchars($path) . "</a>";
}
echo "</h3></div>";
            
            $items = scandir($uploadDir);
            $folders = [];
            $files = [];
            $fileCount = 0;
            $folderCount = 0;
            
            foreach ($items as $item) {
                if ($item == '.' || $item == '..') continue;
                $fullPath = $uploadDir . $item;
                if (is_dir($fullPath)) {
                    $folders[] = $item;
                    $folderCount++;
                } elseif (is_file($fullPath) && $item != 'file_manager.php' && !isNotAllowed($item)) {
                    $files[] = $item;
                    $fileCount++;
                }
            }

            // Sort folders and files alphabetically
            sort($folders);
            sort($files);

            // Display folders first
            foreach ($folders as $folder) {
                echo "<div class='file-item'>";
                echo "<span class='file-name' style='cursor: pointer;' onclick=\"navigateFolder('" . htmlspecialchars($folder, ENT_QUOTES) . "')\">📁 " . htmlspecialchars($folder) . "</span>";
                echo "<div class='file-item' style='padding: 1px'>";
                echo "<div><button class='rename' onclick=\"renameFolder('" . htmlspecialchars($folder, ENT_QUOTES) . "')\">&#9998;</button></div>";
                echo "<div><button class='delete' onclick=\"deleteFolder('" . htmlspecialchars($folder, ENT_QUOTES) . "')\">&#10006;</button></div>";
                echo "</div>";
                echo "</div>";
            }

            // Then display files
            foreach ($files as $file) {
                $isImage = isImage($file);
                echo "<div class='file-item'>";
                if ($isImage) {
                    echo "<span class='file-name'><span style='cursor: pointer;' onclick=\"showImage('" . htmlspecialchars($currentDir . $file, ENT_QUOTES) . "')\">🔍</span> " . htmlspecialchars($file) . "</span>";
                } else {
                    echo "<span class='file-name'>" . htmlspecialchars($file) . "</span>";
                }
                echo "<div class='file-item' style='padding: 1px'>";
                echo "<div><button onclick=\"moveFile('" . htmlspecialchars($file, ENT_QUOTES) . "')\">&#128449;</button></div>"; // New move button
                echo "<div><a href='?download=true&file=" . urlencode($file) . "&dir=" . urlencode($currentDir) . "'><button type='button'>&#9947;</button></a></div>";
                
                echo "<div><button class='rename' onclick=\"renameFile('" . htmlspecialchars($file, ENT_QUOTES) . "')\">&#9998;</button></div>";
                echo "<div><button class='delete' onclick=\"deleteFile('" . htmlspecialchars($file, ENT_QUOTES) . "')\">&#10006;</button></div>";
                echo "</div>";
                echo "</div>";
            }
            echo "<div class='file-item'><small>Folders: $folderCount, Files: $fileCount</small></div>";
            ?>
        </div>
    </div>
</body>
</html>

<script>
    function uploadFile(file) {
        let formData = new FormData();
        formData.append('file', file);
        
        fetch('file_manager.php<?php echo isset($_GET['dir']) ? "?dir=" . urlencode($_GET['dir']) : ""; ?>', {
            method: 'POST',
            body: formData
        }).then(response => response.json()).then(result => {
            if (result.status === 'overwrite') {
                if (confirm(result.message)) {
                    let formData = new FormData();
                    formData.append('file', file);
                    formData.append('overwrite', true);
                    
                    fetch('file_manager.php<?php echo isset($_GET['dir']) ? "?dir=" . urlencode($_GET['dir']) : ""; ?>', {
                        method: 'POST',
                        body: formData
                    }).then(response => response.json()).then(result => {
                        alert(result.message);
                        location.reload();
                    });
                }
            } else {
                alert(result.message);
                location.reload();
            }
        });
    }
    
    function renameFile(oldName) {
        let extension = oldName.split('.').pop();
        let baseName = oldName.substring(0, oldName.lastIndexOf('.'));
        let newName = prompt('Enter new name:', baseName);
        if (newName) {
            let formData = new FormData();
            formData.append('rename', true);
            formData.append('oldName', oldName);
            formData.append('newName', newName + '.' + extension);
            
            fetch('file_manager.php<?php echo isset($_GET['dir']) ? "?dir=" . urlencode($_GET['dir']) : ""; ?>', {
                method: 'POST',
                body: formData
            }).then(response => response.json()).then(result => {
                alert(result.message);
                location.reload();
            });
        }
    }
    
    function deleteFile(file) {
        if (confirm('Are you sure you want to delete this file?')) {
            let formData = new FormData();
            formData.append('delete', true);
            formData.append('file', file);
            
            fetch('file_manager.php<?php echo isset($_GET['dir']) ? "?dir=" . urlencode($_GET['dir']) : ""; ?>', {
                method: 'POST',
                body: formData
            }).then(response => response.json()).then(result => {
                alert(result.message);
                location.reload();
            });
        }
    }
    
    function handleDrop(event) {
        event.preventDefault();
        let files = event.dataTransfer.files;
        for (let i = 0; i < files.length; i++) {
            uploadFile(files[i]);
        }
    }
    
    function handleDragOver(event) {
        event.preventDefault();
    }
    
    document.addEventListener('DOMContentLoaded', () => {
    let dropArea = document.getElementById('drop-area');
    let fileInput = document.getElementById('file-upload-input');

    dropArea.addEventListener('dragover', handleDragOver);
    dropArea.addEventListener('drop', handleDrop);
    
    // Add click event listener to the drop area
    dropArea.addEventListener('click', () => {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', function() {
        let files = this.files;
        for (let i = 0; i < files.length; i++) {
            uploadFile(files[i]);
        }
    });
});
    
    function showImage(file) {
        let imageOverlay = document.createElement('div');
        imageOverlay.id = 'image-overlay';
        imageOverlay.style.position = 'fixed';
        imageOverlay.style.top = '0';
        imageOverlay.style.left = '0';
        imageOverlay.style.width = '100%';
        imageOverlay.style.height = '100%';
        imageOverlay.style.backgroundColor = 'rgba(0,0,0,0.8)';
        imageOverlay.style.display = 'flex';
        imageOverlay.style.justifyContent = 'center';
        imageOverlay.style.alignItems = 'center';
        imageOverlay.style.zIndex = '1000';
        
        let image = document.createElement('img');
        image.src = file;
        image.style.maxWidth = '90%';
        image.style.maxHeight = '90%';
        
        imageOverlay.appendChild(image);
        
        imageOverlay.addEventListener('click', function() {
            document.body.removeChild(imageOverlay);
        });
        
        document.body.appendChild(imageOverlay);
    }

    function createFolder() {
        let folderName = prompt('Enter folder name:');
        if (folderName) {
            let formData = new FormData();
            formData.append('createFolder', true);
            formData.append('folderName', folderName);

            fetch('file_manager.php<?php echo isset($_GET['dir']) ? "?dir=" . urlencode($_GET['dir']) : ""; ?>', {
                method: 'POST',
                body: formData
            }).then(response => response.json()).then(result => {
                alert(result.message);
                location.reload();
            });
        }
    }

    function navigateFolder(folder) {
        let currentUrl = new URL(window.location.href);
        let currentDir = currentUrl.searchParams.get('dir') || '';
        let newDir = currentDir ? currentDir + '/' + folder : folder;
        window.location.href = `file_manager.php?dir=${encodeURIComponent(newDir)}`;
    }

    function setBackButtonText() {
    let currentUrl = new URL(window.location.href);
    let currentDir = currentUrl.searchParams.get('dir') || '';
    let backButton = document.getElementById('backButton');
    
    if (currentDir === '') {
        backButton.innerHTML = 'HOME';
    } else {
        backButton.innerHTML = '&#9664; BACK';
    }
    }
    
    function goBack() {
        let currentUrl = new URL(window.location.href);
        let currentDir = currentUrl.searchParams.get('dir') || '';
        let newDir = currentDir.split('/').slice(0, -1).join('/');
        window.location.href = newDir ? `file_manager.php?dir=${encodeURIComponent(newDir)}` : 'file_manager.php';
    }
    
    // Call this function when the page loads
    document.addEventListener('DOMContentLoaded', setBackButtonText);
    
    function renameFolder(oldName) {
        let newName = prompt('Enter new folder name:', oldName);
        if (newName && newName !== oldName) {
            let formData = new FormData();
            formData.append('renameFolder', true);
            formData.append('oldName', oldName);
            formData.append('newName', newName);
    
            fetch('file_manager.php<?php echo isset($_GET['dir']) ? "?dir=" . urlencode($_GET['dir']) : ""; ?>', {
                method: 'POST',
                body: formData
            }).then(response => response.json()).then(result => {
                alert(result.message);
                location.reload();
            });
        }
    }
    
    function deleteFolder(folder) {
        if (confirm('Are you sure you want to delete this folder and all its contents?')) {
            let formData = new FormData();
            formData.append('deleteFolder', true);
            formData.append('folder', folder);
    
            fetch('file_manager.php<?php echo isset($_GET['dir']) ? "?dir=" . urlencode($_GET['dir']) : ""; ?>', {
                method: 'POST',
                body: formData
            }).then(response => response.json()).then(result => {
                alert(result.message);
                location.reload();
            });
        }
    }

    function moveFile(file) {
    let currentDir = '<?php echo getCurrentDir(); ?>';
    let destinationFolder = prompt('Enter destination folder path (leave empty for root):', currentDir);
    if (destinationFolder !== null) {  // Check if user didn't cancel the prompt
        let formData = new FormData();
        formData.append('moveFile', true);
        formData.append('fileName', file);
        formData.append('destinationFolder', destinationFolder);
        
        fetch('file_manager.php<?php echo isset($_GET['dir']) ? "?dir=" . urlencode($_GET['dir']) : ""; ?>', {
            method: 'POST',
            body: formData
        }).then(response => response.json()).then(result => {
            alert(result.message);
            if (result.status === 'success') {
                location.reload();
            }
        });
    }
}
</script>