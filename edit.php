<?php
require 'koneksi.php';
$input = file_get_contents('php://input');
$data = json_decode($input, true);
//terima data dari mobile
$id = trim($data['id']);
$judul = trim($data['judul']);
$deskripsi = trim($data['deskripsi']);
http_response_code(201);
if ($judul != '' and $deskripsi != '') {
    $query = mysqli_query($koneksi, "update catatan set judul='$judul',deskripsi='$deskripsi' where 
id='$id'");
    $pesan = true;
} else {
    $pesan = false;
}
echo json_encode($pesan);
echo mysqli_error($koneksi);
