<?php
require 'koneksi.php';
$input = file_get_contents('php://input');
$data = json_decode($input, true);
//terima data dari mobile
$judul = trim($data['judul']);
$deskripsi = trim($data['deskripsi']);
http_response_code(201);
if ($judul != '' and $deskripsi != '') {
    $query = mysqli_query($koneksi, "insert into catatan(judul,deskripsi) values('$judul','$deskripsi')");
    $pesan = true;
} else {
    $pesan = false;
}
echo json_encode($pesan);
echo mysqli_error($koneksi);
