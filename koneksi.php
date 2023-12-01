<?php
//header untuk menangani cors policy
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
// header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Headers: X-Requested-With, Content-Type, Origin, Authorization, Accept, Client-Security-Token, Accept-Encoding');
header('Content-Type: application/json, charset=utf-8');
//membuat variable koneksi ke mysql
$koneksi = mysqli_connect('localhost','root','','responsi') or die ('koneksi gagal');