
    <?php
   
$inputs = (int)readline('Enter number of total inputs: ');

$array = [];
for ($i=1; $i <= $inputs; $i++) { 
    $array[] = (int)readline('Enter input '.$i.': ');
}

for($j = 0; $j < $inputs; $j++) {
    for($i = 0; $i < $inputs-1; $i++){
        if($array[$i] > $array[$i+1]) {
            $temp = $array[$i+1];
            $array[$i+1]=$array[$i];
            $array[$i]=$temp;
        }       
    }
}


$count = 0;
echo "\n3 biggest odd numbers : ";
for ($i=$inputs - 1; $i >= 0 ; $i--) { 
    if($array[$i] % 2 != 0 && $count < 3){
        echo $array[$i];
        $count += 1;
        if ($count < 3) {
            echo ',';
        }
    }
}

$count = 0;
echo "\n3 smallest odd numbers : ";
for ($i=0; $i < $inputs; $i++) { 
    if($array[$i] % 2 != 0 && $count < 3){
        echo $array[$i];
        $count += 1;
        if ($count < 3) {
            echo ',';
        }
    }
}

echo "\n";
?>

