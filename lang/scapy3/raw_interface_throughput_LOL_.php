#!/usr/local/bin/php

##
##  _ancient_possibly_trashed_php_analyze_raw_bytes_thru_target_interface__
##  _might_need_refactoring_for_modern_cloud_instances__
##  _lol_might__
##
#################################

<?php
# Author: Unknown

$eth = $argv[1];
if( !isset($eth) ) $eth = "eth0";
$dir = $argv[2];
if( !isset($dir) ) $dir = "both";
        echo "Stats for $eth in direction: $dir\n";

        $cmd='ifconfig '.$eth.' | grep RX | grep bytes | sed  -r "s/^.*RX bytes://;s/\(.*TX bytes://;s/\(.*//"';
        echo "Running: $cmd\n\n";
        $input = `$cmd`;

        list($last_rx,$last_tx)=explode(" ",$input);

        if ($dir == "rx") $last_x = $last_rx;
        if ($dir == "tx") $last_x = $last_tx;
        if ($dir == "both") $last_x = $last_rx + $last_tx;

        $last_rx = $last_rx / 1024;
        $last_tx = $last_tx / 1024;

while (true){

        $input = `$cmd`;
        list($rx,$tx)=explode(" ",$input);

        if ($dir == "rx") $x = $rx;
        if ($dir == "tx") $x = $tx;
        if ($dir == "both") $x = $rx + $tx;

        $x = $x / 1024;

        $diff_x = number_format($x - $last_x,2,".","");

        echo "$dir: ";
        $star=0;
        while($star<$diff_x){
                echo "*";
                $star=$star+10;
        }
        echo "- $diff_x KBps (" . $diff_x * 8 . " kbps)";
        echo "\n";


        $last_x = $x;

        sleep(1);
}

######################################
