<?php

trait MyLogger
{
    /**
     * Ergänzt SendDebug um die Möglichkeit Objekte und Array auszugeben.
     *
     * @access protected
     * @param string $Message Nachricht für Data.
     * @param WebSocketFrame|mixed $Data Daten für die Ausgabe.
     * @return int $Format Ausgabeformat für Strings.
     */
        protected function ModErrorLog($log, $ModName, $text, $array){
        if($log){
            $path = "/home/pi/pi-share/"; 
            $file=$ModName.".log";
            
            $datum = date("d.m.Y");
            $uhrzeit = date("H:i");
            $logtime = $datum." - ".$uhrzeit." Uhr";
            if (!$array){

                    $array = '-';
            }

            //prüfen, ob file vorhanden.
            //if (file_exists($path.$filename)) {



                    if(($FileHandle = fopen($path.$file, "a")) === false) {
                            //SetValue($ID_OutEnabled, false);
                            Exit;
                    }
                    if (is_array($array)){
                            //$comma_seperated=implode("\r\n",$array);
                            $comma_seperated=print_r($array, true);
                    }
                    else {
                            $comma_seperated=$array;
                    }
                    fwrite($FileHandle, $logtime.": ".$text.": ");
                    fwrite($FileHandle, $comma_seperated."\r\n");
                    fclose($FileHandle);
           //}
        }
    }
}