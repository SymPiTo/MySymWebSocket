<?php

require_once(__DIR__ . "/../libs/NetworkTraits.php");
require_once(__DIR__ . "/../libs/WebsocketClass.php");  // diverse Klassen
require_once(__DIR__ . "/../libs/MyTraits.php");


use PTLS\TLSContext;
use PTLS\Exceptions\TLSAlertException;

/*
 * @addtogroup network
 * @{
 *
 * @package       Network
 * @file          module.php
 * @author        Michael Tröger <micha@nall-chan.net>get
 * @copyright     2017 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 * @version       1.2
 */

/**
 * WebsocketServer Klasse implementiert das Websocket-Protokoll für einen ServerSocket.
 * Erweitert IPSModule.
 *
 * @package       Network
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2017 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 * @version       1.2
 * @example <b>Ohne</b>
 * @property WebSocket_ClientList $Multi_Clients
 * @property bool $UseTLS
 * @property bool $UsePlain
 * @property string {$ClientIP.$ClientPort}
 * @property string {"Buffer".$ClientIP.$ClientPort} Buffer für Nutzdaten
 * @property string {"BufferTLS".$ClientIP.$ClientPort} Buffer für TLS-Nutzdaten
 * @property TLS {"Multi_TLS_".$ClientIP.$ClientPort} TLS-Object
 * @property array {"BufferListe_Multi_TLS_".$ClientIP.$ClientPort}
 * @property string $CertData
 * @property string $KeyData
 * @property string $KeyPassword
 * @property int $ParentID
 * @property int $PingInterval
 * @property bool $NoNewClients
 *
 */
 

class MyWebsocketServer extends IPSModule
{
    //Traits verbinden
    use MyDebugHelper,
        InstanceStatus,
        MyBufferHelper,
        MyLogger;

    /**
     * Interne Funktion des SDK.
     *
     * @access public 
     */
    
   

    public function Create()
    {
        parent::Create();
        $this->RegisterPropertyBoolean("da", true); 
        $this->SetBuffer("hc0", "");
        $this->SetBuffer("hc1", "");
        $this->SetBuffer("CamBuffer", "");
        $this->SetBuffer("OldData", "");
        $this->SetBuffer("IpsVars", "");
        $this->SetBuffer("IpsVarsFast", "");

        //create server Socket if not exist
        $this->RequireParent("{8062CF2B-600E-41D6-AD4B-1BA66C32D6ED}");
        $this->Multi_Clients = new WebSocket_ClientList();
        $this->NoNewClients = true;
     
        $this->RegisterPropertyString("WhiteList", "[]");
        $this->RegisterPropertyBoolean("Open", false);
        $this->RegisterPropertyBoolean("ErrLog", true);
        $this->RegisterPropertyInteger("UpdateInterval", 5000);
        $this->RegisterPropertyInteger("IDcommand", 0);
        $this->RegisterPropertyInteger("Port", 8080);
        $this->RegisterPropertyInteger("Interval", 0);
        $this->RegisterPropertyString("URI", "/");
        $this->RegisterPropertyBoolean("BasisAuth", false);
        $this->RegisterPropertyString("Username", "");
        $this->RegisterPropertyString("Password", "");
        $this->RegisterPropertyBoolean("TLS", false);
        $this->RegisterPropertyBoolean("Plain", true);
        $this->RegisterPropertyString("CertFile", "");
        $this->RegisterPropertyString("KeyFile", "");
        $this->RegisterPropertyString("KeyPassword", "xxx");
        $this->RegisterTimer('KeepAlivePing', 0, 'MyWSS_KeepAlive($_IPS[\'TARGET\']);');
        // Daten die von Client kommen werden in folgende Variable geschrieben
        $variablenID = $this->RegisterVariableString("CommandSendToServer", "CommandSendToServer");
        IPS_SetInfo ($variablenID, "WSS"); 
        //Bei  Variablenänderung folgender Variable wird dieser Inhalt an alle Clients gesendet
        $this->RegisterVariableString("DataSendToClient", "DataSendToClient");

        //4 Variable der verbundenen Clients IP anlegen
        $variablenID = $this->RegisterVariableString("Client1", "connected Client 1");    
        IPS_SetInfo ($variablenID, "WSS"); 
        $variablenID = $this->RegisterVariableString("Client2", "connected Client 2"); 
        IPS_SetInfo ($variablenID, "WSS"); 
        $variablenID = $this->RegisterVariableString("Client3", "connected Client 3");
        IPS_SetInfo ($variablenID, "WSS"); 
        $variablenID = $this->RegisterVariableString("Client4", "connected Client 4"); 
        IPS_SetInfo ($variablenID, "WSS"); 
        $variablenID = $this->RegisterVariableString("Message", "Meldung"); 
        IPS_SetInfo ($variablenID, "WSS"); 

        $this->RegisterVariableString("dummyID", "DummyID", "", 0);
        $this->setvalue("dummyID", "XXXX");
        
        //Status Variablen für Server
        $variablenID = $this->RegisterVariableBoolean("active", "WSS_active", "~Switch");
        IPS_SetInfo ($variablenID, "WSS"); 
        

        //Variable für zu übertragende Variable (Array) anlegen
        $this->RegisterVariableString("CamSendVars", "Cam Variablen"); 
        //Listen Einträge als JSON regisrieren
        // zum umwandeln in ein Array 
        // $IPSVars = json_decode($this->ReadPropertyString("IPSVars"));
        //$this->RegisterPropertyString("IPSVars", "[]");
        
        // Timer erstellen zum senden der Variablen
         $this->RegisterTimer("UpdateVars", 0 , 'MyWSS_sendIPSVars($_IPS[\'TARGET\'],false);');
       
    }

    /**
     * Interne Funktion des SDK.
     *
     * @access public
     */
    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        $this->SendDebug('Messagesink:'.$SenderID, $Message, 0);
        /*registrierte IPS Meldungen
            IPS_KERNELMESSAGE       wird nicht verwendet da nur für alte Version
            IPS_KERNELSTARTED       10001	Wird nach KR_READY gesendet und synchron abgearbeitet
            IPS_KERNELSHUTDOWN      10002	Wir vor KR_UNINIT gesendet und synchron abgearbeitet
            FM_DISCONNECT           11102	Instanz wurde getrennt
            FM_CONNECT              11101	Instanz wurde verbunden
            IM_CHANGESTATUS         10506	Einstellungen haben sich geändert
            VM_UPDATE               10603	Variable wurde aktualisiert
        */
        $log = $this->ReadPropertyBoolean("ErrLog");
        switch ($Message) {
            case IPS_KERNELMESSAGE:
                if ($Data[0] != KR_READY) {
                    break;
                }
            case IPS_KERNELSTARTED:
                $this->ApplyChanges();
                break;
            case IPS_KERNELSHUTDOWN:
                $this->DisconnectAllClients();
                break;
            case FM_DISCONNECT:
                $this->ModErrorLog($log, "WebsocketServer", "Meldung aus IPS MessageSInk: ", "Socket Disconnected");
                $this->LogMessage("WebsocketServer:Meldung aus IPS MessageSInk: Socket Disconnetcted", KL_WARNING);
                $this->NoNewClients = true;
                $this->RemoveAllClients();
                $this->RegisterParent();
                break;
            case FM_CONNECT:
                $this->ModErrorLog($log, "WebsocketServer", "Meldung aus IPS MessageSInk: ", "Socket connected");
                $this->LogMessage("WebsocketServer:Meldung aus IPS MessageSink: Socket connetcted", KL_WARNING);
                $this->ApplyChanges();
                break;
            case IM_CHANGESTATUS:
                if ($SenderID == $this->ParentID) {
                    if ($Data[0] == IS_ACTIVE) {
                        $this->NoNewClients = false;
                    } else {
                        $this->NoNewClients = true;
                        $this->RemoveAllClients();
                    }
                }
                break;
            case VM_UPDATE:
                //VM_UPDATE - EventVariable wird über "WSS1" registriert
                //$this->SendDebug('VM_UPDATE', $SenderID, 0);
                /* ----- Variablen Änderung erkannt -> Daten holen und an Clients senden ---- */
            
                $this->sendIPSVars(false);
            
           
                break;
        }
    }

    /**
     * Interne Funktion des SDK.
     *
     * @access public
     */
    public function GetConfigurationForm()
    {
        $data = json_decode(file_get_contents(__DIR__ . "/form.json"));
        if ((float) IPS_GetKernelVersion() < 4.2) {
            $data->elements[8]->type = "ValidationTextBox";
            $data->elements[8]->caption = "Path to certificate";
            unset($data->elements[8]->extensions);
            $data->elements[9]->type = "ValidationTextBox";
            $data->elements[9]->caption = "Path to private key";
            unset($data->elements[9]->extensions);
        }
        return json_encode($data);
    }

    /**
     * Interne Funktion des SDK.
     *
     * @access public
     */
    public function GetConfigurationForParent()
    {
        $Config['Port'] = $this->ReadPropertyInteger('Port');
        $Config['Open'] = $this->ReadPropertyBoolean('Open');
        return json_encode($Config);
    }

    /**
     * Interne Funktion des SDK.
     *
     * @access public
     */
    public function ApplyChanges()
    {
        setvalue($this->GetIDForIdent("active"),$this->ReadPropertyBoolean("Open"));
        if($this->ReadPropertyBoolean("Open")){
            $this->SetTimerInterval("UpdateVars", $this->ReadPropertyInteger("UpdateInterval"));
            
            $this->SendDebug("START", "Modul ist AKTIV",0);
        }
        else {
            $this->SetTimerInterval("UpdateVars", 0);
        }
        //Variable für Webfront ausblenden.
        IPS_SetHidden ($this->GetIDForIdent("CommandSendToServer"), true );
        
        IPS_SetHidden ($this->GetIDForIdent("DataSendToClient"), true );
        
        $this->NoNewClients = true;

        if ((float) IPS_GetKernelVersion() < 4.2) {
            $this->RegisterMessage(0, IPS_KERNELMESSAGE);
        } else {
            $this->RegisterMessage(0, IPS_KERNELSTARTED);
            $this->RegisterMessage(0, IPS_KERNELSHUTDOWN);
        }
        
        
        $this->RegisterMessage($this->InstanceID, FM_CONNECT);
        $this->RegisterMessage($this->InstanceID, FM_DISCONNECT);

        //Event Variable definieren - wird über Eintrag in INFO = WSS1 automatisch registriert
        //$this->RegisterMessage(13996, VM_UPDATE); // incommng call

        if (IPS_GetKernelRunlevel() <> KR_READY) {
            return;
        }

        $this->SetTimerInterval('KeepAlivePing', 0);

        $OldParentID = $this->ParentID;
        if ($this->HasActiveParent() and ($OldParentID > 0)) {
            $this->DisconnectAllClients();
        }

        parent::ApplyChanges();

       
        $NewState = IS_ACTIVE;
        $this->UseTLS = $this->ReadPropertyBoolean('TLS');
        $this->UsePlain = $this->ReadPropertyBoolean('Plain');
        //$this->SendDebug('UsePlain', ($this->UsePlain ? "true" : "false"), 0);
        //$this->SendDebug('UseTLS', ($this->UseTLS ? "true" : "false"), 0);
        if ($this->UseTLS) {
            $basedir = IPS_GetKernelDir() . "cert";
            if (!file_exists($basedir)) {
                mkdir($basedir);
            }
            if (($this->ReadPropertyString("CertFile") == "") and ($this->ReadPropertyString("KeyFile") == "")) {
                return $this->CreateNewCert($basedir);
            }

            try {
                if ((float) IPS_GetKernelVersion() < 4.2) {
                    $CertFile = @file_get_contents($this->ReadPropertyString("CertFile"));
                    $KeyFile = @file_get_contents($this->ReadPropertyString("KeyFile"));
                } else {
                    //Convert old settings
                    $CertFile = $this->ReadPropertyString("CertFile");
                    $KeyFile = $this->ReadPropertyString("KeyFile");
                    if (is_file($CertFile)) {
                        IPS_SetProperty($this->InstanceID, "CertFile", @file_get_contents($this->ReadPropertyString("CertFile")));
                    }
                    if (is_file($KeyFile)) {
                        IPS_SetProperty($this->InstanceID, "KeyFile", @file_get_contents($this->ReadPropertyString("KeyFile")));
                    }
                    if (IPS_HasChanges($this->InstanceID)) {
                        IPS_ApplyChanges($this->InstanceID);
                        return;
                    }

                    // Read new settings
                    $CertFile = base64_decode($CertFile);
                    $KeyFile = base64_decode($KeyFile);
                }

                if ($CertFile) {
                    $this->CertData = 'data://text/plain;base64,' . base64_encode($CertFile);
                } else {
                    throw new Exception('Certificate missing or not found');
                }

                if ($KeyFile) {
                    $this->KeyData = 'data://text/plain;base64,' . base64_encode($KeyFile);
                } else {
                    throw new Exception('Private key missing or not found');
                }

//                if (strlen($this->ReadPropertyString("KeyPassword")) == 0)
//                    throw new Exception('Password for private key missing');

                $this->KeyPassword = $this->ReadPropertyString("KeyPassword");
            } catch (Exception $exc) {
                echo $this->Translate($exc->getMessage());
                $this->UseTLS = false;
                $NewState = IS_EBASE + 1;
            }
        }

        $Open = $this->ReadPropertyBoolean('Open');
        $Port = $this->ReadPropertyInteger('Port');
        $this->PingInterval = $this->ReadPropertyInteger('Interval');
        if (!$Open) {
            $NewState = IS_INACTIVE;
        } else {
            if (($Port < 1) or ($Port > 65535)) {
                $NewState = IS_EBASE + 2;
                $Open = false;
                trigger_error($this->Translate('Port invalid'), E_USER_NOTICE);
            } else {
                if (($this->PingInterval != 0) and ($this->PingInterval < 5)) {
                    $this->PingInterval = 0;
                    $NewState = IS_EBASE + 4;
                    $Open = false;
                    trigger_error($this->Translate('Ping interval to small'), E_USER_NOTICE);
                }
            }
        }
        $ParentID = $this->RegisterParent();

        // Zwangskonfiguration des ServerSocket
        if ($ParentID > 0) {
            if (IPS_GetProperty($ParentID, 'Port') <> $Port) {
                IPS_SetProperty($ParentID, 'Port', $Port);
            }
            if (IPS_GetProperty($ParentID, 'Open') <> $Open) {
                IPS_SetProperty($ParentID, 'Open', $Open);
            }
            if (IPS_HasChanges($ParentID)) {
                @IPS_ApplyChanges($ParentID);
            }
        } else {
            if ($Open) {
                $NewState = IS_INACTIVE;
                $Open = false;
            }
        }

        if ($Open && !$this->HasActiveParent($ParentID)) {
            $NewState = IS_EBASE + 2;
        }

        $this->SetStatus($NewState);
        $this->NoNewClients = false;
        $this->RegisterIPSMessages();
        
    }

    ################## PRIVATE

    /**
     * Erzeugt ein selbst-signiertes Zertifikat.
     *
     * @access private
     * @param string $basedir Der Speicherort der Zertifikate.
     * @return boolean True bei Erflog, sonst false
     */
    public function CreateNewCert(string $basedir)
    {
        $CN = 'IPSymcon';
        $EMAIL = IPS_GetLicensee();
        $basedir .= DIRECTORY_SEPARATOR . $this->InstanceID;
        $configfile = $basedir . ".cnf";
        $certfile = $basedir . ".cer";
        $keyfile = $basedir . ".key";
        $newLine = "\r\n";

        $strCONFIG = 'default_md = sha256' . $newLine;
        $strCONFIG .= 'default_days = 3650' . $newLine;
        $strCONFIG .= $newLine;
        $strCONFIG .= 'x509_extensions = x509v3' . $newLine;
        $strCONFIG .= '[ req ]' . $newLine;
        $strCONFIG .= 'default_bits = 2048' . $newLine;
        $strCONFIG .= 'distinguished_name = req_DN' . $newLine;
        $strCONFIG .= 'string_mask = nombstr' . $newLine;
        $strCONFIG .= 'prompt = no' . $newLine;
        $strCONFIG .= 'req_extensions = v3_req' . $newLine;
        $strCONFIG .= $newLine;
        $strCONFIG .= '[ req_DN ]' . $newLine;
        $strCONFIG .= 'countryName = DE' . $newLine;
        $strCONFIG .= 'stateOrProvinceName = none' . $newLine;
        $strCONFIG .= 'localityName = none' . $newLine;
        $strCONFIG .= '0.organizationName = "Home"' . $newLine;
        $strCONFIG .= 'organizationalUnitName  = "IPS"' . $newLine;
        $strCONFIG .= 'commonName = ' . $CN . $newLine;
        $strCONFIG .= 'emailAddress = ' . $EMAIL . $newLine;
        $strCONFIG .= $newLine;
        $strCONFIG .= '[ v3_req ]' . $newLine;
        $strCONFIG .= 'basicConstraints=CA:FALSE' . $newLine;
        $strCONFIG .= 'subjectKeyIdentifier=hash' . $newLine;
        $strCONFIG .= $newLine;
        $strCONFIG .= '[ x509v3 ]' . $newLine;
        $strCONFIG .= 'basicConstraints=CA:FALSE' . $newLine;
        $strCONFIG .= 'nsCertType       = server' . $newLine;
        $strCONFIG .= 'keyUsage         = digitalSignature,nonRepudiation,keyEncipherment' . $newLine;
        $strCONFIG .= 'extendedKeyUsage = msSGC,nsSGC,serverAuth' . $newLine;
        $strCONFIG .= 'subjectKeyIdentifier=hash' . $newLine;
        $strCONFIG .= 'authorityKeyIdentifier=keyid,issuer:allways' . $newLine;
        $strCONFIG .= 'issuerAltName = issuer:copy' . $newLine;
        $strCONFIG .= 'subjectAltName = IP:192.168.201.34' . $newLine;
        $strCONFIG .= $newLine;
//        $strCONFIG .= '[alt_names]' . $newLine;
//        $strCONFIG .= 'email = '.$EMAIL . $newLine;
//        $strCONFIG .= 'IP = 192.168.201.34' . $newLine;
//        $strCONFIG .= $newLine;

        $fp = fopen($configfile, 'w');
        fwrite($fp, $strCONFIG);
        fclose($fp);

        $dn = array(
            "countryName" => "DE",
            "stateOrProvinceName" => "none",
            "localityName" => "none",
            "organizationName" => "Home",
            "organizationalUnitName" => "IPS",
            "commonName" => "$CN",
            "emailAddress" => "$EMAIL"
        );

        $config = array(
            "config" => "$configfile",
            "encrypt_key" => true);

        $configKey = array(
            "config" => "$configfile",
            "encrypt_key" => true,
            "digest_alg" => "sha512",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $pk = openssl_pkey_new($configKey);
        openssl_pkey_export($pk, $pkexport, 'Symcon', $config);
        if ((float) IPS_GetKernelVersion() < 4.2) {
            $fp = fopen($keyfile, 'w');
            fwrite($fp, $pkexport);
            fclose($fp);
            IPS_SetProperty($this->InstanceID, "KeyFile", $basedir . ".key");
        } else {
            IPS_SetProperty($this->InstanceID, "KeyFile", base64_encode($pkexport));
        }


        $csr = openssl_csr_new($dn, $pk, $config);
        if ($csr) {
            $cert = openssl_csr_sign($csr, null, $pk, 730, $config);
            if ($cert) {
                openssl_x509_export($cert, $certout);
                if ((float) IPS_GetKernelVersion() < 4.2) {
                    $fp = fopen($certfile, 'w');
                    fwrite($fp, $certout);
                    fclose($fp);
                    IPS_SetProperty($this->InstanceID, "CertFile", $basedir . ".cer");
                } else {
                    IPS_SetProperty($this->InstanceID, "CertFile", base64_encode($certout));
                }
            } else {
                unlink($configfile);
                return false;
            }
        } else {
            unlink($configfile);
            return false;
        }
        unlink($configfile);
        IPS_SetProperty($this->InstanceID, "KeyPassword", "Symcon");
        IPS_ApplyChanges($this->InstanceID);
        return true;
    }

    /**
     * Wertet den Handshake des Clients aus.
     *
     * @access private
     * @param string $Data Die Daten des Clients.
     * @return boolean|HTTP_ERROR_CODES True bei Erfolg, HTTP_ERROR_CODES bei Fehler, false wenn nicht genug Daten.
     */
    
    private function ReceiveHandshake(string $Data)
    {
        $this->SendDebug('Receive Handshake', $Data, 0);
        $log = $this->ReadPropertyBoolean("ErrLog");
        if (preg_match("/^GET ? (.*) HTTP\/1.1\r\n/", $Data, $match)) {
            $this->SendDebug('Receive Handshake', $match, 0);

            if (substr($Data, -4) != "\r\n\r\n") {
                $this->SendDebug('WAIT', $Data, 0);
                return false;
            }
            //authentification token prüfen
            if(preg_match("/.*[?](.*)/",$match[1], $keymatch)){
                
                $token =  explode("=", $keymatch[1]);
                 
                if($token[1] != "tboercskten"){
                    $this->SendDebug('Auth Token', "not accepted", 0);
                    $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "Auth Token not accepted.");
                    return HTTP_ERROR_CODES::Unauthorized;
                }
                else{
                    $this->SendDebug('Auth Token', "accepted", 0);
                }
                
            }
            else{
                //auth Token nicht vorhanden
                $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "Auth Token not available.");
                $this->LogMessage("WebsocketServer: ReceiveHandshake: Auth Token not available.", KL_WARNING);
                return HTTP_ERROR_CODES::Not_Found;
            }
            if(preg_match("/.*[?](.*)/",$match[1], $keymatch)){
                $this->SendDebug('Receive Handshake KEY', $keymatch, 0);
                $pos = stripos($keymatch[0], "?");
                $uri = substr($keymatch[0], 0, $pos);
            }
            else{
                $uri =  $match[1];
            }

            $this->SendDebug('Receive Handshake URI', $uri, 0);
            if ($uri != trim($this->ReadPropertyString('URI'))) {
                $this->SendDebug('Wrong URI requested', $Data, 0);
                $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", 'Wrong URI requested:'.$Data);
                $this->LogMessage("WebsocketServer: ReceiveHandshake: Wrong URI requested. ".$Data, KL_WARNING);
                return HTTP_ERROR_CODES::Not_Found;
            }
            if ($this->ReadPropertyBoolean('BasisAuth')) {
                $realm = base64_encode($this->ReadPropertyString('Username') . ':' . $this->ReadPropertyString('Password'));
                if (preg_match("/Authorization: Basic (.*)\r\n/", $Data, $match)) {
                    if ($match[1] != $realm) {
                        $this->SendDebug('Unauthorized Connection:', base64_decode($match[1]), 0);
                        $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "Unauthorized Connection:");
                        $this->LogMessage("WebsocketServer: ReceiveHandshake: Unauthorized Connection.", KL_WARNING);
                        return HTTP_ERROR_CODES::Forbidden;
                    }
                } else {
                    $this->SendDebug('Authorization missing', '', 0);
                    $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "Authorization missing:");
                    $this->LogMessage("WebsocketServer: ReceiveHandshake: Authorization missing.", KL_WARNING);
                    return HTTP_ERROR_CODES::Unauthorized;
                }
            }
            if (preg_match("/Connection: (.*)\r\n/", $Data, $match)) {
                if (strtolower($match[1]) != 'upgrade') {
                    $this->SendDebug('WRONG Connection:', $match[1], 0);
                    $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "Method_Not_Allowed - WRONG Connection:");
                    $this->LogMessage("WebsocketServer: ReceiveHandshake: Method_Not_Allowed - WRONG Connection.", KL_WARNING);
                    return HTTP_ERROR_CODES::Method_Not_Allowed;
                }
            } else {
                $this->SendDebug('MISSING', 'Connection: Upgrade', 0);
                $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "Bad_Request:");
                $this->LogMessage("WebsocketServer: ReceiveHandshake: Bad_Request.", KL_WARNING);
                return HTTP_ERROR_CODES::Bad_Request;
            }
            if (preg_match("/Upgrade: (.*)\r\n/", $Data, $match)) {
                if (strtolower($match[1]) != 'websocket') {
                    $this->SendDebug('WRONG Upgrade:', $match[1], 0);
                    $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "WRONG Upgrade.");
                    $this->LogMessage("WebsocketServer: ReceiveHandshake: WRONG Upgrade.", KL_WARNING);
                    return HTTP_ERROR_CODES::Method_Not_Allowed;
                }
            } else {
                $this->SendDebug('MISSING', 'Upgrade: websocket', 0);
                $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "MISSING Upgrade.");
                $this->LogMessage("WebsocketServer: ReceiveHandshake: MISSING Upgrade.", KL_WARNING);
                return HTTP_ERROR_CODES::Bad_Request;
            }
            if (preg_match("/Sec-WebSocket-Version: (.*)\r\n/", $Data, $match)) {
                if (strpos($match[1], '13') === false) {
                    $this->SendDebug('WRONG Version:', $match[1], 0);
                    $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "WRONG Version:".$match[1]);
                    return HTTP_ERROR_CODES::Not_Acceptable;
                }
            } else {
                $this->SendDebug('MISSING', 'Sec-WebSocket-Version', 0);
                $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "MISSING Sec-WebSocket-Version");
                return HTTP_ERROR_CODES::Bad_Request;
            }
            if (!preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $Data, $match)) {
                $this->SendDebug('MISSING', 'Sec-WebSocket-Key', 0);
                $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "MISSING Sec-WebSocket-Key");
                return HTTP_ERROR_CODES::Bad_Request;
            }
            return true;
        }
        $this->SendDebug('Invalid HTTP-Request', $Data, 0);
        $this->ModErrorLog($log, "WebSocketServer", "ReceiveHandshake", "Invalid HTTP-Request");
        $this->LogMessage("WebsocketServer: ReceiveHandshake: Invalid HTTP-Request.", KL_WARNING);
        return HTTP_ERROR_CODES::Bad_Request;
    }

    /**
     * Sendet den HTTP-Response an den Client.
     *
     * @access private
     * @param HTTP_ERROR_CODES $Code Der HTTP Code welcher versendet werden soll.
     * @param string $Data Die empfangenen Daten des Clients.
     * @param Websocket_Client $Client Der Client vom welchen die Daten empfangen wurden.
     *  match Array:    [0] => Sec-WebSocket-Key: ZnIWnMD5fCyXY6bGcari0g==
     *                  [1] => ZnIWnMD5fCyXY6bGcari0g==
     */
    private function SendHandshake(int $Code, string $Data, Websocket_Client $Client)
    {
        $log = $this->ReadPropertyBoolean("ErrLog");
        try {
            preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $Data, $match);
            if (isset($match)){
                $this->LogMessage("WebsocketServer: SendHandshake-Data:.".$match[0], KL_DEBUG);
                $SendKey = base64_encode(sha1($match[1] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
                $Header[] = 'HTTP/1.1 ' . HTTP_ERROR_CODES::ToString($Code);
                if ($Code == HTTP_ERROR_CODES::Unauthorized) {
                    $Header[] = 'WWW-Authenticate: Basic';
                }
                //$Header[] = 'Date: '; // Datum fehlt !
                $Header[] = 'Server: IP-Symcon Websocket Gateway';
                if ($Code == HTTP_ERROR_CODES::Web_Socket_Protocol_Handshake) {
                    $Header[] = 'Connection: Upgrade';
                    $Header[] = 'Sec-WebSocket-Accept: ' . $SendKey;
                    $Header[] = 'Upgrade: websocket';
                    $Header[] = "\r\n";
                    $SendHeader = implode("\r\n", $Header);
                } else {
                    $Header[] = 'Content-Length:' . strlen(HTTP_ERROR_CODES::ToString($Code));
                    $Header[] = "\r\n";
                    $SendHeader = implode("\r\n", $Header) . HTTP_ERROR_CODES::ToString($Code);
                }
                $this->SendDebug('SendHandshake ' . $Client->ClientIP . ':' . $Client->ClientPort, $SendHeader, 0);
                $SendData = $this->MakeJSON($Client, $SendHeader);
                if ($SendData) {
                    //Daten an I/O Schnittstelle senden
                    $this->SendDataToParent($SendData);
                }
            } else {
                $this->LogMessage("Websocket: Websocket-key nicht vorhanden.", KL_ERROR); 
            }
        } catch (exception $e) {
            //code for exception
            $this->LogMessage("WebsocketServer: SendHandshake-Data:.".$Data, KL_ERROR);
            $this->LogMessage("WebsocketServer: SendHandshake-Match:".$match, KL_ERROR);
        }

    }

    /**
     * Erzeugt aus einen Datenframe ein JSON für den Datenaustausch mit dem IO.
     *
     * @param Websocket_Client $Client Der Client an welchen die Daten gesendet werden.
     * @param string $Data Die Nutzdaten
     * @param type $UseTLS Bei false wird TLS nicht benutzt, auch wenn der Client dies erwartet.
     * @return boolean|string Der JSON-String zum versand an den IO, im Fehlerfall false.
     */
    private function MakeJSON(Websocket_Client $Client, string $Data, $UseTLS = false, int $Type = SocketType::Data)
    {
        if ($Type == SocketType::Data) {
            if ($UseTLS and $Client->UseTLS) {
                $this->SendDebug('Send TLS', $Data, 0);
                try {
                    $this->lock($Client->ClientIP . $Client->ClientPort);
                    $TLS = $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort};
                    $Send = $TLS->output($Data)->decode();
                    $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = $TLS;
                    $this->unlock($Client->ClientIP . $Client->ClientPort);
                } catch (Exception $exc) {
                    return false;
                }
                $Data = $Send;
            }
            $this->SendDebug('Send', $Data, 0);
        } else {
            $this->SendDebug('Send', SocketType::ToString($Type), 0);
        }
        $SendData['DataID'] = '{C8792760-65CF-4C53-B5C7-A30FCC84FEFE}';
        $SendData['Buffer'] = utf8_encode($Data);
        $SendData['ClientIP'] = $Client->ClientIP;
        $SendData['ClientPort'] = $Client->ClientPort;
        $SendData['Type'] = $Type;
        return json_encode($SendData);
    }

    /**
     * Dekodiert die empfangenen Daten und sendet sie an die Childs.
     *
     * @access private
     * @param WebSocketFrame $Frame Ein Objekt welches einen kompletten Frame enthält.
     * @param Websocket_Client $Client Der Client von welchem die Daten empfangen wurden.
     */
    private function DecodeFrame(WebSocketFrame $Frame, Websocket_Client $Client)
    {
        $this->SendDebug('DECODE', $Frame, ($Frame->OpCode == WebSocketOPCode::continuation) ? $this->PayloadTyp - 1 : $Frame->OpCode - 1);
        switch ($Frame->OpCode) {
            case WebSocketOPCode::ping:
                $this->SendPong($Client, $Frame->Payload);
                return;
            case WebSocketOPCode::close:
                $this->SendDebug('Receive', 'Client send stream close !', 0);
                $Client->State = WebSocketState::CloseReceived;
                $this->SendDisconnect($Client);
                // wird nicht beötigt, da keine Daten weitergegeben werden 5.1.2020
                // $this->SendDataToChilds('', $Client); // RAW Childs
                return;
            case WebSocketOPCode::text:
            case WebSocketOPCode::binary:
                $this->{'OpCode' . $Client->ClientIP . $Client->ClientPort} = $Frame->OpCode;
                $Data = $Frame->Payload;
                break;
            case WebSocketOPCode::continuation:
                $Data = $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} . $Frame->Payload;
                break;
            case WebSocketOPCode::pong:
                $this->{'Pong' . $Client->ClientIP . $Client->ClientPort} = $Frame->Payload;
                $this->{'WaitForPong' . $Client->ClientIP . $Client->ClientPort} = true;
                $JSON['DataID'] = '{8F1F6C32-B1AD-4B7F-8DFB-1244A96FCACF}';
                $JSON['Buffer'] = utf8_encode($Frame->Payload);
                $JSON['ClientIP'] = $Client->ClientIP;
                $JSON['ClientPort'] = $Client->ClientPort;
                $JSON['FrameTyp'] = WebSocketOPCode::pong;
                $Data = json_encode($JSON);
               // $this->SendDataToChildren($Data); WIRD nicht benötigt da kein Weiterleiten an children  
                return;
        }
        if ($Frame->Fin) {
            // wird nicht benötigt, da keine Daten weitergegeben werden an andere Module 5.1.20202
            //$this->SendDataToChilds($Data, $Client); // RAW Childs
            //gesendete Daten vom Client werden ausgewertet
            //$this->SendDebug("received Data: ",$Data, 0);
            $this->CommandToServer($Data);
        } else {
            $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = $Data;
        }
    }

    /**
     * Setzt den Intervall des Timer auf den nächsten Timeout eines Client.
     *
     * @access private
     */
    private function SetNextTimer()
    {
        $this->SetTimerInterval('KeepAlivePing', 0);
        $Clients = $this->Multi_Clients;
        $Client = $Clients->GetNextTimeout($this->PingInterval + 1);
        $this->SendDebug('NextTimeout', $Client, 0);
        if ($Client === false) {
            $next = 0;
        } else {
            $next = $Client->Timestamp - time();
            if ($next == 0) {
                $next = 0.001;
            }
            if ($next < 0) {
                $next = 0;
            }
        }
        $this->SendDebug('TIMER NEXT', $next, 0);
        $this->SetTimerInterval('KeepAlivePing', $next * 1000);
    }

    /**
     * Sendet einen Pong an einen Client.
     *
     * @access private
     * @param Websocket_Client $Client Der Client an welchen das Pong versendet wird.
     * @param string $Payload Der Payloaf des Pong.
     */
    private function SendPong(Websocket_Client $Client, string $Payload = null)
    {
        $this->Send($Payload, WebSocketOPCode::pong, $Client);
    }

    /**
     * Sendet ein Connection Close an alle Clients.
     *
     * @access private
     */
    private function DisconnectAllClients()
    {
        $this->SetTimerInterval('KeepAlivePing', 0);
        $Clients = $this->Multi_Clients;
        foreach ($Clients->GetClients() as $Client) {
            $this->SendDisconnect($Client);
        }
        $this->Multi_Clients = new WebSocket_ClientList();
    }

    /**
     * Sendet einen Close an einen Client und löscht alle Buffer dieses Clients.
     *
     * @access private
     * @param Websocket_Client $Client Der Client an welchen das Close gesendet wird.
     * @return bool True bei Erfolg, sonst false.
     */
    private function SendDisconnect(Websocket_Client $Client)
    {
        $ret = false;
        if ($Client->State == WebSocketState::CloseReceived) {
            $ret = true;
            $this->SendDebug('Send', 'Answer Client stream close !', 0);
            $this->Send("", WebSocketOPCode::close, $Client);
        }
        if ($Client->State == WebSocketState::Connected) {
            $this->SendDebug('Send', 'Server send stream close !', 0);
            $Clients = $this->Multi_Clients;
            $Client->State = WebSocketState::CloseSend;
            $Clients->Update($Client);
            $this->Multi_Clients = $Clients;
            $this->Send("", WebSocketOPCode::close, $Client);
            $ret = $this->WaitForClose($Client);
            $this->CloseConnection($Client);
        }

        $this->RemoveOneClient($Client);
        //entfernt 3.1.2020
        //$Clients = $this->Multi_Clients;
        //$Clients->Remove($Client);
        //$this->Multi_Clients = $Clients;

        return $ret;
    }
    public function  RestartServer() {
        $this->RemoveAllClients();
        $id = $this->InstanceID;
        IPS_SetProperty($id, "Open", false); //I/O Instanz soll aktiviert sein.
        IPS_ApplyChanges($id); //Neue Konfiguration übernehmen
        IPS_SetProperty($id, "Open", true); //I/O Instanz soll aktiviert sein.
        IPS_ApplyChanges($id); //Neue Konfiguration übernehmen
            
    }
    
    private function RemoveOneClient(Websocket_Client $Client)
    {
        $log = $this->ReadPropertyBoolean("ErrLog");
        
        $this->LogMessage("WebsocketServer: Entferne Client aus Liste".$Client->ClientIP.$Client->ClientPort, KL_WARNING);
        $this->ClearClientBuffer($Client);
        $Clients = $this->Multi_Clients;
        $this->SendDebug("RemoveOneClient: ", "entferne Client: ". $Client->ClientIP.":".$Client->ClientPort, 0);

        $Clients->Remove($Client);
        $this->Multi_Clients = $Clients;
        // ----------------------------------------
                    //added 4.1.2020

                    //alle verbundenen Clients in Variable schreiben
                    $cl = $Clients->GetClients();
                    //$this->SendDebug("Verbundener Client", $cl, 0);
                    foreach ($cl as $key => $value) {
                        //$this->SendDebug("Verbundene Clients:".$key, $value->ClientIP, 0);
                        $liste[$key] =  $value->ClientIP.":". $value->ClientPort;
                        $this->LogMessage("WebsocketServer: Bereinigt & verbundener Client".$liste[$key], KL_WARNING);
                        $this->ModErrorLog($log, "WebsocketServer", "Bereinigt & verbundener Client", $liste[$key]);
                    }
                    if (!empty($liste)){
                        $this->writeClients($liste);
                    }
                    
        // --------------------------------------------------------------------
        $this->SetNextTimer();
    }

    /**
     * Leert die ClientListe und alle entsprechenden Buffer der Clients.
     *
     * @access private
     */
    private function RemoveAllClients()
    {
        $Clients = $this->Multi_Clients;
        foreach ($Clients->GetClients() as $Client) {
            $this->ClearClientBuffer($Client);
        }
        $this->Multi_Clients = new WebSocket_ClientList();
    }

    /**
     * Leert die entsprechenden Buffer eines Clients.
     *
     * @param Websocket_Client $Client Der zu löschende Client.
     */
    private function ClearClientBuffer(Websocket_Client $Client)
    {
        $this->SetBuffer('OpCode' . $Client->ClientIP . $Client->ClientPort, '');
        $this->SetBuffer('Buffer' . $Client->ClientIP . $Client->ClientPort, '');
        $this->SetBuffer('Pong' . $Client->ClientIP . $Client->ClientPort, '');
        $this->SetBuffer('WaitForPong' . $Client->ClientIP . $Client->ClientPort, '');
        $this->SetBuffer('WaitForClose' . $Client->ClientIP . $Client->ClientPort, '');
        $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
        $this->SetBuffer('BufferListe_Multi_TLS_' . $Client->ClientIP . $Client->ClientPort, '');
    }

    /**
     * Wartet auf eine Handshake-Antwort.
     *
     * @access private
     * @param Websocket_Client $Client
     * @return string|bool Der Payload des Pong, oder im Fehlerfall false.
     */
    private function WaitForPong(Websocket_Client $Client)
    //Leseversuche von 500 auf 1000 erhöht
    {
        for ($i = 0; $i < 1000; $i++) {
            if ($this->{'WaitForPong' . $Client->ClientIP . $Client->ClientPort} === true) {
                $Payload = $this->{'Pong' . $Client->ClientIP . $Client->ClientPort};
                $this->{'Pong' . $Client->ClientIP . $Client->ClientPort} = "";
                $this->{'WaitForPong' . $Client->ClientIP . $Client->ClientPort} = false;
                //$this->ModErrorLog($log, "WebsocketServer", "Pong erhalten nach x Versuchen: ", $i);
                return $Payload;
            }
            IPS_Sleep(5); 
        }
        return false;
    }

    /**
     * Wartet auf eine Close-Antwort eines Clients.
     *
     * @access private
     * @param Websocket_Client $Client
     * @return bool True bei Erfolg, sonst false.
     */
    private function WaitForClose(Websocket_Client $Client)
    {
        for ($i = 0; $i < 500; $i++) {
            if ($this->{'WaitForClose' . $Client->ClientIP . $Client->ClientPort} === true) {
                $this->{'WaitForClose' . $Client->ClientIP . $Client->ClientPort} = false;
                return true;
            }
            IPS_Sleep(5);
        }
        return false;
    }

    /**
     * Versendet RawData mit OpCode an den IO.
     *
     * @access private
     * @param string $RawData Das zu sende Payload
     * @param WebSocketOPCode $OPCode Der zu benutzende OPCode
     * @param Websocket_Client $Client Der Client an welchen die Daten gesendet werden sollen.
     * @param bool $Fin True wenn Ende von Payload erreicht.
     */
    private function Send(string $RawData, int $OPCode, Websocket_Client $Client, $Fin = true){
        $log = $this->ReadPropertyBoolean("ErrLog");
        if (IPS_SemaphoreEnter("SemaSend", 5000)){
            // ...Kritischer Codeabschnitt
            $WSFrame = new WebSocketFrame($OPCode, $RawData);
            $WSFrame->Fin = $Fin;
            $Frame = $WSFrame->ToFrame();
            $this->SendDebug('Send', $WSFrame, 0);
            $SendData = $this->MakeJSON($Client, $Frame);
            if ($SendData) {
               $this->SendDataToParent($SendData);
            }
            //Semaphore wieder freigeben!
            IPS_SemaphoreLeave("SemaSend");
        }
        else
        {
            // ...Keine ausführung Möglich. Ein anderes Skript nutzt den "KritischenPunkt" 
            // für länger als 5 Sekunde, sodass unsere Wartezeit überschritten wird.
            $this->ModErrorLog($log, "WebSocketServer", "send", 'Send Vorgang wurde länger als 5 Sekunden blockiert');
            $this->LogMessage("WebsocketServer: ReceiveHandshake: Send Vorgang wurde länger als 5 Sekunden blockiert.", KL_WARNING);
        }
    }


    ################## DATAPOINTS CHILDS





    private function SplitTLSFrames(string &$Payload)
    {
        $Frames = [];
        while (strlen($Payload) > 0) {
            $len = unpack('n', substr($Payload, 3, 2))[1] + 5;
            if (strlen($Payload) >= $len) {
                $this->SendDebug('Receive TLS Frame', substr($Payload, 0, $len), 0);
                $Frames[] = substr($Payload, 0, $len);
                $Payload = substr($Payload, $len);
            } else {
                break;
            }
        }
        return $Frames;
    }
    private function ProcessIncomingData(Websocket_Client &$Client, string $Payload)
    {
        $log = $this->ReadPropertyBoolean("ErrLog");
        $this->SendDebug('Receive ' . $Client->ClientIP . ':' . $Client->ClientPort, $Payload, 0);
        if ($Client->State == WebSocketState::init) { //new
            if ($this->UseTLS and ( (ord($Payload[0]) >= 0x14) && (ord($Payload[0]) <= 0x18) && (ord($Payload[1]) == 0x03))) { //valid header wenn TLS is active
                $Client->State = WebSocketState::TLSisReceived;
                $Client->UseTLS = true;
                $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = '';
                $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = '';
                // TLS Config
                $TLSconfig = \PTLS\TLSContext::getServerConfig([
                            'key_pair_files' => [
                                'cert' => [$this->CertData],
                                'key'  => [$this->KeyData, $this->KeyPassword]
                            ]
                ]);
                $this->SendDebug('NEW TLSContex', '', 0);
                //$this->lock($Client->ClientIP . $Client->ClientPort);
                $this->lock($Client->ClientIP . $Client->ClientPort);
                $TLS = \PTLS\TLSContext::createTLS($TLSconfig);
            }
            if ($this->UsePlain and ( preg_match("/^GET ?.* HTTP\/1.1\r\n/", $Payload, $match))) { //valid header wenn Plain is active
                $Client->State = WebSocketState::HandshakeReceived;
                $this->SendDebug('Receive'.'Handshake Received',$match, 0);
                $Client->UseTLS = false;
                $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = '';
            }
        } else {
            if ($Client->UseTLS) {
                $this->SendDebug('OLD TLSContex', '', 0);
                $this->lock($Client->ClientIP . $Client->ClientPort);
                $TLS = $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort};
            }
        }
        if ($Client->UseTLS) {
            $Payload = $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} .= $Payload;
            if ((ord($Payload[0]) >= 0x14) && (ord($Payload[0]) <= 0x18) && (ord($Payload[1]) == 0x03)) {
                $TLSFrames = $this->SplitTLSFrames($Payload);
                $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = $Payload;
                $Payload = '';
                foreach ($TLSFrames as $TLSFrame) {
                    $this->SendDebug('TLS Frame', $TLSFrame, 0);
                    if ($Client->State != WebSocketState::TLSisReceived) {
                        $TLS->encode($TLSFrame);
                        $Payload .= $TLS->input();
                        continue;
                    }
                    if ($Client->State == WebSocketState::TLSisReceived) {
                        try {
                            $TLS->encode($TLSFrame);
                        } catch (\PTLS\Exceptions\TLSAlertException $e) {
                            if (strlen($out = $e->decode())) {
                                $this->SendDebug('Send TLS Handshake error', $out, 0);
                                $this->ModErrorLog($log, "WebSocketServer", "ProcessIncomingData", "Send TLS Handshake error");
                                $SendData = $this->MakeJSON($Client, $out, false);
                                if ($SendData) {
                                    $this->SendDataToParent($SendData);
                                }
                            }
                            $this->SendDebug('Send TLS Handshake error', $e->getMessage(), 0);
                            $this->ModErrorLog($log, "WebSocketServer", "ProcessIncomingData", 'Send TLS Handshake error'.$e->getMessage());
                            trigger_error($e->getMessage(), E_USER_NOTICE);
                            $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
                            $this->unlock($Client->ClientIP . $Client->ClientPort);
                            $this->CloseConnection($Client);
                            return;
                        } catch (\PTLS\Exceptions\TLSException $e) {
                            $this->SendDebug('Send TLS Handshake error', $e->getMessage(), 0);
                            trigger_error($e->getMessage(), E_USER_NOTICE);
                            $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
                            $this->unlock($Client->ClientIP . $Client->ClientPort);
                            $this->CloseConnection($Client);
                            return;
                        }
                        try {
                            $out = $TLS->decode();
                        } catch (\PTLS\Exceptions\TLSException $e) {
                            trigger_error($e->getMessage(), E_USER_NOTICE);
                            $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
                            $this->unlock($Client->ClientIP . $Client->ClientPort);
                            $this->CloseConnection($Client);
                            return;
                        }
                        if (strlen($out)) {
                            $this->SendDebug('Send TLS Handshake', $out, 0);
                            $SendData = $this->MakeJSON($Client, $out, false);
                            if ($SendData) {
                                $this->SendDataToParent($SendData);
                            }
                        }
                        if ($TLS->isHandshaked()) {
                            $Client->State = WebSocketState::HandshakeReceived;
                            $this->SendDebug('TLS ProtocolVersion', $TLS->getDebug()->getProtocolVersion(), 0);
                            $UsingCipherSuite = explode("\n", $TLS->getDebug()->getUsingCipherSuite());
                            unset($UsingCipherSuite[0]);
                            foreach ($UsingCipherSuite as $Line) {
                                $this->SendDebug(trim(substr($Line, 0, 14)), trim(substr($Line, 15)), 0);
                            }
                        }
                    }
                }
                $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = $TLS;
                $this->unlock($Client->ClientIP . $Client->ClientPort);
            } else { // Anfang (inkl. Buffer) paßt nicht
                $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = '';
                $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
                $this->unlock($Client->ClientIP . $Client->ClientPort);
                $this->CloseConnection($Client);
                return; // nix sichern
            }
        }
        if (strlen($Payload) == 0) {
            return;
        }
        if ($Client->State == WebSocketState::HandshakeReceived) {
            $NewData = $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} . $Payload;
            $CheckData = $this->ReceiveHandshake($NewData);
            if ($CheckData === true) { // Daten komplett und heil.
                $this->SendHandshake(HTTP_ERROR_CODES::Web_Socket_Protocol_Handshake, $NewData, $Client); //Handshake senden
                $this->SendDebug('SUCCESSFULLY CONNECT', $Client, 0);
                // wird nicht benötigt, da keine Daten an  andere Module weitergegeben werden 5.1 2020
                //$this->SendDataToChilds('', $Client);
                $Client->State = WebSocketState::Connected; // jetzt verbunden
                $Client->Timestamp = time() + $this->ReadPropertyInteger('Interval');
                // ----------------------------------------------------------------------
                //  4.1.2020  added
                // Client ist nun verbunden - Es werden Initial die Werte geschrieben und der Update Timer gesetzt
                //$this->SendText("1234567890");
                    //nach Handshake Initial alle Daten von Server abrufen und an alle Clients senden
                    $this->SendDebug("Info", "sende Initial Variablen an alle Clients", 0);
                     
                    $this->sendIPSVars(true);
                    // und Sende Timer starten
                    $this->SendDebug("Info", "starte Update Timer", 0);
                    $this->SetTimerInterval("UpdateVars", $this->ReadPropertyInteger("UpdateInterval"));
                //------------------------------------------------------------------

            } elseif ($CheckData === false) { // Daten nicht komplett, buffern.
                $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = $CheckData;
            } else { // Daten komplett, aber defekt.
                $this->SendHandshake($CheckData, $NewData, $Client);
                $this->CloseConnection($Client);
            }
        } elseif ($Client->State == WebSocketState::Connected) { // bekannt und verbunden
            $NewData = $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} . $Payload;
            $this->SendDebug('ReceivePacket ' . $Client->ClientIP . $Client->ClientPort, $NewData, 1);
            while (true) {
                if (strlen($NewData) < 2) {
                    break;
                }
                $Frame = new WebSocketFrame($NewData);
                if ($NewData == $Frame->Tail) {
                    break;
                }
                $NewData = $Frame->Tail;
                $Frame->Tail = null;
                $this->DecodeFrame($Frame, $Client);
                $Client->Timestamp = time() + $this->ReadPropertyInteger('Interval');
            }
            $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = $NewData;
            
        } elseif ($Client->State == WebSocketState::CloseSend) {
            $this->SendDebug('Receive', 'client answer server stream close !', 0);
            $this->{'WaitForClose' . $Client->ClientIP . $Client->ClientPort} = true;
        }
    }
    private function CloseConnection(Websocket_Client $Client)
    {
        $SendSocketClose = $this->MakeJSON($Client, '', false, SocketType::Disconnected);
        $this->SendDataToParent($SendSocketClose);
    }

    ################## DATAPOINTS PARENT
    /**
     * Sendet die Rohdaten an untergeordnetet Module
     * Wird nicht benötigt 5.1.2020
     * @access private
     * @param string $RawData Die Nutzdaten.
     * @param Websocket_Client $Client Der Client von welchem die Daten empfangen wurden.
     */


    /**
     * Interne Funktion des SDK. Nimmt Daten von Childs (HTML Client) entgegen und sendet Diese weiter.
     *
     * @access public
     * @param string $JSONString
     * @result bool true wenn Daten gesendet werden konnten, sonst false.
     */
 

    /**
     * Empfängt Daten vom Parent ServerSocket I/O auf port9000.
     *
     * @access public
     * @param string $JSONString Das empfangene JSON-kodierte Objekt vom Parent.
     */
    public function ReceiveData($JSONString)
    {
        $log = $this->ReadPropertyBoolean("ErrLog");
        $data = json_decode($JSONString);
        unset($data->DataID);
        //$this->SendDebug('incoming', $data, 0);
        $Payload = utf8_decode($data->Buffer);
        $Clients = $this->Multi_Clients;
        $IncomingClient = new Websocket_Client($data->ClientIP, $data->ClientPort, WebSocketState::init);
        $this->SendDebug("Eingehende Client Anfrage: ", $IncomingClient->ClientIP, 0);
        $this->LogMessage("WebsocketServer: Receive Clientanfrage: ".$IncomingClient->ClientIP, KL_MESSAGE);
        //prüfen of Client in Whitelist enthalten, sonst ignorieren
        $safeClient = $this->checkWhitelist($IncomingClient->ClientIP);
        if($safeClient){
            //prüfen ob Client schon in Clients - Liste
            $Client = $Clients->GetByIpPort($IncomingClient);
            $this->SendDebug(($Client ? 'OLD' : 'NEW') . ' CLIENT', SocketType::ToString($data->Type), 0);
            switch ($data->Type) {
                case 0: /* Data */
                    if ($Client === false) {
                        $this->SendDebug('no Connection for Data found', $IncomingClient->ClientIP . ':' . $IncomingClient->ClientPort, 0);
                        $this->ModErrorLog($log, "WebsocketServer", "Receive Data: ", "no Connection for Data found - Verbindung wird geschlossen.");
                        $this->LogMessage("WebsocketServer: Receive Data: no Connection for Data found - Verbindung wird geschlossen.", KL_MESSAGE);
                        $this->CloseConnection($IncomingClient);
                    } else {
                        $this->ProcessIncomingData($Client, $Payload);
                        $Clients->Update($Client);
                        
                    }
                    break;
                case 1: /* Connected */
                    if (!$this->NoNewClients) {
                        $this->SendDebug('new Connection', $IncomingClient->ClientIP . ':' . $IncomingClient->ClientPort, 0);
                        $this->LogMessage("WebsocketServer: Eingehende Verbindung.".$IncomingClient->ClientIP . ':' . $IncomingClient->ClientPort, KL_MESSAGE );
                        $this->ClearClientBuffer($IncomingClient);
                        $Clients->Update($IncomingClient);

                


    
                        //added 4.1.2020

                        //alle verbundenen Clients in Variable schreiben
                        $cl = $Clients->GetClients();
                        //$this->SendDebug("Verbundener Client", $IncomingClient->state, 0);
                        foreach ($cl as $key => $value) {
                            //$this->SendDebug("Verbundene Clients", $value->ClientIP, 0);
                            $liste[$key] =  $value->ClientIP.":". $value->ClientPort;
                        }
                        $this->writeClients($liste);
                    

                    }
                    break;
                case 2: /* Disconnected */
                    if ($Client === false) {
                        $this->ModErrorLog($log, "WebsocketServer", "Receive Data: ", "no Connection to disconnect found");
                        $this->LogMessage("WebsocketServer: Receive Data: no Connection to disconnect found.", KL_MESSAGE);
                        $this->SendDebug('no Connection to disconnect found', $IncomingClient->ClientIP . ':' . $IncomingClient->ClientPort, 0);
                    } else {
                        $this->ModErrorLog($log, "WebsocketServer", "Receive Data: ", "Client send closed");
                        $this->LogMessage("WebsocketServer: Receive Data: Client send closed.", KL_WARNING);
                        $this->ModErrorLog($log, "WebsocketServer", "Receive Data: ",  $Payload);
                        $this->LogMessage("WebsocketServer: Receive Data: ".$Payload, KL_WARNING);
                        $Clients->Remove($Client);
                        $this->ClearClientBuffer($Client);
                        $this->SendDebug('unWrite', $Client->ClientIP.":".$Client->ClientPort, 0);
                        $this->unWriteClient($Client->ClientIP.":".$Client->ClientPort);
        
                    }
                    break;
            }
            $this->Multi_Clients = $Clients;
            $this->SetNextTimer();
        }
        else{
            $this->LogMessage("WebsocketServer: Whiliste Check-nicht zugelassene IP:".$IncomingClient->ClientIP, KL_ERROR);
            $this->SendDebug('WebsocketServer: Whiliste Check-nicht zugelassene IP:', $IncomingClient->ClientIP, 0);
        }
    }







    ################## PUBLIC
    //-----------------------------------------------------------------------------
    /* Function: CommandToServer
    ...............................................................................
    Beschreibung: Daten vom Client werden in Befehle umgesetzt und ausgeführt.
       
        command()       => führt das script CommandFromClient aus. (verlinkt im Formular)
        func();         => führt eine Funktion eines Moduls aus     
                        => call_user_func_array($MyFunktion, $param);
    ...............................................................................
    Parameters: 
            command((IPS Befehl, ID, parameter (array))
        func(STV_setChannelbyName, 44308, param as array)
        
    ...............................................................................
    Returns:    
        none
    ------------------------------------------------------------------------------  */
    public function CommandToServer(string $Data){
        $this->SendDebug('Received following Data from Client', $Data, 0); 
 

            $command = $Data; 
            $JSONcmd = JSON_decode($command, true);//Umwandeln in Array
            $this->SendDebug('CommandToServer_JsonData', $JSONcmd, 0);


            /* --------- prüfen ob das noch verwendet wird - ersetzt durch func --------- */
            if(substr($command, 0, 7) == 'command'){
            $command = substr($command, 8, strlen($command)-9);
            SetValueString($this->GetIDForIdent("CommandSendToServer"), $command);
            
                IPS_RunScript($this->ReadPropertyInteger('IDcommand'));
                $this->SendDebug('extrahierte Werte sind = ', $command, 0);
            }
            else{
                if(isset($JSONcmd[0])){
                    if(substr($JSONcmd[0], 0, 4) == 'func'){
                        SetValueString(26720, $command);
                        //IPS_RunScript(22954);

                        $DataSet = json_decode($command);
        
                        foreach($DataSet as $key => $command){
                            $command = explode(",", substr($command, 5, strlen($command)-6));
                            //print_r($command);
                            foreach ($command as $key => $value) {
                                if($key == 0){
                                    $MyFunktion = $value; 
                                }
                                else{
                                    //Wert wird negiert
                                    if(substr($value,0,6) == "toggle"){
                                        $toggleId = substr($value,6,5) ;
                                        $value = !getvalue($toggleId);
                                    }
                                    $param[$key-1] = $value;
                                }
                            }
                            //param[2] = '"'.param[2].'"';
                            if($MyFunktion != ""){
                                call_user_func_array($MyFunktion, $param);
                            }   
                        }





                    }
                }
            }



        
    }
    
    /**
     * Wird vom Timer aufgerufen.
     * Sendet einen Ping an den Client welcher als nächstes das Timeout erreicht.
     *
     * @access public
     */
    public function KeepAlive()
    {
        $this->SendDebug('KeepAlive', 'start', 0);
        $this->SetTimerInterval('KeepAlivePing', 0);
        $Client = true;
        while ($Client) {
            $Clients = $this->Multi_Clients;
            $Client = $Clients->GetNextTimeout(1);
            if ($Client === false) {
                break;
            }
            if (@$this->SendPing($Client->ClientIP, $Client->ClientPort, '') === false) {
                $this->SendDebug('TIMEOUT ' . $Client->ClientIP . ':' . $Client->ClientPort, 'Ping timeout', 0);
                $this->SendDebug("sendPing Ergebnis: ", "entferne Client: ". $Client->ClientIP.":".$Client->ClientPort, 0);
                $this->RemoveOneClient($Client);
                $this->SendDebug("sendPing Ergebnis: ", "Schliesse Verbindung zu Client: ". $Client->ClientIP.":".$Client->ClientPort, 0);
                $this->CloseConnection($Client);
            }
        }
        $this->SendDebug('KeepAlive', 'end', 0);
    }

    /**
     * Versendet einen Ping an einen Client.
     *
     * @access public
     * @param string $ClientIP Die IP-Adresse des Client.
     * @param string $ClientPort Der Port des Client.
     * @param string $Text Der Payload des Ping.
     * @return bool True bei Erfolg, im Fehlerfall wird eine Warnung und false ausgegeben.
     */
    public function SendPing(string $ClientIP, string $ClientPort, string $Text)
    {
        $this->LogMessage("WebsocketServer: sende PING", KL_MESSAGE);
        $log = $this->ReadPropertyBoolean("ErrLog");
        $Client = $this->Multi_Clients->GetByIpPort(new Websocket_Client($ClientIP, $ClientPort));
        if ($Client === false) {
            $this->SendDebug('Unknow client', $ClientIP . ':' . $ClientPort, 0);
            trigger_error($this->Translate('Unknow client') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
            $this->ModErrorLog($log, "WebSocketServer", "SendPing", "Unknow client");
            $this->LogMessage("WebsocketServer: SendPing: Unknow client.", KL_WARNING);
            return false;
        }
        if ($Client->State != WebSocketState::Connected) {
            $this->SendDebug('Client not connected', $ClientIP . ':' . $ClientPort, 0);
            trigger_error($this->Translate('Client not connected') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
            $this->ModErrorLog($log, "WebSocketServer", "SendPing", "'Client not connected");
            $this->LogMessage("WebsocketServer: SendPing: Client not connected.", KL_WARNING);
            return false;
        }
        $this->SendDebug('Send Ping' . $Client->ClientIP . ':' . $Client->ClientPort, $Text, 0);
        $this->Send($Text, WebSocketOPCode::ping, $Client);
        $Result = $this->WaitForPong($Client);
        $this->{'Pong' . $Client->ClientIP . $Client->ClientPort} = '';
        if ($Result === false) {
            $this->SendDebug('Timeout ' . $Client->ClientIP . ':' . $Client->ClientPort, '', 0);
            $this->ModErrorLog($log, "WebsocketServer", "Receive of Pong from Client failed", $Result);
            $this->LogMessage("WebsocketServer: Receive of Pong from Client failed".$Result, KL_ERROR);
            trigger_error($this->Translate('Timeout'), E_USER_NOTICE);
            $this->RemoveOneClient($Client);
            $this->CloseConnection($Client);
            return false;
        }
        if ($Result !== $Text) {
            $this->SendDebug('Error in Pong ' . $Client->ClientIP . ':' . $Client->ClientPort, $Result, 0);
            $this->ModErrorLog($log, "WebsocketServer", "Wrong pong received from Client failed", $Result);
            $this->LogMessage("WebsocketServer: Wrong pong received from Client failed".$Result, KL_ERROR);
            trigger_error($this->Translate('Wrong pong received'), E_USER_NOTICE);
            $this->SendDisconnect($Client);
            return false;
        }
        return true;
 
    }
    
    
        public function SendTextToClient(string $ClientIP, string $ClientPort, string $Text)
    {
        $Client = $this->Multi_Clients->GetByIpPort(new Websocket_Client($ClientIP, $ClientPort));
        /*
        if ($Client === false) {
            $this->SendDebug('Unknow client', $ClientIP . ':' . $ClientPort, 0);
            //Fehler Ausgabe
                $text = "SendTextToClient: Unknow client. ";
                $array =  $ClientIP . ':' . $ClientPort;
                $this->ModErrorLog($log, "MyWebSocketSever", $text, $array);
            //Fehler Ausgabe Ende
            trigger_error($this->Translate('Unknow client') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
            return false;
        }
        */
        /*
        if ($Client->State != WebSocketState::Connected) {
            $this->SendDebug('Client not connected', $ClientIP . ':' . $ClientPort, 0);
            //Fehler Ausgabe
                $text = "SendTextToClient: Client not connected. ";
                $array =  $ClientIP . ':' . $ClientPort;
                $this->ModErrorLog($log, "MyWebSocketSever", $text, $array);
            //Fehler Ausgabe Ende
            trigger_error($this->Translate('Client not connected') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
            return false;
        }
        */
        $this->SendDebug('Send Text Message to Client' . $Client->ClientIP . ':' . $Client->ClientPort, $Text, 0);
        $this->Send($Text, WebSocketOPCode::text, $Client);

        return true;
    }
    
        public function SendText(string $Text)
    {
        $this->SendDebug('SendText Funktion wird ausgeführt' ,"uuuuuuu" , 0);
        //$Client = $this->Multi_Clients->GetByIpPort(new Websocket_Client($ClientIP, $ClientPort));
        //$ClientList = $this->Multi_Clients->GetClients();
        $log = $this->ReadPropertyBoolean("ErrLog");
        $Clients = $this->Multi_Clients;
        $liste = array(); 
        //alle verbundenen Clients in Variable schreiben
        $cl = $Clients->GetClients();
        //$this->SendDebug("Verbundener Client", $IncomingClient->state, 0);
        foreach ($cl as $key => $value) {
             //$this->SendDebug("Verbundene Clients", $value->ClientIP, 0);
            $liste[$key] =  $value->ClientIP.":". $value->ClientPort;
        }

        //$Clients = $this->Multi_Clients->GetClients();
       
        if (count($liste) > 0){
           $this->SendDebug('Client Liste =' , $liste, 0);

            foreach ($cl as $Client) {

                /*
                 $ClientIP = $Client->ClientIP ;
                $ClientPort = $Client->ClientPort;

                if ($Client === false) {
                    //Fehler Ausgabe
                        $text = "SendText: Client not known. ";
                        $array =  $Client->ClientIP;
                        $this->ModErrorLog($log, "MyWebSocketSever", $text, $array);
                    //Fehler Ausgabe Ende
                     $this->SendDebug('Unknow Multi-client', $ClientIP . ':' . $ClientPort, 0);
                    trigger_error($this->Translate('Unknow client') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
                    //return false;
                }
                else if ($Client->State != WebSocketState::Connected) {
                    //Fehler Ausgabe
                        $text = "SendText: Client known, but not connected. ";
                        $array =  $Client->ClientIP;
                        $this->ModErrorLog($log, "MyWebSocketSever", $text, $array);
                    //Fehler Ausgabe Ende
                    $this->SendDebug('Multi-Client not connected', $ClientIP . ':' . $ClientPort, 0);
                    trigger_error($this->Translate('Client not connected') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
                    // Client ist nicht richtig verbunden IP OK aber Port hat sich geändert.
                    //TB 21.10.2019 ergänzt entferne Client wenn nicht verbunden
                    $this->SendDebug('Entferne Client da nicht verbunden: ', $ClientIP . ':' . $ClientPort, 0);
                   
                     
                    //$this->Multi_Clients->Remove($Client);
                    $x = $this->Multi_Clients->GetClients();

                    $this->SendDebug('bereinigte Client Liste: ',  $x, 0);
                    //$this->RestartServer();
                    //return false;
                }
                else if ($Client->State == WebSocketState::Connected) {
                    $this->SendDebug('Send Text Message to Multi-Client' . $Client->ClientIP . ':' . $Client->ClientPort, $Text, 0);
                    $this->SendDebug('Textlänge Message: ' , strlen($Text), 0);
                    $this->Send($Text, WebSocketOPCode::text, $Client);
                }
                */
             
                $this->SendDebug('Send Text Message to Multi-Client' . $Client->ClientIP . ':' . $Client->ClientPort, $Text, 0);
                $this->SendDebug('Textlänge Message: ' , strlen($Text), 0);
                $this->SendDebug('Status des Multi-Client' ,  WebSocketState::Connected , 0);
                if(WebSocketState::Connected == 3){
                    $this->Send($Text, WebSocketOPCode::text, $Client);
                }
            }
            return true;
        }
        else{
           
            //kein Client verbunden
            $this->SendDebug('Kein Client verbunden: ' , "nicht verbunden", 0);
            $this->ModErrorLog($log, "WebSocketServer", "SendText: ", 'kein Client verbunden.');
            $this->LogMessage("WebsocketServer: kein Client verbunden", KL_ERROR);
            return false;
        }
    } 

    
 
    /* --------------------------------------------------------------------------- 
    Function: RegisterEvent
    ...............................................................................
    legt einen Event an wenn nicht schon vorhanden
      Beispiel:
      ("Wochenplan", "SwitchTimeEvent".$this->InstanceID, 2, $this->InstanceID, 20);  
      ...............................................................................
    Parameters: 
      $Name        -   Name des Events
      $Ident       -   Ident Name des Events
      $Typ         -   Typ des Events (1=cyclic 2=Wochenplan)
      $Parent      -   ID des Parents
      $Position    -   Position der Instanz
    ...............................................................................
    Returns:    
        none 
    -------------------------------------------------------------------------------*/
    private function RegisterVarEvent($Name, $Ident, $Typ, $ParentID, $Position, $trigger, $var)
    {
            $EventID =  @IPS_GetEventIDByName($Name, $ParentID);
            if($EventID === false) {
                //we need to create one
                $EventID = IPS_CreateEvent($Typ);
                IPS_SetParent($EventID, $ParentID);
                @IPS_SetIdent($EventID, $Ident);
                IPS_SetName($EventID, $Name);
                IPS_SetPosition($EventID, $Position);
                IPS_SetEventTrigger($EventID, $trigger, $var);   //OnChange für Variable $var
                $cmd = "MyWSS_getIPSVars(".$this->InstanceID.");";
                IPS_SetEventScript($EventID, $cmd );
                IPS_SetEventActive($EventID, true);
            } 
            else{
            }
            return $EventID;
    }    
    
    /* ----------------------------------------------------------------------------------------------------- 
    Function: RegisterCategory
    ...............................................................................
     *  Legt ein Unterverzeichnis an
     * Beispiel:
     *  
    ...............................................................................
    Parameters: 
 
    .......................................................................................................
    Returns:    
        none
    -------------------------------------------------------------------------------------------------------- */
    private function RegisterCategory($catName ) {
        $KategorieID = @IPS_GetCategoryIDByName($catName, $this->InstanceID);
        if ($KategorieID === false){
            // Anlegen einer neuen Kategorie mit dem Namen $catName
            $CatID = IPS_CreateCategory();       // Kategorie anlegen
            IPS_SetName($CatID, $catName); // Kategorie benennen
            IPS_SetParent($CatID, $this->InstanceID); // Kategorie einsortieren unterhalb der der Instanz
        }
        return $KategorieID;
    }
    
    
        /* ----------------------------------------------------------------------------
         Function: getIPSVars
        ...............................................................................
         * holt die Variablen aus der Event Liste und packt sie in ein Array
         * und sendet sie an den client
        ...............................................................................
        Parameters: 
            none.
        ..............................................................................
        Returns:   
             none
        ------------------------------------------------------------------------------- */
	public function getIPSVars(){
            
            $IPSVariables = json_decode($this->ReadPropertyString("IPSVars"));
            //$this->SendDebug('Event Variable', $IPSVariables, 0);
            foreach($IPSVariables as $IPSVariable) {
                $varid = $IPSVariable->ID;
                $data['ID'.$varid] = getvalue($varid);
            }
            

            
			$a = getvalue(11938);
			$b = date('m/d/Y H:i:s', $a);
			$h = substr($b,11,2);
			$m = substr($b,14,2);
			$data['ID11938'] = $h.':'.$m;
			
			$a = getvalue(57942);
			$b = date('m/d/Y H:i:s', $a);
			$h = substr($b,11,2);
			$m = substr($b,14,2);
			$data['ID57942'] = $h.':'.$m;	
 
            $reply = 	array();
           // $this->SendDebug('updateIPSvalues', $data, 0);
            $c =array($data, $reply);
            
            $xml = json_encode($c);
            $this->SendText($xml);
            //zum sichtbar machen
            setvalue($this->GetIDForIdent("DataSendToClient"), $xml);
        } 

        /* ----------------------------------------------------------------------------
         Function: sendIPSVarsToClients2
        ...............................................................................
         * holt die Variablen aus der Event Liste und packt sie in ein Array
         * und sendet sie an den client
         * Diese Funktion wird zyklisch alle x sekunden ausgeführt
        ...............................................................................
        Parameters: 
            init
        ..............................................................................
        Returns:   
             none
        ------------------------------------------------------------------------------- */
	    public function sendIPSVars($init){
            /* --------- nur Daten senden wenn mindestens 1 Client verbunden ist -------- */
            $Clients = $this->Multi_Clients;
            $cl = $Clients->CountClients();
            //$this->SendDebug('sendIPSVarsNew: ', 'es sind '.$cl.' Clients verbunden', 0);
            //$this->SendDebug('sendIPSVars: ', 'sende Daten"', 0);
            if ($cl>0){
                //$this->SendDebug('sendIPSVarsNew: ',  'Variable auf doppelte untersuchen.', 0);
                
                /* ---------------- Daten aller Variable aus den Puffer lesen --------------- */
                $IPSdataArr = json_decode($this->GetBuffer('IPSdata'), true);
                //$this->SendDebug('sendIPSVarsNew: Anzahl-IPSdata: ',  count($IPSdataArr), 0);

                /* ----------------- Alle WSSVariable aus dem Puffer IPSdata ---------------- */
                foreach($IPSdataArr as $key =>  $IPSVariable) {
                    $varid = $IPSVariable['ID'];
                    //$this->SendDebug('sendIPSVarsNew: IPSVariable: ', $key.' : '. $varid, 0);
                    try {
                        if(!IPS_VariableExists($varid)){
                            throw new Exception('Variable mit ID '.$varid.'ist nicht vorhanden.');  
                        }
                    }
                    catch (Exception $e) {
                        //$varid = $this->GetIDForIdent("dummyID");
                        $this->SendDebug('sendIPSVarsNew:', 'Caught exception: '.$e->getMessage(), 0);
                        $this->SetValue("Message", "Variable fehlt:".$varid);
                    }
                    finally{
                        $IPSdata[$key]['ID'] = $varid;
                        $wert = getvalue($varid);
                        //prüfen ov $wert ein String oder ein Array ist
 
                            if(substr($wert,0,1) == "["){
                                //ein Array
                                
                                $this->SendDebug('sendIPSVarsTest: ', json_decode($wert), 0);
                                
                            }

                 

                        //$this->SendDebug('sendIPSVarsNew: wert: ', $varid.' : '.$wert, 0);

                        /* - Beim Ersten Senden alle Variable als changed markieren und alle senden - */
                        /* -------- danach prüfen ob sich der Wert der Variable verändert hat ------- */
                        /* ------------------------ und als changed markieren ----------------------- */
                         
                        if($init){
                            $IPSdata[$key]['changed'] = 'y';
                            $data['ID'.$varid]['value'] = $wert;
                            $data['ID'.$varid]['changed'] = 'y';
                            $IPSdata[$key]['hash'] = md5($wert);
                        } 
                        else{
                            if($IPSVariable['hash'] == md5($wert)) {
                                $IPSdata[$key]['changed'] = 'n';
                            }
                            else {
                                $IPSdata[$key]['changed'] = 'y';
                                if($varid == "11938" or $varid == "57942"){
                                    $b = date('m/d/Y H:i:s', $wert);
                                    $h = substr($b,11,2);
                                    $m = substr($b,14,2);
                                    $wert = $h.':'.$m;
                                }
                                $data['ID'.$varid]['value'] = $wert;
                                $data['ID'.$varid]['changed'] = 'y';
                            }
                            $IPSdata[$key]['hash'] = md5($wert);
                        }

                    }
                }
                //$this->SendDebug('sendIPSVarsNew: ',  'speichere Daten.', 0);
                /* ------------ schreibt aktuelle Werte zurück in history Buffer ------------ */
                $this->SetBuffer('IPSdata', json_encode($IPSdata));
                
                /* ------ Daten die sich verändert haben ausfiltern (['changed'] == 'y' ----- */
                $new = array_filter($IPSdata, function ($var) {
                    return ($var['changed'] == 'y');
                });
                //$this->SendDebug('sendIPSVarsNew: ', 'Anzahl gefilterte Vars: '.count($new), 0);
                //$this->SendDebug('changed Variables:', $new, 0);

                /* --------------------- 2 Standard Variablen hinzufügen -------------------- */
                /*
                    $a = getvalue(11938);
                    $b = date('m/d/Y H:i:s', $a);
                    $h = substr($b,11,2);
                    $m = substr($b,14,2);
                    $data['ID11938']['value'] = $h.':'.$m;
                    $data['ID11938']['changed'] = true; 
                    //Sonnenuntergang
                    $a = getvalue(57942);
                    $b = date('m/d/Y H:i:s', $a);
                    $h = substr($b,11,2);
                    $m = substr($b,14,2);
                    $data['ID57942']['value'] = $h.':'.$m;	
                    $data['ID57942']['changed'] = true;
                */

                $this->SendDebug("DataTest:", $data, 0);
                if(!empty($data)){
                    if(count($data)>5){
                        /* ----------- geänderte Daten in Pakete zu 20 Variablen aufteilen ---------- */
                        $pakete = array_chunk($data, 5, true);
                        $this->SendDebug("MultiTest:", $pakete, 0);
                        /* --------------------------- alle Pakete senden --------------------------- */
                    } 
                    elseif(count($data)<6){
                        $pakete = $data;
                        $this->SendDebug("singleTest:", $pakete, 0);
                    }
                    foreach ($pakete as $daten) {
                        $this->SendDebug("filterTest:", $daten, 0);
                         
                        $paket['PaketNr'] = $key;
                            $c = array($daten, $paket);
                            try {
                                $json1 = json_encode($c);
                                //$this->SendDebug("JSON1 - Paket 1 Error", json_last_error(), 0);
                            } catch (JsonException $err) { }
                            if (json_last_error() !== JSON_ERROR_NONE) {
                                switch(json_last_error()) {
                                    case JSON_ERROR_NONE:
                                        $fehler = ' - Keine Fehler';
                                    break;
                                    case JSON_ERROR_DEPTH:
                                        $fehler = ' - Maximale Stacktiefe überschritten';
                                    break;
                                    case JSON_ERROR_STATE_MISMATCH:
                                        $fehler = ' - Unterlauf oder Nichtübereinstimmung der Modi';
                                    break;
                                    case JSON_ERROR_CTRL_CHAR:
                                        $fehler = ' - Unerwartetes Steuerzeichen gefunden';
                                    break;
                                    case JSON_ERROR_SYNTAX:
                                        $fehler = ' - Syntaxfehler, ungültiges JSON';
                                    break;
                                    case JSON_ERROR_UTF8:
                                        $fehler = ' - Missgestaltete UTF-8 Zeichen, möglicherweise fehlerhaft kodiert';
                                    break;
                                    default:
                                    $fehler = ' - Unbekannter Fehler';
                                    break;
                                }
                                //$this->ModErrorLog($log, "WebSocketServer", "sendIPSVars-Paket1 Fehler", $fehler);
                                $this->SendDebug("PAKETFehler:",$fehler, 0);
                            }
                            else{
                                //$this->SendDebug("PAKETJSON:","sende Paket ".$key, 0);
                                $this->setvalue("DataSendToClient", "Daten: " .count($data).' von '.count($IPSdata));
                                $this->SendText($json1);
                            }
                    }
                }



            //Cam Bilder übertragen aber nur Einzeln
            $CamVariablesjson = $this->getvalue("CamSendVars");
            $CamVariables = json_decode($CamVariablesjson);
            
            $c = 0;
            foreach($CamVariables as $CamVariable) {
                //prüfen ob Variable verfügbar sind
                $camid = $CamVariable->ID;
                try {
                    if(!IPS_VariableExists($camid)){
                        throw new Exception('Variable mit ID '.$camid.'ist nicht vorhanden.');  
                    }
                }
                catch (Exception $e) {
                    //$varid = $this->GetIDForIdent("dummyID");
                    $this->SendDebug('Caught exception: ',  $e->getMessage(), 0);
                    $this->SetValue("Message", "CamVariable fehlt:".$camid);
                    $this->ModErrorLog($log, "WebSocketServer", "sendIPSVars", "CamVariable ".$camid." fehlt.");
                }
                finally{
                    $c = $c + 1;
                       $camdata['ID'.$camid] = getvalue($camid);
                }

                //Prüfen ob CamBild sich verändert hat.
                $CamdataNewHash = md5(serialize($camdata));
                $CamdataOldHash = $this->GetBuffer("CamBuffer");
                $this->SendDebug("CamData- Hash Codes Neu - Alt: ", $CamdataNewHash." - ".$CamdataOldHash, 0);
                if($CamdataNewHash !== $CamdataOldHash){
                    $paket['PaketNr'] = 3;
                    $c3 = array($camdata, $paket);
                    try {
                        $json3 = json_encode($c3);
                        $this->SendDebug("JSON3 - Paket 3 Error", json_last_error(), 0);
                    } catch (JsonException $err) { }
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        switch(json_last_error()) {
                            case JSON_ERROR_NONE:
                                $fehler = ' - Keine Fehler';
                            break;
                            case JSON_ERROR_DEPTH:
                                $fehler = ' - Maximale Stacktiefe überschritten';
                            break;
                            case JSON_ERROR_STATE_MISMATCH:
                                $fehler = ' - Unterlauf oder Nichtübereinstimmung der Modi';
                            break;
                            case JSON_ERROR_CTRL_CHAR:
                                $fehler = ' - Unerwartetes Steuerzeichen gefunden';
                            break;
                            case JSON_ERROR_SYNTAX:
                                $fehler = ' - Syntaxfehler, ungültiges JSON';
                            break;
                            case JSON_ERROR_UTF8:
                                $fehler = ' - Missgestaltete UTF-8 Zeichen, möglicherweise fehlerhaft kodiert';
                            break;
                            default:
                            $fehler = ' - Unbekannter Fehler';
                            break;
                        }
                        $this->ModErrorLog($log, "WebSocketServer", "sendIPSVars-Paket1 Fehler", $fehler);
                        $this->SendDebug("PAKET2Fehler:",$fehler, 0);
                    }
                    else{
                        $dataNewHash = md5($json3);
                       // $this->SendDebug("PAKETJSON3:","sende Paket 3", 0);
                        //$this->setvalue("DataSendToClient", "Paket 3");
                        $this->SendText($json3);
                    }
                    $this->SetBuffer("CamBuffer", $dataNewHash);
                }
                else{
                    $this->SendDebug("PAKETJSON3:", "Daten haben sich nicht geändert keine Übertragung.", 0);
                }                

            }

            }

        }
    
      
        
        
    /* ----------------------------------------------------------------------------
     Function: RegisterIPSMessages
    ...............................................................................
     Alle IP Symcon Variable mit der Beschreibung WSS oder WSS1 werden ausgelesen 
     und in ein file "/media/newfile.txt" und in die Variablen Liste "IpsSenVars" 
     geschrieben. Alle Variable in dieser Liste werden von WSS übertragen.
     Aktualisierung dieser Liste nur Manuell über die Konfiguration. 
    ...............................................................................
     Parameters: 
        none.
    ..............................................................................
     Returns:   
        none
    ------------------------------------------------------------------------------- */
	public function RegisterIPSMessages(){
        
        /* ------- Diese Funktion wird initial beim Erstellen des Moduls oder ------- */
        /* -------------- bei Änderungen der Modul Parameter aufgerufen -------------- */

        /* ----------- Dieser Abschnitt wird eigentlich nicht mehr genutzt ---------- */
        /* -------- es wird nur noch verwendet für das unregister der Events -------- */
        //Alle alten Events löschen und neu anlegen
        //IPS_DeleteEvent($EreignisID);

        /* ---------------- WSS1 Message Events löschen --------------- */
        $IPSdataFastArr = [];
        $IPSdataFastArr = json_decode($this->GetBuffer('IPSdataFast'), true);
        if(!empty($IPSdataFastArr)){
            /* ----------------- Alle WSSVariable aus dem Puffer IPSdataFast ---------------- */
            foreach($IPSdataFastArr as $key =>  $IPSVariableFast) {
                $varid = $IPSVariableFast['ID'];
                $this->UnregisterMessage(intval($varid), VM_UPDATE);
            }
        }
            
        /* ---------------- Alle VariablenIDs aus Symcon DB auslesen ---------------- */
        $alleVariablen = IPS_GetVariableList();
        $i = 0; 
        $c = 0;
 
        /* -- Alle Variablen die in Info Feld einen Eintrag "WSS" oder "WSS1" haben - */
        /* --------------------- in ein Array IpsVars schreiben --------------------- */
        $IpsVarsFast = [];
        /* ------------------------- $var = IPS Variable ID ------------------------- */
        foreach($alleVariablen as $key => $var){
            $IPSVariable = IPS_GetObject($var);
            $Info = $IPSVariable['ObjectInfo'];
           
            if ($Info === "WSS" or $Info === "WSS1"){
                $IpsVars[$i]['ID'] = $var;
                $IpsVars[$i]['hash'] = '';
                $IpsVars[$i]['changed'] = 'n';

                $i++;
                /* -------- Ist die Variable mit WSS1 markiert = schnelle Ausführung -------- */
                /* -------------- für diese Variable ein Änderungsevent anlegen ------------- */
                if($Info === "WSS1"){
                    $this->RegisterMessage($var, VM_UPDATE);  
                    $IpsVarsFast[$i]['ID'] = $var;
                }
            }
            if ($Info === "WSSCAM"){
                $CamVars[$c]['ID'] = $var;
            }
        }
        $VarAr['ID'.$var] ='';
            
            
        /* -------------- Alle IPS Daten "WSS" und "WSS1" in den Puffer schreiben -------------- */
        $this->SetBuffer('IPSdata', json_encode($IpsVars));

        /* -------------- Alle IPS Daten "WSS1" in den Puffer schreiben -------------- */
        $this->SetBuffer('IPSdataFast', json_encode($IpsVarsFast));

        $this->SetValue('CamSendVars', json_encode($CamVars));
    }
        
        
	//*****************************************************************************
	/* Function: Kernel()
        ...............................................................................
        Stammverzeichnis von IP Symcon
        ...............................................................................
        Parameter:  

        --------------------------------------------------------------------------------
        return:  

        --------------------------------------------------------------------------------
        Status  checked 11.6.2018
        //////////////////////////////////////////////////////////////////////////////*/
        Protected function Kernel(){ 
            $Kernel = str_replace("\\", "/", IPS_GetKernelDir());
            return $Kernel;
        }
        
	//*****************************************************************************
	/* Function: writeClients()
        ...............................................................................
         schreibt Clients in 4 Variable
        ...............................................................................
        Parameter:  

        --------------------------------------------------------------------------------
        return:  

        --------------------------------------------------------------------------------
        Status  checked 11.6.2018
        //////////////////////////////////////////////////////////////////////////////*/
        Protected function writeClients($list){ 
            //CLients in 4 Variable schreiben
             
            $n = 0;
            setValue($this->GetIDForIdent("Client1"),'');   
            setValue($this->GetIDForIdent("Client2"),'');    
            setValue($this->GetIDForIdent("Client3"),'');    
            setValue($this->GetIDForIdent("Client4"),'');   
            foreach ($list as $key => $value) {
                
                if($n == 0){
                    $this->setValue("Client1", $value);
                }
                elseif($n == 1){
                    $this->setValue("Client2", $value);
                }
                elseif($n == 2){
                    $this->setValue("Client3", $value);
                }
                elseif($n == 3){
                    $this->setValue("Client4", $value);
                }  
                $n = $n + 1;
            }
                      
          
        }
        Protected function unWriteClient($clientIP_Port){ 
            //CLients in 4 Variable schreiben
            
            $this->SendDebug("unWrite del", $clientIP_Port, 0);
            if($this->getvalue("Client1") == $clientIP_Port){
                $this->setValue("Client1",'');
            }
            if($this->getvalue("Client2") == $clientIP_Port){
                $this->setValue("Client2",''); 
            }
            if($this->getvalue("Client3") == $clientIP_Port){
                $this->setValue("Client3",'');
            }
            if($this->getvalue("Client4") == $clientIP_Port){
                $this->setValue("Client4",''); 
            }     
            $this->setvalue("DataSendToClient", "stopped");
        }





        Protected function checkWhitelist($ClIP){
            $WhiteListData = json_decode($this->ReadPropertyString("WhiteList"));
            $this->SendDebug('checkWhitelist: ' , $ClIP, 0);
            $this->SendDebug('checkWhitelist: ' , $WhiteListData, 0);
            foreach($WhiteListData as $WhiteListDataRow) {
                
                    $this->SendDebug('Vergleiche Whitelist: ' , $ClIP . ':' . $WhiteListDataRow->WhiteListIP, 0);
                    if ($ClIP == $WhiteListDataRow->WhiteListIP){
                        return true;
                    }
     					
            };
            return false;
        }
}


