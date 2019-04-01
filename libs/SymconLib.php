<?php
$_IPS = array (
  'SELF' => 0,
  'SENDER' => '',
  'VALUE' => 0,
  'OLDVALUE' => 0,
  'VARIABLE' => 0,
  'EVENT' => 0,
  'TRIGGER' => 0,
  'TARGET' => 0,
  'ACTION' => 0,
  'INSTANCE' => 0,
  'THREAD' => 0,
  'FORM' => 0,
  'COMPONENT' => '',
  'DIRECTION' => 0,
  'DURATION' => 0,
  'INSTANCE2' => 0,
  'STATUS' => 0,
  'STATUSTEXT' => '',
  'CONNECTION' => 0,
  'DATA' => '',
  'CONFIGURATOR' => '',
  'INSTANCES' => 
  array (
  ),
  'INVERTS' => 
  array (
  ),
  'CLIENTIP' => '',
  'CLIENTPORT' => 0,
);
define('MODULETYPE_CORE', 0);
define('MODULETYPE_IO', 1);
define('MODULETYPE_SPLITTER', 2);
define('MODULETYPE_DEVICE', 3);
define('MODULETYPE_CONFIGURATOR', 4);
define('MODULETYPE_DISCOVERY', 5);
define('OBJECTTYPE_CATEGORY', 0);
define('OBJECTTYPE_INSTANCE', 1);
define('OBJECTTYPE_VARIABLE', 2);
define('OBJECTTYPE_SCRIPT', 3);
define('OBJECTTYPE_EVENT', 4);
define('OBJECTTYPE_MEDIA', 5);
define('OBJECTTYPE_LINK', 6);
define('VARIABLETYPE_BOOLEAN', 0);
define('VARIABLETYPE_INTEGER', 1);
define('VARIABLETYPE_FLOAT', 2);
define('VARIABLETYPE_STRING', 3);
define('SCRIPTTYPE_PHP', 0);
define('EVENTTYPE_TRIGGER', 0);
define('EVENTTYPE_CYCLIC', 1);
define('EVENTTYPE_SCHEDULE', 2);
define('EVENTTRIGGERTYPE_ONUPDATE', 0);
define('EVENTTRIGGERTYPE_ONCHANGE', 1);
define('EVENTTRIGGERTYPE_ONLIMITEXCEED', 2);
define('EVENTTRIGGERTYPE_ONLIMITDROP', 3);
define('EVENTTRIGGERTYPE_ONVALUE', 4);
define('EVENTCYCLICDATETYPE_NONE', 0);
define('EVENTCYCLICDATETYPE_ONCE', 1);
define('EVENTCYCLICDATETYPE_DAY', 2);
define('EVENTCYCLICDATETYPE_WEEK', 3);
define('EVENTCYCLICDATETYPE_MONTH', 4);
define('EVENTCYCLICDATETYPE_YEAR', 5);
define('EVENTCYCLICTIMETYPE_ONCE', 0);
define('EVENTCYCLICTIMETYPE_SECOND', 1);
define('EVENTCYCLICTIMETYPE_MINUTE', 2);
define('EVENTCYCLICTIMETYPE_HOUR', 3);
define('EVENTCONDITIONCOMPARISON_EQUAL', 0);
define('EVENTCONDITIONCOMPARISON_NOTEQUAL', 1);
define('EVENTCONDITIONCOMPARISON_GREATER', 2);
define('EVENTCONDITIONCOMPARISON_GREATEROREQUAL', 3);
define('EVENTCONDITIONCOMPARISON_SMALLER', 4);
define('EVENTCONDITIONCOMPARISON_SMALLEROREQUAL', 5);
define('MEDIATYPE_DASHBOARD', 0);
define('MEDIATYPE_IMAGE', 1);
define('MEDIATYPE_SOUND', 2);
define('MEDIATYPE_STREAM', 3);
define('MEDIATYPE_CHART', 4);
define('MEDIATYPE_DOCUMENT', 5);
define('IPS_BASE', 10000);
define('IPS_MODULEBASE', 20000);
define('IPS_KERNELSTARTED', 10001);
define('IPS_KERNELSHUTDOWN', 10002);
define('IPS_KERNELMESSAGE', 10100);
define('KR_CREATE', 10101);
define('KR_INIT', 10102);
define('KR_READY', 10103);
define('KR_UNINIT', 10104);
define('KR_SHUTDOWN', 10105);
define('IPS_LOGMESSAGE', 10200);
define('KL_MESSAGE', 10201);
define('KL_SUCCESS', 10202);
define('KL_NOTIFY', 10203);
define('KL_WARNING', 10204);
define('KL_ERROR', 10205);
define('KL_DEBUG', 10206);
define('KL_CUSTOM', 10207);
define('IPS_MODULEMESSAGE', 10300);
define('ML_LOAD', 10301);
define('ML_UNLOAD', 10302);
define('IPS_OBJECTMESSAGE', 10400);
define('OM_REGISTER', 10401);
define('OM_UNREGISTER', 10402);
define('OM_CHANGEPARENT', 10403);
define('OM_CHANGENAME', 10404);
define('OM_CHANGEINFO', 10405);
define('OM_CHANGETYPE', 10406);
define('OM_CHANGESUMMARY', 10407);
define('OM_CHANGEPOSITION', 10408);
define('OM_CHANGEREADONLY', 10409);
define('OM_CHANGEHIDDEN', 10410);
define('OM_CHANGEICON', 10411);
define('OM_CHILDADDED', 10412);
define('OM_CHILDREMOVED', 10413);
define('OM_CHANGEIDENT', 10414);
define('OM_CHANGEDISABLED', 10415);
define('IPS_INSTANCEMESSAGE', 10500);
define('IM_CREATE', 10501);
define('IM_DELETE', 10502);
define('IM_CONNECT', 10503);
define('IM_DISCONNECT', 10504);
define('IM_CHANGESTATUS', 10505);
define('IM_CHANGESETTINGS', 10506);
define('IM_CHANGEATTRIBUTE', 10507);
define('IM_SEARCHMESSAGE', 10510);
define('IM_SEARCHSTART', 10511);
define('IM_SEARCHSTOP', 10512);
define('IM_SEARCHUPDATE', 10513);
define('IPS_VARIABLEMESSAGE', 10600);
define('VM_CREATE', 10601);
define('VM_DELETE', 10602);
define('VM_UPDATE', 10603);
define('VM_CHANGEPROFILENAME', 10604);
define('VM_CHANGEPROFILEACTION', 10605);
define('IPS_SCRIPTMESSAGE', 10700);
define('SM_CREATE', 10701);
define('SM_DELETE', 10702);
define('SM_CHANGEFILE', 10703);
define('SM_BROKEN', 10704);
define('SM_UPDATE', 10705);
define('IPS_EVENTMESSAGE', 10800);
define('EM_CREATE', 10801);
define('EM_DELETE', 10802);
define('EM_UPDATE', 10803);
define('EM_CHANGEACTIVE', 10804);
define('EM_CHANGELIMIT', 10805);
define('EM_CHANGESCRIPT', 10806);
define('EM_CHANGETRIGGER', 10807);
define('EM_CHANGETRIGGERVALUE', 10808);
define('EM_CHANGETRIGGEREXECUTION', 10809);
define('EM_CHANGECYCLIC', 10810);
define('EM_CHANGECYCLICDATEFROM', 10811);
define('EM_CHANGECYCLICDATETO', 10812);
define('EM_CHANGECYCLICTIMEFROM', 10813);
define('EM_CHANGECYCLICTIMETO', 10814);
define('EM_ADDSCHEDULEACTION', 10815);
define('EM_REMOVESCHEDULEACTION', 10816);
define('EM_CHANGESCHEDULEACTION', 10817);
define('EM_ADDSCHEDULEGROUP', 10818);
define('EM_REMOVESCHEDULEGROUP', 10819);
define('EM_CHANGESCHEDULEGROUP', 10820);
define('EM_ADDSCHEDULEGROUPPOINT', 10821);
define('EM_REMOVESCHEDULEGROUPPOINT', 10822);
define('EM_CHANGESCHEDULEGROUPPOINT', 10823);
define('EM_ADDCONDITION', 10824);
define('EM_REMOVECONDITION', 10825);
define('EM_CHANGECONDITION', 10826);
define('EM_ADDCONDITIONVARIABLERULE', 10827);
define('EM_REMOVECONDITIONVARIABLERULE', 10828);
define('EM_CHANGECONDITIONVARIABLERULE', 10829);
define('EM_ADDCONDITIONDATERULE', 10830);
define('EM_REMOVECONDITIONDATERULE', 10831);
define('EM_CHANGECONDITIONDATERULE', 10832);
define('EM_ADDCONDITIONTIMERULE', 10833);
define('EM_REMOVECONDITIONTIMERULE', 10834);
define('EM_CHANGECONDITIONTIMERULE', 10835);
define('IPS_MEDIAMESSAGE', 10900);
define('MM_CREATE', 10901);
define('MM_DELETE', 10902);
define('MM_CHANGEFILE', 10903);
define('MM_AVAILABLE', 10904);
define('MM_UPDATE', 10905);
define('MM_CHANGECACHED', 10906);
define('IPS_LINKMESSAGE', 11000);
define('LM_CREATE', 11001);
define('LM_DELETE', 11002);
define('LM_CHANGETARGET', 11003);
define('IPS_FLOWMESSAGE', 11100);
define('FM_CONNECT', 11101);
define('FM_DISCONNECT', 11102);
define('FM_CHILDADDED', 11103);
define('FM_CHILDREMOVED', 11104);
define('IPS_ENGINEMESSAGE', 11200);
define('SE_UPDATE', 11201);
define('SE_EXECUTE', 11202);
define('SE_RUNNING', 11203);
define('IPS_PROFILEMESSAGE', 11300);
define('PM_CREATE', 11301);
define('PM_DELETE', 11302);
define('PM_CHANGETEXT', 11303);
define('PM_CHANGEVALUES', 11304);
define('PM_CHANGEDIGITS', 11305);
define('PM_CHANGEICON', 11306);
define('PM_ASSOCIATIONADDED', 11307);
define('PM_ASSOCIATIONREMOVED', 11308);
define('PM_ASSOCIATIONCHANGED', 11309);
define('IPS_TIMERMESSAGE', 11400);
define('TM_REGISTER', 11401);
define('TM_UNREGISTER', 11402);
define('TM_CHANGEINTERVAL', 11403);
define('TM_CHANGEPROGRESS', 11404);
define('TM_MESSAGE', 11405);
define('IS_SBASE', 100);
define('IS_CREATING', 101);
define('IS_ACTIVE', 102);
define('IS_DELETING', 103);
define('IS_INACTIVE', 104);
define('IS_NOTCREATED', 105);
define('IS_EBASE', 200);
define('IF_UNKNOWN', 0);
define('IF_NEW', 1);
define('IF_OLD', 2);
define('IF_CURRENT', 3);
define('IF_UNSUPPORTED', 4);
function AC_AddLoggedValues(int $InstanceID, int $VariableID, array $Values) { return true; }
function AC_ChangeVariableID(int $InstanceID, int $OldVariableID, int $NewVariableID) { return true; }
function AC_DeleteVariableData(int $InstanceID, int $VariableID, int $StartTime, int $EndTime) { return 0; }
function AC_FetchChartData(int $InstanceID, int $ObjectID, int $StartTime, int $TimeSpan, int $Density) { return Array(); }
function AC_GetAggregatedValues(int $InstanceID, int $VariableID, int $AggregationSpan, int $StartTime, int $EndTime, int $Limit) { return Array(); }
function AC_GetAggregationType(int $InstanceID, int $VariableID) { return 0; }
function AC_GetAggregationVariables(int $InstanceID, bool $CalculateStatistics) { return Array(); }
function AC_GetGraphStatus(int $InstanceID, int $VariableID) { return true; }
function AC_GetLoggedValues(int $InstanceID, int $VariableID, int $StartTime, int $EndTime, int $Limit) { return Array(); }
function AC_GetLoggingStatus(int $InstanceID, int $VariableID) { return true; }
function AC_ReAggregateVariable(int $InstanceID, int $VariableID) { return true; }
function AC_RenderChart(int $InstanceID, int $ObjectID, int $StartTime, int $TimeSpan, int $Density, bool $IsExtrema, bool $IsDyn, int $Width, int $Height) { return ''; }
function AC_SetAggregationType(int $InstanceID, int $VariableID, int $AggregationType) { return true; }
function AC_SetGraphStatus(int $InstanceID, int $VariableID, bool $Active) { return true; }
function AC_SetLoggingStatus(int $InstanceID, int $VariableID, bool $Active) { return true; }
function ALL_ReadConfiguration(int $InstanceID) { return true; }
function ALL_SetAnalog(int $InstanceID, int $ChannelID, float $Value) { return true; }
function ALL_SwitchActor(int $InstanceID, int $ChannelID, bool $DeviceOn) { return true; }
function ALL_SwitchMode(int $InstanceID, bool $DeviceOn) { return true; }
function ALL_UpdateValues(int $InstanceID) { return true; }
function CC_ActivateServer(int $InstanceID) { return true; }
function CC_GetQRCodeSVG(int $InstanceID, int $WebFrontConfiguratorID) { return ''; }
function CC_GetURL(int $InstanceID) { return ''; }
function CC_MakeRequest(int $InstanceID, string $Endpoint, string $RequestData) { return ''; }
function CMI_UpdateValues(int $InstanceID) { return true; }
function CSCK_SendText(int $InstanceID, string $Text) { return true; }
function Cutter_ClearBuffer(int $InstanceID) { return true; }
function DMX_FadeChannel(int $InstanceID, int $Channel, int $Value, float $FadingSeconds) { return true; }
function DMX_FadeChannelDelayed(int $InstanceID, int $Channel, int $Value, float $FadingSeconds, float $DelayedSeconds) { return true; }
function DMX_FadeRGB(int $InstanceID, int $R, int $G, int $B, float $FadingSeconds) { return true; }
function DMX_FadeRGBDelayed(int $InstanceID, int $R, int $G, int $B, float $FadingSeconds, float $DelayedSeconds) { return true; }
function DMX_RequestInfo(int $InstanceID) { return true; }
function DMX_ResetInterface(int $InstanceID) { return true; }
function DMX_SetBlackOut(int $InstanceID, bool $BlackoutOn) { return true; }
function DMX_SetChannel(int $InstanceID, int $Channel, int $Value) { return true; }
function DMX_SetRGB(int $InstanceID, int $R, int $G, int $B) { return true; }
function DS_CallScene(int $InstanceID, int $SceneID) { return true; }
function DS_DimSet(int $InstanceID, int $Intensity) { return true; }
function DS_GetKnownDevices(int $InstanceID) { return Array(); }
function DS_RequestBinaryInputs(int $InstanceID) { return true; }
function DS_RequestSensorInputs(int $InstanceID) { return true; }
function DS_RequestStatus(int $InstanceID) { return true; }
function DS_RequestToken(int $InstanceID, string $Username, string $Password) { return true; }
function DS_SaveScene(int $InstanceID, int $SceneID) { return true; }
function DS_ShutterMove(int $InstanceID, int $Position) { return true; }
function DS_ShutterMoveDown(int $InstanceID) { return true; }
function DS_ShutterMoveUp(int $InstanceID) { return true; }
function DS_ShutterStepDown(int $InstanceID) { return true; }
function DS_ShutterStepUp(int $InstanceID) { return true; }
function DS_ShutterStop(int $InstanceID) { return true; }
function DS_SwitchMode(int $InstanceID, bool $DeviceOn) { return true; }
function DS_UndoScene(int $InstanceID, int $SceneID) { return true; }
function EIB_Char(int $InstanceID, string $Value) { return true; }
function EIB_Counter16bit(int $InstanceID, int $Value) { return true; }
function EIB_Counter32bit(int $InstanceID, int $Value) { return true; }
function EIB_Counter8bit(int $InstanceID, int $Value) { return true; }
function EIB_Date(int $InstanceID, string $Value) { return true; }
function EIB_DimControl(int $InstanceID, int $Value) { return true; }
function EIB_DimValue(int $InstanceID, int $Value) { return true; }
function EIB_DriveBladeValue(int $InstanceID, int $Value) { return true; }
function EIB_DriveMove(int $InstanceID, bool $Value) { return true; }
function EIB_DriveShutterValue(int $InstanceID, int $Value) { return true; }
function EIB_DriveStep(int $InstanceID, bool $Value) { return true; }
function EIB_FloatValue(int $InstanceID, float $Value) { return true; }
function EIB_GetKnownDevices(int $InstanceID) { return Array(); }
function EIB_Move(int $InstanceID, int $Command) { return true; }
function EIB_Position(int $InstanceID, int $Position) { return true; }
function EIB_PriorityControl(int $InstanceID, int $Value) { return true; }
function EIB_PriorityPosition(int $InstanceID, bool $Value) { return true; }
function EIB_RequestInfo(int $InstanceID) { return true; }
function EIB_RequestStatus(int $InstanceID) { return true; }
function EIB_Scale(int $InstanceID, int $Value) { return true; }
function EIB_SearchDevices(int $InstanceID) { return true; }
function EIB_SetRGB(int $InstanceID, int $R, int $G, int $B) { return true; }
function EIB_SetRGBW(int $InstanceID, int $R, int $G, int $B, int $W) { return true; }
function EIB_Str(int $InstanceID, string $Value) { return true; }
function EIB_Switch(int $InstanceID, bool $Value) { return true; }
function EIB_Time(int $InstanceID, string $Value) { return true; }
function EIB_UploadDataPointFile(int $InstanceID, string $Content) { return true; }
function EIB_Value(int $InstanceID, float $Value) { return true; }
function ENO_DimSet(int $InstanceID, int $Intensity) { return true; }
function ENO_RequestStatus(int $InstanceID) { return true; }
function ENO_SendCST(int $InstanceID, bool $value) { return true; }
function ENO_SendCTM(int $InstanceID, int $value) { return true; }
function ENO_SendCV(int $InstanceID, float $value) { return true; }
function ENO_SendERH(int $InstanceID, bool $value) { return true; }
function ENO_SendFANOR(int $InstanceID, int $value) { return true; }
function ENO_SendFANOR_2(int $InstanceID, bool $value) { return true; }
function ENO_SendLearn(int $InstanceID) { return true; }
function ENO_SendLearnEx(int $InstanceID) { return true; }
function ENO_SendRO(int $InstanceID, int $value) { return true; }
function ENO_SendSPS(int $InstanceID, float $value) { return true; }
function ENO_SetActiveMessage(int $InstanceID, int $Message) { return true; }
function ENO_SetButtonLock(int $InstanceID, bool $Active) { return true; }
function ENO_SetFanStage(int $InstanceID, int $FanStage) { return true; }
function ENO_SetIntensity(int $InstanceID, bool $DeviceOn, int $Intensity) { return true; }
function ENO_SetLockFanStage(int $InstanceID, bool $Locked) { return true; }
function ENO_SetLockRoomOccupancy(int $InstanceID, bool $Locked) { return true; }
function ENO_SetMode(int $InstanceID, int $Mode) { return true; }
function ENO_SetOverride(int $InstanceID, int $Override) { return true; }
function ENO_SetPosition(int $InstanceID, int $Position) { return true; }
function ENO_SetRoomOccupancy(int $InstanceID, bool $Occupied) { return true; }
function ENO_SetTemperature(int $InstanceID, float $Temperature) { return true; }
function ENO_SetTemperature1(int $InstanceID, float $Temperature) { return true; }
function ENO_ShutterMoveDown(int $InstanceID) { return true; }
function ENO_ShutterMoveDownEx(int $InstanceID, float $Seconds) { return true; }
function ENO_ShutterMoveUp(int $InstanceID) { return true; }
function ENO_ShutterMoveUpEx(int $InstanceID, float $Seconds) { return true; }
function ENO_ShutterStepDown(int $InstanceID) { return true; }
function ENO_ShutterStepUp(int $InstanceID) { return true; }
function ENO_ShutterStop(int $InstanceID) { return true; }
function ENO_SwitchMode(int $InstanceID, bool $Value) { return true; }
function ENO_SwitchModeEx(int $InstanceID, bool $DeviceOn, int $SendMode) { return true; }
function ENO_SwitchVacationMode(int $InstanceID, bool $Value) { return true; }
function FHT_RequestData(int $InstanceID) { return true; }
function FHT_SetDay(int $InstanceID, int $Value) { return true; }
function FHT_SetHour(int $InstanceID, int $Value) { return true; }
function FHT_SetMinute(int $InstanceID, int $Value) { return true; }
function FHT_SetMode(int $InstanceID, int $Mode) { return true; }
function FHT_SetMonth(int $InstanceID, int $Value) { return true; }
function FHT_SetTemperature(int $InstanceID, float $Temperature) { return true; }
function FHT_SetYear(int $InstanceID, int $Value) { return true; }
function FHZ_GetFHTQueue(int $InstanceID) { return Array(); }
function FHZ_GetFreeBuffer(int $InstanceID) { return 0; }
function FS20_DimDown(int $InstanceID) { return true; }
function FS20_DimUp(int $InstanceID) { return true; }
function FS20_SetIntensity(int $InstanceID, int $Intensity, int $Duration) { return true; }
function FS20_SwitchDuration(int $InstanceID, bool $DeviceOn, int $Duration) { return true; }
function FS20_SwitchMode(int $InstanceID, bool $DeviceOn) { return true; }
function GetValue(int $VariableID) { return ''; }
function GetValueBoolean(int $VariableID) { return true; }
function GetValueFloat(int $VariableID) { return 0.0; }
function GetValueFormatted(int $VariableID) { return ''; }
function GetValueInteger(int $VariableID) { return 0; }
function GetValueString(int $VariableID) { return ''; }
function HC_TargetValue(int $InstanceID, float $Value) { return true; }
function HID_SendEvent(int $InstanceID, int $ReportID, string $Text) { return true; }
function HMS_ReleaseFI(int $InstanceID, int $Delay) { return true; }
function HM_GetKnownDevices(int $InstanceID) { return Array(); }
function HM_LoadDevices(int $InstanceID, int $Protocol) { return true; }
function HM_ReadServiceMessages(int $InstanceID) { return Array(); }
function HM_RequestStatus(int $InstanceID, string $Parameter) { return true; }
function HM_WriteValueBoolean(int $InstanceID, string $Parameter, bool $Value) { return true; }
function HM_WriteValueFloat(int $InstanceID, string $Parameter, float $Value) { return true; }
function HM_WriteValueInteger(int $InstanceID, string $Parameter, int $Value) { return true; }
function HM_WriteValueString(int $InstanceID, string $Parameter, string $Value) { return true; }
function IG_UpdateImage(int $InstanceID) { return true; }
function IMAP_DeleteMail(int $InstanceID, string $UID) { return true; }
function IMAP_GetCachedMails(int $InstanceID) { return Array(); }
function IMAP_GetMailEx(int $InstanceID, string $UID) { return Array(); }
function IMAP_UpdateCache(int $InstanceID) { return true; }
function IPS_ApplyChanges(int $InstanceID) { return true; }
function IPS_CategoryExists(int $CategoryID) { return true; }
function IPS_ConnectInstance(int $InstanceID, int $ParentID) { return true; }
function IPS_CreateCategory() { return 0; }
function IPS_CreateEvent(int $EventType) { return 0; }
function IPS_CreateInstance(string $ModuleID) { return 0; }
function IPS_CreateLink() { return 0; }
function IPS_CreateMedia(int $MediaType) { return 0; }
function IPS_CreateScript(int $ScriptType) { return 0; }
function IPS_CreateVariable(int $VariableType) { return 0; }
function IPS_CreateVariableProfile(string $ProfileName, int $ProfileType) { return true; }
function IPS_DeleteCategory(int $CategoryID) { return true; }
function IPS_DeleteEvent(int $EventID) { return true; }
function IPS_DeleteInstance(int $InstanceID) { return true; }
function IPS_DeleteLink(int $LinkID) { return true; }
function IPS_DeleteMedia(int $MediaID, bool $DeleteFile) { return true; }
function IPS_DeleteScript(int $ScriptID, bool $DeleteFile) { return true; }
function IPS_DeleteVariable(int $VariableID) { return true; }
function IPS_DeleteVariableProfile(string $ProfileName) { return true; }
function IPS_DisableDebug(int $ID) { return true; }
function IPS_DisconnectInstance(int $InstanceID) { return true; }
function IPS_EnableDebug(int $ID, int $Duration) { return true; }
function IPS_EventExists(int $EventID) { return true; }
function IPS_Execute(string $Filename, string $Parameter, bool $ShowWindow, bool $WaitResult) { return ''; }
function IPS_ExecuteEx(string $Filename, string $Parameter, bool $ShowWindow, bool $WaitResult, int $SessionID) { return ''; }
function IPS_FunctionExists(string $FunctionName) { return true; }
function IPS_GetCategory(int $CategoryID) { return Array(); }
function IPS_GetCategoryIDByName(string $Name, int $ParentID) { return 0; }
function IPS_GetCategoryList() { return Array(); }
function IPS_GetChildrenIDs(int $ID) { return Array(); }
function IPS_GetCompatibleInstances(int $InstanceID) { return Array(); }
function IPS_GetCompatibleModules(string $ModuleID) { return Array(); }
function IPS_GetConfiguration(int $InstanceID) { return ''; }
function IPS_GetConfigurationForParent(int $InstanceID) { return ''; }
function IPS_GetConfigurationForm(int $InstanceID) { return ''; }
function IPS_GetDemoExpiration() { return 0; }
function IPS_GetEvent(int $EventID) { return Array(); }
function IPS_GetEventIDByName(string $Name, int $ParentID) { return 0; }
function IPS_GetEventList() { return Array(); }
function IPS_GetEventListByType(int $EventType) { return Array(); }
function IPS_GetFunction(string $FunctionName) { return Array(); }
function IPS_GetFunctionList(int $InstanceID) { return Array(); }
function IPS_GetFunctionListByModuleID(string $ModuleID) { return Array(); }
function IPS_GetFunctions(array $InstanceIDs) { return Array(); }
function IPS_GetFunctionsMap(array $InstanceIDs) { return Array(); }
function IPS_GetInstance(int $InstanceID) { return Array(); }
function IPS_GetInstanceIDByName(string $Name, int $ParentID) { return 0; }
function IPS_GetInstanceList() { return Array(); }
function IPS_GetInstanceListByModuleID(string $ModuleID) { return Array(); }
function IPS_GetInstanceListByModuleType(int $ModuleType) { return Array(); }
function IPS_GetKernelDate() { return 0; }
function IPS_GetKernelDir() { return ''; }
function IPS_GetKernelDirEx() { return ''; }
function IPS_GetKernelPlatform() { return ''; }
function IPS_GetKernelRevision() { return ''; }
function IPS_GetKernelRunlevel() { return 0; }
function IPS_GetKernelStartTime() { return 0; }
function IPS_GetKernelVersion() { return ''; }
function IPS_GetLibraries(array $LibraryIDs) { return Array(); }
function IPS_GetLibrary(string $LibraryID) { return Array(); }
function IPS_GetLibraryList() { return Array(); }
function IPS_GetLibraryModules(string $LibraryID) { return Array(); }
function IPS_GetLicensee() { return ''; }
function IPS_GetLimitDemo() { return 0; }
function IPS_GetLimitServer() { return ''; }
function IPS_GetLimitVariables() { return 0; }
function IPS_GetLimitWebFront() { return 0; }
function IPS_GetLink(int $LinkID) { return Array(); }
function IPS_GetLinkIDByName(string $Name, int $ParentID) { return 0; }
function IPS_GetLinkList() { return Array(); }
function IPS_GetLiveConsoleCRC() { return ''; }
function IPS_GetLiveConsoleFile() { return ''; }
function IPS_GetLiveDashboardCRC() { return ''; }
function IPS_GetLiveDashboardFile() { return ''; }
function IPS_GetLiveUpdateVersion() { return ''; }
function IPS_GetLocation(int $ID) { return ''; }
function IPS_GetLogDir() { return ''; }
function IPS_GetMedia(int $MediaID) { return Array(); }
function IPS_GetMediaContent(int $MediaID) { return ''; }
function IPS_GetMediaIDByFile(string $FilePath) { return 0; }
function IPS_GetMediaIDByName(string $Name, int $ParentID) { return 0; }
function IPS_GetMediaList() { return Array(); }
function IPS_GetMediaListByType(int $MediaType) { return Array(); }
function IPS_GetModule(string $ModuleID) { return Array(); }
function IPS_GetModuleList() { return Array(); }
function IPS_GetModuleListByType(int $ModuleType) { return Array(); }
function IPS_GetModules(array $ModuleIDs) { return Array(); }
function IPS_GetName(int $ID) { return ''; }
function IPS_GetObject(int $ID) { return Array(); }
function IPS_GetObjectIDByIdent(string $Ident, int $ParentID) { return 0; }
function IPS_GetObjectIDByName(string $Name, int $ParentID) { return 0; }
function IPS_GetObjectList() { return Array(); }
function IPS_GetOption(string $Option) { return ''; }
function IPS_GetOptionList() { return Array(); }
function IPS_GetParent(int $ID) { return 0; }
function IPS_GetProperty(int $InstanceID, string $Name) { return ''; }
function IPS_GetScript(int $ScriptID) { return Array(); }
function IPS_GetScriptContent(int $ScriptID) { return ''; }
function IPS_GetScriptEventList(int $ScriptID) { return Array(); }
function IPS_GetScriptFile(int $ScriptID) { return ''; }
function IPS_GetScriptIDByFile(string $FilePath) { return 0; }
function IPS_GetScriptIDByName(string $Name, int $ParentID) { return 0; }
function IPS_GetScriptList() { return Array(); }
function IPS_GetScriptThread(int $ThreadID) { return Array(); }
function IPS_GetScriptThreadList() { return Array(); }
function IPS_GetScriptThreads(array $ThreadIDs) { return Array(); }
function IPS_GetScriptTimer(int $ScriptID) { return 0; }
function IPS_GetSecurityMode() { return 0; }
function IPS_GetSnapshot() { return Array(); }
function IPS_GetSnapshotChanges(int $LastTimestamp) { return Array(); }
function IPS_GetTimer(int $TimerID) { return Array(); }
function IPS_GetTimerList() { return Array(); }
function IPS_GetTimers(array $TimerIDs) { return Array(); }
function IPS_GetVariable(int $VariableID) { return Array(); }
function IPS_GetVariableEventList(int $VariableID) { return Array(); }
function IPS_GetVariableIDByName(string $Name, int $ParentID) { return 0; }
function IPS_GetVariableList() { return Array(); }
function IPS_GetVariableProfile(string $ProfileName) { return Array(); }
function IPS_GetVariableProfileList() { return Array(); }
function IPS_GetVariableProfileListByType(int $ProfileType) { return Array(); }
function IPS_HasChanges(int $InstanceID) { return true; }
function IPS_HasChildren(int $ID) { return true; }
function IPS_InstanceExists(int $InstanceID) { return true; }
function IPS_IsChild(int $ID, int $ParentID, bool $Recursive) { return true; }
function IPS_IsInstanceCompatible(int $InstanceID, int $ParentInstanceID) { return true; }
function IPS_IsModuleCompatible(string $ModuleID, string $ParentModuleID) { return true; }
function IPS_IsSearching(int $InstanceID) { return true; }
function IPS_LibraryExists(string $LibraryID) { return true; }
function IPS_LinkExists(int $LinkID) { return true; }
function IPS_LogMessage(string $Sender, string $Message) { return true; }
function IPS_MediaExists(int $MediaID) { return true; }
function IPS_ModuleExists(string $ModuleID) { return true; }
function IPS_ObjectExists(int $ID) { return true; }
function IPS_RequestAction(int $InstanceID, string $VariableIdent, $Value) { return true; }
function IPS_ResetChanges(int $InstanceID) { return true; }
function IPS_RunScript(int $ScriptID) { return true; }
function IPS_RunScriptEx(int $ScriptID, array $Parameters) { return true; }
function IPS_RunScriptText(string $ScriptText) { return true; }
function IPS_RunScriptTextEx(string $ScriptText, array $Parameters) { return true; }
function IPS_RunScriptTextWait(string $ScriptText) { return ''; }
function IPS_RunScriptTextWaitEx(string $ScriptText, array $Parameters) { return ''; }
function IPS_RunScriptWait(int $ScriptID) { return ''; }
function IPS_RunScriptWaitEx(int $ScriptID, array $Parameters) { return ''; }
function IPS_ScriptExists(int $ScriptID) { return true; }
function IPS_ScriptThreadExists(int $ThreadID) { return true; }
function IPS_SemaphoreEnter(string $Name, int $Milliseconds) { return true; }
function IPS_SemaphoreLeave(string $Name) { return true; }
function IPS_SendDebug(int $SenderID, string $Message, string $Data, int $Format) { return true; }
function IPS_SendMediaEvent(int $MediaID) { return true; }
function IPS_SetConfiguration(int $InstanceID, string $Configuration) { return true; }
function IPS_SetDisabled(int $ID, bool $Disabled) { return true; }
function IPS_SetEventActive(int $EventID, bool $Active) { return true; }
function IPS_SetEventCondition(int $EventID, int $ConditionID, int $ParentID, int $Operation) { return true; }
function IPS_SetEventConditionDateRule(int $EventID, int $ConditionID, int $RuleID, int $Comparison, int $Day, int $Month, int $Year) { return true; }
function IPS_SetEventConditionTimeRule(int $EventID, int $ConditionID, int $RuleID, int $Comparison, int $Hour, int $Minute, int $Second) { return true; }
function IPS_SetEventConditionVariableRule(int $EventID, int $ConditionID, int $RuleID, int $VariableID, int $Comparison, $Value) { return true; }
function IPS_SetEventCyclic(int $EventID, int $DateType, int $DateValue, int $DateDay, int $DateDayValue, int $TimeType, int $TimeValue) { return true; }
function IPS_SetEventCyclicDateFrom(int $EventID, int $Day, int $Month, int $Year) { return true; }
function IPS_SetEventCyclicDateTo(int $EventID, int $Day, int $Month, int $Year) { return true; }
function IPS_SetEventCyclicTimeFrom(int $EventID, int $Hour, int $Minute, int $Second) { return true; }
function IPS_SetEventCyclicTimeTo(int $EventID, int $Hour, int $Minute, int $Second) { return true; }
function IPS_SetEventLimit(int $EventID, int $Count) { return true; }
function IPS_SetEventScheduleAction(int $EventID, int $ActionID, string $Name, int $Color, string $ScriptText) { return true; }
function IPS_SetEventScheduleGroup(int $EventID, int $GroupID, int $Days) { return true; }
function IPS_SetEventScheduleGroupPoint(int $EventID, int $GroupID, int $PointID, int $StartHour, int $StartMinute, int $StartSecond, int $ActionID) { return true; }
function IPS_SetEventScript(int $EventID, string $EventScript) { return true; }
function IPS_SetEventTrigger(int $EventID, int $TriggerType, int $TriggerVariableID) { return true; }
function IPS_SetEventTriggerSubsequentExecution(int $EventID, bool $AllowSubsequentExecutions) { return true; }
function IPS_SetEventTriggerValue(int $EventID, $TriggerValue) { return true; }
function IPS_SetHidden(int $ID, bool $Hidden) { return true; }
function IPS_SetIcon(int $ID, string $Icon) { return true; }
function IPS_SetIdent(int $ID, string $Ident) { return true; }
function IPS_SetInfo(int $ID, string $Info) { return true; }
function IPS_SetLicense(string $Licensee, string $LicenseContent) { return true; }
function IPS_SetLinkTargetID(int $LinkID, int $ChildID) { return true; }
function IPS_SetMediaCached(int $MediaID, bool $Cached) { return true; }
function IPS_SetMediaContent(int $MediaID, string $Content) { return true; }
function IPS_SetMediaFile(int $MediaID, string $FilePath, bool $FileMustExists) { return true; }
function IPS_SetName(int $ID, string $Name) { return true; }
function IPS_SetOption(string $Option, $Value) { return true; }
function IPS_SetParent(int $ID, int $ParentID) { return true; }
function IPS_SetPosition(int $ID, int $Position) { return true; }
function IPS_SetProperty(int $InstanceID, string $Name, $Value) { return true; }
function IPS_SetScriptContent(int $ScriptID, string $Content) { return true; }
function IPS_SetScriptFile(int $ScriptID, string $FilePath) { return true; }
function IPS_SetScriptTimer(int $ScriptID, int $Interval) { return true; }
function IPS_SetSecurity(int $Mode, string $Password) { return true; }
function IPS_SetVariableCustomAction(int $VariableID, int $ScriptID) { return true; }
function IPS_SetVariableCustomProfile(int $VariableID, string $ProfileName) { return true; }
function IPS_SetVariableProfileAssociation(string $ProfileName, float $AssociationValue, string $AssociationName, string $AssociationIcon, int $AssociationColor) { return true; }
function IPS_SetVariableProfileDigits(string $ProfileName, int $Digits) { return true; }
function IPS_SetVariableProfileIcon(string $ProfileName, string $Icon) { return true; }
function IPS_SetVariableProfileText(string $ProfileName, string $Prefix, string $Suffix) { return true; }
function IPS_SetVariableProfileValues(string $ProfileName, float $MinValue, float $MaxValue, float $StepSize) { return true; }
function IPS_Sleep(int $Milliseconds) { return true; }
function IPS_StartSearch(int $InstanceID) { return true; }
function IPS_StopSearch(int $InstanceID) { return true; }
function IPS_SupportsSearching(int $InstanceID) { return true; }
function IPS_TimerExists(int $TimerID) { return true; }
function IPS_VariableExists(int $VariableID) { return true; }
function IPS_VariableProfileExists(string $ProfileName) { return true; }
function IRT_ListButtons(int $InstanceID, string $Remote) { return Array(); }
function IRT_ListRemotes(int $InstanceID) { return Array(); }
function IRT_SendOnce(int $InstanceID, string $Remote, string $Button) { return true; }
function KNX_DoWrite(int $InstanceID, $Value) { return true; }
function KNX_RenameVariables(int $InstanceID) { return true; }
function KNX_RequestStatus(int $InstanceID) { return true; }
function KNX_WriteDPT1(int $InstanceID, bool $B) { return true; }
function KNX_WriteDPT10(int $InstanceID, int $WeekDay, int $TimeOfDay) { return true; }
function KNX_WriteDPT11(int $InstanceID, int $Date) { return true; }
function KNX_WriteDPT12(int $InstanceID, int $Value) { return true; }
function KNX_WriteDPT13(int $InstanceID, float $Value) { return true; }
function KNX_WriteDPT14(int $InstanceID, float $Value) { return true; }
function KNX_WriteDPT15(int $InstanceID, int $D1, int $D2, int $D3, int $D4, int $D5, int $D6, bool $E, bool $P, bool $D, bool $C, int $Index) { return true; }
function KNX_WriteDPT16(int $InstanceID, string $Value) { return true; }
function KNX_WriteDPT17(int $InstanceID, int $Value) { return true; }
function KNX_WriteDPT18(int $InstanceID, bool $C, int $SceneNumber) { return true; }
function KNX_WriteDPT19(int $InstanceID, int $Time, int $WeekDay, bool $F, bool $WD, bool $NWD, bool $NY, bool $ND, bool $NDOW, bool $NT, bool $SUTI, bool $CLQ) { return true; }
function KNX_WriteDPT2(int $InstanceID, bool $C, bool $V) { return true; }
function KNX_WriteDPT20(int $InstanceID, int $Value) { return true; }
function KNX_WriteDPT200(int $InstanceID, int $Z, bool $B) { return true; }
function KNX_WriteDPT201(int $InstanceID, int $Z, int $N) { return true; }
function KNX_WriteDPT202(int $InstanceID, int $U, int $Z) { return true; }
function KNX_WriteDPT203(int $InstanceID, float $U, int $Z) { return true; }
function KNX_WriteDPT204(int $InstanceID, float $Value, int $Z) { return true; }
function KNX_WriteDPT205(int $InstanceID, float $Value, int $Z) { return true; }
function KNX_WriteDPT206(int $InstanceID, int $Time, int $Mode) { return true; }
function KNX_WriteDPT207(int $InstanceID, int $Value, bool $Attr0, bool $Attr1, bool $Attr2, bool $Attr3, bool $Attr4, bool $Attr5, bool $Attr6, bool $Attr7) { return true; }
function KNX_WriteDPT209(int $InstanceID, float $Temperature, bool $Attr0, bool $Attr1, bool $Attr2, bool $Attr3, bool $Attr4) { return true; }
function KNX_WriteDPT21(int $InstanceID, bool $Bit0, bool $Bit1, bool $Bit2, bool $Bit3, bool $Bit4, bool $Bit5, bool $Bit6, bool $Bit7) { return true; }
function KNX_WriteDPT210(int $InstanceID, float $Temperature, bool $Attr0, bool $Attr1, bool $Attr2, bool $Attr3, bool $Attr4, bool $Attr5, bool $Attr6, bool $Attr7, bool $Attr8, bool $Attr9, bool $Attr10, bool $Attr11) { return true; }
function KNX_WriteDPT211(int $InstanceID, int $Demand, int $ControllerMode) { return true; }
function KNX_WriteDPT212(int $InstanceID, float $TempSetpoint1, float $TempSetpoint2, float $TempSetpoint3) { return true; }
function KNX_WriteDPT213(int $InstanceID, float $TempSetpoint1, float $TempSetpoint2, float $TempSetpoint3, float $TempSetpoint4) { return true; }
function KNX_WriteDPT214(int $InstanceID, float $Temperature, int $Demand, bool $Attr0, bool $Attr1, bool $Attr2, bool $Attr3, bool $Attr4, bool $Attr5) { return true; }
function KNX_WriteDPT215(int $InstanceID, float $Temperature, int $Power, bool $Attr0, bool $Attr1, bool $Attr2, bool $Attr3, bool $Attr4, bool $Attr5, bool $Attr6, bool $Attr7, bool $Attr8, bool $Attr9, bool $Attr10, bool $Attr11) { return true; }
function KNX_WriteDPT216(int $InstanceID, int $Pnom, int $BstageLimit, int $BurnerType, bool $OilSupport, bool $GasSupport, bool $SolidSupport) { return true; }
function KNX_WriteDPT217(int $InstanceID, int $Magic, int $Version, int $Revision) { return true; }
function KNX_WriteDPT218(int $InstanceID, float $Volume, int $Z) { return true; }
function KNX_WriteDPT219(int $InstanceID, int $LogNumber, int $AlarmPriority, int $ApplicationArea, int $ErrorClass, bool $Attribut0, bool $Attribut1, bool $Attribut2, bool $Attribut3, bool $AlarmStatus0, bool $AlarmStatus1, bool $AlarmStatus2) { return true; }
function KNX_WriteDPT22(int $InstanceID, bool $Bit0, bool $Bit1, bool $Bit2, bool $Bit3, bool $Bit4, bool $Bit5, bool $Bit6, bool $Bit7, bool $Bit8, bool $Bit9, bool $Bit10, bool $Bit11, bool $Bit12, bool $Bit13, bool $Bit14, bool $Bit15) { return true; }
function KNX_WriteDPT220(int $InstanceID, int $DelayTime, float $Temp) { return true; }
function KNX_WriteDPT221(int $InstanceID, int $ManufacturerCode, int $IncrementedNumber) { return true; }
function KNX_WriteDPT222(int $InstanceID, float $Comfort, float $Standby, float $Economy) { return true; }
function KNX_WriteDPT223(int $InstanceID, int $EnergyDem, int $ControllerMode, int $EmergencyMode) { return true; }
function KNX_WriteDPT224(int $InstanceID, float $Cooling, float $Heating, int $ControllerMode, int $EmergencyMode) { return true; }
function KNX_WriteDPT225(int $InstanceID, int $Value0, int $Value1) { return true; }
function KNX_WriteDPT229(int $InstanceID, int $V, int $Z) { return true; }
function KNX_WriteDPT23(int $InstanceID, int $Value) { return true; }
function KNX_WriteDPT230(int $InstanceID, int $ManufactID, int $IdentNumber, int $Version, int $Medium) { return true; }
function KNX_WriteDPT231(int $InstanceID, string $Language, string $Region) { return true; }
function KNX_WriteDPT232(int $InstanceID, int $R, int $G, int $B) { return true; }
function KNX_WriteDPT234(int $InstanceID, string $LanguageCode) { return true; }
function KNX_WriteDPT235(int $InstanceID, int $ActiveElectricalEnergy, int $Tariff, bool $E, bool $T) { return true; }
function KNX_WriteDPT236(int $InstanceID, bool $D, int $P, int $M) { return true; }
function KNX_WriteDPT237(int $InstanceID, bool $CE, bool $BF, bool $LF, bool $RR, bool $AI, int $Addr) { return true; }
function KNX_WriteDPT238(int $InstanceID, bool $B7, bool $B6, int $Value) { return true; }
function KNX_WriteDPT239(int $InstanceID, int $SetValue, bool $ChannelActivation) { return true; }
function KNX_WriteDPT240(int $InstanceID, int $HeightPos, int $SlatsPos, bool $ValidHeightPos, bool $ValidSlatsPos) { return true; }
function KNX_WriteDPT241(int $InstanceID, int $HeightPos, int $SlatsPos, bool $A, bool $B, bool $C, bool $D, bool $E, bool $F, bool $G, bool $H, bool $I, bool $J, bool $K, bool $L, bool $M, bool $N, bool $O, bool $P) { return true; }
function KNX_WriteDPT242(int $InstanceID, int $XAxis, int $YAxis, int $Brightness, bool $C, bool $B) { return true; }
function KNX_WriteDPT25(int $InstanceID, int $Busy, int $Nak) { return true; }
function KNX_WriteDPT251(int $InstanceID, int $R, int $G, int $B, int $W, bool $ValidR, bool $ValidG, bool $ValidB, bool $ValidW) { return true; }
function KNX_WriteDPT26(int $InstanceID, int $SceneNumber, bool $B) { return true; }
function KNX_WriteDPT27(int $InstanceID, bool $S0, bool $S1, bool $S2, bool $S3, bool $S4, bool $S5, bool $S6, bool $S7, bool $S8, bool $S9, bool $S10, bool $S11, bool $S12, bool $S13, bool $S14, bool $S15, bool $M0, bool $M1, bool $M2, bool $M3, bool $M4, bool $M5, bool $M6, bool $M7, bool $M8, bool $M9, bool $M10, bool $M11, bool $M12, bool $M13, bool $M14, bool $M15) { return true; }
function KNX_WriteDPT29(int $InstanceID, int $Value) { return true; }
function KNX_WriteDPT3(int $InstanceID, bool $C, int $StepCode) { return true; }
function KNX_WriteDPT30(int $InstanceID, bool $Bit0, bool $Bit1, bool $Bit2, bool $Bit3, bool $Bit4, bool $Bit5, bool $Bit6, bool $Bit7, bool $Bit8, bool $Bit9, bool $Bit10, bool $Bit11, bool $Bit12, bool $Bit13, bool $Bit14, bool $Bit15, bool $Bit16, bool $Bit17, bool $Bit18, bool $Bit19, bool $Bit20, bool $Bit21, bool $Bit22, bool $Bit23) { return true; }
function KNX_WriteDPT31(int $InstanceID, int $Value) { return true; }
function KNX_WriteDPT4(int $InstanceID, string $Value) { return true; }
function KNX_WriteDPT5(int $InstanceID, int $U) { return true; }
function KNX_WriteDPT6(int $InstanceID, bool $A, bool $B, bool $C, bool $D, bool $E, int $F) { return true; }
function KNX_WriteDPT7(int $InstanceID, int $Value) { return true; }
function KNX_WriteDPT8(int $InstanceID, float $Value) { return true; }
function KNX_WriteDPT9(int $InstanceID, float $Value) { return true; }
function LCN_AddGroup(int $InstanceID, int $Group) { return true; }
function LCN_AddIntensity(int $InstanceID, int $Intensity) { return true; }
function LCN_Beep(int $InstanceID, bool $SpecialTone, int $Count) { return true; }
function LCN_DeductIntensity(int $InstanceID, int $Intensity) { return true; }
function LCN_Fadeout(int $InstanceID, int $Intensity, int $Ramp) { return true; }
function LCN_FlipRelay(int $InstanceID) { return true; }
function LCN_GetKnownDevices(int $InstanceID) { return Array(); }
function LCN_LimitOutput(int $InstanceID, int $Value, int $Time, string $TimeType) { return true; }
function LCN_LoadScene(int $InstanceID, int $Scene) { return true; }
function LCN_LockTargetValue(int $InstanceID, int $Target) { return true; }
function LCN_RampStop(int $InstanceID) { return true; }
function LCN_ReleaseTargetValue(int $InstanceID, int $Target) { return true; }
function LCN_RemoveGroup(int $InstanceID, int $Group) { return true; }
function LCN_RequestLights(int $InstanceID) { return true; }
function LCN_RequestRead(int $InstanceID) { return true; }
function LCN_RequestStatus(int $InstanceID) { return true; }
function LCN_RequestThresholds(int $InstanceID) { return true; }
function LCN_SaveScene(int $InstanceID, int $Scene) { return true; }
function LCN_SearchDevices(int $InstanceID, int $Segment) { return true; }
function LCN_SelectSceneRegister(int $InstanceID, int $Register) { return true; }
function LCN_SendCommand(int $InstanceID, string $Function, string $Data) { return true; }
function LCN_SetDisplayText(int $InstanceID, int $Row, string $Text) { return true; }
function LCN_SetDisplayTime(int $InstanceID, int $Row, int $Seconds) { return true; }
function LCN_SetIntensity(int $InstanceID, int $Intensity, int $Ramp) { return true; }
function LCN_SetLamp(int $InstanceID, int $Lamp, string $Action) { return true; }
function LCN_SetRGBW(int $InstanceID, int $R, int $G, int $B, int $W) { return true; }
function LCN_SetRelay(int $InstanceID, string $Value) { return true; }
function LCN_SetTargetValue(int $InstanceID, int $Target, float $Value) { return true; }
function LCN_ShiftTargetValue(int $InstanceID, int $Target, float $RelativeValue) { return true; }
function LCN_ShutterMove(int $InstanceID, int $Position) { return true; }
function LCN_ShutterMoveDown(int $InstanceID) { return true; }
function LCN_ShutterMoveUp(int $InstanceID) { return true; }
function LCN_ShutterStop(int $InstanceID) { return true; }
function LCN_StartFlicker(int $InstanceID, string $Depth, string $Speed, int $Count) { return true; }
function LCN_StopFlicker(int $InstanceID) { return true; }
function LCN_SwitchDurationMin(int $InstanceID, int $Minutes, string $Fadeout, bool $Retentive) { return true; }
function LCN_SwitchDurationSec(int $InstanceID, int $Seconds, string $Fadeout, bool $Retentive) { return true; }
function LCN_SwitchMemory(int $InstanceID, int $Ramp) { return true; }
function LCN_SwitchMode(int $InstanceID, int $Ramp) { return true; }
function LCN_SwitchRelay(int $InstanceID, bool $SwitchOn) { return true; }
function LCN_SwitchRelayTimer(int $InstanceID, int $Timerfactor) { return true; }
function MBUS_UpdateValues(int $InstanceID) { return true; }
function MC_CreateModule(int $InstanceID, string $ModuleURL) { return true; }
function MC_DeleteModule(int $InstanceID, string $Module) { return true; }
function MC_GetModule(int $InstanceID, string $Module) { return Array(); }
function MC_GetModuleList(int $InstanceID) { return Array(); }
function MC_GetModuleRepositoryInfo(int $InstanceID, string $Module) { return Array(); }
function MC_GetModuleRepositoryLocalBranchList(int $InstanceID, string $Module) { return Array(); }
function MC_GetModuleRepositoryRemoteBranchList(int $InstanceID, string $Module) { return Array(); }
function MC_IsModuleClean(int $InstanceID, string $Module) { return true; }
function MC_IsModuleUpdateAvailable(int $InstanceID, string $Module) { return true; }
function MC_IsModuleValid(int $InstanceID, string $Module) { return true; }
function MC_ReloadModule(int $InstanceID, string $Module) { return true; }
function MC_RevertModule(int $InstanceID, string $Module) { return true; }
function MC_UpdateModule(int $InstanceID, string $Module) { return true; }
function MC_UpdateModuleRepositoryBranch(int $InstanceID, string $Module, string $Branch) { return true; }
function MSCK_SendPacket(int $InstanceID, string $Text, string $ClientIP, int $ClientPort) { return true; }
function MSCK_SendText(int $InstanceID, string $Text) { return true; }
function MXC_DimBrighter(int $InstanceID) { return true; }
function MXC_DimDarker(int $InstanceID) { return true; }
function MXC_DimSet(int $InstanceID, int $Intensity) { return true; }
function MXC_DimStop(int $InstanceID) { return true; }
function MXC_GetKnownDevices(int $InstanceID) { return Array(); }
function MXC_RequestInfo(int $InstanceID) { return true; }
function MXC_RequestStatus(int $InstanceID) { return true; }
function MXC_SearchDevices(int $InstanceID) { return true; }
function MXC_SendBoolean(int $InstanceID, bool $Value) { return true; }
function MXC_SendFloat(int $InstanceID, float $Value) { return true; }
function MXC_SendInteger(int $InstanceID, int $Value) { return true; }
function MXC_SetTemperature(int $InstanceID, float $Temperature) { return true; }
function MXC_ShutterMoveDown(int $InstanceID) { return true; }
function MXC_ShutterMoveUp(int $InstanceID) { return true; }
function MXC_ShutterStepDown(int $InstanceID) { return true; }
function MXC_ShutterStepUp(int $InstanceID) { return true; }
function MXC_ShutterStop(int $InstanceID) { return true; }
function MXC_SwitchMode(int $InstanceID, bool $DeviceOn) { return true; }
function MXC_UploadDataPointFile(int $InstanceID, string $Content) { return true; }
function ModBus_RequestRead(int $InstanceID) { return true; }
function ModBus_WriteCoil(int $InstanceID, bool $Value) { return true; }
function ModBus_WriteRegister(int $InstanceID, float $Value) { return true; }
function ModBus_WriteRegisterByte(int $InstanceID, int $Value) { return true; }
function ModBus_WriteRegisterChar(int $InstanceID, int $Value) { return true; }
function ModBus_WriteRegisterDWord(int $InstanceID, int $Value) { return true; }
function ModBus_WriteRegisterInt64(int $InstanceID, float $Value) { return true; }
function ModBus_WriteRegisterInteger(int $InstanceID, int $Value) { return true; }
function ModBus_WriteRegisterReal(int $InstanceID, float $Value) { return true; }
function ModBus_WriteRegisterReal64(int $InstanceID, float $Value) { return true; }
function ModBus_WriteRegisterShort(int $InstanceID, int $Value) { return true; }
function ModBus_WriteRegisterWord(int $InstanceID, int $Value) { return true; }
function NC_ActivateServer(int $InstanceID) { return true; }
function NC_AddDevice(int $InstanceID, string $Token, string $Provider, string $DeviceID, string $Name, int $WebFrontConfiguratorID) { return ''; }
function NC_GetDevices(int $InstanceID) { return Array(); }
function NC_PushNotification(int $InstanceID, int $WebFrontConfiguratorID, string $Title, string $Body, string $Sound) { return true; }
function NC_PushNotificationEx(int $InstanceID, int $WebFrontConfiguratorID, string $Title, string $Body, string $Sound, int $CategoryID, int $TargetID) { return true; }
function NC_RemoveDevice(int $InstanceID, int $DeviceID) { return true; }
function NC_RemoveDeviceConfigurator(int $InstanceID, int $DeviceID, int $WebFrontConfiguratorID) { return true; }
function NC_SetDeviceConfigurator(int $InstanceID, int $DeviceID, int $WebFrontConfiguratorID, bool $Enabled) { return true; }
function NC_SetDeviceName(int $InstanceID, int $DeviceID, string $Name) { return true; }
function NC_TestDevice(int $InstanceID, int $DeviceID) { return true; }
function OW_GetKnownDevices(int $InstanceID) { return Array(); }
function OW_RequestStatus(int $InstanceID) { return true; }
function OW_SetPin(int $InstanceID, int $Pin, bool $SwitchOn) { return true; }
function OW_SetPort(int $InstanceID, int $Value) { return true; }
function OW_SetPosition(int $InstanceID, int $Value) { return true; }
function OW_SetStrobe(int $InstanceID, bool $Status) { return true; }
function OW_SwitchMode(int $InstanceID, bool $SwitchOn) { return true; }
function OW_ToggleMode(int $InstanceID) { return true; }
function OW_WriteBytes(int $InstanceID, string $Data) { return true; }
function OW_WriteBytesMasked(int $InstanceID, string $Data, int $Mask) { return true; }
function OZW_GetKnownDevices(int $InstanceID) { return Array(); }
function OZW_GetKnownItems(int $InstanceID) { return Array(); }
function OZW_RequestStatus(int $InstanceID) { return true; }
function OZW_UpdateItems(int $InstanceID) { return true; }
function OZW_WriteDataPoint(int $InstanceID, $Value) { return true; }
function OZW_WriteDataPointEx(int $InstanceID, string $DataPoint, $Value) { return true; }
function PC_Enter(int $InstanceID) { return true; }
function PC_Leave(int $InstanceID) { return true; }
function PJ_Backlight(int $InstanceID, bool $Status) { return true; }
function PJ_Beep(int $InstanceID, int $TenthOfASecond) { return true; }
function PJ_DimRGBW(int $InstanceID, int $R, int $RTime, int $G, int $GTime, int $B, int $BTime, int $W, int $WTime) { return true; }
function PJ_DimServo(int $InstanceID, int $Channel, int $Value, int $Steps) { return true; }
function PJ_LCDText(int $InstanceID, int $Line, string $Text) { return true; }
function PJ_RequestStatus(int $InstanceID) { return true; }
function PJ_RunProgram(int $InstanceID, int $Type) { return true; }
function PJ_SetLEDs(int $InstanceID, bool $Green, bool $Yellow, bool $Red) { return true; }
function PJ_SetRGBW(int $InstanceID, int $R, int $G, int $B, int $W) { return true; }
function PJ_SetServo(int $InstanceID, int $Channel, int $Value) { return true; }
function PJ_SetVoltage(int $InstanceID, float $Voltage) { return true; }
function PJ_SwitchDuration(int $InstanceID, bool $DeviceOn, int $Duration) { return true; }
function PJ_SwitchLED(int $InstanceID, int $LED, bool $Status) { return true; }
function PJ_SwitchMode(int $InstanceID, bool $DeviceOn) { return true; }
function POP3_DeleteMail(int $InstanceID, string $UID) { return true; }
function POP3_GetCachedMails(int $InstanceID) { return Array(); }
function POP3_GetMailEx(int $InstanceID, string $UID) { return Array(); }
function POP3_UpdateCache(int $InstanceID) { return true; }
function RegVar_GetBuffer(int $InstanceID) { return ''; }
function RegVar_SendEvent(int $InstanceID, int $ReportID, string $Text) { return true; }
function RegVar_SendPacket(int $InstanceID, string $Text, string $ClientIP, int $ClientPort) { return true; }
function RegVar_SendText(int $InstanceID, string $Text) { return true; }
function RegVar_SetBuffer(int $InstanceID, string $Text) { return true; }
function RequestAction(int $VariableID, $Value) { return true; }
function RequestActionEx(int $VariableID, $Value, string $Sender) { return true; }
function S7_RequestRead(int $InstanceID) { return true; }
function S7_Write(int $InstanceID, float $Value) { return true; }
function S7_WriteBit(int $InstanceID, bool $Value) { return true; }
function S7_WriteByte(int $InstanceID, int $Value) { return true; }
function S7_WriteChar(int $InstanceID, int $Value) { return true; }
function S7_WriteDWord(int $InstanceID, int $Value) { return true; }
function S7_WriteInteger(int $InstanceID, int $Value) { return true; }
function S7_WriteReal(int $InstanceID, float $Value) { return true; }
function S7_WriteShort(int $InstanceID, int $Value) { return true; }
function S7_WriteString(int $InstanceID, string $Value) { return true; }
function S7_WriteWord(int $InstanceID, int $Value) { return true; }
function SC_CreateSkin(int $InstanceID, string $SkinURL) { return true; }
function SC_DeleteSkin(int $InstanceID, string $Skin) { return true; }
function SC_GetSkin(int $InstanceID, string $Skin) { return Array(); }
function SC_GetSkinIconContent(int $InstanceID, string $Skin, string $Icon) { return ''; }
function SC_GetSkinList(int $InstanceID) { return Array(); }
function SC_GetSkinRepositoryInfo(int $InstanceID, string $Skin) { return Array(); }
function SC_GetSkinRepositoryLocalBranchList(int $InstanceID, string $Skin) { return Array(); }
function SC_GetSkinRepositoryRemoteBranchList(int $InstanceID, string $Skin) { return Array(); }
function SC_IsSkinClean(int $InstanceID, string $Skin) { return true; }
function SC_IsSkinUpdateAvailable(int $InstanceID, string $Skin) { return true; }
function SC_IsSkinValid(int $InstanceID, string $Skin) { return true; }
function SC_Move(int $InstanceID, int $Position) { return true; }
function SC_MoveDown(int $InstanceID, int $Duration) { return true; }
function SC_MoveUp(int $InstanceID, int $Duration) { return true; }
function SC_RevertSkin(int $InstanceID, string $Skin) { return true; }
function SC_Stop(int $InstanceID) { return true; }
function SC_UpdateSkin(int $InstanceID, string $Skin) { return true; }
function SC_UpdateSkinRepositoryBranch(int $InstanceID, string $Skin, string $Branch) { return true; }
function SMS_RequestBalance(int $InstanceID) { return 0.0; }
function SMS_RequestStatus(int $InstanceID, string $MsgID) { return ''; }
function SMS_Send(int $InstanceID, string $Number, string $Text) { return ''; }
function SMTP_SendMail(int $InstanceID, string $Subject, string $Textg) { return true; }
function SMTP_SendMailAttachment(int $InstanceID, string $Subject, string $Text, string $Filename) { return true; }
function SMTP_SendMailAttachmentEx(int $InstanceID, string $Address, string $Subject, string $Text, string $Filename) { return true; }
function SMTP_SendMailEx(int $InstanceID, string $Address, string $Subject, string $Text) { return true; }
function SMTP_SendMailMedia(int $InstanceID, string $Subject, string $Text, int $MediaID) { return true; }
function SMTP_SendMailMediaEx(int $InstanceID, string $Address, string $Subject, string $Text, int $MediaID) { return true; }
function SPRT_SendText(int $InstanceID, string $Text) { return true; }
function SPRT_SetBreak(int $InstanceID, bool $OnOff) { return true; }
function SPRT_SetDTR(int $InstanceID, bool $OnOff) { return true; }
function SPRT_SetRTS(int $InstanceID, bool $OnOff) { return true; }
function SSCK_SendPacket(int $InstanceID, string $Text, string $ClientIP, int $ClientPort) { return true; }
function SSCK_SendText(int $InstanceID, string $Text) { return true; }
function SetValue(int $VariableID, $Value) { return true; }
function SetValueBoolean(int $VariableID, bool $Value) { return true; }
function SetValueFloat(int $VariableID, float $Value) { return true; }
function SetValueInteger(int $VariableID, int $Value) { return true; }
function SetValueString(int $VariableID, string $Value) { return true; }
function Sys_GetBattery() { return Array(); }
function Sys_GetCPUInfo() { return Array(); }
function Sys_GetHardDiskInfo() { return Array(); }
function Sys_GetMemoryInfo() { return Array(); }
function Sys_GetNetworkInfo() { return Array(); }
function Sys_GetProcessInfo() { return Array(); }
function Sys_GetSpooler() { return Array(); }
function Sys_GetURLContent(string $URL) { return ''; }
function Sys_GetURLContentEx(string $URL, array $Options) { return ''; }
function Sys_Ping(string $Host, int $Timeout) { return true; }
function TTS_GenerateFile(int $InstanceID, string $Text, string $Filename, int $Format) { return true; }
function TTS_Speak(int $InstanceID, string $Text, bool $Wait) { return true; }
function UC_DuplicateObject(int $InstanceID, int $ID, int $ParentID, bool $Recursive) { return true; }
function UC_FindInFiles(int $InstanceID, array $Files, string $SearchStr) { return Array(); }
function UC_FindInvalidStrings(int $InstanceID) { return Array(); }
function UC_FindReferences(int $InstanceID, int $ID) { return Array(); }
function UC_FixInvalidStrings(int $InstanceID, array $References) { return true; }
function UC_GetIconContent(int $InstanceID, string $Icon) { return ''; }
function UC_GetIconList(int $InstanceID) { return Array(); }
function UC_GetLastLogMessages(int $InstanceID, int $Type) { return Array(); }
function UC_GetLogMessageStatistics(int $InstanceID) { return Array(); }
function UC_RenameScript(int $InstanceID, int $ScriptID, string $Filename) { return true; }
function UC_ReplaceInFiles(int $InstanceID, array $Files, string $SearchStr, string $ReplaceStr) { return Array(); }
function UC_RequestLicenseData(int $InstanceID) { return true; }
function UC_ResetLastLogMessages(int $InstanceID) { return true; }
function UC_ResetLogMessageStatistics(int $InstanceID) { return true; }
function UC_SendUsageData(int $InstanceID) { return true; }
function USCK_SendPacket(int $InstanceID, string $Text, string $ClientIP, int $ClientPort) { return true; }
function USCK_SendText(int $InstanceID, string $Text) { return true; }
function UVR_UpdateValues(int $InstanceID) { return true; }
function VELLEUSB_ReadAnalogChannel(int $InstanceID, int $Channel) { return 0; }
function VELLEUSB_ReadCounter(int $InstanceID, int $Counter) { return 0; }
function VELLEUSB_ReadDigital(int $InstanceID) { return 0; }
function VELLEUSB_ReadDigitalChannel(int $InstanceID, int $Channel) { return true; }
function VELLEUSB_ResetCounter(int $InstanceID, int $Counter) { return true; }
function VELLEUSB_SetCounterDebounceTime(int $InstanceID, int $Counter, int $Time) { return true; }
function VELLEUSB_WriteAnalogChannel(int $InstanceID, int $Channel, int $Value) { return true; }
function VELLEUSB_WriteDigital(int $InstanceID, int $Value) { return true; }
function VELLEUSB_WriteDigitalChannel(int $InstanceID, int $Channel, bool $Value) { return true; }
function VIO_PushText(int $InstanceID, string $Text) { return true; }
function VIO_PushTextHEX(int $InstanceID, string $Text) { return true; }
function VIO_SendText(int $InstanceID, string $Text) { return true; }
function VOIP_Connect(int $InstanceID, string $Number) { return 0; }
function VOIP_Disconnect(int $InstanceID, int $ConnectionID) { return true; }
function VOIP_GetConnection(int $InstanceID, int $ConnectionID) { return Array(); }
function VOIP_GetData(int $InstanceID, int $ConnectionID) { return ''; }
function VOIP_PlayWave(int $InstanceID, int $ConnectionID, string $Filename) { return true; }
function VOIP_SetData(int $InstanceID, int $ConnectionID, string $Data) { return true; }
function WAC_AddFile(int $InstanceID, string $Filename) { return true; }
function WAC_ClearPlaylist(int $InstanceID) { return true; }
function WAC_GetPlaylistFile(int $InstanceID, int $Position) { return ''; }
function WAC_GetPlaylistLength(int $InstanceID) { return 0; }
function WAC_GetPlaylistPosition(int $InstanceID) { return 0; }
function WAC_GetPlaylistTitle(int $InstanceID, int $Position) { return ''; }
function WAC_Next(int $InstanceID) { return true; }
function WAC_Pause(int $InstanceID) { return true; }
function WAC_Play(int $InstanceID) { return true; }
function WAC_PlayFile(int $InstanceID, string $Filename) { return true; }
function WAC_Prev(int $InstanceID) { return true; }
function WAC_SetPlaylistPosition(int $InstanceID, int $Position) { return true; }
function WAC_SetPosition(int $InstanceID, int $Seconds) { return true; }
function WAC_SetRepeat(int $InstanceID, bool $DoRepeat) { return true; }
function WAC_SetShuffle(int $InstanceID, bool $DoShuffle) { return true; }
function WAC_SetVolume(int $InstanceID, int $Volume) { return true; }
function WAC_Stop(int $InstanceID) { return true; }
function WFC_AddItem(int $InstanceID, string $ID, string $ClassName, string $Configuration, string $ParentID) { return true; }
function WFC_AudioNotification(int $InstanceID, string $Title, int $MediaID) { return true; }
function WFC_DeleteItem(int $InstanceID, string $ID) { return true; }
function WFC_Execute(int $InstanceID, int $ActionID, int $TargetID, $Value) { return ''; }
function WFC_FetchChartData(int $InstanceID, int $ObjectID, int $StartTime, int $TimeSpan, int $Density) { return Array(); }
function WFC_GetAggregatedValues(int $InstanceID, int $VariableID, int $AggregationSpan, int $StartTime, int $EndTime, int $Limit) { return Array(); }
function WFC_GetItems(int $InstanceID) { return Array(); }
function WFC_GetLoggedValues(int $InstanceID, int $VariableID, int $StartTime, int $EndTime, int $Limit) { return Array(); }
function WFC_GetSnapshot(int $InstanceID) { return ''; }
function WFC_GetSnapshotChanges(int $InstanceID, int $LastTimeStamp) { return ''; }
function WFC_GetSnapshotChangesEx(int $InstanceID, int $CategoryID, int $LastTimeStamp) { return ''; }
function WFC_GetSnapshotEx(int $InstanceID, int $CategoryID) { return ''; }
function WFC_OpenCategory(int $InstanceID, int $CategoryID) { return true; }
function WFC_PushNotification(int $InstanceID, string $Title, string $Text, string $Sound, int $TargetID) { return true; }
function WFC_RegisterPNS(int $InstanceID, string $Token, string $Provider, string $DeviceID, string $DeviceName) { return ''; }
function WFC_Reload(int $InstanceID) { return true; }
function WFC_RenderChart(int $InstanceID, int $ObjectID, int $StartTime, int $TimeSpan, int $Density, bool $IsExtrema, bool $IsDyn, int $Width, int $Height) { return ''; }
function WFC_SendNotification(int $InstanceID, string $Title, string $Text, string $Icon, int $Timeout) { return true; }
function WFC_SendPopup(int $InstanceID, string $Title, string $Text) { return true; }
function WFC_SetItems(int $InstanceID, string $Items) { return true; }
function WFC_SwitchPage(int $InstanceID, string $PageName) { return true; }
function WFC_UpdateConfiguration(int $InstanceID, string $ID, string $Configuration) { return true; }
function WFC_UpdateParentID(int $InstanceID, string $ID, string $ParentID) { return true; }
function WFC_UpdatePosition(int $InstanceID, string $ID, int $Position) { return true; }
function WFC_UpdateVisibility(int $InstanceID, string $ID, bool $Visible) { return true; }
function WWW_UpdatePage(int $InstanceID) { return true; }
function WinLIRC_SendOnce(int $InstanceID, string $Remote, string $Button) { return true; }
function WuT_SwitchMode(int $InstanceID, bool $DeviceOn) { return true; }
function WuT_UpdateValue(int $InstanceID) { return true; }
function WuT_UpdateValues(int $InstanceID) { return true; }
function XBee_SendBuffer(int $InstanceID, int $DestinationDevice, string $Buffer) { return true; }
function XBee_SendCommand(int $InstanceID, string $Command) { return ''; }
function ZW_AssociationAddToGroup(int $InstanceID, int $Group, int $Node) { return true; }
function ZW_AssociationRemoveFromGroup(int $InstanceID, int $Group, int $Node) { return true; }
function ZW_Basic(int $InstanceID, int $Value) { return true; }
function ZW_ColorRGBWW(int $InstanceID, int $Red, int $Green, int $Blue, int $WarmWhite, int $ColdWhite) { return true; }
function ZW_ConfigurationGetValue(int $InstanceID, int $Parameter) { return 0; }
function ZW_ConfigurationResetValue(int $InstanceID, int $Parameter) { return true; }
function ZW_ConfigurationResetValueEx(int $InstanceID, int $Parameter, int $Size) { return true; }
function ZW_ConfigurationSetValue(int $InstanceID, int $Parameter, int $Value) { return true; }
function ZW_ConfigurationSetValueEx(int $InstanceID, int $Parameter, int $Size, int $Value) { return true; }
function ZW_DeleteFailedDevice(int $InstanceID, int $NodeID) { return true; }
function ZW_DimDown(int $InstanceID) { return true; }
function ZW_DimDownEx(int $InstanceID, int $Duration) { return true; }
function ZW_DimSet(int $InstanceID, int $Intensity) { return true; }
function ZW_DimSetEx(int $InstanceID, int $Intensity, int $Duration) { return true; }
function ZW_DimStop(int $InstanceID) { return true; }
function ZW_DimUp(int $InstanceID) { return true; }
function ZW_DimUpEx(int $InstanceID, int $Duration) { return true; }
function ZW_DoorLockOperation(int $InstanceID, int $Mode) { return true; }
function ZW_GetKnownDevices(int $InstanceID) { return Array(); }
function ZW_GetUserCodeList(int $InstanceID) { return Array(); }
function ZW_GetWakeUpQueue(int $InstanceID) { return Array(); }
function ZW_LockMode(int $InstanceID, bool $Locked) { return true; }
function ZW_MeterReset(int $InstanceID) { return true; }
function ZW_Optimize(int $InstanceID) { return true; }
function ZW_ProtectionSet(int $InstanceID, int $Mode) { return true; }
function ZW_PulseThermostatFanModeSet(int $InstanceID, int $FanMode) { return true; }
function ZW_PulseThermostatModeSet(int $InstanceID, int $Mode) { return true; }
function ZW_PulseThermostatPowerModeSet(int $InstanceID, int $PowerMode) { return true; }
function ZW_PulseThermostatSetPointSet(int $InstanceID, int $SetPoint, float $Value) { return true; }
function ZW_RequestAssociations(int $InstanceID) { return Array(); }
function ZW_RequestInfo(int $InstanceID) { return true; }
function ZW_RequestRoutingList(int $InstanceID) { return Array(); }
function ZW_RequestStatus(int $InstanceID) { return true; }
function ZW_RequestVersion(int $InstanceID) { return Array(); }
function ZW_RequestWakeUpInterval(int $InstanceID) { return Array(); }
function ZW_ResetToDefault(int $InstanceID) { return true; }
function ZW_SearchDevices(int $InstanceID) { return true; }
function ZW_SearchMainDevice(int $InstanceID) { return 0; }
function ZW_SearchSubDevices(int $InstanceID) { return Array(); }
function ZW_ShutterMoveDown(int $InstanceID) { return true; }
function ZW_ShutterMoveUp(int $InstanceID) { return true; }
function ZW_ShutterStop(int $InstanceID) { return true; }
function ZW_StartAddDevice(int $InstanceID) { return true; }
function ZW_StartAddNewPrimaryController(int $InstanceID) { return true; }
function ZW_StartRemoveDevice(int $InstanceID) { return true; }
function ZW_StopAddDevice(int $InstanceID) { return true; }
function ZW_StopAddNewPrimaryController(int $InstanceID) { return true; }
function ZW_StopRemoveDevice(int $InstanceID) { return true; }
function ZW_SwitchAllMode(int $InstanceID, int $Mode) { return true; }
function ZW_SwitchMode(int $InstanceID, bool $DeviceOn) { return true; }
function ZW_Test(int $InstanceID) { return true; }
function ZW_TestDevice(int $InstanceID, int $NodeID) { return true; }
function ZW_ThermostatFanModeSet(int $InstanceID, int $FanMode) { return true; }
function ZW_ThermostatModeSet(int $InstanceID, int $Mode) { return true; }
function ZW_ThermostatSetPointSet(int $InstanceID, int $SetPoint, float $Value) { return true; }
function ZW_UserCodeLearn(int $InstanceID, bool $Enabled) { return true; }
function ZW_UserCodeRemove(int $InstanceID, int $Identifier) { return true; }
function ZW_WakeUpComplete(int $InstanceID) { return true; }
function ZW_WakeUpKeepAlive(int $InstanceID, bool $KeepAlive) { return true; }
function ZW_WakeUpSetInterval(int $InstanceID, int $Seconds) { return true; }
class IPSModule {
	protected $InstanceID;
	public function __construct($InstanceID) {}
	public function Create() { return true; }
	public function Destroy() { return true; }
	protected function GetIDForIdent(string $Ident) { return 0; }
	protected function RegisterPropertyBoolean(string $Name, bool $DefaultValue) { return true; }
	protected function RegisterPropertyInteger(string $Name, int $DefaultValue) { return true; }
	protected function RegisterPropertyFloat(string $Name, float $DefaultValue) { return true; }
	protected function RegisterPropertyString(string $Name, string $DefaultValue) { return true; }
	protected function RegisterAttributeBoolean(string $Name, bool $DefaultValue) { return true; }
	protected function RegisterAttributeInteger(string $Name, int $DefaultValue) { return true; }
	protected function RegisterAttributeFloat(string $Name, float $DefaultValue) { return true; }
	protected function RegisterAttributeString(string $Name, string $DefaultValue) { return true; }	
	protected function RegisterTimer(string $Ident, int $Milliseconds, string $ScriptText) { return 0; }
	protected function SetTimerInterval(string $Ident, int $Milliseconds) { return true; }
	protected function RegisterScript(string $Ident, string $Name, string $Content = '', int $Position = 0) { return 0; }
	protected function RegisterVariableBoolean(string $Ident, string $Name, string $Profile = '', int $Position = 0) { return 0; }
	protected function RegisterVariableInteger(string $Ident, string $Name, string $Profile = '', int $Position = 0) { return 0; }
	protected function RegisterVariableFloat(string $Ident, string $Name, string $Profile = '', int $Position = 0) { return 0; }
	protected function RegisterVariableString(string $Ident, string $Name, string $Profile = '', int $Position = 0) { return 0; }
	protected function UnregisterVariable(string $Ident) { return true; }
	protected function MaintainVariable(string $Ident, string $Name, int $Type, string $Profile, int $Position, bool $Keep) { return true; }
	protected function EnableAction(string $Ident) { return true; }
	protected function DisableAction(string $Ident) { return true; }
	protected function MaintainAction(string $Ident, bool $Keep) { return true; }
	protected function GetValue(string $Ident) { return ''; }
	protected function SetValue(string $Ident, $Value) { return true; }	
	protected function ReadPropertyBoolean(string $Name) { return true; }
	protected function ReadPropertyInteger(string $Name) { return 0; }
	protected function ReadPropertyFloat(string $Name) { return 0.0; }
	protected function ReadPropertyString(string $Name) { return ''; }
	protected function ReadAttributeBoolean(string $Name) { return true; }
	protected function ReadAttributeInteger(string $Name) { return 0; }
	protected function ReadAttributeFloat(string $Name) { return 0.0; }
	protected function ReadAttributeString(string $Name) { return ''; }	
	protected function WriteAttributeBoolean(string $Name, bool $Value) { return true; }
	protected function WriteAttributeInteger(string $Name, int $Value) { return true; }
	protected function WriteAttributeFloat(string $Name, float $Value) { return true; }
	protected function WriteAttributeString(string $Name, string $Value) { return true; }	
	protected function SendDataToParent(string $Data) { return ''; }
	protected function SendDataToChildren(string $Data) { return true; }
	protected function ConnectParent(string $ModuleID) { return true; }
	protected function RequireParent(string $ModuleID) { return true; }
	protected function ForceParent(string $ModuleID) { return true; }
	protected function SetStatus(int $Status) { return true; }
	protected function SetSummary(string $Summary) { return true; }
	protected function SetBuffer(string $Name, string $Data) { return true; }
	protected function GetBuffer(string $Name) { return ''; }
	protected function GetBufferList() { return []; }	
	protected function SendDebug(string $Message, string $Data, int $Format) { return true; }
	protected function RegisterMessage(int $SenderID, int $Message) { return true; }
	protected function UnregisterMessage(int $SenderID, int $Message) { return true; }
	protected function GetMessageList() { return []; }
	protected function RegisterReference(int $ID) { return true; }
	protected function UnregisterReference(int $ID) { return true; }
	protected function GetReferenceList() { return []; }
	public function MessageSink($TimeStamp, $SenderID, $Message, $Data) { return true; }
	public function ApplyChanges() { return true; }
	protected function LogMessage(string $Message, int $Type) { return true; }
	protected function SetReceiveDataFilter(string $RequiredRegexMatch) { return true; }
	public function ReceiveData($JSONString) { return true; }
	protected function SetForwardDataFilter(string $RequiredRegexMatch) { return true; }
	public function ForwardData($JSONString) { return ''; }
	public function RequestAction($Ident, $Value) { return true; }
	public function GetConfigurationForm() { return ''; }
	public function GetConfigurationForParent() { return ''; }
	public function Translate(string $Text) { return ''; }
}