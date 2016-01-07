-- based on山东高速视频监控设备联网技术规范
-- Bin.Wu@axis.com
-- version 1.0.1.0
-- 2016/01/07
-- protocol name: SDHW (for UDP) SDHWC (for TCP)
-- ================================================================================================
--	how to use lua
--	1 find "Global configuration" path:
--		1.1 run wireshark
--		1.2 Help->About wireshark
--		1.3 "Global configuration" is listed in "Folders" tab
--	2 put this lua file into "Global configuration" path
--	3 modify init.lua in "Global configuration" path
--		3.1 make sure "disable_lua" is set to false
--		3.2 goto file end, find and duplicate "dofile(DATA_DIR.."console.lua")"
--		3.3 change "console.lua" to this lua file name
--	4 close and restart wireshark. Go for Analyze->Enable Protocols. New protocol should be in the list.
-- ================================================================================================

function _Error(desc, range, pinfo, tree)
	pinfo.cols.info:set(desc)
	pinfo.cols.info:prepend("[X]")
	local errtree = tree:add(range, desc)
	errtree:add_expert_info(PI_MALFORMED, PI_ERROR);
end

function _Warning(desc, range, pinfo, tree)
	pinfo.cols.info:prepend("!")
	local errtree = tree:add(range, desc)
	errtree:add_expert_info(PI_MALFORMED, PI_WARN);
end
-- ------------------------------------------------------------------------------------------------
--  SDHW
-- ------------------------------------------------------------------------------------------------

-- msgtype for f_SDHW.msgtype
local MsgType ={
[0x0001] = "[REQ]ENCODER REG",
[0x0002] = "[REQ]DECODER REG",
[0x0003] = "[REQ]QUERY",
[0x0006] = "[REQ]REBOOT",
[0x0007] = "[REQ]TIME SYNC",
[0x0008] = "[REQ]NETWORK CONFIGURATION",
[0x0009] = "[REQ]PLAY STREAM",
[0x000A] = "[REQ]STOP STREAM",
[0x000B] = "[REQ]SET STREAM PARAM",
[0x000C] = "[REQ]PTZ",
[0x000D] = "[REQ]SET DI PARAM",
[0x000E] = "[REQ]SET DO PARAM",
[0x8004] = "[RSP]ENCODER QUERY",
[0x8005] = "[RSP]DECODER QUERY",
}
-- protocol fields
-- SDHW.identity ... can be used as filter
local p_SDHW = Proto("SDHW", "Shandong Highway")
local f_SDHW = p_SDHW.fields
f_SDHW.identity = ProtoField.uint32("SDHW.identity","Identity", base.HEX)
f_SDHW.version = ProtoField.uint16("SDHW.version","Version", base.HEX)
f_SDHW.msgtype = ProtoField.uint16("SDHW.msgtype","Msg Type", base.HEX, MsgType)
f_SDHW.msgsn = ProtoField.uint16("SDHW.msgsn","Msg SN")
f_SDHW.bodylength = ProtoField.uint16("SDHW.bodylength","Body Length")

-- construct tree
function p_SDHW.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol:set("SDHW")
	local buffer_len = buffer:len()
	local myProtoTree = tree:add(p_SDHW, buffer:range(0, buffer_len), "SDHW")
	local offset = 0

	-- check head length
	if buffer_len < 12 then
		_Error(string.format("Invalid Message Length(%d)", buffer_len), buffer:range(0, buffer_len), pinfo, myProtoTree)
		return
	end
	-- construct head tree
	local headtree = myProtoTree:add(buffer:range(offset, 12), "Msg Head")
	-- check identity
	local identity = buffer:range(offset, 4):uint()
	
	if identity ~= 0xE1DDF2DA then
		_Error(string.format("Invalid Message Identity(0x%08x)", identity), buffer:range(offset, 4), pinfo, headtree)
		return
	end
	headtree:add(f_SDHW.identity, buffer:range(offset, 4))
	offset = offset + 4
	-- versoin
	headtree:add(f_SDHW.version, buffer:range(offset, 2))
	offset = offset + 2
	-- msgtype
	local msgmethod = buffer:range(offset, 2):uint()
	local typetree = headtree:add(f_SDHW.msgtype, buffer:range(offset, 2))

	if nil == MsgType[msgmethod] then
		_Warning(string.format("Unknown Message Type(0x%04x)", msgmethod), buffer:range(offset, 2), pinfo, typetree)
	else
		pinfo.cols.info:set(MsgType[msgmethod])
	end
	offset = offset + 2
	-- msgsn
	headtree:add(f_SDHW.msgsn, buffer:range(offset, 2))
	offset = offset + 2
	-- body length
	local bodylength = buffer:range(offset, 2):uint()
	local bodylengthtree = headtree:add(f_SDHW.bodylength, buffer:range(offset, 2))
	offset = offset + 2

	if bodylength > 0 then
		-- body length check
		if buffer_len - offset ~= bodylength then
			_Warning(string.format("Bad Body Length(%d). Actually(%d)", bodylength, buffer_len - offset), buffer:range(offset), pinfo, bodylengthtree)
		end
		-- construct body tree
		local bodytree = myProtoTree:add(buffer:range(offset), "Msg Body")
		-- use existed dissector to deal with xml
		Dissector.get("xml"):call(buffer:range(offset):tvb(), pinfo, bodytree)
	end
end

-- register protocol fields for SDHW
local udp_port_table = DissectorTable.get("udp.port")
local SDHW_server_port=15000
local SDHW_device_port=15001
local SDHW_multicast_port=15002
udp_port_table:add(SDHW_server_port, p_SDHW)
udp_port_table:add(SDHW_device_port, p_SDHW)
udp_port_table:add(SDHW_multicast_port, p_SDHW)

-- ------------------------------------------------------------------------------------------------
--  SDHWC
--  In Info column, {MSGx?} means there are ?s msg in the packet,
--  ! means there is a warning for malformed content
--  X means there is an error for malformed content
-- ------------------------------------------------------------------------------------------------
-- msgtype for f_SDHWC.msgtype
local MsgTypeC_Control = 3
local MsgTypeC_Video = 16
local MsgTypeC_Audio = 32

local MsgTypeC ={
[MsgTypeC_Control] = "CONTROL_MSG",
[MsgTypeC_Video] = "VIDEO",
[MsgTypeC_Audio] = "AUDIO",
}
-- BOOL Value
local v_BOOL ={
[0x0] = "False",
[0x1] = "True",
}

-- cmd name
local CmdName ={
[0x01] = "START_VIDEO",
[0x02] = "STOP_VIDEO",
[0x09] = "GET_NETWORK_INFO",
[0x0C] = "REBOOT",
[0x0E] = "USER_LOGIN",
[0x18] = "GET_MULTICAST_INFO",
[0x20] = "GET_VIDEO_ENC_PARAM",
[0x21] = "ASK_FOR_KEYFRAME",
[0x25] = "COM_CMD_TO_DEVICE",
[0x26] = "COM_CMD_FROM_DEVICE",
[0x27] = "START_COM",
[0x2B] = "ALARM",
[0x71] = "START_AUDIO",
[0x72] = "STOP_AUDIO",
[0x81] = "GET_NETWORK_INFO_EXT",
[0xFFFF]= "STREAM",
}

-- stream format
local StreamFormat ={
[0x01100001]=MsgTypeC[MsgTypeC_Audio],
[0x328]="SIF",
[0x358]="HDI",
[0x368]="D1",
[0x3D8]="720P",
[0x3E8]="1080P",
[0xFFFF]= MsgTypeC[MsgTypeC_Control],
}
-- bitrate mode
local BitrateMode ={
[0] = "CBR",
[1] = "VBR"
}
-- protocol fields
-- SDHWC.msgtype ... can be used as filter
local p_SDHWC = Proto("SDHWC", "Shandong Highway Compatible")
local f_SDHWC = p_SDHWC.fields
f_SDHWC.msgtype = ProtoField.uint8("SDHWC.msgtype","Msg Type", base.HEX, MsgTypeC)
f_SDHWC.vfmark = ProtoField.uint8("SDHWC.vfmark","Video Frame Mark", base.HEX)
f_SDHWC.vfmark_fb = ProtoField.uint8("SDHWC.vfmark.fb","Is Frame Begin", base.HEX, v_BOOL, 0x01)
f_SDHWC.vfmark_fe = ProtoField.uint8("SDHWC.vfmark.fe","Is Frame End", base.HEX, v_BOOL, 0x02)
f_SDHWC.vfmark_kf = ProtoField.uint8("SDHWC.vfmark.kf","Is Key Frame", base.HEX, v_BOOL, 0x04)
f_SDHWC.reserved1 = ProtoField.uint16("SDHWC.reserved1", "Reserved1", base.HEX)
f_SDHWC.msglength = ProtoField.uint32("SDHWC.msglength", "Msg Length")
f_SDHWC.srcaddr = ProtoField.ipv4("SDHWC.srcaddr", "Src Addr")
f_SDHWC.dstaddr = ProtoField.ipv4("SDHWC.dstaddr", "Dst Addr")
f_SDHWC.avsn = ProtoField.uint32("SDHWC.avsn", "AV SN")
f_SDHWC.cmd = ProtoField.uint32("SDHWC.cmd", "Command", base.HEX, CmdName)
f_SDHWC.sformat = ProtoField.uint32("SDHWC.sformat", "Stream Format", base.HEX, StreamFormat)
f_SDHWC.subdevice = ProtoField.int32("SDHWC.subdevice", "Sub Device", base.DEC)
f_SDHWC.timestamp = ProtoField.uint32("SDHWC.timestamp", "Time Stamp", base.LOCAL)
f_SDHWC.identity = ProtoField.uint16("SDHWC.identity", "Identity", base.HEX)
f_SDHWC.reserved2 = ProtoField.uint16("SDHWC.reserved2", "Reserved2", base.HEX)

local msgtype

function treeadd(tree, field, range)
	if msgtype == MsgTypeC_Control then
		return tree:add(field, range)
	else
		return tree:add_le(field, range)
	end
end

function uintget(range)
	if msgtype == MsgTypeC_Control then
		return range:uint()
	else
		return range:le_uint()
	end 
		
end

-- cmd dissector
-- START_VIDEO
local TransportMode = {
[0x0001] = "TCP",
[0x0002] = "UDP Unicast",
[0x0200] = "UDP Multicast",
}
function deal_START_VIDEO(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 16 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 16), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Stream Format
	local format = uintget(buffer:range(offset, 4))
	tree:add(buffer:range(offset, 4), string.format("Stream Format: 0x%08x", format))
	offset = offset + 4
	-- Bitrate Mode
	local bitratemode = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("Bitrate Mode: 0x%02x", bitratemode))
	offset = offset + 1
	-- Quality
	local quality = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("Quality: %d (0x%02x)", quality, quality))
	offset = offset + 1
	-- Framerate Coefficient
	local framerateco = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("Framerate Coefficient: %d (0x%02x)", framerateco, framerateco))
	offset = offset + 1
	-- Encoding Reset
	local encodingreset = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("Encoding Reset: 0x%02x", encodingreset))
	offset = offset + 1
	-- Bitrate
	local bitrate = uintget(buffer:range(offset, 4))
	tree:add(buffer:range(offset, 4), string.format("Bitrate : %d (0x%08x)", bitrate, bitrate))
	offset = offset + 4
	-- Transport Mode
	local transportmode = uintget(buffer:range(offset, 4))
	if nil == TransportMode[transportmode] then
		_Error(string.format("Invalid Transport Mode(0x%08x)", transportmode), buffer:range(offset, 4), pinfo, tree)
		return
	else
		tree:add(buffer:range(offset, 4), string.format("Transport Mode : %s (0x%08x)", TransportMode[transportmode], transportmode))
		prototree:append_text(string.format("(via %s)", TransportMode[transportmode]))
		pinfo.cols.info:append(string.format("(via %s)", TransportMode[transportmode]))
	end	
	offset = offset + 4

end
-- STOP_VIDEO
function deal_STOP_VIDEO(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 1 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 1), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- flag
	local flag = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("flag: 0x%08x", flag))
	offset = offset + 1
end
-- GET_NETWORK_INFO
f_SDHWC.GET_NETWORK_INFO_ip = ProtoField.ipv4("SDHWC.GET_NETWORK_INFO_ip", "IP")
f_SDHWC.GET_NETWORK_INFO_netmask = ProtoField.ipv4("SDHWC.GET_NETWORK_INFO_netmask", "Subnet Mask")
f_SDHWC.GET_NETWORK_INFO_gateway = ProtoField.ipv4("SDHWC.GET_NETWORK_INFO_gateway", "Gateway")
f_SDHWC.GET_NETWORK_INFO_mac = ProtoField.ether("SDHWC.GET_NETWORK_INFO_mac", "MAC")
f_SDHWC.GET_NETWORK_INFO_runingtime = ProtoField.relative_time("SDHWC.GET_NETWORK_INFO_runingtime", "Running Time")

function deal_GET_NETWORK_INFO(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 28 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 28), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Version
	local version = uintget(buffer:range(offset, 4))
	tree:add(buffer:range(offset, 4), string.format("Version: 0x%08x", version))
	offset = offset + 4
	-- IP
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_ip, buffer:range(offset, 4))
	offset = offset + 4
	-- Subnet Mask
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_netmask, buffer:range(offset, 4))
	offset = offset + 4
	-- Gateway
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_gateway, buffer:range(offset, 4))
	offset = offset + 4
	-- MAC
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_mac, buffer:range(offset, 6))
	offset = offset + 6
	-- Reserved
	tree:add(buffer:range(offset, 2), string.format("Reserved: 0x%04x", uintget(buffer:range(offset, 2))))
	offset = offset + 2
	-- Running Time
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_runingtime, buffer:range(offset, 4))
	offset = offset + 4

	prototree:append_text("(RSP)")
	pinfo.cols.info:append("(RSP)")

end
-- REBOOT
function deal_REBOOT(buffer, pinfo, tree, prototree)
	-- never run here
end
-- USER_LOGIN
f_SDHWC.USER_LOGIN_ip = ProtoField.ipv4("SDHWC.USER_LOGIN_ip", "IP")

function deal_USER_LOGIN(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 12 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 12), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Prior
	local version = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("Prior: 0x%02x", version))
	offset = offset + 1
	-- Reserved
	tree:add(buffer:range(offset, 3), string.format("Reserved: 0x%06x", uintget(buffer:range(offset, 3))))
	offset = offset + 3
	-- User ID
	local userid = uintget(buffer:range(offset, 4))
	tree:add(buffer:range(offset, 4), string.format("User ID: 0x%08x", userid))
	offset = offset + 4
	-- IP
	treeadd(tree, f_SDHWC.USER_LOGIN_ip, buffer:range(offset, 4))
	offset = offset + 4

end
-- GET_MULTICAST_INFO
f_SDHWC.GET_MULTICAST_INFO_multicastip = ProtoField.ipv4("SDHWC.GET_MULTICAST_INFO_multicastip", "Multicast IP")
function deal_GET_MULTICAST_INFO(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 8 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 8), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Multicast IP
	treeadd(tree, f_SDHWC.GET_MULTICAST_INFO_multicastip, buffer:range(offset, 4))
	offset = offset + 4
	-- Port
	local port = uintget(buffer:range(offset, 2))
	tree:add(buffer:range(offset, 2), string.format("Port: %d", port))
	offset = offset + 2
	-- Reserved
	tree:add(buffer:range(offset, 2), string.format("Reserved: 0x%04x", uintget(buffer:range(offset, 2))))
	offset = offset + 2

	prototree:append_text("(RSP)")
	pinfo.cols.info:append("(RSP)")
end
-- GET_VIDEO_ENC_PARAM
f_SDHWC.GET_VIDEO_ENC_PARAM_format = ProtoField.uint32("SDHWC.GET_VIDEO_ENC_PARAM_format", "Stream Format", base.HEX, StreamFormat)
f_SDHWC.GET_VIDEO_ENC_PARAM_brmode = ProtoField.uint32("SDHWC.GET_VIDEO_ENC_PARAM_brmode", "Bitrate Mode", base.HEX, BitrateMode)
function deal_GET_VIDEO_ENC_PARAM(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 20 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 20), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Stream Format
	local sformat = uintget(buffer:range(offset, 4))
	treeadd(tree, f_SDHWC.GET_VIDEO_ENC_PARAM_format, buffer:range(offset, 4))
	offset = offset + 4
	-- Bitrate
	local bitrate = uintget(buffer:range(offset, 4))
	tree:add(buffer:range(offset, 4), string.format("Bitrate : %d Kbps(0x%08x)", bitrate, bitrate))
	offset = offset + 4
	-- I Frame Interval
	local interval = uintget(buffer:range(offset, 4))
	tree:add(buffer:range(offset, 4), string.format("I Frame Interval : %d (0x%08x)", interval, interval))
	offset = offset + 4
	-- Framerate
	local framerate = uintget(buffer:range(offset, 2))
	tree:add(buffer:range(offset, 2), string.format("Bitrate : %d fps(0x%04x)", framerate, framerate))
	offset = offset + 2
	-- Quality
	local quality = uintget(buffer:range(offset, 2))
	tree:add(buffer:range(offset, 2), string.format("Quality: %d (0x%04x)", quality, quality))
	offset = offset + 2
	-- Bitrate Mode
	local bitratemode = uintget(buffer:range(offset, 2))
	treeadd(tree, f_SDHWC.GET_VIDEO_ENC_PARAM_brmode, buffer:range(offset, 2))
	offset = offset + 2
	-- Reserved
	tree:add(buffer:range(offset, 2), string.format("Reserved: 0x%04x", uintget(buffer:range(offset, 2))))
	offset = offset + 2

	prototree:append_text("(RSP)")
	pinfo.cols.info:append("(RSP)")
end
-- ASK_FOR_KEYFRAME
function deal_ASK_FOR_KEYFRAME(buffer, pinfo, tree, prototree)
	-- never run here
end
-- COM
-- VIRTUAL_CAMARE
local VcOpCode={
[0x00] = "DEV_VIRTUAL_CAMERA_OP_UP",
[0x01] = "DEV_VIRTUAL_CAMERA_OP_DOWN",
[0x02] = "DEV_VIRTUAL_CAMERA_OP_LEFT",
[0x03] = "DEV_VIRTUAL_CAMERA_OP_RIGHT",
[0x04] = "DEV_VIRTUAL_CAMERA_OP_LEFT_UP",
[0x05] = "DEV_VIRTUAL_CAMERA_OP_LEFT_DOWN",
[0x06] = "DEV_VIRTUAL_CAMERA_OP_RIGHT_UP",
[0x07] = "DEV_VIRTUAL_CAMERA_OP_RIGHT_DOWN",
[0x08] = "DEV_VIRTUAL_CAMERA_OP_FOCUS_ADD",
[0x09] = "DEV_VIRTUAL_CAMERA_OP_FOCUS_DEC",
[0x0A] = "DEV_VIRTUAL_CAMERA_OP_IRIS_ADD",
[0x0B] = "DEV_VIRTUAL_CAMERA_OP_IRIS_DEC",
[0x0C] = "DEV_VIRTUAL_CAMERA_OP_ZOOM_ADD",
[0x0D] = "DEV_VIRTUAL_CAMERA_OP_ZOOM_DEC",
[0x0E] = "DEV_VIRTUAL_CAMERA_OP_PRESET_SET",
[0x0F] = "DEV_VIRTUAL_CAMERA_OP_PRESET_VIEW",
[0x10] = "DEV_VIRTUAL_CAMERA_OP_ALL_STOP",
[0x31] = "DEV_VIRTUAL_CAMERA_OP_AUX_CTRL_ON",
[0x32] = "DEV_VIRTUAL_CAMERA_OP_AUX_CTRL_OFF",
[0x33] = "DEV_VIRTUAL_CAMERA_OP_SET_CRUISE_START",
[0x34] = "DEV_VIRTUAL_CAMERA_OP_SET_CRUISE_END",
[0x35] = "DEV_VIRTUAL_CAMERA_OP_START_CRUISE",
[0x36] = "DEV_VIRTUAL_CAMERA_OP_STOP_CRUISE",
}
f_SDHWC._VIRTUAL_CAMARE_vcop = ProtoField.uint8("SDHWC.GET_VIDEO_ENC_PARAM_brmode", "Visual Camera Operation", base.HEX, VcOpCode)
function _deal_VIRTUAL_CAMARE(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len ~= 5 then
		_Error(string.format("Invalid Length(%d), Should be %d", buffer_len, 5), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Visual Camera Operation
	local vcop = uintget(buffer:range(offset, 1))
	local vcoptree = treeadd(tree, f_SDHWC._VIRTUAL_CAMARE_vcop, buffer:range(offset, 1))
	if nil == VcOpCode[vcop] then
		_Warning(string.format("Unknown Operation Code(0x%02x)", vcop), buffer:range(offset, 1), pinfo, typetree)
		prototree:append_text(string.format("(DEV_VIRTUAL_CAMERA_OP 0x%02x)", vcop))
		pinfo.cols.info:append(string.format("(DEV_VIRTUAL_CAMERA_OP 0x%02x)", vcop))
	else
		prototree:append_text(string.format("(%s)", VcOpCode[vcop]))
		pinfo.cols.info:append(string.format("(%s)", VcOpCode[vcop]))
	end
	offset = offset + 1
	-- Channel ID
	local channelid = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("Channel ID : %d", channelid))
	offset = offset + 1
	-- Operation Speed
	local opspeed = uintget(buffer:range(offset, 1))
	local opspeedtree = tree:add(buffer:range(offset, 1), string.format("Operation Speed : %d", channelid))
	if opspeed > 15 then
		_Warning(string.format("Invalid Operation Speed(%d), Should be ranged in [0, 15]", opspeed), buffer:range(offset, 1), pinfo, typetree)
	end
	offset = offset + 1
	-- Preset ID
	local presetid = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("Preset ID : %d", presetid))
	offset = offset + 1
	-- Reserved
	tree:add(buffer:range(offset, 1), string.format("Reserved: 0x%02x", uintget(buffer:range(offset, 1))))
	offset = offset + 1
end
-- VIDEO_ALARM

local VaOpCode={
[0x01] = "VIDEO_ALARM_OP_GET_ALARM",
[0x02] = "VIDEO_ALARM_OP_NOTIFY",
}

local VaAlarmType={
[0x01] = "ALARM ON",
[0x02] = "ALARM OFF",
[0x03] = "CURRENT ALARM",
}
f_SDHWC._VIDEO_ALARM_OP_alarmtype = ProtoField.uint32("SDHWC._VIDEO_ALARM_OP_alarmtype", "Alarm Type", base.HEX, VaAlarmType)
f_SDHWC._VIDEO_ALARM_OP_alarmevent_tamper = ProtoField.uint32("SDHWC._VIDEO_ALARM_OP_alarmevent.tamper","Is Tamper", base.HEX, v_BOOL, 0x01)
f_SDHWC._VIDEO_ALARM_OP_alarmevent_videolost = ProtoField.uint32("SDHWC._VIDEO_ALARM_OP_alarmevent.videolost","Is Video Lost", base.HEX, v_BOOL, 0x02)
f_SDHWC._VIDEO_ALARM_OP_alarmevent_motion = ProtoField.uint32("SDHWC._VIDEO_ALARM_OP_alarmevent.tamper","Is Motion", base.HEX, v_BOOL, 0x04)

function _deal_VIDEO_ALARM_OP_GET_ALARM_alarmevent(buffer, pinfo, tree, prototree)
	local alarmevent = uintget(buffer:range(0, 4))
	local alarmeventtree = tree:add(buffer:range(offset, 4), string.format("Alarm Event : 0x%08x", uintget(buffer:range(offset, 4))))
	local isTamper = 0
	local isVideoLost = 0
	local isMotion = 0
	treeadd(alarmeventtree, f_SDHWC._VIDEO_ALARM_OP_alarmevent_tamper, buffer:range(offset, 4))
	if  buffer:range(0, 4):bitfield(31) == 1 then
		isTamper = 1
		alarmeventtree:append_text(", Tamper")
	end	
	treeadd(alarmeventtree, f_SDHWC._VIDEO_ALARM_OP_alarmevent_videolost, buffer:range(offset, 4))
	if  buffer:range(0, 4):bitfield(30) == 1 then
		isVideoLost = 1
		vfmarktree:append_text(", Video Lost")
	end	
	treeadd(alarmeventtree, f_SDHWC._VIDEO_ALARM_OP_alarmevent_motion, buffer:range(offset, 4))
	if  buffer:range(0, 4):bitfield(29) == 1 then
		isMotion = 1
		vfmarktree:append_text(", Motion")
	end		
end
-- VIDEO_ALARM_OP_GET_ALARM
function deal_VIDEO_ALARM_OP_GET_ALARM(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	
	if isreq then
		tree:add(buffer:range(offset, 4), string.format("Channel ID: %d", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Alarm Type : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Alarm Event : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
 	else	
		tree:add(buffer:range(offset, 4), string.format("Channel ID: %d", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		local alarmtype = uintget(buffer:range(offset, 4))
		local alarmtypetree = treeadd(tree, f_SDHWC._VIDEO_ALARM_OP_alarmtype, buffer:range(offset, 4))
		if 0x00000003 ~= alarmtype then
			_Warning(string.format("Bad Alarm Type(0x%08x)", alarmtype), buffer:range(offset, 4), pinfo, alarmtypetree)
		end
		offset = offset + 4
		_deal_VIDEO_ALARM_OP_GET_ALARM_alarmevent(buffer:range(offset, 4):tvb(), pinfo, tree, prototree)
		offset = offset + 4
	end
end

-- deal_VIDEO_ALARM_OP_NOTIFY
function deal_VIDEO_ALARM_OP_NOTIFY(buffer, pinfo, tree, prototree, isreq)
	local offset = 0

	tree:add(buffer:range(offset, 4), string.format("Channel ID: %d", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	local alarmtype = uintget(buffer:range(offset, 4))
	local alarmtypetree = treeadd(tree, f_SDHWC._VIDEO_ALARM_OP_alarmtype, buffer:range(offset, 4))
	if 0x00000001 ~= alarmtype  or 0x00000002 ~= alarmtype then
		_Warning(string.format("Bad Alarm Type(0x%08x)", alarmtype), buffer:range(offset, 4), pinfo, alarmtypetree)
	end
	offset = offset + 4
	_deal_VIDEO_ALARM_OP_GET_ALARM_alarmevent(buffer:range(offset, 4):tvb(), pinfo, tree, prototree)
	offset = offset + 4
end

local VaOpCodeHandler={
[0x01] = deal_VIDEO_ALARM_OP_GET_ALARM,
[0x02] = deal_VIDEO_ALARM_OP_NOTIFY,
}
f_SDHWC._VIDEO_ALARM_vaop = ProtoField.uint8("SDHWC._VIDEO_ALARM_vaop", "Video Alarm Operation", base.HEX, VaOpCode)
function _deal_VIDEO_ALARM(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len ~= 13 then
		_Error(string.format("Invalid Length(%d), Should be %d", buffer_len, 33), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Video Alarm Operation
	local vaop = uintget(buffer:range(offset, 1))
	local vaoptree = treeadd(tree, f_SDHWC._VIDEO_ALARM_vaop, buffer:range(offset, 1))
	if nil == VaOpCode[vaop] then
		_Warning(string.format("Unknown Operation Code(0x%02x)", vaop), buffer:range(offset, 1), pinfo, typetree)
		prototree:append_text(string.format("(VIDEO_ALARM_OP 0x%02x)", vaop))
		pinfo.cols.info:append(string.format("(VIDEO_ALARM_OP 0x%02x)", vaop))
		return
	else
		prototree:append_text(string.format("(%s)", VaOpCode[vaop]))
		pinfo.cols.info:append(string.format("(%s)", VaOpCode[vaop]))
	end
	offset = offset + 1
	VaOpCodeHandler[vaop](buffer, pinfo, tree, prototree, isreq)

end
-- DIGITAL_IO
local DiOpCode={
[0x01] = "DIGITAL_IO_CFG",
[0x03] = "DIGITAL_IO_ALARM_STATE",
[0x04] = "DIGITAL_IO_SET_OUTPUT_STATE",
[0x05] = "DIGITAL_IO_OUTPUT_STATE",
}

-- DIGITAL_IO_CFG
function _deal_DIGITAL_IO_CFG(buffer, pinfo, tree, prototree, isreq)
	local offset = 0

	if isreq then
		local i = 0
		for i = 0, 7, 1 do
			tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
			offset = offset + 4
		end
	else
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("DI Reference : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("DO Reference : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("DI Enable : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 1), string.format("DO Num : %d", uintget(buffer:range(offset, 1))))
		offset = offset + 1
		tree:add(buffer:range(offset, 1), string.format("Reserved : 0x%02x", uintget(buffer:range(offset, 1))))
		offset = offset + 1
		tree:add(buffer:range(offset, 1), string.format("DI Num : %d", uintget(buffer:range(offset, 1))))
		offset = offset + 1
		tree:add(buffer:range(offset, 1), string.format("Reserved : 0x%02x", uintget(buffer:range(offset, 1))))
		offset = offset + 1
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
	end
end

-- DIGITAL_IO_ALARM_STATE
function _deal_DIGITAL_IO_ALARM_STATE(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	
	if isreq then
		local i = 0
		for i = 0, 7, 1 do
			tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
			offset = offset + 4
		end
	else
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Effective Alarm Mask : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Original Alarm Mask : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Effective Alarm : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Original Alarm : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
	end
end

-- DIGITAL_IO_SET_OUTPUT_STATE
function _deal_DIGITAL_IO_SET_OUTPUT_STATE(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	
	tree:add(buffer:range(offset, 4), string.format("DI Alarm Effectivity Mask : 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	tree:add(buffer:range(offset, 4), string.format("DI Alarm Enablity Mask : 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	tree:add(buffer:range(offset, 4), string.format("DO Alarm Effectivity Mask : 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	tree:add(buffer:range(offset, 4), string.format("DO Alarm Enablity Mask : 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
end

-- DIGITAL_IO_OUTPUT_STATE
function _deal_DIGITAL_IO_OUTPUT_STATE(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	
	if isreq then
		local i = 0
		for i = 0, 7, 1 do
			tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
			offset = offset + 4
		end
	else	
		tree:add(buffer:range(offset, 4), string.format("DI Alarm Effectivity Mask : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("DI Alarm Enablity Mask : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("DO Alarm Effectivity Mask : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("DO Alarm Enablity Mask : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
		tree:add(buffer:range(offset, 4), string.format("Reserved : 0x%08x", uintget(buffer:range(offset, 4))))
		offset = offset + 4
	end
end
local DiOpCodeHandler={
[0x01] = _deal_DIGITAL_IO_CFG,
[0x03] = _deal_DIGITAL_IO_ALARM_STATE,
[0x04] = _deal_DIGITAL_IO_SET_OUTPUT_STATE,
[0x05] = _deal_DIGITAL_IO_OUTPUT_STATE,
}
f_SDHWC._DIGITAL_IO_diop = ProtoField.uint8("SDHWC._DIGITAL_IO_diop", "Digital IO Operation", base.HEX, DiOpCode)

function _deal_DIGITAL_IO(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len ~= 33 then
		_Error(string.format("Invalid Length(%d), Should be %d", buffer_len, 33), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Digital IO Operation
	local diop = uintget(buffer:range(offset, 1))
	local dioptree = treeadd(tree, f_SDHWC._DIGITAL_IO_diop, buffer:range(offset, 1))
	if nil == DiOpCode[diop] then
		_Warning(string.format("Unknown Operation Code(0x%02x)", diop), buffer:range(offset, 1), pinfo, typetree)
		prototree:append_text(string.format("(DIGITAL_IO_OP 0x%02x)", diop))
		pinfo.cols.info:append(string.format("(DIGITAL_IO_OP 0x%02x)", diop))
		return
	else
		prototree:append_text(string.format("(%s)", DiOpCode[diop]))
		pinfo.cols.info:append(string.format("(%s)", DiOpCode[diop]))
	end
	offset = offset + 1
	DiOpCodeHandler[diop](buffer, pinfo, tree, prototree, isreq)
end
-- SYNC_TIME
f_SDHWC.SYNC_TIME_gmttime = ProtoField.absolute_time("SDHWC.SYNC_TIME_gmttime", "GMT Time")

function _deal_SYNC_TIME(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len ~= 9 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 9), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Operation
	local op = uintget(buffer:range(offset, 1))
	local optree = tree:add(buffer:range(offset, 1), string.format("Operation : 0x%02x", op))
	if 2 ~= op then
		_Warning(string.format("Unknown Operation Code(0x%02x)", op), buffer:range(offset, 1), pinfo, optree)
	end
	offset = offset + 1
	-- GMT TIME
	treeadd(tree, f_SDHWC.SYNC_TIME_gmttime, buffer:range(offset, 4))
	offset = offset + 4
	-- Time Zone
	tree:add(buffer:range(offset, 4), string.format("Time Zone : %d", uintget(buffer:range(offset, 4))))
	offset = offset + 4
end

-- UNKNOWN
function _deal_UNKOWN_COM_CMD(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	local buffer_len = buffer:len()

	if buffer_len < 20 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 20), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
end
local ComSubFuncCodeHandler = {
[0x20] = _deal_VIRTUAL_CAMARE,
[0xEE] = _deal_VIDEO_ALARM,
[0xF3] = _deal_DIGITAL_IO,
[0xF7] = _deal_SYNC_TIME,
}
local ComSubFuncCodeName = {
[0x20] = "VIRTUAL_CAMARE",
[0xEE] = "VIDEO_ALARM",
[0xF3] = "DIGITAL_IO",
[0xF7] = "SYNC_TIME",
}

-- COM_CMD
f_SDHWC.COM_subfunc = ProtoField.uint8("SDHWC.COM_subfunc", "Sub Function", base.HEX, ComSubFuncCodeName)
function deal_COM_CMD(buffer, pinfo, tree, prototree, isreq)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len > 1024 then
		_Error(string.format("Invalid Length(%d), Should be at most %d", buffer_len, 1024), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Start Flag
	local startflag = uintget(buffer:range(offset, 1))
	local startflagtree = tree:add(buffer:range(offset, 1), string.format("Start Flag : 0x%02x", startflag))
	if 0x55 ~= startflag then
		_Error(string.format("Invalid Start Flag(0x%02x)", startflag), buffer:range(offset, 1), pinfo, startflagtree)
		return
	end
	offset = offset + 1
	-- Sub Function
	local subfunc = uintget(buffer:range(offset, 1))
	local subfunctree = treeadd(tree, f_SDHWC.COM_subfunc, buffer:range(offset, 1))
	if nil == ComSubFuncCodeName[subfunc] then
		_Warning(string.format("Unknown Sub Function(0x%02x)", subfunc), buffer:range(offset, 1), pinfo, subfunctree)
		pinfo.cols.info:append(string.format("(0x%02x)", subfunc))
		prototree:append_text(string.format("(0x%02x)", subfunc))

	end
	offset = offset + 1
	-- Cmd Length
	local cmdlength = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("Cmd Length : %d", cmdlength))
	if cmdlength + 5 > buffer_len then
		_Error(string.format("Invalid Cmd Length(%d)", cmdlength), buffer:range(offset, 1), pinfo, tree)
		return
	end
	offset = offset + 1
	-- calculate checksum
	local checksum_result = 0
	local i = 0
	for i = 0, cmdlength - 1, 1
	do
		checksum_result = checksum_result + buffer:range(offset + i, 1):uint()
	end

	if nil ~= ComSubFuncCodeHandler[subfunc] then
		ComSubFuncCodeHandler[subfunc](buffer:range(offset, cmdlength):tvb(), pinfo, tree, prototree, isreq)
	else
		_deal_UNKOWN_COM_CMD(buffer:range(offset, cmdlength):tvb(), pinfo, tree, prototree, isreq)
	end
	
	offset = offset + cmdlength
	-- Checksum
	local checksum = uintget(buffer:range(offset, 1))
	local checksumtree = tree:add(buffer:range(offset, 1), string.format("Checksum : 0x%02x", checksum))
	if checksum_result ~= checksum then
		_Warning(string.format("Bad Checksum(0x%02x), Should be(0x%02x)", checksum, checksum_result), buffer:range(offset, 1), pinfo, checksumtree)
	end
	offset = offset + 1
	-- End Flag
	local endflag = uintget(buffer:range(offset, 1))
	local endflagtree = tree:add(buffer:range(offset, 1), string.format("End Flag : 0x%02x", endflag))
	if 0xAA ~= endflag then
		_Error(string.format("Invalid End Flag(0x%02x)", endflag), buffer:range(offset, 1), pinfo, endflagtree)
		return
	end
	offset = offset + 1

end
function deal_COM_CMD_REQ(buffer, pinfo, tree, prototree)
	deal_COM_CMD(buffer, pinfo, tree, prototree, 1)
end
function deal_COM_CMD_RSP(buffer, pinfo, tree, prototree)
	deal_COM_CMD(buffer, pinfo, tree, prototree, 0)
end
-- START_COM
function deal_START_COM(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 28 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 28), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Port
	tree:add(buffer:range(offset, 4), string.format("Port: %d", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	-- Speed
	tree:add(buffer:range(offset, 4), string.format("Speed: %d", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	-- Width
	tree:add(buffer:range(offset, 4), string.format("Width: %d", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	-- End
	tree:add(buffer:range(offset, 4), string.format("End: 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	-- Check
	tree:add(buffer:range(offset, 4), string.format("Check: 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	-- Reserved
	tree:add(buffer:range(offset, 4), string.format("Reserved: 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4
	-- Mode
	tree:add(buffer:range(offset, 4), string.format("Mode: 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4

end
-- ALARM
function deal_ALARM(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 4 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 28), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Effective Alarm Mask
	tree:add(buffer:range(offset, 4), string.format("Effective Alarm Mask : 0x%08x", uintget(buffer:range(offset, 4))))
	offset = offset + 4

end
-- START_AUDIO
function deal_START_AUDIO(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 1 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 1), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- flag
	local flag = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("flag: 0x%08x", flag))
	offset = offset + 1
end
-- STOP_AUDIO
function deal_STOP_AUDIO(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 1 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 1), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- flag
	local flag = uintget(buffer:range(offset, 1))
	tree:add(buffer:range(offset, 1), string.format("flag: 0x%08x", flag))
	offset = offset + 1
end
-- GET_NETWORK_INFO_EXT
function deal_GET_NETWORK_INFO_EXT(buffer, pinfo, tree, prototree)
	local offset = 0
	local buffer_len = buffer:len()
	if buffer_len < 28 then
		_Error(string.format("Invalid Length(%d), Should be at least %d", buffer_len, 28), buffer:range(0, buffer_len), pinfo, tree)
		return
	end
	-- Version
	local version = uintget(buffer:range(offset, 4))
	tree:add(buffer:range(offset, 4), string.format("Version: 0x%08x", version))
	offset = offset + 4
	-- IP
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_ip, buffer:range(offset, 4))
	offset = offset + 4
	-- Subnet Mask
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_netmask, buffer:range(offset, 4))
	offset = offset + 4
	-- Gateway
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_gateway, buffer:range(offset, 4))
	offset = offset + 4
	-- MAC
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_mac, buffer:range(offset, 6))
	offset = offset + 6
	-- Reserved
	tree:add(buffer:range(offset, 2), string.format("Reserved: 0x%04x", uintget(buffer:range(offset, 2))))
	offset = offset + 2
	-- Running Time
	treeadd(tree, f_SDHWC.GET_NETWORK_INFO_runingtime, buffer:range(offset, 4))
	offset = offset + 4
	-- Device Type
	local devicetype = uintget(buffer:range(offset, 4))
	tree:add(buffer:range(offset, 4), string.format("Device Type: 0x%08x",devicetype))
	offset = offset + 4

	prototree:append_text("(RSP)")
	pinfo.cols.info:append("(RSP)")

end-- STREAM
function deal_STREAM(buffer, pinfo, tree, prototree)
end

-- cmd dissector
local CmdHandler = {
[0x01] = deal_START_VIDEO,
[0x02] = deal_STOP_VIDEO,
[0x09] = deal_GET_NETWORK_INFO,
[0x0C] = deal_REBOOT,
[0x0E] = deal_USER_LOGIN,
[0x18] = deal_GET_MULTICAST_INFO,
[0x20] = deal_GET_VIDEO_ENC_PARAM,
[0x21] = deal_ASK_FOR_KEYFRAME,
[0x25] = deal_COM_CMD_REQ,
[0x26] = deal_COM_CMD_RSP,
[0x27] = deal_START_COM,
[0x2B] = deal_ALARM,
[0x71] = deal_START_AUDIO,
[0x72] = deal_STOP_AUDIO,
[0x81] = deal_GET_NETWORK_INFO_EXT,
[0xFFFF]= deal_STREAM,
}
-- construct tree
function SDHWC_dissector(buffer, pinfo, tree, count)
	pinfo.cols.protocol:set("SDHWC")
	local buffer_len = buffer:len()
	local myProtoTree = tree:add(p_SDHWC, buffer:range(0, buffer_len), string.format("SDHWC[%d]", count))
	local offset = 0
	-- check head length
	if buffer_len < 40 then
		_Error(string.format("Invalid Message Length(%d)", buffer_len), buffer:range(0, buffer_len), pinfo, myProtoTree)
		return
	end
	-- construct head tree
	local headtree = treeadd(myProtoTree, buffer:range(offset, 40), "Msg Head")

	-- msgtype
	msgtype = buffer:range(offset, 1):uint()
	local typetree = treeadd(headtree, f_SDHWC.msgtype, buffer:range(offset, 1))
	if nil == MsgTypeC[msgtype] then
		_Error(string.format("Unknown Message Type(0x%02x)", msgtype), buffer:range(offset, 1), pinfo, typetree)
		return
	end
	offset = offset + 1
	-- vfmark
	local vfmarktree = treeadd(headtree, f_SDHWC.vfmark, buffer:range(offset, 1))
	local isFB = 0
	local isFE = 0
	local isKF = 0
	
	if msgtype == MsgTypeC_Video then
		treeadd(vfmarktree, f_SDHWC.vfmark_fb, buffer:range(offset, 1))
		if  buffer:range(offset, 1):bitfield(7) == 1 then
			isFB = 1
			vfmarktree:append_text(", Frame Begin")
		end	
		treeadd(vfmarktree, f_SDHWC.vfmark_fe, buffer:range(offset, 1))
		if  buffer:range(offset, 1):bitfield(6) == 1 then
			isFE = 1
			vfmarktree:append_text(", Frame End")
		end	
		treeadd(vfmarktree, f_SDHWC.vfmark_kf, buffer:range(offset, 1))
		if  buffer:range(offset, 1):bitfield(5) == 1 then
			isKF = 1
			vfmarktree:append_text(", Key Frame")
		end	
	elseif uintget(buffer:range(offset, 1)) ~= 0 then
		_Warning(string.format("Should Be 0x00 in %s", MsgTypeC[msgtype]), buffer:range(offset, 1), pinfo, vfmarktree)
	end
	offset = offset + 1

	-- reserved1
	treeadd(headtree, f_SDHWC.reserved1, buffer:range(offset, 2))
	offset = offset + 2
	-- msg length
	local msglength = uintget(buffer:range(offset, 4))
	local msglengthtree = treeadd(headtree, f_SDHWC.msglength, buffer:range(offset, 4))
	-- body length check
	if buffer_len < msglength then
		_Warning(string.format("Bad Msg Length(%d). Actual(%d)", msglength, buffer_len), buffer:range(0), pinfo, msglengthtree)
	end
	if msgtype == MsgTypeC_Video and msglength > 2048 then
		_Warning(string.format("Msg Length %d should NOT over 2048 in %s", msglength, MsgTypeC[msgtype]), buffer:range(offset, 4), pinfo, msglengthtree)
	end
	if msgtype == MsgTypeC_Audio and msglength > 1024 then
		_Warning(string.format("Msg Length %d should NOT over 1024 in %s", msglength, MsgTypeC[msgtype]), buffer:range(offset, 4), pinfo, msglengthtree)
	end
	offset = offset + 4
	
	-- srcaddr
	treeadd(headtree, f_SDHWC.srcaddr, buffer:range(offset, 4))
	offset = offset + 4

	-- dstaddr
	treeadd(headtree, f_SDHWC.dstaddr, buffer:range(offset, 4))
	offset = offset + 4

	-- avsn
	local avsntree = treeadd(headtree, f_SDHWC.avsn, buffer:range(offset, 4))
	local avsn = uintget(buffer:range(offset, 4))
	if uintget(buffer:range(offset, 4)) ~= 0 and msgtype ~= MsgTypeC_Video and msgtype ~= MsgTypeC_Audio then
		_Warning(string.format("Should be 0x00000000 in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), pinfo, avsntree)
	end
	offset = offset + 4

	-- cmd
	local cmd = uintget(buffer:range(offset, 4))
	local cmdtree = treeadd(headtree, f_SDHWC.cmd, buffer:range(offset, 4))
	local tmpcmdname
	if cmd ~= 0xFFFF and msgtype ~= MsgTypeC_Control then
		_Warning(string.format("Should be 0x0000FFFF in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), pinfo, cmdtree)
	end
	if nil == CmdName[cmd] then
		_Warning(string.format("Unknown Command (0x%08x)", cmd), buffer:range(offset, 4), pinfo, cmdtree)
		tmpcmdname = string.format("0x%08x", cmd)
	else
		tmpcmdname = string.format("%s", CmdName[cmd])
	end
	if msgtype ~= MsgTypeC_Control then
		tmpcmdname = string.format("%s <%d>", tmpcmdname, avsn)
		if msgtype == MsgTypeC_Video then
			if isKF == 1 then
				tmpcmdname = string.format("%s KeyFrame", tmpcmdname)
			end
			if isFB == 1 then
				tmpcmdname = string.format("%s FrameBegin", tmpcmdname)
			end
			if isFE == 1 then
				tmpcmdname = string.format("%s FrameEnd", tmpcmdname)
			end

		end
		-- eg [VIDEO STREAM], [VIDEO 0x00000001]
		tmpcmdname = string.format("[%s %s]", MsgTypeC[msgtype], tmpcmdname)
	else
		tmpcmdname = string.format("[%s]", tmpcmdname)
	end

	pinfo.cols.info:append(tmpcmdname)
	myProtoTree:append_text(tmpcmdname)

	offset = offset + 4

	-- sformat
	local sformat = uintget(buffer:range(offset, 4))
	local sformattree = treeadd(headtree, f_SDHWC.sformat, buffer:range(offset, 4))
	if sformat ~= 0xFFFF and msgtype == MsgTypeC_Control then
		_Warning(string.format("Should be 0x0000FFFF in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), pinfo, sformattree)
	end
	if sformat ~= 0x01100001 and msgtype == MsgTypeC_Audio then
		_Warning(string.format("Should be 0x01100001 in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), pinfo, sformattree)
	end
	offset = offset + 4

	-- subdevice
	treeadd(headtree, f_SDHWC.subdevice, buffer:range(offset, 4))
	offset = offset + 4

	-- timestamp
	local timestamp = uintget(buffer:range(offset, 4))
	local timestamptree = treeadd(headtree, f_SDHWC.timestamp, buffer:range(offset, 4))
	if timestamp ~= 0x0 and msgtype == MsgTypeC_Control then
		_Warning(string.format("Should be 0x00000000 in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), pinfo, timestamptree)
	end
	offset = offset + 4

	-- identity
	local identity = uintget(buffer:range(offset, 2))
	if 0x3455 ~= identity then
		_Error(string.format("Invalid Message Identity(0x%04x)", identity), buffer:range(offset, 2), pinfo, headtree)
		return
	end
	treeadd(headtree, f_SDHWC.identity, buffer:range(offset, 2))
	offset = offset + 2

	-- reserved2
	treeadd(headtree, f_SDHWC.reserved2, buffer:range(offset, 2))
	offset = offset + 2

	if msglength > 40 then
		-- construct body tree
		local bodytree = treeadd(myProtoTree, buffer:range(offset, msglength - 40), "Msg Body")
		-- call corresponding command dissector
		if nil ~= CmdHandler[cmd] then
			CmdHandler[cmd](buffer:range(offset, msglength - 40):tvb(), pinfo, bodytree, myProtoTree)
		end
	end

	if msglength < buffer_len then
		SDHWC_dissector(TvbRange.tvb(buffer:range(msglength)), pinfo, tree, count + 1)
	elseif count > 0 then  
		pinfo.cols.info:prepend(string.format("{MSGx%d} ", count + 1))
	end
end

last_tcp_port = 9000
function p_SDHWC.dissector(buffer, pinfo, tree)
	pinfo.cols.info:set("")
	SDHWC_dissector(buffer, pinfo, tree, 0)
	if pinfo.src_port ~= last_tcp_port then
		last_tcp_port = pinfo.src_port
		udp_port_table:add(last_tcp_port, p_SDHWC)
	end
end

-- register protocol fields for SDHWC
local tcp_port_table = DissectorTable.get("tcp.port")
local SDHWC_server_port=9000
local SDHWC_audio_port=9003
tcp_port_table:add(SDHWC_server_port, p_SDHWC)
udp_port_table:add(SDHWC_audio_port, p_SDHWC)
