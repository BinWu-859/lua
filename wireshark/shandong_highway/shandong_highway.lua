-- based on山东高速视频监控设备联网技术规范
-- Bin.Wu@axis.com
-- versioin 1.0.0.11
-- 2016/01/05
-- protocal name: SDHW (for UDP) SDHWC (for TCP)
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
	local errtree = tree:add(range, desc)
	errtree:add_expert_info(PI_MALFORMED, PI_ERROR);
end

function _Warning(desc, range, pinfo, tree)
	if pinfo ~= nil then
		pinfo.cols.info:set(desc)
	end
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
		_Error(string.format("Invalid Message Identity(0x%08X)", identity), buffer:range(offset, 4), pinfo, headtree)
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
		_Warning(string.format("Unknown Message Type(0x%04X)", msgmethod), buffer:range(offset, 2), pinfo, typetree)
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
			_Warning(string.format("Bad Body Length(%d). Actually(%d)", bodylength, buffer_len - offset), buffer:range(offset), nil, bodylengthtree)
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
-- ------------------------------------------------------------------------------------------------
-- msgtype for f_SDHWC.msgtype
local MsgTypeC_Control = 3
local MsgTypeC_Video = 16
local MsgTypeC_Audio = 32

local MsgTypeC ={
[MsgTypeC_Control] = "CONTROL MSG",
[MsgTypeC_Video] = "VIDEO STREAM",
[MsgTypeC_Audio] = "AUDIO STREAM",
}
-- BOOL Value
local v_BOOL ={
[0x0] = "False",
[0x1] = "True",
}

-- cmd name
local CmdName ={
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
-- construct tree
function p_SDHWC.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol:set("SDHWC")

	local buffer_len = buffer:len()
	local myProtoTree = tree:add(p_SDHWC, buffer:range(0, buffer_len), "SDHWC")
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
		_Warning(string.format("Unknown Message Type(0x%02X)", msgtype), buffer:range(offset, 2), pinfo, typetree)
	else
		pinfo.cols.info:set(MsgTypeC[msgtype])
	end

	offset = offset + 1
	-- vfmark
	local vfmarktree = treeadd(headtree, f_SDHWC.vfmark, buffer:range(offset, 1))

	if msgtype == MsgTypeC_Video then
		treeadd(vfmarktree, f_SDHWC.vfmark_fb, buffer:range(offset, 1))
		if  buffer:range(offset, 1):bitfield(7) == 1 then
			vfmarktree:append_text(", Frame Begin")
		end	
		treeadd(vfmarktree, f_SDHWC.vfmark_fe, buffer:range(offset, 1))
		if  buffer:range(offset, 1):bitfield(6) == 1 then
			vfmarktree:append_text(", Frame End")
		end	
		treeadd(vfmarktree, f_SDHWC.vfmark_kf, buffer:range(offset, 1))
		if  buffer:range(offset, 1):bitfield(5) == 1 then
			vfmarktree:append_text(", Key Frame")
		end	
	elseif uintget(buffer:range(offset, 1)) ~= 0 then
		_Warning(string.format("Should Be 0x00 in %s", MsgTypeC[msgtype]), buffer:range(offset, 1), nil, vfmarktree)
	end
	offset = offset + 1

	-- reserved1
	treeadd(headtree, f_SDHWC.reserved1, buffer:range(offset, 2))
	offset = offset + 2
	-- msg length
	local msglength = uintget(buffer:range(offset, 4))
	local msglengthtree = treeadd(headtree, f_SDHWC.msglength, buffer:range(offset, 4))
		-- body length check
	if buffer_len ~= msglength then
		_Warning(string.format("Bad Msg Length(%d). Actual(%d)", msglength, buffer_len), buffer:range(0), nil, msglengthtree)
	end
	if msgtype == MsgTypeC_Video and msglength > 2048 then
		_Warning(string.format("Msg Length %d should NOT over 2048 in %s", msglength, MsgTypeC[msgtype]), buffer:range(offset, 4), nil, msglengthtree)
	end
	if msgtype == MsgTypeC_Audio and msglength > 1024 then
		_Warning(string.format("Msg Length %d should NOT over 1024 in %s", msglength, MsgTypeC[msgtype]), buffer:range(offset, 4), nil, msglengthtree)
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
	if uintget(buffer:range(offset, 4)) ~= 0 and msgtype ~= MsgTypeC_Video and msgtype ~= MsgTypeC_Audio then
		_Warning(string.format("Should be 0x00000000 in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), nil, avsntree)
	end
	offset = offset + 4

	-- cmd
	local cmd = uintget(buffer:range(offset, 4))
	local cmdtree = treeadd(headtree, f_SDHWC.cmd, buffer:range(offset, 4))
	if cmd ~= 0xFFFF and msgtype ~= MsgTypeC_Control then
		_Warning(string.format("Should be 0x0000FFFF in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), nil, cmdtree)
	end
	offset = offset + 4

	-- sformat
	local sformat = uintget(buffer:range(offset, 4))
	local sformattree = treeadd(headtree, f_SDHWC.sformat, buffer:range(offset, 4))
	if sformat ~= 0xFFFF and msgtype == MsgTypeC_Control then
		_Warning(string.format("Should be 0x0000FFFF in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), nil, sformattree)
	end
	if sformat ~= 0x01100001 and msgtype == MsgTypeC_Audio then
		_Warning(string.format("Should be 0x01100001 in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), nil, sformattree)
	end
	offset = offset + 4

	-- subdevice
	treeadd(headtree, f_SDHWC.subdevice, buffer:range(offset, 4))
	offset = offset + 4

	-- timestamp
	local timestamp = uintget(buffer:range(offset, 4))
	local timestamptree = treeadd(headtree, f_SDHWC.timestamp, buffer:range(offset, 4))
	if timestamp ~= 0x0 and msgtype == MsgTypeC_Control then
		_Warning(string.format("Should be 0x00000000 in %s", MsgTypeC[msgtype]), buffer:range(offset, 4), nil, timestamptree)
	end
	offset = offset + 4

	-- identity
	local identity = uintget(buffer:range(offset, 2))
	if 0x3455 ~= identity then
		_Error(string.format("Invalid Message Identity(0x%04X)", identity), buffer:range(offset, 2), pinfo, headtree)
		return
	end
	treeadd(headtree, f_SDHWC.identity, buffer:range(offset, 2))
	offset = offset + 2

	-- reserved2
	treeadd(headtree, f_SDHWC.reserved2, buffer:range(offset, 2))
	offset = offset + 2

	
	if msglength > 40 then
		-- construct body tree
		local bodytree = treeadd(myProtoTree, buffer:range(offset), "Msg Body")
		-- use existed dissector to deal with xml
--		Dissector.get("xml"):call(buffer:range(offset):tvb(), pinfo, bodytree)
	end
end

-- register protocol fields for SDHWC
local tcp_port_table = DissectorTable.get("tcp.port")
local SDHWC_server_port=9000
local SDHWC_audio_port=9003
tcp_port_table:add(SDHWC_server_port, p_SDHWC)
udp_port_table:add(SDHWC_audio_port, p_SDHWC)
