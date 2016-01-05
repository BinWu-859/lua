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
	local identity = buffer:range(offset,4):uint()

	if identity ~= 0xE1DDF2DA then
		_Error(string.format("Invalid Message Identity(0x%08X)", identity), buffer:range(offset, 4), pinfo, headtree)
		return
	end
	headtree:add(f_SDHW.identity, buffer:range(offset,4))
	offset = offset + 4
	-- versoin
	headtree:add(f_SDHW.version, buffer:range(offset,2))
	offset = offset + 2
	-- msgtype
	local msgmethod = buffer:range(offset,2):uint()
	local typetree = headtree:add(f_SDHW.msgtype, buffer:range(offset,2))

	if nil == MsgType[msgmethod] then
		_Warning(string.format("Unknown Message Type(0x%04X)", msgmethod), buffer:range(offset,2), pinfo, typetree)
	else
		pinfo.cols.info:set(MsgType[msgmethod])
	end
	offset = offset + 2
	-- msgsn
	headtree:add(f_SDHW.msgsn, buffer:range(offset,2))
	offset = offset + 2
	-- body length
	local bodylength = buffer:range(offset,2):uint()
	local bodylengthtree = headtree:add(f_SDHW.bodylength, buffer:range(offset,2))
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
local MsgType_Control = 3
local MsgType_Video = 16
local MsgType_Audio = 32

local c_MsgType ={
[MsgType_Control] = "CONTROL MSG",
[MsgType_Video] = "VIDEO STREAM",
[MsgType_Audio] = "AUDIO STREAM",
}
-- BOOL Value
local v_BOOL ={
[0x0] = "False",
[0x1] = "True",
}

-- protocol fields
-- SDHWC.msgtype ... can be used as filter
local p_SDHWC = Proto("SDHWC", "Shandong Highway Compatible")
local f_SDHWC = p_SDHWC.fields
f_SDHWC.msgtype = ProtoField.uint8("SDHWC.msgtype","Msg Type", base.HEX, c_MsgType)
f_SDHWC.vfmark = ProtoField.uint8("SDHWC.vfmark","Video Frame Mark", base.HEX)
f_SDHWC.vfmark_fb = ProtoField.uint8("SDHWC.vfmark.fb","Is Frame Begin", base.HEX, v_BOOL, 0x01)
f_SDHWC.vfmark_fe = ProtoField.uint8("SDHWC.vfmark.fe","Is Frame End", base.HEX, v_BOOL, 0x02)
f_SDHWC.vfmark_kf = ProtoField.uint8("SDHWC.vfmark.kf","Is Key Frame", base.HEX, v_BOOL, 0x04)
f_SDHWC.reserved1 = ProtoField.uint16("SDHWC.reserved1", "Reserved", base.HEX)
f_SDHWC.msglength = ProtoField.uint32("SDHWC.msglength", "Msg Length")
f_SDHWC.srcaddr = ProtoField.ipv4("SDHWC.srcaddr", "Src Addr")
f_SDHWC.dstaddr = ProtoField.ipv4("SDHWC.dstaddr", "Dst Addr")
-- construct tree
function p_SDHWC.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol:set("SDHWC")

	local buffer_len = buffer:len()
	local myProtoTree = tree:add(p_SDHW, buffer:range(0, buffer_len), "SDHWC")
	local offset = 0

	-- check head length
	if buffer_len < 40 then
		_Error(string.format("Invalid Message Length(%d)", buffer_len), buffer:range(0, buffer_len), pinfo, myProtoTree)
		return
	end
	-- construct head tree
	local headtree = myProtoTree:add(buffer:range(offset, 40), "Msg Head")

	-- msgtype
	local msgtype = buffer:range(offset,1):uint()
	local typetree = headtree:add(f_SDHWC.msgtype, buffer:range(offset,1))
	if nil == c_MsgType[msgtype] then
		_Warning(string.format("Unknown Message Type(0x%02X)", msgtype), buffer:range(offset, 2), pinfo, typetree)
	else
		pinfo.cols.info:set(c_MsgType[msgtype])
	end

	offset = offset + 1
	-- vfmark
	local vfmarktree = headtree:add(f_SDHWC.vfmark, buffer:range(offset,1))

	if msgtype == MsgType_Video then
		vfmarktree:add(f_SDHWC.vfmark_fb, buffer:range(offset,1))
		if  buffer:range(offset,1):bitfield(7) == 1 then
			vfmarktree:append_text(", Frame Begin")
		end	
		vfmarktree:add(f_SDHWC.vfmark_fe, buffer:range(offset,1))
		if  buffer:range(offset,1):bitfield(6) == 1 then
			vfmarktree:append_text(", Frame End")
		end	
		vfmarktree:add(f_SDHWC.vfmark_kf, buffer:range(offset,1))
		if  buffer:range(offset,1):bitfield(5) == 1 then
			vfmarktree:append_text(", Key Frame")
		end	
	elseif buffer:range(offset,1):uint() ~= 0 then
		_Warning(string.format("Should Be 0x00 in %s", c_MsgType[msgtype]), buffer:range(offset, 1), nil, vfmarktree)
	end
	offset = offset + 1

	-- reserved1
	headtree:add(f_SDHWC.reserved1, buffer:range(offset,2))
	offset = offset + 2
	-- msg length
	local msglength = buffer:range(offset,4):uint()
	local msglengthtree = headtree:add(f_SDHWC.msglength, buffer:range(offset,4))
	offset = offset + 4

	-- body length check
	if buffer_len ~= msglength then
		_Warning(string.format("Bad Msg Length(%d). Actual(%d)", msglength, buffer_len), buffer:range(0), nil, msglengthtree)
	end
	if msgtype == MsgType_Video and msglength > 2048 then
		_Warning(string.format("Msg Length %d should NOT over 2048 in %s", msglength, c_MsgType[MsgType_Video]), buffer:range(offset,4), nil, msglengthtree)
	end
	if msgtype == MsgType_Audio and msglength > 1024 then
		_Warning(string.format("Msg Length %d should NOT over 1024 in %s", msglength, c_MsgType[MsgType_Audio]), buffer:range(offset,4), nil, msglengthtree)
	end

	-- srcaddr
	headtree:add(f_SDHWC.srcaddr, buffer:range(offset,4))
	offset = offset + 4

	-- dstaddr
	headtree:add(f_SDHWC.dstaddr, buffer:range(offset,4))
	offset = offset + 4

	
	
	if msglength > 0 then


		-- construct body tree
		local bodytree = myProtoTree:add(buffer:range(offset), "Msg Body")
		--use existed dissector to deal with xml
		Dissector.get("xml"):call(buffer:range(offset):tvb(), pinfo, bodytree)
	end
end

-- register protocol fields for SDHWC
local tcp_port_table = DissectorTable.get("udp.port")
local SDHWC_server_port=9000
tcp_port_table:add(SDHWC_server_port, p_SDHWC)
