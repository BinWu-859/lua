-- based on山东高速视频监控设备联网技术规范
-- Bin.Wu@axis.com
-- versioin 1.0.0.1
-- 2015/12/15
-- protocal name: SDHW
--================================================================================================
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

-- protocol fields 
-- SDHW.identity ... can be used as filter
local p_SDHW = Proto("SDHW", "Shandong Highway", "SDHW")
local f_identity = ProtoField.uint32("SDHW.identity","identity", base.HEX)
local f_version = ProtoField.uint16("SDHW.version","version", base.HEX)
local f_msgtype = ProtoField.uint16("SDHW.msgtype","msgtype", base.HEX, MsgType)
local f_msgsn = ProtoField.uint16("SDHW.msgsn","msgsn")
local f_bodylength = ProtoField.uint8("SDHW.bodylength","bodylength")
p_SDHW.fields = {f_identity, f_version, f_msgtype,f_msgsn, f_bodylength}

-- msgtype for f_msgtype
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
[0x0100] = "[TEST]TEST",
}

-- construct tree
function p_SDHW.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol:set("SDHW")
	
	local buffer_len = buffer:len()
	local myProtoTree = tree:add(p_SDHW, buffer:range(0, buffer_len), "SDHW")
	local offset = 0

	--check head length
	if buffer_len < 12 then
		pinfo.cols.info:set(string.format("Invalid Message Length(%d)", buffer_len))
		local errtree = myProtoTree:add(buffer:range(0, buffer_len), string.format("Invalid Message Length(%d)", buffer_len))
		errtree:add_expert_info(PI_MALFORMED, PI_ERROR);
		return
	end
	-- construct head tree
	local headtree = myProtoTree:add(buffer:range(offset, 12), "Msg Head")
	--check identity
	local identity = buffer:range(offset,4):uint()

	if identity ~= 0xE1DDF2DA then
		pinfo.cols.info:set(string.format("Invalid Message Identity(0x%08X)", identity))
		errtree = headtree:add(buffer:range(offset,4), string.format("Invalid Message Identity(0x%08X)", identity))
		errtree:add_expert_info(PI_MALFORMED, PI_ERROR);
		return
	end
	headtree:add(f_identity, buffer:range(offset,4))
	offset = offset + 4
	--versoin
	headtree:add(f_version, buffer:range(offset,2))
	offset = offset + 2
	--msgtype
	local msgmethod = buffer:range(offset,2):uint()
    local typetree = headtree:add(f_msgtype, buffer:range(offset,2))
	
    if nil == MsgType[msgmethod] then
		pinfo.cols.info:set(string.format("Invalid Message Type(0x%04X)", msgmethod))
		errtree = headtree:add(buffer:range(offset,2), string.format("Invalid Message Type(0x%04X)", msgmethod))
		errtree:add_expert_info(PI_MALFORMED, PI_ERROR);
		return
	end
	typetree:add(MsgType[msgmethod], buffer:range(offset,2))
	pinfo.cols.info:set(MsgType[msgmethod])
	offset = offset + 2
	--msgsn
    headtree:add(f_msgsn, buffer:range(offset,2))
	offset = offset + 2
	--body length
	local bodylength = buffer:range(offset,2):uint()
    headtree:add(f_bodylength, buffer:range(offset,2))
	offset = offset + 2
	--body length check
	if buffer_len - offset < bodylength then
		--pinfo.cols.info:set(string.format("Bad Body Length(%d)", bodylength))
		errtree = headtree:add(buffer:range(offset), string.format("Bad Body Length(%d). Actual(%d)", bodylength, buffer_len - offset))
		errtree:add_expert_info(PI_MALFORMED, PI_WARN);
		--return
	end
	-- construct body tree
	local bodytree = myProtoTree:add(buffer:range(offset), "Msg Body")
	--use existed dissector to deal with xml
	Dissector.get("xml"):call(buffer:range(offset):tvb(), pinfo, bodytree)
end

-- register protocol fields
local udp_port_table = DissectorTable.get("udp.port")
local SDHW_port=15000
udp_port_table:add(SDHW_port, p_SDHW)

