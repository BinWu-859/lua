-- based on ITU-T Rec.H222.0
-- Bin.Wu@axis.com
-- version 1.0.0.0
-- 2016/01/08
-- protocol name: PS (Program Stream) PS_RTP (Program Stream via RTP)
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
--  PS
-- ------------------------------------------------------------------------------------------------
-- Csonstants
local PACKET_START_CODE = 0x000001BA
local SYSTEM_HEADER_START_CODE = 0x000001BB

local p_PS = Proto("PS", "MPEG Promgram Stream")
local f_PS = p_PS.fields
f_PS.pack_start_code = ProtoField.uint32("ps.pack_start_code","pack_start_code", base.HEX)
f_PS.system_clock_reference_base_high_17bit = ProtoField.uint32("ps.system_clock_reference_base_high_17bit","system_clock_reference_base_high_17bit", base.HEX, nil, 0x3BFFF0)
f_PS.system_clock_reference_base_low_16bit = ProtoField.uint32("ps.system_clock_reference_base_low_16bit","system_clock_reference_base_low_16bit", base.HEX, nil, 0xBFFF8)
f_PS.system_clock_reference_extension = ProtoField.uint16("ps.system_clock_reference_extension","system_clock_reference_extension", base.HEX, nil, 0x3FE)
f_PS.program_mux_rate = ProtoField.uint24("ps.program_mux_rate","program_mux_rate", base.HEX, nil, 0xFFFFFC)
f_PS.reserved = ProtoField.uint8("ps.reserved","reserved", base.HEX, nil, 0xF8)
f_PS.pack_stuffing_length = ProtoField.uint8("ps.pack_stuffing_length","pack_stuffing_length", base.DEC, nil, 0x07)

function check_marker_bit(bitfield, range, pinfo, tree)
	if bitfield ~= 1 then
		_Warning(string.format("miss bit field"), range, pinfo, tree)
	end
end
-- return: next buffer
function pack_header(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	-- A) If this packet is not pack header, just skip
	if PACKET_START_CODE ~= buffer(offset, 4):uint() then
		return buffer
	end
	-- B) evaluate the length of this pack_header
	local pack_header_length = 0
	--- B.1) check the mix length: 112bits, thus 14bytes
	if buffer_len < 14 then		
		_Error(string.format("Bad Packet Size(%d)", buffer_len), buffer:range(0, buffer_len), pinfo, tree)
		return nil
	end
	pack_header_length = 14
	--- B.2) get pack_stuffing_length
	local pack_stuffing_length = buffer(13):bitfield(5, 3)
	pack_header_length = pack_header_length + pack_stuffing_length -- pack_stuffing_length counts in bytes
	--- B.3) evaluate the length system headers
	-- 14 for the pack header length, 4 for the system header start code and 2 for header length 
	if buffer_len > (14 + 4 + 2) and buffer(pack_header_length, 4):uint() == SYSTEM_HEADER_START_CODE then
		pack_header_length = pack_header_length + buffer(14 + 4 - 1, 2):uint()
	end
	-- C) constuct the pack header tree
	-- Byte[0, 3]
	local pack_header_tree = tree:add(p_PS, buffer:range(0, pack_header_length), "Pack Header")
	pack_header_tree:add(f_PS.pack_start_code, buffer(offset, 4))
	offset = offset + 4
	-- Byte[4, 9]
	if buffer:range(offset):bitfield(0, 2) ~= 0x01 then
		_Error(string.format("Bad Bits after pack_start_code"), buffer:range(offset, 1), pinfo, tree)
	end
	check_marker_bit(buffer(offset):bitfield(5), buffer(offset, 1), pinfo, tree)
	check_marker_bit(buffer(offset):bitfield(21), buffer(offset + 2, 1), pinfo, tree)
	check_marker_bit(buffer(offset):bitfield(37), buffer(offset + 3, 1), pinfo, tree)
	check_marker_bit(buffer(offset):bitfield(47), buffer(offset + 4, 1), pinfo, tree)

	-- TODO: [Bin Wu]64bit mask is not working properly. So if wireshark gets updated, some promotion can be done 
	--       to this part for ""system clock reference base"
	pack_header_tree:add(f_PS.system_clock_reference_base_high_17bit, buffer(offset, 3))
	offset = offset + 2
	pack_header_tree:add(f_PS.system_clock_reference_base_low_16bit, buffer(offset, 3))
	offset = offset + 2
	pack_header_tree:add(f_PS.system_clock_reference_extension,  buffer(offset, 2))
	offset = offset + 2
	-- Byte[10, 12]
	check_marker_bit(buffer(offset):bitfield(22), buffer(offset + 2, 1), pinfo, tree)
	check_marker_bit(buffer(offset):bitfield(23), buffer(offset + 2, 1), pinfo, tree)
	pack_header_tree:add(f_PS.program_mux_rate, buffer(offset, 3))
	offset = offset + 3
	-- Byte[13, 13]
	pack_header_tree:add(f_PS.reserved, buffer(offset, 1))
	pack_header_tree:add(f_PS.pack_stuffing_length, buffer(offset, 1))
	offset = offset + 1
	if pack_stuffing_length > 0 then
		local i
		for i = 0, pack_stuffing_length - 1, 1 do
			pack_header_tree:add(buffer:range(offset, 1), string.format("stuffing_byte: 0x%02x", buffer:range(offset, 1):uint()))
		end
	end
	return nil
end
-- return: 1 for True, 0 for False
function check_pacet_start_code_prefix(buffer)
	if nil == buffer then
		return 0
	end
	return 0	
end
-- return: next buffer
function PES_Packet(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	return nil
end

-- construct tree
function p_PS.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol:set("PS")
	local nextbuffer = buffer;
	
	-- Program Stream pack header
	nextbuffer = pack_header(nextbuffer, pinfo, tree)
	if nil == nextbuffer then
		return false
	end
	while check_pacet_start_code_prefix(nextbuffer) do
		-- PES packet
		nextbuffer = PES_Packet(nextbuffer, pinfo, tree)
	end
	return true
end


-- ------------------------------------------------------------------------------------------------
--  PS_RTP
-- ------------------------------------------------------------------------------------------------
local p_PS_RTP = Proto("PS_RTP", "MPEG Promgram Stream via RTP")

function p_PS_RTP.dissector(buffer, pinfo, tree)
	local size = Dissector.get("rtp"):call(buffer, pinfo, tree)
	p_PS.dissector(buffer:range(size):tvb(), pinfo, tree)
end

DissectorTable.get("udp.port"):add_for_decode_as(p_PS_RTP)
DissectorTable.get("tcp.port"):add_for_decode_as(p_PS_RTP)
