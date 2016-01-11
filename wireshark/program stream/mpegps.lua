-- based on ITU-T Rec.H222.0
-- Bin.Wu@axis.com
-- version 1.0.0.1
-- 2016/01/11
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
f_PS.program_mux_rate = ProtoField.uint24("ps.program_mux_rate","program_mux_rate", base.DEC, nil, 0xFFFFFC)
f_PS.reserved = ProtoField.uint8("ps.reserved","reserved", base.HEX, nil, 0xF8)
f_PS.pack_stuffing_length = ProtoField.uint8("ps.pack_stuffing_length","pack_stuffing_length", base.DEC, nil, 0x07)

f_PS.system_header_start_code = ProtoField.uint32("ps.system_header_start_code","system_header_start_code", base.HEX)
f_PS.system_header_header_length = ProtoField.uint16("ps.system_header_header_length","system_header_header_length")
f_PS.rate_bound = ProtoField.uint24("ps.rate_bound","rate_bound", base.DEC, nil, 0x7FFFFE)
f_PS.audio_bound = ProtoField.uint8("ps.audio_bound","audio_bound", base.DEC, nil, 0xFC)
f_PS.fixed_flag = ProtoField.uint8("ps.fixed_flag","fixed_flag", base.HEX, {[0]="Variable Bitrate", [1]="Fixed Bitrate"}, 0x02)
f_PS.CSPS_flag = ProtoField.uint8("ps.CSPS_flag","CSPS_flag", base.HEX, {[0]="CSPS Off", [1]="CSPS On"}, 0x01)
f_PS.system_audio_lock_flag = ProtoField.uint8("ps.system_audio_lock_flag","system_audio_lock_flag", base.HEX, {[0]="Audio Lock Off", [1]="Audio Lock On"}, 0x80)
f_PS.system_video_lock_flag = ProtoField.uint8("ps.system_video_lock_flag","system_video_lock_flag", base.HEX, {[0]="Video Lock Off", [1]="Video Lock On"}, 0x40)
f_PS.video_bound = ProtoField.uint8("ps.video_bound","video_bound", base.DEC, nil, 0x1F)
f_PS.packet_rate_restriction_flag = ProtoField.uint8("ps.packet_rate_restriction_flag","packet_rate_restriction_flag", base.HEX, nil, 0x80)
f_PS.reserved_bits = ProtoField.uint8("ps.reserved_bits","reserved_bits", base.HEX, nil, 0x7F)


function check_marker_bit(bitfield, range, pinfo, tree)
	if bitfield ~= 1 then
		_Warning(string.format("miss bit field"), range, pinfo, tree)
	end
end
function deal_stream_id(buffer, pinfo, tree)
	local stream_id = buffer:range(0, 1):uint()
	tree:add(buffer:range(0, 1), string.format("stream_id: 0x%02x", stream_id))
	if stream_id == 0x10111000 then
		tree:append_text(", all audio streams")
	elseif stream_id == 0x10111001 then
		tree:append_text(", all video streams")
	elseif stream_id <= 0x10111100 then 
		_Warning(string.format("invalid stream_id: 0x%02x", stream_id))
	end
	
end
-- return: next buffer
function system_header(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	local next_buffer = nil
	
	local system_header_tree = tree:add(p_PS, buffer:range(0, buffer(4, 2):uint()), "System Header")
	tree:append_text(", System Header")
	pinfo.cols.info:append(", SystemHeader")

	-- Byte [0, 5]
	system_header_tree:add(f_PS.system_header_start_code, buffer(offset, 4))
	offset = offset + 4
	system_header_tree:add(f_PS.system_header_header_length, buffer(offset, 2))
	offset = offset + 2
	-- Byte [6, 8]
	check_marker_bit(buffer(offset):bitfield(0), buffer(offset, 1), pinfo, tree)
	check_marker_bit(buffer(offset):bitfield(23), buffer(offset + 2, 1), pinfo, tree)
	system_header_tree:add(f_PS.rate_bound, buffer(offset, 3))
	offset = offset + 3
	-- Byte [9, 9]
	system_header_tree:add(f_PS.audio_bound, buffer(offset, 1))
	system_header_tree:add(f_PS.fixed_flag, buffer(offset, 1))
	system_header_tree:add(f_PS.CSPS_flag, buffer(offset, 1))
	local CSPS_flag = buffer(offset, 1):bitfield(7, 1)
	offset = offset + 1
	-- Byte [10, 10]
	check_marker_bit(buffer(offset):bitfield(2), buffer(offset, 1), pinfo, tree)
	system_header_tree:add(f_PS.system_audio_lock_flag, buffer(offset, 1))
	system_header_tree:add(f_PS.system_video_lock_flag, buffer(offset, 1))
	system_header_tree:add(f_PS.video_bound, buffer(offset, 1))
	offset = offset + 1
	-- Byte [11, 11]
	if 1 == CSPS_flag then
		system_header_tree:add(f_PS.packet_rate_restriction_flag, buffer(offset, 1))
	end
	system_header_tree:add(f_PS.reserved_bits, buffer(offset, 1))
	offset = offset + 1

	while offset <  buffer_len and buffer:range(offset):bitfield(0) do
		deal_stream_id(buffer:range(offset):tvb(), pinfo, tree)
		offset = offset + 1
		if buffer:range(offset):bitfield(0, 2) ~= 0x11 then
			_Error(string.format("Bad Bits after stream_id"), buffer:range(offset, 1), pinfo, tree)
		end		
		system_header_tree:add(buffer:range(offset, 1), string.format("P-STD_buffer_bound_scale : %d", buffer(offset):bitfield(2)))
		system_header_tree:add(buffer:range(offset, 2), string.format("P-STD_buffer_size_bound : %d", buffer(offset):bitfield(3, 13)))
		offset = offset + 2
	end
	
	next_buffer = buffer:range(offset):tvb()
	return next_buffer
end

-- return: next buffer
function pack_header(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	local next_buffer = nil
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
	local nextbits = 0
	pack_header_length = pack_header_length + pack_stuffing_length -- pack_stuffing_length counts in bytes
	--- B.3) evaluate the length system headers
	--  4 for the system header start code and 2 for header length 
	if buffer_len > (pack_header_length + 4 + 2) and buffer(pack_header_length, 4):uint() == SYSTEM_HEADER_START_CODE then
		nextbits = SYSTEM_HEADER_START_CODE
		pack_header_length = pack_header_length + buffer(pack_header_length + 4, 2):uint()
	end
	-- C) constuct the pack header tree
	-- Byte[0, 3]
	local pack_header_tree = tree:add(p_PS, buffer:range(0, pack_header_length), "Pack Header")
	pinfo.cols.info:append(", PackHeader")
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
	-- stuffing_byte
	if pack_stuffing_length > 0 then
		local i
		for i = 0, pack_stuffing_length - 1, 1 do
			pack_header_tree:add(buffer:range(offset, 1), string.format("stuffing_byte: 0x%02x", buffer:range(offset, 1):uint()))
			offset = offset + 1
		end
	end
	next_buffer = buffer:range(offset):tvb()
	-- system_header
	if nextbits == SYSTEM_HEADER_START_CODE then
		next_buffer = system_header(buffer, pinfo, pack_header_tree)
	end
	
	return next_buffer
end
-- return: 1 for True, 0 for False
function check_pacet_start_code_prefix(buffer)
	if nil == buffer then
		return 0
	end
	return 0	
end
-- return: next buffer
function PES_packet(buffer, pinfo, tree)
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
	while 1 == check_pacet_start_code_prefix(nextbuffer) do
		-- PES packet
		nextbuffer = PES_packet(nextbuffer, pinfo, tree)
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
