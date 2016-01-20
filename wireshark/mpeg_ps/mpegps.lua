-- based on ITU-T Rec.H222.0
-- Bin.Wu@axis.com
-- version 1.0.0.6
-- 2016/01/20
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
-- Limitation:
-- Only support ONE Mpeg Program Stream with each packet in order.

-- if sth goes wrong, change speed_mod_on to false and have an another try
speed_mod_on = true

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

f_PS.has_pack_header = ProtoField.bool("ps.has_pack_header", "has_pack_header")
f_PS.pack_start_code = ProtoField.uint32("ps.pack_start_code","pack_start_code", base.HEX)
f_PS.system_clock_reference_base_high_17bit = ProtoField.uint32("ps.system_clock_reference_base_high_17bit","system_clock_reference_base_high_17bit", base.HEX, nil, 0x3BFFF0)
f_PS.system_clock_reference_base_low_16bit = ProtoField.uint32("ps.system_clock_reference_base_low_16bit","system_clock_reference_base_low_16bit", base.HEX, nil, 0xBFFF8)
f_PS.system_clock_reference_extension = ProtoField.uint16("ps.system_clock_reference_extension","system_clock_reference_extension", base.HEX, nil, 0x3FE)
f_PS.program_mux_rate = ProtoField.uint24("ps.program_mux_rate","program_mux_rate", base.DEC, nil, 0xFFFFFC)
f_PS.reserved = ProtoField.uint8("ps.reserved","reserved", base.HEX, nil, 0xF8)
f_PS.pack_stuffing_length = ProtoField.uint8("ps.pack_stuffing_length","pack_stuffing_length", base.DEC, nil, 0x07)

f_PS.has_system_header = ProtoField.bool("ps.has_pack_header", "has_pack_header")
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

f_PS.packet_start_code_prefix = ProtoField.uint24("ps.packet_start_code_prefix", "packet_start_code_prefix", base.HEX)

f_PS.has_psm = ProtoField.bool("ps.has_psm", "has_psm")
f_PS.map_stream_id = ProtoField.uint8("ps.map_stream_id", "map_stream_id", base.HEX)
f_PS.program_stream_map_length = ProtoField.uint16("ps.program_stream_map_length", "program_stream_map_length")
f_PS.current_next_indicator = ProtoField.uint8("ps.current_next_indicator", "current_next_indicator", base.HEX, nil, 0x80)
f_PS.psm_reserved1 = ProtoField.uint8("ps.psm_reserved1", "psm_reserved1", base.HEX, nil, 0x60)
f_PS.program_stream_map_version = ProtoField.uint8("ps.program_stream_map_version", "program_stream_map_version", base.HEX, nil, 0x1F)
f_PS.psm_reserved2 = ProtoField.uint8("ps.psm_reserved2", "psm_reserved2", base.HEX, nil, 0xFE)
f_PS.program_stream_info_length = ProtoField.uint16("ps.program_stream_info_length", "program_stream_info_length")
f_PS.elementary_stream_map_length = ProtoField.uint16("ps.elementary_stream_map_length", "elementary_stream_map_length")


function check_marker_bit(bitfield, range, pinfo, tree)
	if bitfield ~= 1 then
		_Warning(string.format("miss bit field"), range, pinfo, tree)
	end
end

-- <<<<<<<<<<<<<<<<<<<<<<<<<< Pack Header & System Header <<<<<<<<<<<<<<<<<<<<<<<<<<
function deal_system_header_stream_id(buffer, pinfo, tree)
	local stream_id = buffer:range(0, 1):uint()
	tree:add(buffer:range(0, 1), string.format("stream_id: 0x%02x", stream_id))
	if stream_id == 0xB8 then -- 0x10111000
		tree:append_text(", all audio streams")
	elseif stream_id == 0xB9 then -- 0x10111001
		tree:append_text(", all video streams")
	elseif stream_id < 0xBC then -- 0x10111100
		_Warning(string.format("invalid stream_id: 0x%02x", stream_id), buffer:range(0, 1), pinfo, tree)
	end
	
end
-- return: next buffer
function  system_header(buffer, pinfo, tree)
	local header_len = 6 + buffer(4, 2):uint()
	local offset = 0
	local next_buffer = nil
	
	local system_header_tree = tree:add(p_PS, buffer:range(0, header_len), "System Header")

	tree:append_text(", System Header")
	pinfo.cols.info:append(", SystemHeader")

	-- Byte [0, 5]
	local start_code_tree = system_header_tree:add(f_PS.system_header_start_code, buffer(offset, 4))
	start_code_tree:add(f_PS.has_system_header, buffer:range(0, 4), true)
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

	while offset <  header_len and buffer:range(offset):bitfield(0) do
		local pstd_buffer_info_tree = system_header_tree:add(buffer:range(offset, 3), "P-STD-buffer_bound_info")
		deal_system_header_stream_id(buffer:range(offset):tvb(), pinfo, pstd_buffer_info_tree)
		offset = offset + 1
		if buffer:range(offset):bitfield(0, 2) ~= 0x3 then
			_Error(string.format("Bad Bits after stream_id"), buffer:range(offset, 1), pinfo, pstd_buffer_info_tree)
		end		
		pstd_buffer_info_tree:add(buffer:range(offset, 1), string.format("P-STD_buffer_bound_scale : %d", buffer(offset):bitfield(2)))
		pstd_buffer_info_tree:add(buffer:range(offset, 2), string.format("P-STD_buffer_size_bound : %d", buffer(offset):bitfield(3, 13)))
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
	local start_code_tree = pack_header_tree:add(f_PS.pack_start_code, buffer(offset, 4))
	start_code_tree:add(f_PS.has_pack_header, buffer:range(0, 4), true)
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
	--       to this part for "system clock reference base"
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
		next_buffer = system_header(next_buffer, pinfo, pack_header_tree)
	end

	return next_buffer
end
-- >>>>>>>>>>>>>>>>>>>>>>>>>> Pack Header & System Header >>>>>>>>>>>>>>>>>>>>>>>>>>
-- <<<<<<<<<<<<<<<<<<<<<<<<<< PSM <<<<<<<<<<<<<<<<<<<<<<<<<< 

-- TODO: [Bin Wu] to implement all the descriptors' dissector
function deal_video_stream_desciptor(buffer, pinfo, tree)
	tree:add(buffer:range(2), "video_stream_desciptor")
end

function deal_unsupported_desciptor(buffer, pinfo, tree)
	tree:add(buffer:range(2), "unsupported_desciptor")
end
-------------------------------------------------------------------------
-- descriptor_tag 	TS 	PS	Identification
-- 0				n/a	n/a	Reserved
-- 1				n/a	n/a	Reserved
-- 2				X	X	video_stream_descriptor
-- 3				X	X	audio_stream_descriptor
-- 4				X	X	hierarchy_descriptor
-- 5				X	X	registration_descriptor
-- 6				X	X	data_stream_alignment_descriptor
-- 7				X	X	target_background_grid_descriptor
-- 8				X	X	Video_window_descriptor
-- 9				X	X	CA_descriptor
-- 10 (0x0A)		X	X	ISO_639_language_descriptor
-- 11 (0x0B)		X	X	System_clock_descriptor
-- 12 (0x0C)		X	X	Multiplex_buffer_utilization_descriptor
-- 13 (0x0D)		X	X	Copyright_descriptor
-- 14 (0x0E)		X		Maximum_bitrate_descriptor
-- 15 (0x0F)		X	X	Private_data_indicator_descriptor
-- 16 (0x10)		X	X	Smoothing_buffer_descriptor
-- 17 (0x11)		X		STD_descriptor
-- 18 (0x12)		X	X	IBP_descriptor
-- 19-26 (0x13-0x1A)X		Defined in ISO/IEC 13818-6
-- 27 (0x1B)		X	X	MPEG-4_video_descriptor
-- 28 (0x1C)		X	X	MPEG-4_audio_descriptor
-- 29 (0x1D)		X	X	IOD_descriptor
-- 30 (0x1E)		X		SL_descriptor
-- 31 (0x1F)		X	X	FMC_descriptor
-- 32 (0x20)		X	X	External_ES_ID_descriptor
-- 33 (0x21)		X	X	MuxCode_descriptor
-- 34 (0x22)		X	X	FmxBufferSize_descriptor
-- 35 (0x23)		X		MultiplexBuffer_descriptor
-- 36-63 (0x24-0x3F)n/a	n/a	ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Reserved
-- 64-255(0x4F-0xFF)n/a	n/a	User Private
local descriptor_handler = {
[0x02] = deal_video_stream_desciptor
}
function dissect_descriptors(length, buffer, pinfo, tree)
	local offset = 0
	local length_count = length
	while length_count > 0 do		
		local descriptor_tag = buffer:range(offset, 1):uint()
		local descriptor_length = buffer:range(offset + 1, 1):uint()
		local descriptor_tree = tree:add(buffer:range(offset, 2 + descriptor_length), "descriptor")
		descriptor_tree:add(buffer:range(offset, 1), string.format("descriptor_tag: 0x%02x", descriptor_tag))		
		descriptor_tree:add(buffer:range(offset + 1, 1), string.format("descriptor_length: %d", descriptor_length))
		
		local handler = descriptor_handler[descriptor_tag] or deal_unsupported_desciptor
		handler(buffer:range(offset, 2 + descriptor_length):tvb(), pinfo, descriptor_tree)
		length_count = length_count - 2 - descriptor_length
		offset = offset + 2 +descriptor_length
	end 
	if length_count < 0 then
		_Error("Wrong Descriptor Length", buffer:range(), pinfo, tree)
	end
end

function program_stream_map(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	local stream_id = buffer:range(3, 1):uint()
	local packet_length = buffer:range(4, 2):uint()

	local psm_tree = tree:add(p_PS, buffer:range(0, 6 + packet_length), "PSM")
	tree:append_text(", PSM")
	pinfo.cols.info:append(", PSM")

	local start_code_tree = psm_tree:add(f_PS.map_stream_id, buffer(3, 1))
	start_code_tree:add(f_PS.has_psm, buffer:range(0, 4), true)
	offset = offset + 4
	
	psm_tree:add(f_PS.program_stream_map_length, buffer:range(offset, 2))
	if buffer:range(offset, 2):uint() > 0x3FA then
		_Warning(string.format("Bad program_stream_map_length"), buffer:range(offset, 2), pinfo, psm_tree)
	end
	offset = offset + 2

	psm_tree:add(f_PS.current_next_indicator, buffer:range(offset, 1))
	psm_tree:add(f_PS.psm_reserved1, buffer:range(offset, 1))
	psm_tree:add(f_PS.program_stream_map_version, buffer:range(offset, 1))
	offset = offset + 1

	psm_tree:add(f_PS.psm_reserved2, buffer:range(offset, 1))
	check_marker_bit(buffer(offset):bitfield(7), buffer(offset, 1), pinfo, psm_tree)
	offset = offset + 1

	local psinfo_length = buffer:range(offset, 2):uint()
	psm_tree:add(f_PS.program_stream_info_length, buffer:range(offset, 2))
	offset = offset + 2

	if psinfo_length > 0 then
		dissect_descriptors(psinfo_length, buffer:range(offset, psinfo_length):tvb(), pinfo, psm_tree)
		offset = offset + psinfo_length
	end
	
	psm_tree:add(f_PS.elementary_stream_map_length, buffer:range(offset, 2))
	local esmap_length = buffer:range(offset, 2):uint()
	offset = offset + 2
	local esmap_start_offset = offset

	while esmap_length > 0 do
		local stream_type = buffer:range(offset, 1):uint() --TODO: [Bin Wu] to present the meaning of stream_type
-- stream_type	description 
-- 0x00 		ITU-T | ISO/IEC Reserved
-- 0x01 		ISO/IEC 11172 Video
-- 0x02 		ITU-T Rec. H.262 | ISO/IEC 13818-2 Video or ISO/IEC 11172-2 constrained parameter video stream
-- 0x03 		ISO/IEC 11172 Audio
-- 0x04 		ISO/IEC 13818-3 Audio
-- 0x05 		ITU-T Rec. H.222.0 | ISO/IEC 13818-1 private_sections
-- 0x06 		ITU-T Rec. H.222.0 | ISO/IEC 13818-1 PES packets containing private data
-- 0x07 		ISO/IEC 13522 MHEG
-- 0x08 		ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Annex A DSM-CC
-- 0x09 		ITU-T Rec. H.222.1
-- 0x0A 		ISO/IEC 13818-6 type A
-- 0x0B 		ISO/IEC 13818-6 type B
-- 0x0C 		ISO/IEC 13818-6 type C
-- 0x0D 		ISO/IEC 13818-6 type D
-- 0x0E 		ITU-T Rec. H.222.0 | ISO/IEC 13818-1 auxiliary
-- 0x0F 		ISO/IEC 13818-7 Audio with ADTS transport syntax
-- 0x10 		ISO/IEC 14496-2 Visual
-- 0x11 		ISO/IEC 14496-3 Audio with the LATM transport syntax as defined in ISO/IEC 14496-3 / AMD 1
-- 0x12 		ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in PES packets
-- 0x13 		ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in ISO/IEC14496_sections.
-- 0x14 		ISO/IEC 13818-6 Synchronized Download Protocol
-- 0x15-0x7F	ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Reserved
-- 0x80-0xFF 	User Private
		local elementary_stream_id = buffer:range(offset + 1, 1):uint()
		local elementary_stream_info_length = buffer:range(offset + 2, 2):uint()
		local elementary_stream_map_tree = psm_tree:add(buffer:range(offset, 4 + elementary_stream_info_length), "elementary_stream_map")
		elementary_stream_map_tree:add(buffer:range(offset, 1), string.format("stream_type: 0x%02x", stream_type))		
		elementary_stream_map_tree:add(buffer:range(offset + 1, 1), string.format("elementary_stream_id: 0x%02x", elementary_stream_id))
		elementary_stream_map_tree:add(buffer:range(offset + 2, 2), string.format("elementary_stream_info_length: %d", elementary_stream_info_length))
		offset = offset + 4
		if elementary_stream_info_length > 0 then
			dissect_descriptors(elementary_stream_info_length, buffer:range(offset, elementary_stream_info_length):tvb(), pinfo, elementary_stream_map_tree)
			offset = offset + elementary_stream_info_length
		end
		esmap_length = esmap_length - 4 - elementary_stream_info_length
	end 
	if esmap_length < 0 then
		_Error("Wrong Descriptor in Elamentary Stream Map", buffer:range(esmap_start_offset, buffer:range(esmap_start_offset - 2, 2):uint()), pinfo, psm_tree)
	end
end
-- >>>>>>>>>>>>>>>>>>>>>>>>>> PSM >>>>>>>>>>>>>>>>>>>>>>>>>>

function program_stream_map_o(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	local stream_id = buffer:range(3, 1):uint()
	local packet_length = buffer:range(4, 2):uint()

	local system_header_tree = tree:add(p_PS, buffer:range(0, 6 + packet_length), "PES_packet")
	tree:append_text(", PES_packet")
	pinfo.cols.info:append(", PES_packet")
	
end

local still_on_working = false 
local last_working_luastr = nil
local last_expected_length = 0
local redisscet_expected_length = {}
-- 3 valid state/type with redissect_buffer elements: true false string
local redissect_buffer = {}

-- return: next buffer
function PES_packet(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local stream_id = buffer:range(3, 1):uint()
	local packet_length = buffer:range(4, 2):uint()

	if buffer_len >= 6 + packet_length then
		if speed_mod_on and not pinfo.visited then
			-- nop
			-- when speed_mod_on, only do assembling job, no deeper dissection
		else
			if stream_id == 0xBC then
				program_stream_map(buffer, pinfo, tree)
			else
				program_stream_map_o(buffer, pinfo, tree)
			end
		end
		if buffer_len == 6 + packet_length then
			return nil
		end

		return buffer:range(6 + packet_length):tvb()
	else
		-- here comes an incompleted packet, start assembling in comming dissection
		if not pinfo.visited then
			still_on_working = true
			last_expected_length = 6 + packet_length
			last_working_luastr = buffer:raw()
		end
		return nil
	end
end

-- return: bool
function check_pacet_start_code_prefix(buffer)
	if nil == buffer then
		return false
	end
	if buffer:range(0, 3):uint() == 0x000001 then
		return true
	end
	return false	
end
-- return buffer, nil for need further segments
function try_assemble_PDU(buffer, pinfo, tree)
	if false == still_on_working and nil == redissect_buffer[pinfo.number] then
		-- info("first dissection: nice start")
		-- a packet start with packet start code 0x000001
		-- record the frame, so that it will pass through in further dissection
		redissect_buffer[pinfo.number] = true
		return buffer
	end
	if nil == last_working_luastr and nil == redissect_buffer[pinfo.number] then
		critical("should not happen")
		return buffer
	end
	if redissect_buffer[pinfo.number] == true then
		-- whatever still_on_working is true or false, redissect_buffer with true
		-- means it does not need to assemble former data  
		return buffer
	end
	
	if redissect_buffer[pinfo.number] == nil then
		-- first time processing dissection
		-- when it is inner fragment packet, it will set false in redissect_buffer
		last_working_luastr = last_working_luastr..buffer:raw()
		redissect_buffer[pinfo.number] = false
		redisscet_expected_length[pinfo.number] = expected_length
		-- otherwise, if it is the final fragment packet, redissect_buffer will used 
		-- to record the entire packet data
		if #last_working_luastr >= last_expected_length then
			redissect_buffer[pinfo.number] = last_working_luastr
			still_on_working = false
			last_working_luastr = nil
			if speed_mod_on then
				-- wireshark may call dissector several times for each PDU, so it will save almost
				-- half of time when just return nil in the first dissection round
				return nil
			else
				return ByteArray.new(redissect_buffer[pinfo.number], true):tvb("PES_packet")
			end
		end
		return nil
	elseif redissect_buffer[pinfo.number] ~= false then
		-- true value will be returned in former judgement
		-- not equal to false means it contains a luastring
		-- so the packet is the final segment, present it!
		return ByteArray.new(redissect_buffer[pinfo.number], true):tvb("PES_packet")
	end
	tree:add(buffer:range(0, 0), "fragment of PES_packet")
	return nil
end

-- construct tree
function p_PS.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol:set("PS")
	--info(string.format("p_PS.dissectorstill_on_working %s  %d visited %s", tostring(still_on_working), pinfo.number, tostring(pinfo.visited)))
	buffer = try_assemble_PDU(buffer, pinfo, tree)
	if nil == buffer then -- if the packet is one of segment, just pass 
		return false
	end
	-- Program Stream pack header
	buffer = pack_header(buffer, pinfo, tree)
	if nil == buffer then -- some error occurs
		return false
	end
	while check_pacet_start_code_prefix(buffer) do
		-- PES packet
		buffer = PES_packet(buffer, pinfo, tree)
	end
	return true
end

function init_function ()
	--info("init_function")
	still_on_working = false
	last_working_luastr = nil
	redissect_buffer = {}
end
-- ------------------------------------------------------------------------------------------------
--  PS_RTP
-- ------------------------------------------------------------------------------------------------
local p_PS_RTP = Proto("PS_RTP", "MPEG Promgram Stream via RTP")

function p_PS_RTP.dissector(buffer, pinfo, tree)
	local size = Dissector.get("rtp"):call(buffer, pinfo, tree)
	p_PS.dissector(buffer:range(size):tvb(), pinfo, tree)
	return true
end
p_PS.init = init_function
DissectorTable.get("udp.port"):add_for_decode_as(p_PS_RTP)
DissectorTable.get("tcp.port"):add_for_decode_as(p_PS_RTP)
