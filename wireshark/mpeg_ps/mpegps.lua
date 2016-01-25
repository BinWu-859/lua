-- based on ITU-T Rec.H222.0(2000)
-- Bin.Wu@axis.com
-- version 1.0.0.12
-- 2016/01/25
-- protocol name: PS (Program Stream) PS_RTP (Program Stream via RTP)
-- PES_packet PackHeader(SystemHeader) PSM PSD
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
-- Notice:
-- Only support file with ONE Mpeg Program Stream and with each packet in the RIGHT order.
-- When PS_RTP cannot be recognized, try using 'Decode As'
-- When INVITE (SIP) packets also exist in the file, PS_RTP may takes no effect. Solution:
--     Use an another protocol to 'Decode As' SIP
--     or Save all rtp packets as a new file, and open to dissect
-- ================================================================================================
-- speed_mod
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
-- Constants
local PACKET_START_CODE = 0x000001BA
local SYSTEM_HEADER_START_CODE = 0x000001BB

local p_PS = Proto("PS", "MPEG Promgram Stream")
local f_PS = p_PS.fields

f_PS.has_pack_header = ProtoField.bool("ps.has_pack_header", "has_pack_header")
f_PS.has_system_header = ProtoField.bool("ps.has_system_header", "has_system_header")
f_PS.has_psm = ProtoField.bool("ps.has_psm", "has_psm")
f_PS.has_psd = ProtoField.bool("ps.has_psd", "has_psd")
f_PS.has_video = ProtoField.bool("ps.has_video", "has_video")
f_PS.has_audio = ProtoField.bool("ps.has_audio", "has_audio")

f_PS.pack_start_code = ProtoField.uint32("ps.pack_start_code", "pack_start_code", base.HEX)
f_PS.system_clock_reference_base = ProtoField.uint64("ps.system_clock_reference_base", "system_clock_reference_base", base.HEX)
f_PS.system_clock_reference_base_bit_32_30 = ProtoField.uint8("ps.system_clock_reference_base_bit_32_30", "system_clock_reference_base_bit_32_30", base.HEX, nil, 0x38)
f_PS.system_clock_reference_base_bit_29_15 = ProtoField.uint32("ps.system_clock_reference_base_bit_29_15", "system_clock_reference_base_bit_29_15", base.HEX, nil, 0x3FFF8)
f_PS.system_clock_reference_base_bit_14_0 = ProtoField.uint32("ps.system_clock_reference_base_bit_14_0", "system_clock_reference_base_bit_14_0", base.HEX, nil, 0x3FFF8)
f_PS.system_clock_reference_extension = ProtoField.uint16("ps.system_clock_reference_extension", "system_clock_reference_extension", base.HEX, nil, 0x3FE)
f_PS.program_mux_rate = ProtoField.uint24("ps.program_mux_rate", "program_mux_rate", base.DEC, nil, 0xFFFFFC)
f_PS.reserved = ProtoField.uint8("ps.reserved", "reserved", base.HEX, nil, 0xF8)
f_PS.pack_stuffing_length = ProtoField.uint8("ps.pack_stuffing_length", "pack_stuffing_length", base.DEC, nil, 0x07)
f_PS.pack_stuffing_byte = ProtoField.bytes("ps.pack_stuffing_byte", "pack_stuffing_byte")
f_PS.system_header_start_code = ProtoField.uint32("ps.system_header_start_code", "system_header_start_code", base.HEX)
f_PS.system_header_header_length = ProtoField.uint16("ps.system_header_header_length", "system_header_header_length")
f_PS.rate_bound = ProtoField.uint24("ps.rate_bound", "rate_bound", base.DEC, nil, 0x7FFFFE)
f_PS.audio_bound = ProtoField.uint8("ps.audio_bound", "audio_bound", base.DEC, nil, 0xFC)
f_PS.fixed_flag = ProtoField.uint8("ps.fixed_flag", "fixed_flag", base.HEX, {[0]="Variable Bitrate", [1]="Fixed Bitrate"}, 0x02)
f_PS.CSPS_flag = ProtoField.uint8("ps.CSPS_flag", "CSPS_flag", base.HEX, {[0]="CSPS Off", [1]="CSPS On"}, 0x01)
f_PS.system_audio_lock_flag = ProtoField.uint8("ps.system_audio_lock_flag", "system_audio_lock_flag", base.HEX, {[0]="Audio Lock Off", [1]="Audio Lock On"}, 0x80)
f_PS.system_video_lock_flag = ProtoField.uint8("ps.system_video_lock_flag", "system_video_lock_flag", base.HEX, {[0]="Video Lock Off", [1]="Video Lock On"}, 0x40)
f_PS.video_bound = ProtoField.uint8("ps.video_bound", "video_bound", base.DEC, nil, 0x1F)
f_PS.packet_rate_restriction_flag = ProtoField.uint8("ps.packet_rate_restriction_flag", "packet_rate_restriction_flag", base.HEX, nil, 0x80)
f_PS.reserved_bits = ProtoField.uint8("ps.reserved_bits", "reserved_bits", base.HEX, nil, 0x7F)

f_PS.packet_start_code_prefix = ProtoField.uint24("ps.packet_start_code_prefix", "packet_start_code_prefix", base.HEX)

f_PS.map_stream_id = ProtoField.uint8("ps.map_stream_id", "map_stream_id", base.HEX)
f_PS.program_stream_map_length = ProtoField.uint16("ps.program_stream_map_length", "program_stream_map_length")
f_PS.current_next_indicator = ProtoField.uint8("ps.current_next_indicator", "current_next_indicator", base.HEX, nil, 0x80)
f_PS.psm_reserved1 = ProtoField.uint8("ps.psm_reserved1", "reserved", base.HEX, nil, 0x60)
f_PS.program_stream_map_version = ProtoField.uint8("ps.program_stream_map_version", "program_stream_map_version", base.HEX, nil, 0x1F)
f_PS.psm_reserved2 = ProtoField.uint8("ps.psm_reserved2", "reserved", base.HEX, nil, 0xFE)
f_PS.program_stream_info_length = ProtoField.uint16("ps.program_stream_info_length", "program_stream_info_length")
f_PS.elementary_stream_map_length = ProtoField.uint16("ps.elementary_stream_map_length", "elementary_stream_map_length")
f_PS.psm_crc = ProtoField.bytes("ps.psm_crc", "crc_32")

f_PS.directory_stream_id = ProtoField.uint8("ps.directory_stream_id", "directory_stream_id", base.HEX)
f_PS.number_of_access_units = ProtoField.uint16("ps.number_of_access_units", "number_of_access_units")
f_PS.prev_directory_offset = ProtoField.uint64("ps.prev_directory_offset", "prev_directory_offset")
f_PS.prev_directory_offset_bit_44_30 = ProtoField.uint64("ps.prev_directory_offset_bit_44_30", "prev_directory_offset_bit_44_30", base.HEX, nil, 0xFE)
f_PS.prev_directory_offset_bit_29_15 = ProtoField.uint64("ps.prev_directory_offset_bit_29_15", "prev_directory_offset_bit_29_15", base.HEX, nil, 0xFE)
f_PS.prev_directory_offset_bit_14_0 = ProtoField.uint64("ps.prev_directory_offset_bit_14_0", "prev_directory_offset_bit_14_0", base.HEX, nil, 0xFE)
f_PS.next_directory_offset = ProtoField.uint64("ps.next_directory_offset", "next_directory_offset")
f_PS.next_directory_offset_bit_44_30 = ProtoField.uint64("ps.next_directory_offset_bit_44_30", "next_directory_offset_bit_44_30", base.HEX, nil, 0xFE)
f_PS.next_directory_offset_bit_29_15 = ProtoField.uint64("ps.next_directory_offset_bit_29_15", "next_directory_offset_bit_29_15", base.HEX, nil, 0xFE)
f_PS.next_directory_offset_bit_14_0 = ProtoField.uint64("ps.next_directory_offset_bit_14_0", "next_directory_offset_bit_14_0", base.HEX, nil, 0xFE)
f_PS.packet_stream_id = ProtoField.uint8("ps.packet_stream_id", "packet_stream_id")
f_PS.PES_header_position_offset_sign = ProtoField.uint8("ps.PES_header_position_offset_sign", "PES_header_position_offset_sign", base.HEX, nil, 0x80)
f_PS.PES_header_position_offset = ProtoField.uint64("ps.PES_header_position_offset", "PES_header_position_offset")
f_PS.PES_header_position_offset_bit_43_30 = ProtoField.uint16("ps.PES_header_position_offset_bit_43_30", "PES_header_position_offset_bit_43_30", base.HEX, nil, 0x7FFE)
f_PS.PES_header_position_offset_bit_29_15 = ProtoField.uint16("ps.PES_header_position_offset_bit_29_15", "PES_header_position_offset_bit_29_15", base.HEX, nil, 0xFFFE)
f_PS.PES_header_position_offset_bit_14_0 = ProtoField.uint16("ps.PES_header_position_offset_bit_14_0", "PES_header_position_offset_bit_14_0", base.HEX, nil, 0xFFFE)
f_PS.reference_offset = ProtoField.uint16("ps.reference_offset", "reference_offset")
f_PS.psd_reserved3 = ProtoField.uint8("ps.psd_reserved3", "reserved", base.HEX, nil, 0x70)
f_PS.psd_PTS = ProtoField.uint64("ps.psd_PTS", "PTS", base.HEX)
f_PS.psd_PTS_bit_32_30 = ProtoField.uint8("ps.psd_PTS_bit_32_30", "PTS_bit_32_30", base.HEX, nil, 0x0E)
f_PS.psd_PTS_bit_29_15 = ProtoField.uint16("ps.psd_PTS_bit_29_15", "PTS_bit_29_15", base.HEX, nil, 0xFFFE)
f_PS.psd_PTS_bit_14_0 = ProtoField.uint16("ps.psd_PTS_bit_14_0", "PTS_bit_14_0", base.HEX, nil, 0xFFFE)
f_PS.psd_bytes_to_read = ProtoField.uint32("ps.psd_bytes_to_read", "bytes_to_read")
f_PS.psd_bytes_to_read_bit_22_8 = ProtoField.uint32("ps.psd_bytes_to_read_bit_22_8", "bytes_to_read_bit_22_8", base.HEX, nil, 0xFFFE)
f_PS.psd_bytes_to_read_bit_7_0 = ProtoField.uint8("ps.psd_bytes_to_read_bit_7_0", "psd_bytes_to_read_bit_7_0")
f_PS.intra_conded_indicator = ProtoField.uint8("ps.intra_conded_indicator", "intra_conded_indicator", base.HEX, nil, 0x80)
f_PS.coding_parameters_indicator = ProtoField.uint8("ps.coding_parameters_indicator", "coding_parameters_indicator", base.HEX, nil, 0x60)
f_PS.psd_reserved4 = ProtoField.uint8("ps.psd_reserved4", "reserved", base.HEX, nil, 0x0F)

f_PS.stream_id = ProtoField.uint8("ps.stream_id", "stream_id", base.HEX)
f_PS.PES_packet_length = ProtoField.uint16("ps.PES_packet_length", "PES_packet_length")
f_PS.PES_packet_data_byte = ProtoField.bytes("ps.PES_packet_data_byte", "PES_packet_data_byte")
f_PS.padding_byte = ProtoField.bytes("ps.padding_byte", "padding_byte")
f_PS.video_stream_number = ProtoField.uint8("ps.video_stream_number", "video_stream_number", base.HEX, nil, 0x0F)
f_PS.audio_stream_number = ProtoField.uint8("ps.audio_stream_number", "audio_stream_number", base.HEX, nil, 0x1F)
f_PS.PES_scrambling_control = ProtoField.uint8("ps.PES_scrambling_control", "PES_scrambling_control", base.HEX, {[0x00]="Not Scrambled", [0x01] = "User Defined"
								, [0x10] = "User Defined", [0x11] = "User Defined"}, 0x30)
f_PS.PES_priority = ProtoField.uint8("ps.PES_priority", "PES_priority", base.HEX, nil, 0x08)
f_PS.data_alignment_indicator = ProtoField.uint8("ps.data_alignment_indicator", "data_alignment_indicator", base.HEX, nil, 0x04)
f_PS.copyright = ProtoField.uint8("ps.copyright", "copyright", base.HEX, nil, 0x02)
f_PS.original_or_copy = ProtoField.uint8("ps.original_or_copy", "original_or_copy", base.HEX, nil, 0x01)
f_PS.PTS_DTS_flags = ProtoField.uint8("ps.PTS_DTS_flags", "PTS_DTS_flags", base.HEX, nil, 0xC0)
f_PS.ESCR_flag = ProtoField.uint8("ps.ESCR_flag", "ESCR_flag", base.HEX, nil, 0x20)
f_PS.ES_rate_flag = ProtoField.uint8("ps.ES_rate_flag", "ES_rate_flag", base.HEX, nil, 0x10)
f_PS.DSM_trick_mode_flag = ProtoField.uint8("ps.DSM_trick_mode_flag", "DSM_trick_mode_flag", base.HEX, nil, 0x08)
f_PS.additional_copy_info_flag = ProtoField.uint8("ps.additional_copy_info_flag", "additional_copy_info_flag", base.HEX, nil, 0x04)
f_PS.PES_CRC_flag = ProtoField.uint8("ps.PES_CRC_flag", "PES_CRC_flag", base.HEX, nil, 0x02)
f_PS.PES_extension_flag = ProtoField.uint8("ps.PES_extension_flag", "PES_extension_flag", base.HEX, nil, 0x01)
f_PS.PES_header_data_length = ProtoField.uint8("ps.PES_header_data_length", "PES_header_data_length")

f_PS.PTS = ProtoField.uint64("ps.PTS", "PTS", base.HEX)
f_PS.PTS_bit_32_30 = ProtoField.uint8("ps.PTS_bit_32_30", "PTS_bit_32_30", base.HEX, nil, 0x0E)
f_PS.PTS_bit_29_15 = ProtoField.uint16("ps.PTS_bit_29_15", "PTS_bit_29_15", base.HEX, nil, 0xFFFE)
f_PS.PTS_bit_14_0 = ProtoField.uint16("ps.PTS_bit_14_0", "PTS_bit_14_0", base.HEX, nil, 0xFFFE)
f_PS.DTS = ProtoField.uint64("ps.DTS", "DTS", base.HEX)
f_PS.DTS_bit_32_30 = ProtoField.uint8("ps.DTS_bit_32_30", "DTS_bit_32_30", base.HEX, nil, 0x0E)
f_PS.DTS_bit_29_15 = ProtoField.uint16("ps.DTS_bit_29_15", "DTS_bit_29_15", base.HEX, nil, 0xFFFE)
f_PS.DTS_bit_14_0 = ProtoField.uint16("ps.DTS_bit_14_0", "DTS_bit_14_0", base.HEX, nil, 0xFFFE)

f_PS.ESCR_reserved = ProtoField.uint64("ps.ESCR_reserved", "reserved", base.HEX, nil, 0xC0)
f_PS.ESCR_base = ProtoField.uint64("ps.ESCR_base", "ESCR_base", base.HEX)
f_PS.ESCR_base_bit_32_30 = ProtoField.uint8("ps.ESCR_base_bit_32_30", "ESCR_base_bit_32_30", base.HEX, nil, 0x38)
f_PS.ESCR_base_bit_29_15 = ProtoField.uint32("ps.ESCR_base_bit_29_15", "ESCR_base_bit_29_15", base.HEX, nil, 0x3FFF8)
f_PS.ESCR_base_bit_14_0 = ProtoField.uint32("ps.ESCR_base_bit_14_0", "ESCR_base_bit_14_0", base.HEX, nil, 0x3FFF8)
f_PS.ESCR_extension = ProtoField.uint16("ps.system_clock_reference_extension", "system_clock_reference_extension", base.HEX, nil, 0x3FE)

f_PS.ES_rate = ProtoField.uint24("ps.ES_rate", "ES_rate", base.HEX, nil, 0x7FFFFE)

local trick_mode_control_name = {
[0x0] = "Fast Forward",
[0x1] = "Slow Motion",
[0x2] = "Freeze Frame",
[0x3] = "Fast Reverse",
[0x4] = "Slow Reverse",}
f_PS.trick_mode_control = ProtoField.uint8("ps.trick_mode_control", "trick_mode_control", base.HEX, trick_mode_control_name, 0xE0)
f_PS.trick_mode_control_field_id = ProtoField.uint8("ps.trick_mode_control_field_id", "field_id", base.HEX, {[0]="Display from topo field only", [1] = "Display from bottom field only",
									[2] = "Display complete frame", [3] = "Reserved"}, 0x18)
f_PS.trick_mode_control_intra_slice_refresh = ProtoField.uint8("ps.trick_mode_control_intra_slice_refresh", "intra_slice_refresh", base.HEX, nil, 0x04)
f_PS.trick_mode_control_frequency_truncation = ProtoField.uint8("ps.trick_mode_control_frequency_truncation", "frequency_truncation", base.HEX, {[0]="Only DC co non-zero",
									[1] = "Only the first three co non-zero", [2] = "Only the first six co non-zero", [3] = "All co non-zeros"}, 0x03)
f_PS.trick_mode_control_rep_cntrl = ProtoField.uint8("ps.trick_mode_control_rep_cntrl", "rep_cntrl", base.HEX, nil, 0x1F)
f_PS.trick_mode_control_reserved3 = ProtoField.uint8("ps.trick_mode_control_reserved3", "reserved", base.HEX, nil, 0x07)
f_PS.trick_mode_control_reserved5 = ProtoField.uint8("ps.trick_mode_control_reserved5", "reserved", base.HEX, nil, 0x1F)

f_PS.additional_copy_info = ProtoField.uint8("ps.additional_copy_info", "additional_copy_info", base.HEX, nil, 0x7F)
f_PS.previous_PES_packet_CRC = ProtoField.bytes("ps.previous_PES_packet_CRC", "previous_PES_packet_CRC")

f_PS.PES_private_data_flag = ProtoField.uint8("ps.PES_private_data_flag", "PES_private_data_flag", base.HEX, nil, 0x80)
f_PS.pack_header_field_flag = ProtoField.uint8("ps.pack_header_field_flag", "pack_header_field_flag", base.HEX, nil, 0x40)
f_PS.program_packet_sequence_counter_flag = ProtoField.uint8("ps.program_packet_sequence_counter_flag", "pack_header_field_flag", base.HEX, nil, 0x20)
f_PS.PSTD_buffer_flag = ProtoField.uint8("ps.PSTD_buffer_flag", "P-STD_buffer_flag", base.HEX, nil, 0x10)
f_PS.PES_extension_reserved = ProtoField.uint8("ps.PES_extension_reserved", "reserved", base.HEX, nil, 0x0E)
f_PS.PES_extension_flag_2 = ProtoField.uint8("ps.PES_extension_flag_2", "PES_extension_flag_2", base.HEX, nil, 0x01)
f_PS.PES_private_data = ProtoField.bytes("ps.PES_private_data", "PES_private_data")
f_PS.packet_field_length = ProtoField.uint8("ps.packet_field_length", "packet_field_length")
f_PS.program_packet_sequence_counter = ProtoField.uint8("ps.program_packet_sequence_counter", "program_packet_sequence_counter", base.HEX, nil, 0x7F)
f_PS.MPEG1_MPEG2_identifier = ProtoField.uint8("ps.MPEG1_MPEG2_identifier", "MPEG1_MPEG2_identifier", base.HEX, nil, 0x40)
f_PS.original_stuff_length = ProtoField.uint8("ps.original_stuff_length", "original_stuff_length", base.HEX, nil, 0x3F)
f_PS.PSTD_buffer_scale = ProtoField.uint8("ps.PSTD_buffer_scale", "P-STD_buffer_scale", base.HEX, nil, 0x20)
f_PS.PSTD_buffer_size = ProtoField.uint16("ps.PSTD_buffer_size", "P-STD_buffer_size", base.HEX, nil, 0x1FFF)
f_PS.PES_extension_field_length = ProtoField.uint8("ps.PES_extension_field_length", "PES_extension_field_length", base.HEX, nil, 0x7F)
f_PS.PES_extension_field = ProtoField.bytes("ps.PES_extension_field", "PES_extension_field")
f_PS.PES_extension_stuffing_byte = ProtoField.bytes("ps.PES_extension_stuffing_byte", "PES_extension_stuffing_byte")


function check_marker_bit(bitfield, range, pinfo, tree)
	if bitfield ~= 1 then
		_Warning(string.format("miss bit field"), range, pinfo, tree)
	end
end

-- <<<<<<<<<<<<<<<<<<<<<<<<<< Pack Header & System Header <<<<<<<<<<<<<<<<<<<<<<<<<<
function deal_system_header_stream_id(buffer, pinfo, tree)
	local stream_id = buffer(0, 1):uint()
	tree:add(buffer(0, 1), string.format("stream_id: 0x%02x", stream_id))
	if stream_id == 0xB8 then -- 0x10111000
		tree:append_text(", all audio streams")
	elseif stream_id == 0xB9 then -- 0x10111001
		tree:append_text(", all video streams")
	elseif stream_id < 0xBC then -- 0x10111100
		_Warning(string.format("invalid stream_id: 0x%02x", stream_id), buffer(0, 1), pinfo, tree)
	end
	
end
-- return: next buffer
function  system_header(buffer, pinfo, tree)
	local header_len = 6 + buffer(4, 2):uint()
	local offset = 0
	local next_buffer = nil
	
	local system_header_tree = tree:add(p_PS, buffer(0, header_len), "System Header")
	pinfo.cols.info:append(", SystemHeader")

	-- Byte[0, 5]
	local start_code_tree = system_header_tree:add(f_PS.system_header_start_code, buffer(offset, 4))
	start_code_tree:add(f_PS.has_system_header, buffer(0, 4), true)
	offset = offset + 4
	system_header_tree:add(f_PS.system_header_header_length, buffer(offset, 2))
	offset = offset + 2
	-- Byte[6, 8]
	check_marker_bit(buffer(offset):bitfield(0), buffer(offset, 1), pinfo, tree)
	check_marker_bit(buffer(offset):bitfield(23), buffer(offset + 2, 1), pinfo, tree)
	system_header_tree:add(f_PS.rate_bound, buffer(offset, 3))
	offset = offset + 3
	-- Byte[9, 9]
	system_header_tree:add(f_PS.audio_bound, buffer(offset, 1))
	system_header_tree:add(f_PS.fixed_flag, buffer(offset, 1))
	system_header_tree:add(f_PS.CSPS_flag, buffer(offset, 1))
	local CSPS_flag = buffer(offset, 1):bitfield(7, 1)
	offset = offset + 1
	-- Byte[10, 10]
	check_marker_bit(buffer(offset):bitfield(2), buffer(offset, 1), pinfo, tree)
	system_header_tree:add(f_PS.system_audio_lock_flag, buffer(offset, 1))
	system_header_tree:add(f_PS.system_video_lock_flag, buffer(offset, 1))
	system_header_tree:add(f_PS.video_bound, buffer(offset, 1))
	offset = offset + 1
	-- Byte[11, 11]
	if 1 == CSPS_flag then
		system_header_tree:add(f_PS.packet_rate_restriction_flag, buffer(offset, 1))
	end
	system_header_tree:add(f_PS.reserved_bits, buffer(offset, 1))
	offset = offset + 1

	while offset <  header_len and buffer(offset):bitfield(0) do
		local pstd_buffer_info_tree = system_header_tree:add(buffer(offset, 3), "P-STD-buffer_bound_info")
		deal_system_header_stream_id(buffer(offset, 1):tvb(), pinfo, pstd_buffer_info_tree)
		offset = offset + 1
		if buffer(offset):bitfield(0, 2) ~= 0x3 then
			_Error(string.format("Bad Bits after stream_id"), buffer(offset, 1), pinfo, pstd_buffer_info_tree)
		end		
		pstd_buffer_info_tree:add(buffer(offset, 1), string.format("P-STD_buffer_bound_scale : %d", buffer(offset):bitfield(2)))
		pstd_buffer_info_tree:add(buffer(offset, 2), string.format("P-STD_buffer_size_bound : %d", buffer(offset):bitfield(3, 13)))
		offset = offset + 2
	end
	
	next_buffer = buffer(offset)
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
		_Error(string.format("Bad Packet Size(%d)", buffer_len), buffer(0, buffer_len), pinfo, tree)
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
	local pack_header_tree = tree:add(p_PS, buffer(0, pack_header_length), "Pack Header")
	pinfo.cols.info:append(", PackHeader")
	local start_code_tree = pack_header_tree:add(f_PS.pack_start_code, buffer(offset, 4))
	start_code_tree:add(f_PS.has_pack_header, buffer(0, 4), true)
	offset = offset + 4
	-- Byte[4, 9]
	if buffer(offset):bitfield(0, 2) ~= 0x1 then
		_Error(string.format("Bad Bits after pack_start_code"), buffer(offset, 1), pinfo, tree)
	end
	check_marker_bit(buffer(offset):bitfield(5), buffer(offset, 1), pinfo, tree)
	check_marker_bit(buffer(offset):bitfield(21), buffer(offset + 2, 1), pinfo, tree)
	check_marker_bit(buffer(offset):bitfield(37), buffer(offset + 3, 1), pinfo, tree)
	check_marker_bit(buffer(offset):bitfield(47), buffer(offset + 4, 1), pinfo, tree)

	local clock_high = buffer(offset):bitfield(2, 1)
	local clock_low = buffer(offset):bitfield(3, 2) * 0x40000000
	clock_low = clock_low + buffer(offset):bitfield(6, 15) * 0x00008000
	clock_low = clock_low + buffer(offset):bitfield(22, 15)
	local system_clock_reference_tree = pack_header_tree:add(buffer(offset, 6), "system_clock_reference")
	local system_clock_reference_base_tree = system_clock_reference_tree:add(f_PS.system_clock_reference_base, buffer(offset, 5), UInt64.new(clock_low, clock_high))
	system_clock_reference_base_tree:add(f_PS.system_clock_reference_base_bit_32_30, buffer(offset, 1))
	system_clock_reference_base_tree:add(f_PS.system_clock_reference_base_bit_29_15, buffer(offset, 3))
	system_clock_reference_base_tree:add(f_PS.system_clock_reference_base_bit_14_0, buffer(offset + 2, 3))
	offset = offset + 4
	system_clock_reference_tree:add(f_PS.system_clock_reference_extension, buffer(offset, 2))
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
		pack_header_tree:add(f_PS.pack_stuffing_byte, buffer(offset, pack_stuffing_length))
		offset = offset + pack_stuffing_length
	end
	next_buffer = buffer(offset):tvb()
	-- system_header
	if nextbits == SYSTEM_HEADER_START_CODE then
		next_buffer = system_header(next_buffer, pinfo, pack_header_tree)
	end

	return next_buffer
end
-- >>>>>>>>>>>>>>>>>>>>>>>>>> Pack Header & System Header >>>>>>>>>>>>>>>>>>>>>>>>>>

-- <<<<<<<<<<<<<<<<<<<<<<<<<< PES_packet <<<<<<<<<<<<<<<<<<<<<<<<<< 

-- <<<<<<<<<<<<<<<<<<<<<<<<<< PSM <<<<<<<<<<<<<<<<<<<<<<<<<< 

-- TODO: [Bin Wu] to implement all the descriptors' dissector
function deal_video_stream_desciptor(buffer, pinfo, tree)
	tree:add(buffer(2), "video_stream_desciptor")
end

function deal_unsupported_desciptor(buffer, pinfo, tree)
	tree:add(buffer(2), "unsupported_desciptor")
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
		local descriptor_tag = buffer(offset, 1):uint()
		local descriptor_length = buffer(offset + 1, 1):uint()
		local descriptor_tree = tree:add(buffer(offset, 2 + descriptor_length), "descriptor")
		descriptor_tree:add(buffer(offset, 1), string.format("descriptor_tag: 0x%02x", descriptor_tag))		
		descriptor_tree:add(buffer(offset + 1, 1), string.format("descriptor_length: %d", descriptor_length))
		
		local handler = descriptor_handler[descriptor_tag] or deal_unsupported_desciptor
		handler(buffer(offset, 2 + descriptor_length):tvb(), pinfo, descriptor_tree)
		length_count = length_count - 2 - descriptor_length
		offset = offset + 2 +descriptor_length
	end 
	if length_count < 0 then
		_Error("Wrong Descriptor Length", buffer(), pinfo, tree)
	end
end

function program_stream_map(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	local packet_length = buffer(4, 2):uint()

	local psm_tree = tree:add(p_PS, buffer(0, 6 + packet_length), "PSM")
	pinfo.cols.info:append(", PSM")
	psm_tree:add(f_PS.packet_start_code_prefix, buffer(0, 3))
	local start_code_tree = psm_tree:add(f_PS.map_stream_id, buffer(3, 1))
	start_code_tree:add(f_PS.has_psm, buffer(0, 4), true)
	offset = offset + 4
	
	psm_tree:add(f_PS.program_stream_map_length, buffer(offset, 2))
	if buffer(offset, 2):uint() > 0x3FA then
		_Warning(string.format("Bad program_stream_map_length"), buffer(offset, 2), pinfo, psm_tree)
	end
	offset = offset + 2

	psm_tree:add(f_PS.current_next_indicator, buffer(offset, 1))
	psm_tree:add(f_PS.psm_reserved1, buffer(offset, 1))
	psm_tree:add(f_PS.program_stream_map_version, buffer(offset, 1))
	offset = offset + 1

	psm_tree:add(f_PS.psm_reserved2, buffer(offset, 1))
	check_marker_bit(buffer(offset):bitfield(7), buffer(offset, 1), pinfo, psm_tree)
	offset = offset + 1

	local psinfo_length = buffer(offset, 2):uint()
	psm_tree:add(f_PS.program_stream_info_length, buffer(offset, 2))
	offset = offset + 2

	if psinfo_length > 0 then
		dissect_descriptors(psinfo_length, buffer(offset, psinfo_length):tvb(), pinfo, psm_tree)
		offset = offset + psinfo_length
	end
	
	psm_tree:add(f_PS.elementary_stream_map_length, buffer(offset, 2))
	local esmap_length = buffer(offset, 2):uint()
	offset = offset + 2
	local esmap_start_offset = offset

	while esmap_length > 0 do
		local stream_type = buffer(offset, 1):uint() --TODO: [Bin Wu] to present the meaning of stream_type
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
		local elementary_stream_id = buffer(offset + 1, 1):uint()
		local elementary_stream_info_length = buffer(offset + 2, 2):uint()
		local elementary_stream_map_tree = psm_tree:add(buffer(offset, 4 + elementary_stream_info_length), "elementary_stream_map")
		elementary_stream_map_tree:add(buffer(offset, 1), string.format("stream_type: 0x%02x", stream_type))		
		elementary_stream_map_tree:add(buffer(offset + 1, 1), string.format("elementary_stream_id: 0x%02x", elementary_stream_id))
		elementary_stream_map_tree:add(buffer(offset + 2, 2), string.format("elementary_stream_info_length: %d", elementary_stream_info_length))
		offset = offset + 4
		if elementary_stream_info_length > 0 then
			dissect_descriptors(elementary_stream_info_length, buffer(offset, elementary_stream_info_length):tvb(), pinfo, elementary_stream_map_tree)
			offset = offset + elementary_stream_info_length
		end
		esmap_length = esmap_length - 4 - elementary_stream_info_length
	end 
	if esmap_length < 0 then
		_Error("Wrong Descriptor in Elamentary Stream Map", buffer(esmap_start_offset, buffer(esmap_start_offset - 2, 2):uint()), pinfo, psm_tree)
	end
	psm_tree:add(f_PS.psm_crc, buffer(offset, 8))
end
-- >>>>>>>>>>>>>>>>>>>>>>>>>> PSM >>>>>>>>>>>>>>>>>>>>>>>>>>
-- <<<<<<<<<<<<<<<<<<<<<<<<<< PSD <<<<<<<<<<<<<<<<<<<<<<<<<< 
function program_stream_directory(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	local packet_length = buffer(4, 2):uint()
	
	local header_tree = tree:add(p_PS, buffer(0, 6 + packet_length), "PSD")
	pinfo.cols.info:append(", PSD")

	header_tree:add(f_PS.packet_start_code_prefix, buffer(0, 3))
	local start_code_tree = header_tree:add(f_PS.directory_stream_id, buffer(3, 1))
	start_code_tree:add(f_PS.has_psd, buffer(0, 4), true)

	offset = offset + 4
	
	header_tree:add(f_PS.PES_packet_length, buffer(offset, 2))
	offset = offset + 2

	check_marker_bit(buffer(offset):bitfield(15), buffer(offset, 1), pinfo, header_tree)
	header_tree:add(f_PS.number_of_access_units, buffer(offset, 1))
	number_of_access_units = buffer(offset):bitfield(15)
	offset = offset + 1

	local pd_offset_high = buffer(offset):bitfield(0, 13)
	local pd_offset_low = buffer(offset):bitfield(13, 2) * 0x40000000
	pd_offset_low = pd_offset_low + buffer(offset):bitfield(16, 15) * 0x00008000
	pd_offset_low = pd_offset_low + buffer(offset):bitfield(32, 15)

	local prev_directory_offset_tree = header_tree:add(f_PS.prev_directory_offset, buffer(offset, 6), UInt64.new(pd_offset_low, pd_offset_high))

	check_marker_bit(buffer(offset):bitfield(15), buffer(offset + 1, 1), pinfo, prev_directory_offset_tree)
	check_marker_bit(buffer(offset):bitfield(31), buffer(offset + 3, 1), pinfo, prev_directory_offset_tree)
	check_marker_bit(buffer(offset):bitfield(47), buffer(offset + 5, 1), pinfo, prev_directory_offset_tree)

	prev_directory_offset_tree:add(f_PS.prev_directory_offset_bit_44_30, buffer(offset, 2))
	prev_directory_offset_tree:add(f_PS.prev_directory_offset_bit_29_15, buffer(offset + 2, 2))
	prev_directory_offset_tree:add(f_PS.prev_directory_offset_bit_14_0, buffer(offset + 4, 2))
	offset = offset + 6

	local nd_offset_high = buffer(offset):bitfield(0, 13)
	local nd_offset_low = buffer(offset):bitfield(13, 2) * 0x40000000
	nd_offset_low = nd_offset_low + buffer(offset):bitfield(16, 15) * 0x00008000
	nd_offset_low = nd_offset_low + buffer(offset):bitfield(32, 15)

	local next_directory_offset_tree = header_tree:add(f_PS.next_directory_offset, buffer(offset, 6), UInt64.new(nd_offset_low, nd_offset_high))

	check_marker_bit(buffer(offset):bitfield(15), buffer(offset + 1, 1), pinfo, next_directory_offset_tree)
	check_marker_bit(buffer(offset):bitfield(31), buffer(offset + 3, 1), pinfo, next_directory_offset_tree)
	check_marker_bit(buffer(offset):bitfield(47), buffer(offset + 5, 1), pinfo, next_directory_offset_tree)

	next_directory_offset_tree:add(f_PS.next_directory_offset_bit_44_30, buffer(offset, 2))
	next_directory_offset_tree:add(f_PS.next_directory_offset_bit_29_15, buffer(offset + 2, 2))
	next_directory_offset_tree:add(f_PS.next_directory_offset_bit_14_0, buffer(offset + 4, 2))
	offset = offset + 6
	local i
	for i = 0, number_of_access_units - 1, 1 do
		local access_unit_tree = header_tree:add(buffer(offset, 18), "access_unit")
		access_unit_tree:add(f_PS.packet_stream_id, buffer(offset, 1))
		offset = offset + 1

		access_unit_tree:add(f_PS.PES_header_position_offset_sign, buffer(offset, 1))

		local hp_offset_high = buffer(offset):bitfield(1, 12)
		local hp_offset_low = buffer(offset):bitfield(13, 2) * 0x40000000
		hp_offset_low = hp_offset_low + buffer(offset):bitfield(16, 15) * 0x00008000
		hp_offset_low = hp_offset_low + buffer(offset):bitfield(32, 15)

		local hp_offset_tree = access_unit_tree:add(f_PS.PES_header_position_offset, buffer(offset, 6), UInt64.new(hp_offset_low, hp_offset_high))

		check_marker_bit(buffer(offset):bitfield(15), buffer(offset + 1, 1), pinfo, hp_offset_tree)
		check_marker_bit(buffer(offset):bitfield(31), buffer(offset + 3, 1), pinfo, hp_offset_tree)
		check_marker_bit(buffer(offset):bitfield(47), buffer(offset + 5, 1), pinfo, hp_offset_tree)

		hp_offset_tree:add(f_PS.PES_header_position_offset_bit_42_30, buffer(offset, 2))
		hp_offset_tree:add(f_PS.PES_header_position_offset_bit_29_15, buffer(offset + 2, 2))
		hp_offset_tree:add(f_PS.PES_header_position_offset_bit_14_0, buffer(offset + 4, 2))
		offset = offset + 6
		
		access_unit_tree:add(f_PS.reference_offset, buffer(offset, 2))
		offset = offset + 2

		check_marker_bit(buffer(offset):bitfield(0), buffer(offset, 1), pinfo, access_unit_tree)
		access_unit_tree:add(f_PS.psd_reserved3, buffer(offset, 1))


		local PTS_high = buffer(offset):bitfield(4, 1)
		local PTS_low = buffer(offset):bitfield(5, 2) * 0x40000000
		PTS_low = PTS_low + buffer(offset):bitfield(8, 15) * 0x00008000
		PTS_low = PTS_low + buffer(offset):bitfield(24, 15)
		
		local PTS_tree = access_unit_tree:add(f_PS.psd_PTS, buffer(offset, 5), UInt64.new(PTS_low, PTS_high))
		check_marker_bit(buffer(offset):bitfield(7), buffer(offset, 1), pinfo, PTS_tree)
		check_marker_bit(buffer(offset):bitfield(23), buffer(offset + 2, 1), pinfo, PTS_tree)
		check_marker_bit(buffer(offset):bitfield(39), buffer(offset + 4, 1), pinfo, PTS_tree)

		PTS_tree:add(f_PS.psd_PTS_bit_32_30, buffer(offset, 1))
		PTS_tree:add(f_PS.psd_PTS_bit_29_15, buffer(offset + 1, 2))
		PTS_tree:add(f_PS.psd_PTS_bit_14_0, buffer(offset + 3, 2))
		offset = offset + 5

		local bytes_to_read = buffer(offset):bitfield(0, 15) * 0x08
		bytes_to_read = bytes_to_read + buffer(offset):bitfield(16, 8)

		local bytes_to_read_tree = access_unit_tree:add(f_PS.bytes_to_read, buffer(offset, 3), bytes_to_read)
		check_marker_bit(buffer(offset):bitfield(15), buffer(offset, 1), pinfo, bytes_to_read_tree)
		bytes_to_read_tree:add(f_PS.bytes_to_read_bit_22_8, buffer(offset, 1))
		bytes_to_read_tree:add(f_PS.bytes_to_read_bit_7_0, buffer(offset + 2, 1))
		offset = offset + 3
		
		access_unit_tree:add(f_PS.intra_conded_indicator, buffer(offset, 1))
		access_unit_tree:add(f_PS.coding_parameters_indicator, buffer(offset, 1))
		access_unit_tree:add(f_PS.psd_reserved4, buffer(offset, 1))
		offset = offset + 1
	end
end
-- >>>>>>>>>>>>>>>>>>>>>>>>>> PSD >>>>>>>>>>>>>>>>>>>>>>>>>>
function padding_stream(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	local packet_length = buffer(4, 2):uint()

	local header_tree = tree:add(p_PS, buffer(0, 6 + packet_length), "padding_stream")
	pinfo.cols.info:append(", padding_stream")

	header_tree:add(f_PS.packet_start_code_prefix, buffer(0, 3))
	header_tree:add(f_PS.stream_id, buffer( 3, 1))
	offset = offset + 4
	
	header_tree:add(f_PS.PES_packet_length, buffer(offset, 2))
	offset = offset + 2
	header_tree:add(f_PS.padding_byte, buffer(offset, packet_length))

end
function deal_av_stream_id(buffer, pinfo, tree, root)
	local stream_id = buffer(0, 1):uint()
	if stream_id >= 0xC0 and stream_id <= 0xDF then
		-- audio
		local audio_id = buffer(0):bitfield(3, 5)
		tree:add(f_PS.audio_stream_number, buffer(0, 1))
		tree:add(f_PS.has_audio, buffer(0, 1), true)
		pinfo.cols.info:append(string.format("_audio_%d", audio_id));
		root:append_text(string.format("_audio_%d", audio_id))
	elseif stream_id >= 0xE0 and stream_id <= 0xEF then
		-- video
		local video_id = buffer(0):bitfield(4, 4)
		tree:add(f_PS.video_stream_number, buffer(0, 1))
		tree:add(f_PS.has_video, buffer(0, 1), true)
		pinfo.cols.info:append(string.format("_video_%d", video_id));
		root:append_text(string.format("_video_%d", video_id))
	end
end
function with_PES_header(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	local stream_id = buffer(3, 1):uint()
	local packet_length = buffer(4, 2):uint()
	
	local header_tree = tree:add(p_PS, buffer(0, 6 + packet_length), "PES_packet")
	pinfo.cols.info:append(", PES_packet")

	header_tree:add(f_PS.packet_start_code_prefix, buffer(0, 3))

	local stream_id_tree = header_tree:add(f_PS.stream_id, buffer(3, 1))
	deal_av_stream_id(buffer(3, 1):tvb(), pinfo, stream_id_tree, header_tree)
	offset = offset + 4
	
	header_tree:add(f_PS.PES_packet_length, buffer(offset, 2))
	offset = offset + 2
	if buffer(offset):bitfield(0, 2) ~= 0x2 then
		_Error(string.format("Bad Bits after PES_packet_length"), buffer(offset, 1), pinfo, header_tree)
	end
	-- Byte[6, 6]
	header_tree:add(f_PS.PES_scrambling_control, buffer(offset, 1))
	header_tree:add(f_PS.PES_priority, buffer(offset, 1))
	header_tree:add(f_PS.data_alignment_indicator, buffer(offset, 1))
	header_tree:add(f_PS.copyright, buffer(offset, 1))
	header_tree:add(f_PS.original_or_copy, buffer(offset, 1))
	offset = offset + 1
	-- Byte[7, 7]
	local all_flags = buffer(offset, 1):uint()
	header_tree:add(f_PS.PTS_DTS_flags, buffer(offset, 1))
	local PTS_DTS_flags = buffer(offset):bitfield(0, 2)
	if 0x1 == PTS_DTS_flags then
		_Error(string.format("Forbiddened PTS_DTS_flags value"), buffer(offset, 1), pinfo, header_tree)
	end
	header_tree:add(f_PS.ESCR_flag, buffer(offset, 1))
	local ESCR_flag = buffer(offset):bitfield(2, 1)
	header_tree:add(f_PS.ES_rate_flag, buffer(offset, 1))
	local ES_rate_flag = buffer(offset):bitfield(3, 1)
	header_tree:add(f_PS.DSM_trick_mode_flag, buffer(offset, 1))
	local DSM_trick_mode_flag = buffer(offset):bitfield(4, 1)
	header_tree:add(f_PS.additional_copy_info_flag, buffer(offset, 1))
	local additional_copy_info_flag = buffer(offset):bitfield(5, 1)
	header_tree:add(f_PS.PES_CRC_flag, buffer(offset, 1))
	local PES_CRC_flag = buffer(offset):bitfield(6, 1)
	header_tree:add(f_PS.PES_extension_flag, buffer(offset, 1))
	local PES_CRC_flag = buffer(offset):bitfield(7, 1)
	offset = offset + 1
	-- Byte[8, 8]
	header_tree:add(f_PS.PES_header_data_length, buffer(offset, 1))
	local PES_header_data_length = buffer(offset, 1):uint()
	offset = offset + 1
	local PES_header_data_start = offset
	-- optional fields	
	if all_flags ~= 0 then
		local optional_fields_tree = header_tree:add(buffer(offset, PES_header_data_length), "optional_fields")
		-- PTS_DTS_flags PTS
		if 0x2 <= PTS_DTS_flags then
			if buffer(offset):bitfield(0, 4) ~= PTS_DTS_flags then
				_Error(string.format("Bad Bits in PTS_DTS_flags field"), buffer(offset, 1), pinfo, header_tree)
			end

			local PTS_high = buffer(offset):bitfield(4, 1)
			local PTS_low = buffer(offset):bitfield(5, 2) * 0x40000000
			PTS_low = PTS_low + buffer(offset):bitfield(8, 15) * 0x00008000
			PTS_low = PTS_low + buffer(offset):bitfield(24, 15)
			
			local PTS_tree = optional_fields_tree:add(f_PS.PTS, buffer(offset, 5), UInt64.new(PTS_low, PTS_high))

			check_marker_bit(buffer(offset):bitfield(7), buffer(offset, 1), pinfo, PTS_tree)
			check_marker_bit(buffer(offset):bitfield(23), buffer(offset + 2, 1), pinfo, PTS_tree)
			check_marker_bit(buffer(offset):bitfield(39), buffer(offset + 4, 1), pinfo, PTS_tree)

			PTS_tree:add(f_PS.PTS_bit_32_30, buffer(offset, 1))
			PTS_tree:add(f_PS.PTS_bit_29_15, buffer(offset + 1, 2))
			PTS_tree:add(f_PS.PTS_bit_14_0, buffer(offset + 3, 2))
			offset = offset + 5
		end
		-- PTS_DTS_flags DTS
		if 0x3 == PTS_DTS_flags then
			if buffer(offset):bitfield(0, 4) ~= 0x01 then
				_Error(string.format("Bad Bits in PTS_DTS_flags field"), buffer(offset, 1), pinfo, header_tree)
			end
			check_marker_bit(buffer(offset):bitfield(7), buffer(offset, 1), pinfo, optional_fields_tree)
			check_marker_bit(buffer(offset):bitfield(23), buffer(offset + 2, 1), pinfo, optional_fields_tree)
			check_marker_bit(buffer(offset):bitfield(39), buffer(offset + 4, 1), pinfo, optional_fields_tree)
			
			local DTS_high = buffer(offset):bitfield(4, 1)
			local DTS_low = buffer(offset):bitfield(5, 2) * 0x40000000
			DTS_low = DTS_low + buffer(offset):bitfield(8, 15) * 0x00008000
			DTS_low = DTS_low + buffer(offset):bitfield(24, 15)
			
			local DTS_tree = optional_fields_tree:add(f_PS.DTS, buffer(offset, 5), UInt64.new(DTS_low, DTS_high))
			DTS_tree:add(f_PS.DTS_bit_32_30, buffer(offset, 1))
			DTS_tree:add(f_PS.DTS_bit_29_15, buffer(offset + 1, 2))
			DTS_tree:add(f_PS.DTS_bit_14_0, buffer(offset + 3, 2))
			offset = offset + 5
		end
		-- ESCR_flag
		if 1 == ESCR_flag then
			local ESCR_tree = optional_fields_tree:add(buffer(offset, 6), "ESCR")
			ESCR_tree:add(f_PS.ESCR_reserved, buffer(offset, 1))
			check_marker_bit(buffer(offset):bitfield(5), buffer(offset, 1), pinfo, ESCR_tree)
			check_marker_bit(buffer(offset):bitfield(21), buffer(offset + 2, 1), pinfo, ESCR_tree)
			check_marker_bit(buffer(offset):bitfield(37), buffer(offset + 3, 1), pinfo, ESCR_tree)
			check_marker_bit(buffer(offset):bitfield(47), buffer(offset + 4, 1), pinfo, ESCR_tree)

			local clock_high = buffer(offset):bitfield(2, 1)
			local clock_low = buffer(offset):bitfield(3, 2) * 0x40000000
			clock_low = clock_low + buffer(offset):bitfield(6, 15) * 0x00008000
			clock_low = clock_low + buffer(offset):bitfield(22, 15)
			local ESCR_base_tree = ESCR_tree:add(f_PS.ESCR_base, buffer(offset, 5), UInt64.new(clock_low, clock_high))
			ESCR_base_tree:add(f_PS.ESCR_base_bit_32_30, buffer(offset, 1))
			ESCR_base_tree:add(f_PS.ESCR_base_bit_29_15, buffer(offset, 3))
			ESCR_base_tree:add(f_PS.ESCR_base_bit_14_0, buffer(offset + 2, 3))
			offset = offset + 4
			ESCR_tree:add(f_PS.ESCR_extension,  buffer(offset, 2))
			offset = offset + 2	
		end
		-- ES_rate_flag
		if 1 == ES_rate_flag then
			local ES_rate_tree = optional_fields_tree:add(buffer(offset, 3), "ES_rate")
			check_marker_bit(buffer(offset):bitfield(0), buffer(offset, 1), pinfo, ES_rate_tree)
			check_marker_bit(buffer(offset):bitfield(23), buffer(offset + 2, 1), pinfo, ES_rate_tree)
			ES_rate_tree:add(f_PS.ES_rate, buffer(offset, 3))
			offset = offset + 3
		end
		-- DSM_trick_mode_flag
		if 1 == DSM_trick_mode_flag then
			local DSM_trick_mode_tree = optional_fields_tree:add(buffer(offset, 1), "DSM_trick_mode")
			DSM_trick_mode_tree:add(f_PS.trick_mode_control, buffer(offset, 1))
			local trick_mode_control = buffer(offset):bitfield(0, 3)
			if trick_mode_control == 0 or trick_mode_control == 3 then
				DSM_trick_mode_tree:append_text(string.format(", %s", trick_mode_control_name[trick_mode_control]))
				DSM_trick_mode_tree:add(f_PS.trick_mode_control_field_id, buffer(offset, 1))
				DSM_trick_mode_tree:add(f_PS.trick_mode_control_intra_slice_refresh, buffer(offset, 1))
				DSM_trick_mode_tree:add(f_PS.trick_mode_control_frequency_truncation, buffer(offset, 1))
			elseif trick_mode_control == 1 or trick_mode_control == 4 then
				DSM_trick_mode_tree:append_text(string.format(", %s", trick_mode_control_name[trick_mode_control]))
				DSM_trick_mode_tree:add(f_PS.trick_mode_control_rep_cntrl, buffer(offset, 1))
			elseif trick_mode_control == 2 then
				DSM_trick_mode_tree:append_text(string.format(", %s", trick_mode_control_name[trick_mode_control]))
				DSM_trick_mode_tree:add(f_PS.trick_mode_control_field_id, buffer(offset, 1))
				DSM_trick_mode_tree:add(f_PS.trick_mode_control_reserved3, buffer(offset, 1))
			else
				DSM_trick_mode_tree:add(f_PS.trick_mode_control_reserved5, buffer(offset, 1))
			end
			offset = offset + 1
		end
		-- additional_copy_info_flag
		if 1 == additional_copy_info_flag then
			local additional_copy_info_tree = optional_fields_tree:add(buffer(offset, 1), "additional_copy_info")
			check_marker_bit(buffer(offset):bitfield(0), buffer(offset, 1), pinfo, additional_copy_info_tree)
			additional_copy_info_tree:add(f_PS.additional_copy_info, buffer(offset, 1))
			offset = offset + 1
		end
		-- PES_CRC_flag
		if 1 == PES_CRC_flag then
			local PES_CRC_tree = optional_fields_tree:add(buffer(offset, 2), "PES_CRC")
			optional_fields_tree:add(f_PS.previous_PES_packet_CRC, buffer(offset, 2))
			offset = offset + 2
		end
		-- PES_extension_flag
		if 1 == PES_extension_flag then
			local PES_extension_tree = optional_fields_tree:add(buffer(offset, 2), "PES_extension")
			PES_extension_tree:add(f_PS.PES_private_data_flag, buffer(offset, 1))
			local PES_private_data_flag = buffer(offset):bitfield(0)
			PES_extension_tree:add(f_PS.pack_header_field_flag, buffer(offset, 1))
			local pack_header_field_flag = buffer(offset):bitfield(1)
			PES_extension_tree:add(f_PS.program_packet_sequence_counter_flag, buffer(offset, 1))
			local program_packet_sequence_counter_flag = buffer(offset):bitfield(2)
			PES_extension_tree:add(f_PS.PSTD_buffer_flag, buffer(offset, 1))
			local PSTD_buffer_flag = buffer(offset):bitfield(3)
			PES_extension_tree:add(f_PS.PES_extension_reserved, buffer(offset, 1))
			local PES_private_data_flag = buffer(offset):bitfield(4, 3)
			PES_extension_tree:add(f_PS.PES_extension_flag_2, buffer(offset, 1))
			local PES_extension_flag_2 = buffer(offset):bitfield(7)
			offset = offset + 1
			if 1 == PES_private_data_flag then
				local PES_private_data_tree = optional_fields_tree:add(buffer(offset, 16), "PES_private_data")
				PES_private_data_tree:add(f_PS.PES_private_data, buffer(offset, 16))
				offset = offset + 16
			end
			if 1 == pack_header_field_flag then
				local packet_field_length = buffer(offset, 1):uint()
				local pack_header_field_tree = optional_fields_tree:add(buffer(offset, 1 + packet_field_length), "pack_header_field")
				pack_header_field_tree:add(f_PS.packet_field_length, buffer(offset, 1))
				offset = offset + 1
				pack_header(buffer(offset, packet_field_length), pinfo, pack_header_field_tree)
				offset = offset + packet_field_length
			end
			if 1 == program_packet_sequence_counter_flag then
				local program_packet_sequence_counter_tree = optional_fields_tree:add(buffer(offset, 2), "program_packet_sequence_counter")
				check_marker_bit(buffer(offset):bitfield(0), buffer(offset, 1), pinfo, program_packet_sequence_counter_tree)
				check_marker_bit(buffer(offset):bitfield(8), buffer(offset + 1, 1), pinfo, program_packet_sequence_counter_tree)
				program_packet_sequence_counter_tree:add(f_PS.program_packet_sequence_counter, buffer(offset, 1))
				offset = offset + 1
				program_packet_sequence_counter_tree:add(f_PS.MPEG1_MPEG2_identifier, buffer(offset, 1))
				program_packet_sequence_counter_tree:add(f_PS.original_stuff_length, buffer(offset, 1))
			end
			if 1 == PSTD_buffer_flag then
				local PSTD_buffer_tree = optional_fields_tree:add(buffer(offset, 2), "P-STD_buffer")
				if buffer(offset):bitfield(0, 2) ~= 0x3 then
					_Error(string.format("Bad Bits in PSTD_buffer"), buffer(offset, 1), pinfo, PSTD_buffer_tree)
				end
				PSTD_buffer_tree:add(f_PS.PSTD_buffer_scale, buffer(offset, 1))
				PSTD_buffer_tree:add(f_PS.PSTD_buffer_size, buffer(offset, 2))
				offset = offset + 2
			end
			if 1 == PES_extension_flag_2 then
				local PES_extension_field_length = buffer(offset):bitfield(1, 7)
				local PES_extension_field_tree = optional_fields_tree:add(buffer(offset, 1 + PES_extension_field_length))
				check_marker_bit(buffer(offset):bitfield(0), buffer(offset, 1), pinfo, PES_extension_field_tree)
				PES_extension_field_tree:add(f_PS.PES_extension_field_length, buffer(offset, 1))
				offset = offset + 1
				PES_extension_field_tree:add(f_PS.PES_extension_field, buffer(offset, PES_extension_field_length))
				offset = offset + PES_extension_field_length
			end
		end
		
	end
	
	local stuffing_byte_length = PES_header_data_length - offset + PES_header_data_start
	if stuffing_byte_length > 0 then
		header_tree:add(f_PS.PES_extension_stuffing_byte, buffer(offset, stuffing_byte_length))
		offset = offset + stuffing_byte_length
	end
	local remain_data_length = packet_length + 6 - offset
	if remain_data_length > 0 then
		header_tree:add(f_PS.PES_packet_data_byte, buffer(offset, remain_data_length))
	end
end

function without_PES_header(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local offset = 0
	local stream_id = buffer(3, 1):uint()
	local packet_length = buffer(4, 2):uint()

	local header_tree = tree:add(p_PS, buffer(0, 6 + packet_length), "PES_packet")
	tree:append_text(", PES_packet")
	pinfo.cols.info:append(", PES_packet")

	header_tree:add(f_PS.packet_start_code_prefix, buffer(0, 3))
	header_tree:add(f_PS.stream_id, buffer( 3, 1))
	offset = offset + 4
	
	header_tree:add(f_PS.PES_packet_length, buffer(offset, 2))
	offset = offset + 2
	header_tree:add(f_PS.PES_packet_data_byte, buffer(offset, packet_length))

end

local need_assemble = false 
local last_working_luastr = nil
local last_expected_length = 0
-- 3 valid state/type with redissect_buffer elements: true false string
local redissect_buffer = {}

--=============================================================================================================================================
-- Stream_id assignments
-----------------------------------------------------------------------------------------------------------------------------------------------
-- stream_id						Note	stream coding
-- 1011 1100(0xBC)					1		program_stream_map
-- 1011 1101(0xBD)					2		private_stream_1
-- 1011 1110(0xBE)							padding_stream
-- 1011 1111(0xBF)					3		private_stream_2
-- 110x xxxx(0xC0-0xDF)						ISO/IEC 13818-3 or ISO/IEC 11172-3 or ISO/IEC 13818-7 or ISO/IEC 14496-3 audio stream number x xxxx
--											MPEG-2 Audio       MPEG-1 Audio       AAC                MPEG-4 Audio 	
-- 1110 xxxx(0xE0-0xEF)						ITU-T Rec. H.262 | ISO/IEC 13818-2 or ISO/IEC 11172-2 or ISO/IEC 14496-2 video stream number xxxx
--											                   MPEG-2 Video       MPEG-1 Video       MPEG-4 Video
-- 1111 0000(0xF0)					3		ECM_stream
-- 1111 0001(0xF1)					3		EMM_stream
-- 1111 0010(0xF2)					5		ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Annex A or ISO/IEC 13818-6_DSMCC_stream
-- 1111 0011(0xF3)					2		ISO/IEC_13522_stream
-- 1111 0100(0xF4)					6		ITU-T Rec. H.222.1 type A
-- 1111 0101(0xF5)					6		ITU-T Rec. H.222.1 type B
-- 1111 0110(0xF6)					6		ITU-T Rec. H.222.1 type C
-- 1111 0111(0xF7)					6		ITU-T Rec. H.222.1 type D
-- 1111 1000(0xF8)					6		ITU-T Rec. H.222.1 type E
-- 1111 1001(0xF9)					7		ancillary_stream
-- 1111 1010(0xFA)							ISO/IEC14496-1_SL-packetized_stream
-- 1111 1011(0xFB)							ISO/IEC14496-1_FlexMux_stream
-- 1111 1100¡­1111 1110(0xFC-0xFE)			reserved data stream
-- 1111 1111(0xFF)					4		program_stream_directory
-----------------------------------------------------------------------------------------------------------------------------------------------
-- The notation x means that the values '0' or '1' are both permitted and results in the same stream type. The stream number is given by
-- the values taken by the x¡¯s.
-- NOTE 1 - PES packets of type program_stream_map have unique syntax specified in 2.5.4.1.
-- NOTE 2 - PES packets of type private_stream_1 and ISO/IEC_13552_stream follow the same PES packet syntax as those for
-- ITU-T Rec. H.262 | ISO/IEC 13818-2 video and ISO/IEC 13818-3 audio streams.
-- NOTE 3 - PES packets of type private_stream_2, ECM_stream and EMM_stream are similar to private_stream_1 except no syntax
-- is specified after PES_packet_length field.
-- NOTE 4 - PES packets of type program_stream_directory have a unique syntax specified in 2.5.5.
-- NOTE 5 - PES packets of type DSM-CC_stream have a unique syntax specified in ISO/IEC 13818- 6.
-- NOTE 6 - This stream_id is associated with stream_type 0x09 in Table 2-29.
-- NOTE 7 - This stream_id is only used in PES packets, which carry data from a Program Stream or an ISO/IEC 11172-1 System
-- Stream, in a Transport Stream (refer to 2.4.3.7).
-----------------------------------------------------------------------------------------------------------------------------------------------
local PES_header_stream_id_handler={
[0xBC] = program_stream_map,
[0xBE] = padding_stream,
[0xBF] = without_PES_header,
[0xF0] = without_PES_header,
[0xF1] = without_PES_header,
[0xF2] = without_PES_header,
[0xF8] = without_PES_header,
[0xFF] = program_stream_directory,
-- otherwise with_PES_header
}
-- return: next buffer
function PES_packet(buffer, pinfo, tree)
	local buffer_len = buffer:len()
	local stream_id = 0
	local packet_length = 0

	if buffer_len > 6 then 
		stream_id = buffer(3, 1):uint()
		packet_length = buffer(4, 2):uint()

		if buffer_len >= 6 + packet_length then
			if speed_mod_on and not pinfo.visited then
				-- nop
				-- when speed_mod_on, only do assembling job, no deeper dissection
			else
				local handler = PES_header_stream_id_handler[stream_id] or with_PES_header
				handler(buffer, pinfo, tree)
			end
			
			if buffer_len == 6 + packet_length then
				return nil
			else
				return buffer(6 + packet_length):tvb()
			end
		end
	end
	-- here comes an incompleted packet, start assembling in comming dissection
	if speed_mod_on and pinfo.visited then
		tree:add(buffer(0), "Start of fragment of PES_packet")
		return nil
	else
		tree:add(buffer(0), "Start of fragment of PES_packet")
		need_assemble = true
		last_expected_length = 6 + packet_length
		last_working_luastr = buffer:raw()
		return nil
	end
end
-- >>>>>>>>>>>>>>>>>>>>>>>>>> PES_packet >>>>>>>>>>>>>>>>>>>>>>>>>>

-- return: bool
function check_pacet_start_code_prefix(buffer)
	if nil == buffer then
		return false
	end
	if buffer(0, 3):uint() == 0x000001 then
		return true
	end
	return false	
end
-- return buffer, nil for need further segments
function try_assemble_PDU(buffer, pinfo, tree)
	if false == need_assemble and nil == redissect_buffer[pinfo.number] then
		 info(string.format("first dissection: nice start %d", pinfo.number))
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
		-- whatever need_assemble is true or false, redissect_buffer with true
		-- means it does not need to assemble former data  
		return buffer
	end
	
	if redissect_buffer[pinfo.number] == nil then
		-- first time processing dissection
		-- when it is inner fragment packet, it will set false in redissect_buffer
		last_working_luastr = last_working_luastr..buffer:raw()
		redissect_buffer[pinfo.number] = false
		-- otherwise, if it is the final fragment packet, redissect_buffer will used 
		-- to record the entire packet data
		if #last_working_luastr >= last_expected_length then
			redissect_buffer[pinfo.number] = last_working_luastr
			need_assemble = false
			last_working_luastr = nil
			--if speed_mod_on then
				-- wireshark may call dissector several times for each PDU, so it will save almost
				-- half of time when just return nil in at first dissection round
				-- return nil
				--
				-- NOTICE!!!! When return nil at the first round, if this PDU contains a part of data of the following PES_packet
				-- the following PES_packet will NOT be assembled correctly
				-- So a tvb SHOULD be created and returned here, no shortcut!
			--else
				return ByteArray.new(redissect_buffer[pinfo.number], true):tvb("PES_packet")
			--end
		end
		return nil
	elseif redissect_buffer[pinfo.number] ~= false then
		-- true value will be returned in former judgement
		-- not equal to false means it contains a luastring
		-- so the packet is the final segment, present it!
		return ByteArray.new(redissect_buffer[pinfo.number], true):tvb("PES_packet")
	end
	tree:add(buffer(0, 0), "fragment of PES_packet")
	return nil
end

-- construct tree
function p_PS.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol:set("PS")
	--info(string.format("p_PS.dissector need_assemble %s  %d visited %s", tostring(need_assemble), pinfo.number, tostring(pinfo.visited)))
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
	need_assemble = false
	last_working_luastr = nil
	redissect_buffer = {}
end
-- ------------------------------------------------------------------------------------------------
--  PS_RTP
-- ------------------------------------------------------------------------------------------------
local p_PS_RTP = Proto("PS_RTP", "MPEG Promgram Stream via RTP")

function p_PS_RTP.dissector(buffer, pinfo, tree)
	local size = Dissector.get("rtp"):call(buffer, pinfo, tree)
	p_PS.dissector(buffer(size):tvb(), pinfo, tree)
	return true
end
p_PS.init = init_function
DissectorTable.get("udp.port"):add_for_decode_as(p_PS_RTP)
DissectorTable.get("tcp.port"):add_for_decode_as(p_PS_RTP)
--DissectorTable.get("udp.port"):add_for_decode_as(p_PS)
--DissectorTable.get("tcp.port"):add_for_decode_as(p_PS)