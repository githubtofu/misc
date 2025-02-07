-- place in ~/.config/wireshark/plugins/

local p_xrce_dds = Proto("xrce-dds", "XRCE-DDS");
local p_xrce_dds_header = Proto("xrce-dds-header", "Header");
local p_xrce_dds_submessage = Proto("xrce-dds-submessage", "Submessage");
local p_xrce_dds_create_client_payload = Proto("xrce-dds-create_client_payload", "Create Client Message Payload");
local p_xrce_dds_create_payload = Proto("xrce-dds-create_payload", "Create Message Payload");

local f_sessionId = ProtoField.uint8("xrce-dds.sessionId", "sessionId", base.HEX)
local f_streamId = ProtoField.uint8("xrce-dds.streamId", "streamId", base.HEX)
local f_sequenceNr = ProtoField.uint16("xrce-dds.sequenceNr", "sequenceNr", base.DEC)
local f_clientKey = ProtoField.uint32("xrce-dds.clientKey", "clientKey", base.HEX)

local f_submessageId = ProtoField.uint8("xrce-dds.submessageId", "submessageId", base.HEX)
local f_flags = ProtoField.uint8("xrce-dds.flags", "flags", base.HEX)
local f_endiannessFlag = ProtoField.uint8("xrce-dds.endiannessFlag", "endianness", base.HEX)
local f_reuseBit = ProtoField.uint8("xrce-dds.reuseBit", "reuseBit", base.HEX)
local f_replaceBit = ProtoField.uint8("xrce-dds.replaceBit", "replaceBit", base.HEX)
local f_submessageLength = ProtoField.uint16("xrce-dds.submessageLength", "submessageLength", base.HEX)

local f_dir = ProtoField.uint8("multi.direction", "Direction", base.DEC, { [1] = "incoming", [0] = "outgoing"})
local f_text = ProtoField.string("multi.text", "Text")

local f_xrceCookie = ProtoField.uint32("xrce-dds.xrceCookie", "Cookie", base.HEX)
local f_xrceVersion = ProtoField.uint8("xrce-dds.xrceVersion", "Version", base.HEX)
local f_xrceVendorId = ProtoField.uint8("xrce-dds.xrceVendorId", "VendorId", base.HEX)
local f_reqClientKey = ProtoField.uint32("xrce-dds.reqClientKey", "ClientKey", base.HEX)
local f_reqSessionId = ProtoField.uint8("xrce-dds.reqSessionId", "SessionId", base.HEX)
local f_properties = ProtoField.uint8("xrce-dds.properties", "Properties", base.HEX)

local f_requestId = ProtoField.uint8("xrce-dds.requestId", "RequestId", base.HEX)
local f_objectId = ProtoField.uint8("xrce-dds.objectId", "ObjectId", base.HEX)
local f_objectVariant = ProtoField.uint8("xrce-dds.objectVariant", "ObjectVariant", base.HEX)
local f_objectDisc = ProtoField.uint8("xrce-dds.objectDisc", "ObjectDiscriminator", base.HEX)
local f_padding1 = ProtoField.uint8("xrce-dds.padding1", "Padding", base.HEX)
local f_length = ProtoField.uint8("xrce-dds.length", "Length", base.HEX)
local f_string_representation = ProtoField.string("xrce-dds.StringRepresentation", "String Representation")

p_xrce_dds_header.fields = { f_sessionId, f_streamId, f_sequenceNr, f_clientKey } 
p_xrce_dds_submessage.fields = { f_submessageId, f_flags, f_submessageLength } 
p_xrce_dds_create_client_payload.fields = { f_xrceCookie, f_xrceVersion, f_xrceVendorId, f_reqClientKey, f_reqSessionId, f_properties} 
p_xrce_dds_create_payload.fields = { f_requestId, f_objectId , f_objectVariant, f_objectDisc, f_padding1, f_length, f_string_representation }
-- p_xrce_dds.fields = { f_sessionId, f_streamId, f_sequenceNr, f_dir, f_text }

local data_dis = Dissector.get("data")
local SUBMESSAGE_ID =  {
    [0] = "CREATE_CLIENT",
    [1] = "CREATE",
    [2] = "GET_INFO",
    [3] = "DELETE_ID",
    [4] = "STATUS_AGENT",
    [5] = "STATUS",
    [6] = "INFO",
    [7] = "WRITE_DATA",
    [8] = "READ_DATA",
    [9] = "DATA",
    [10] = "ACKNACK",
    [11] = "HEARTBEAT",
    [12] = "RESET",
    [13] = "FRAGMENT",
    [14] = "TIMESTAMP",
    [15] = "TIMESTAMP_REPLY",
    [255] = "PERFORMANCE",
}

local OBJK_VARIANT = {
    [0] = "OBJK_INVALID",
    [1] = "OBJK_PARTICIPANT",
    [2] = "OBJK_TOPIC",
    [3] = "OBJK_PUBLISHER",
    [4] = "OBJK_SUBSCRIBER",
    [5] = "OBJK_DATAWRITER",
    [6] = "OBJK_DATAREADER",
    [7] = "OBJK_TYPE",
    [10] = "OBJK_TYPE",
    [11] = "OBJK_QOSPROFILE",
    [12] = "OBJK_APPLICATION",
    [13] = "OBJK_AGENT",
    [14] = "OBJK_CLIENT",
    [15] = "OBJK_OTHER",
}

local OBJK_REP3_BASE_DISC = {
    [1] = "REPRESENTATION_BY_REFERENCE",
    [2] = "REPRESENTATION_AS_XML_STRING",
    [3] = "REPRESENTATION_IN_BINARY",
}

Dissector.list()

function p_xrce_dds.dissector(buf, pkt, tree)
        pkt.cols.protocol = "XRCE-DDS"

        if buf(0,4):string() == "RTPS" then
            return 0
        end

        local len = 0
        local subtree = tree:add(p_xrce_dds, buf())
        local header = subtree:add(p_xrce_dds_header, buf())
        header:add(f_sessionId, buf(0,1))
        local streamId = buf(1,1):uint()
        if streamId == 0 then
            header:add(f_streamId, buf(1,1)):append_text(" (NONE)")
        elseif streamId == 1 then
            header:add(f_streamId, buf(1,1)):append_text(" (BEST EFFORTS(BUILT-IN))")
        elseif streamId < 128 then
            header:add(f_streamId, buf(1,1)):append_text(" (BEST EFFORTS)")
        elseif streamId == 128 then
            header:add(f_streamId, buf(1,1)):append_text(" (RELIABLE(BUILT-IN))")
        else
            header:add(f_streamId, buf(1,1)):append_text(" (RELIABLE)")
        end
        if streamId == 0 then
            header:add(f_sequenceNr, buf(2,2)):append_text(" (No order imposed)")
        else
            header:add(f_sequenceNr, buf(2,2))
        end
        local sessionId = buf(0,1):uint()
        if sessionId <= 127 then
            subtree:add(f_clientKey, buf(4,4))
            len = 8
        else
            len = 4
        end



        local session_id = buf(0,1):uint()

        local submessage = subtree:add(p_xrce_dds_submessage, buf())
        local submessage_id = buf(len,1):uint()
        submessage:add(f_submessageId, buf(len, 1)):append_text(" (" .. SUBMESSAGE_ID[submessage_id] .. ")")
        len = len + 1
        submessage:add(f_flags, buf(len, 1))
        local flags = buf(len, 1):uint()
        if flags > 127 then
            submessage:add(f_endiannessFlag, "1......."):append_text(" Endianness(Little) ")
            flags = flags - 128
        else
            submessage:add(f_endiannessFlag, "0......."):append_text(" Endianness(Big) ")
        end
        if flags > 64 then
            submessage:add(f_reuseBit, ".1......"):append_text(" REUSE")
            flags = flags - 64
        else
            submessage:add(f_reuseBit, ".0......"):append_text(" NO REUSE")
        end
        if flags > 32 then
            submessage:add(f_replaceBit, "..1....."):append_text(" REPLACE")
            flags = flags - 64
        else
            submessage:add(f_replaceBit, "..0....."):append_text(" NO REPLACE")
        end
        len = len + 1
        local submessageLengthByte1 = buf(len, 1):uint()
        local submessageLengthByte2 = buf(len + 1, 1):uint()
        local submessageLength = submessageLengthByte2 * 256 + submessageLengthByte1
        submessage:add(f_submessageLength, buf(len, 2)):append_text(" (" .. submessageLength .. ")")
        len = len + 2
        if submessage_id == 0 then --CREATE_CLIENT message
            local create_client_payload = subtree:add(p_xrce_dds_create_client_payload, buf())
            create_client_payload:add(f_xrceCookie, buf(len, 4)):append_text(" ('x', 'R', C', 'E')")
            len = len + 4
            create_client_payload:add(f_xrceVersion, buf(len, 2))
            len = len + 2
            create_client_payload:add(f_xrceVendorId, buf(len, 2))
            len = len + 2
            create_client_payload:add(f_reqClientKey, buf(len, 4))
            len = len + 4
            create_client_payload:add(f_reqSessionId, buf(len, 1))
            len = len + 1
            local properties = buf(len, 1):uint()
            local propertiesString = " (No properties)"
            if properties > 0 then
                propertiesString = " (Properties Present)"
            end
            create_client_payload:add(f_properties, buf(len, 1)):append_text(propertiesString)
            len = len + 1
        elseif submessage_id == 1 then --CREATE message
            local create_payload = subtree:add(p_xrce_dds_create_payload, buf())
            create_payload:add(f_requestId, buf(len, 2))
            len = len + 2
            create_payload:add(f_objectId, buf(len, 2))
            len = len + 2
            local object_variant = buf(len, 1):uint()
            local object_variant_string = "UNKNOWN Variant"
            if object_variant == 1 then
                object_variant_string = OBJK_VARIANT[object_variant]
            end
            create_payload:add(f_objectVariant, buf(len, 1)):append_text(" (" .. object_variant_string .. ")")
            len = len + 1
            local object_disc = buf(len, 1):uint()
            local object_disc_string = OBJK_REP3_BASE_DISC[object_disc]
            create_payload:add(f_objectDisc, buf(len, 1)):append_text(" (" .. object_disc_string .. ")")
            len = len + 1
            create_payload:add(f_padding1, buf(len, 2))
            len = len + 2
            local length_byte1 = buf(len, 1):uint()
            local length_byte2 = buf(len + 1, 1):uint()
            local length = length_byte1 + length_byte2 * 256 -- probably shorter than this
            create_payload:add(f_length, buf(len, 4)):append_text(" (" .. length .. ")")
            len = len + 4
            if object_disc < 3 then
                create_payload:add(f_string_representation, buf(len, length))
                len = len + length
            end
        end



end


local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(2018, p_xrce_dds)
udp_encap_table:add(7400, p_xrce_dds)
udp_encap_table:add(8009, p_xrce_dds)

