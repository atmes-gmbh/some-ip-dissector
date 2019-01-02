-----------------------------------
-- SOME/IP Dissector
-- Copyright 2018 ATMES GmbH

-- Version 1.1		- Add reserved to Subscribe Eventgroup

-- Version 1.0
-----------------------------------


local E_msgTypes = {
	[0]     = "REQUEST",
	[1]     = "REQUEST_NO_RETURN",
	[2]     = "NOTIFICATION",
	[64]    = "REQUEST_ACK",
	[65]    = "REQUEST_NO_RETURN_ACK",
	[66]    = "NOTIFICATION_ACK",
	[128]   = "RESPONSE",
	[129]   = "ERROR",
	[192]   = "RESPONSE_ACK",
	[193]   = "ERROR_ACK"
}

local E_retCodes = {
	[0]     = "OK",
	[1]     = "NOT_OK",
	[2]     = "UNKNOWN_SERVICE",
	[3]     = "UNKNOWN_METHOD",
	[4]     = "NOT_READY",
	[5]     = "NOT_REACHABLE",
	[6]     = "TIMEOUT",
	[7]     = "WRONG_PROTOCOL_VERSION",
	[8]     = "WRONG_INTERFACE_VERSION",
	[9]     = "MALFORMED_MESSAGE",
	[10]    = "WRONG_MESSAGE_TYPE"
}

local E_sdTypes = {
	[0] 	= "FIND SERVICE",
	[1] 	= "OFFER SERVICE",
	[6] 	= "SUBSCRIBE EVENTGROUP",
	[7]	 	= "SUBSCRIBE EVENTGROUP ACK"
}

local E_sdOptTypes = {
	[1]     = "CONFIGURATION",
	[2]     = "LOAD BALANCING",
	[4]     = "IPv4 ENDPOINT",
[6]     = "IPv6 ENDPOINT",
	[20]    = "IPv4 MULTICAST",
	[22]    = "IPV6 MULTICAST",
	[36]    = "IPv4 SD_ENDPOINT",
	[38]    = "IPv6 SD_ENDPOINT"
}

local E_sdL4 = {
	[6]     = "TCP",
	[17]    = "UDP"
}

pSomeIP = Proto("someip_","SOME/IP")
local f_serviceId	= ProtoField.uint16("someip.serviceId","Service ID",base.HEX)
local f_methodId	= ProtoField.uint16("someip.methodId","Method ID",base.HEX)
local f_length      = ProtoField.uint32("someip.length","Length",base.HEX)
local f_clientId	= ProtoField.uint16("someip.clientId","Client ID",base.HEX)
local f_sessionId	= ProtoField.uint16("someip.sessionId","Session ID",base.HEX)
local f_proVersion  = ProtoField.uint8("someip.proVersion","Protocol Version",base.HEX)
local f_intVersion  = ProtoField.uint8("someip.intVersion","Interface Version",base.HEX)
local f_msgType     = ProtoField.uint8("someip.msgType","Message Type",base.HEX)
local f_returnCode  = ProtoField.uint8("someip.returnCode","Return Code",base.HEX)
pSomeIP.fields = {f_serviceId, f_methodId, f_length, f_proVersion, f_intVersion, f_clientId, f_sessionId, f_msgType, f_returnCode}

local pSdHeader = Proto("sdHeader","sdHeader")
local f_sdHeaderLen	= ProtoField.uint16("sd.sdHeaderLen","Length of entries array",base.HEX)
local f_sdReserved  = ProtoField.uint24("sd.sdReserved","Reserved",base.HEX)
local f_sdFlags     = ProtoField.uint8("sd.sdFlags","Flags",base.HEX)
pSdHeader.fields = {f_sdFlags, f_sdReserved, f_sdHeaderLen}

local pSd = Proto("sd_","sd")
local f_sdType      = ProtoField.uint8("sd.sdType","Type",base.HEX)
local f_sdIndex1    = ProtoField.uint8("sd.sdIndex1","Index 1st Options",base.HEX)
local f_sdIndex2    = ProtoField.uint8("sd.sdIndex2","Index 2nd Options",base.HEX)
local f_sdNum1      = ProtoField.uint8("sd.sdNum1","# of 1st Options",base.HEX)
local f_sdNum2      = ProtoField.uint8("sd.sdNum2","# of 2nd Options",base.HEX)
local f_sdServiceId = ProtoField.uint16("sd.sdServiceId","Service ID",base.HEX)
local f_sdInstId    = ProtoField.uint16("sd.sdInstId","Instance ID",base.HEX)
local f_sdMajor     = ProtoField.uint8("sd.sdMajor","Major Version",base.HEX)
local f_sdTtl       = ProtoField.uint24("sd.sdTtl","TTL",base.HEX)
local f_sdMinor     = ProtoField.uint32("sd.sdMinor","Minor Version",base.HEX)
local f_sdReserved2 = ProtoField.uint16("sd.sdReserved2","Reserved",base.HEX)
local f_sdEventgroup= ProtoField.uint16("sd.sdEventgroup","Eventgroup ID",base.HEX)
local f_sdOptionLen = ProtoField.uint32("sd.sdOptionLen","Length of Option Array",base.HEX)

local f_sdIpv4      = ProtoField.ipv4("sd.sdIpv4","IPv4 address")
local f_sdPort      = ProtoField.uint16("sd.sdPort","Port",base.HEX)
local f_sdLen       = ProtoField.uint16("sd.sdLen","Length",base.HEX)
local f_sdOptType   = ProtoField.uint8("sd.sdOptType","Type",base.HEX)
local f_sdL4        = ProtoField.uint8("sd.sdL4","L4-Protocol",base.HEX) 
pSd.fields = {f_sdType, f_sdIndex1, f_sdIndex2, f_sdNum1, f_sdNum2, f_sdServiceId, f_sdInstId, f_sdMajor, f_sdTtl, f_sdMinor, f_sdReserved2, f_sdEventgroup, f_sdOptionLen, f_sdIpv4, f_sdPort, f_sdLen, f_sdOptType, f_sdL4}


local function getSd(buf, pkt, root)

	local andmore = " [and more]"

	subtree = root:add("SD Header")
	
	local tvbr = buf:range(0,1)

	flags = subtree:add(f_sdFlags, buf(0,1))
	reboot = tvbr:bitfield(0,1)
	flags:add("Reboot: " .. reboot)
	unicast = tvbr:bitfield(1,1)
	flags:add("Unicast: " .. unicast)
	
	subtree:add(f_sdReserved, buf(1, 3))
	local length = subtree:add(f_sdHeaderLen, buf(4,4))
	length:append_text(" (" .. buf(4,4):uint() .." bytes)")
	
	local lenEntries = buf(4,4):uint() / 16
	if (lenEntries < 1) then
		return 
	end
	
	local dataPos = 8
	local entrySize = 16
	local firstEntry = nil
	for i = 0, lenEntries - 1 do
		if (dataPos + entrySize <= buf:reported_length_remaining()) then
		
			local name = "NULL"
			if E_sdTypes[buf(dataPos,1):uint()] ~= nil then
				name = E_sdTypes[buf(dataPos,1):uint()]
			end
			
			if firstEntry == nil then
				firstEntry = name
			else
				if (string.find(firstEntry, name) ~= nil) and (string.find(firstEntry, andmore) == nil) then
					firstEntry = firstEntry .. andmore
				end
			end
			
			sd = root:add(name)
			
			sdtype = sd:add(f_sdType, buf(dataPos, 1))
			sdtype:append_text(" (" .. name ..")")
			sd:add(f_sdIndex1, buf(dataPos + 1, 1))
			sd:add(f_sdIndex2, buf(dataPos + 2, 1))
			sd:add(f_sdNum1, buf(dataPos + 3, 1):bitfield(0,4))
			sd:add(f_sdNum2, buf(dataPos + 3, 1):bitfield(4,4))
			sd:add(f_sdServiceId, buf(dataPos + 4, 2))
			sd:add(f_sdInstId, buf(dataPos + 6, 2))
			sd:add(f_sdMajor, buf(dataPos + 8, 1))
			ttl = sd:add(f_sdTtl, buf(dataPos + 9, 3))
			ttl:append_text(" (" .. buf(dataPos + 9, 3):uint() .." seconds)")
			sd:add(f_sdReserved2, buf(dataPos + 12, 2))
			if (buf(dataPos, 1):uint() > 0x5) then
				sd:add(f_sdEventgroup, buf(dataPos + 14, 2))
			else
				sd:add(f_sdMinor, buf(dataPos + 14, 4))
			end
		
		else
			break
		end
		dataPos = dataPos + entrySize;
	end -- end for
	
	if firstEntry ~= nil then
		pkt.cols.info = "SOME/IP SD: " .. firstEntry
	else
		pkt.cols.info = "SOME/IP SD"
	end
	
	if (dataPos + 8 > buf:reported_length_remaining()) then
		return
	end	
	
	sdOptionLen = root:add(f_sdOptionLen, buf(dataPos, 4))
	sdOptionLen:append_text(" (" .. buf(dataPos, 4):uint() .." bytes)")
	
	local count = 0
	local optionLen = buf(dataPos, 4):uint()
	dataPos = dataPos + 4
	if (optionLen > 0) then
		while ((dataPos < buf:reported_length_remaining())) do 
		
			-- IP v4 Endpoint Option / IPv4 Multicast Option
			if ((buf(dataPos + 2,1):uint() == 0x04) or (buf(dataPos + 2,1):uint() == 0x14)) then

				local name = "NULL"
				if E_sdOptTypes[buf(dataPos + 2,1):uint()] ~= nil then
					name = E_sdOptTypes[buf(dataPos + 2,1):uint()]
				end
				
				sdopt = root:add("[" .. count .. "]" .. name)			

				sdLenOpt = sdopt:add(f_sdLen, buf(dataPos, 2))
				sdLenOpt:append_text(" (" .. buf(dataPos,2):uint() .." bytes)")
				sdTypeO = sdopt:add(f_sdOptType, buf(dataPos + 2, 1))
				sdTypeO:append_text(" (" .. name ..")")
				sdopt:add(f_sdIpv4, buf(dataPos + 4, 4))
				sdL4 = sdopt:add(f_sdL4, buf(dataPos + 9, 1))
				if E_sdL4[buf(dataPos + 9,1):uint()] ~= nil then
					sdL4:append_text(" (" ..  E_sdL4[buf(dataPos + 9,1):uint()] ..")")
				end			
				sdPort = sdopt:add(f_sdPort, buf(dataPos + 10, 2))
				sdPort:append_text(" (" .. buf(dataPos + 10,2):uint() ..")")

				dataPos = dataPos + 12
			end -- IP v4 Endpoint Option / IPv4 Multicast Option		
	
--TODO:

	
			count = count + 1
			if (count > 0xFF) then
				break
			end
		end
	end
	
end

function pSomeIP.dissector(buf, pkt, root)
   
	local copyStartByte = 0
	local sizeSomeIpHeader = 16
	
	while (copyStartByte < buf:reported_length_remaining()) do
		if (buf:reported_length_remaining() >= sizeSomeIpHeader) then
			local lenSection = buf(copyStartByte + 4,4):uint()

			subtree = root:add(pSomeIP,buf(0))

			----------
			-- Header
			----------
			
			-- Service ID
			subtree:add(f_serviceId,buf(copyStartByte + 0,2))
			-- Method ID
			subtree:add(f_methodId,buf(copyStartByte + 2,2))
			-- Length
			local length = subtree:add(f_length,buf(copyStartByte + 4,4))
			length:append_text(" (" .. buf(copyStartByte + 4,4):uint() .." bytes)")
			-- Client ID
			subtree:add(f_clientId,buf(copyStartByte + 8,2))
			-- Session ID
			subtree:add(f_sessionId,buf(copyStartByte + 10,2))
			-- Protocol Version
			subtree:add(f_proVersion,buf(copyStartByte + 12,1))
			-- Interface Version
			subtree:add(f_intVersion,buf(copyStartByte + 13,1))

			-- Message type
			local msgType = subtree:add(f_msgType,buf(copyStartByte + 14,1))
			if E_msgTypes[buf(copyStartByte + 14,1):uint()] ~= nil then
				msgType:append_text(" (" .. E_msgTypes[buf(copyStartByte + 14,1):uint()] ..")")
			end

			-- Return Code
			local retCode = subtree:add(f_returnCode,buf(copyStartByte + 15,1))
			if E_retCodes[buf(copyStartByte + 15,1):uint()] ~= nil then
				retCode:append_text(" (" .. E_retCodes[buf(copyStartByte + 15,1):uint()] ..")")
			end


			if ((buf(copyStartByte + 0,2):uint() == 0xffff) and (buf(copyStartByte + 2,2):uint() == 0x8100)) then
				pkt.cols.protocol = "SOME/IP SD"
				subtree:append_text(" SD")
				
				---------------------
				-- Service Discovery
				---------------------			
				getSd(buf(copyStartByte + 16):tvb(), pkt, subtree)			
			else
				pkt.cols.protocol = "SOME/IP"
				pkt.cols.info = "SOME/IP"
			end
							
			copyStartByte = copyStartByte + lenSection + 8;
		else
			break
		end
	end -- end while

end

function pSomeIP.init()

    local udp_table = DissectorTable.get("udp.port")
    local tcp_table = DissectorTable.get("tcp.port")

    for i,port in ipairs{30490,30491,30492,30500,30501,30502,30503,30504,30505,50025,50015} do
        udp_table:add(port,pSomeIP)
        tcp_table:add(port,pSomeIP)
    end
	
end
