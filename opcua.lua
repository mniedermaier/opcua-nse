---
-- OPC UA (IEC 62541) client library for the Nmap Scripting Engine.
--
-- Implements the OPC UA Connection Protocol (UACP) and the OPC UA Binary
-- encoding described in OPC 10000-6, plus the subset of services from
-- OPC 10000-4 that is useful for network discovery and security auditing:
--
-- * <code>HEL</code>/<code>ACK</code>/<code>ERR</code> handshake with buffer negotiation
-- * <code>OpenSecureChannel</code> with SecurityPolicy <code>None</code>
-- * Chunked message assembly (<code>C</code>/<code>F</code>/<code>A</code> chunk types)
-- * <code>GetEndpoints</code>, <code>FindServers</code>, <code>FindServersOnNetwork</code>
-- * <code>CreateSession</code>, <code>ActivateSession</code>, <code>Read</code>, <code>Browse</code>
--
-- Everything is decoded through a cursor object (<code>Reader</code>) that knows the
-- OPC UA built-in types, so structures are parsed rather than skipped by
-- hard-coded byte offsets.
--
-- Typical use:
-- <code>
--   local conn = opcua.Connection:new(host, port)
--   local status, err = conn:connect()
--   local endpoints, err = conn:get_endpoints()
--   conn:close()
-- </code>
--
-- @author Matthias Niedermaier
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"
local sslcert = require "sslcert"
local rand = require "rand"

_ENV = stdnse.module("opcua", stdnse.seeall)

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

--- Default and vendor-specific OPC UA TCP ports.
PORTS = {4840, 4843, 4845, 4855, 4885, 4897, 26543, 48010, 48020, 48030,
         48040, 48050, 49320, 49380, 51210, 53530, 62541}

--- Service names carrying OPC UA (nmap-services and the proposed probe).
SERVICES = {"opcua-tcp", "opc-ua-tcp", "opcua", "opcua-tls"}

SECURITY_POLICY_BASE = "http://opcfoundation.org/UA/SecurityPolicy#"
SECURITY_POLICY_NONE = SECURITY_POLICY_BASE .. "None"
TRANSPORT_PROFILE_BINARY = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"

--- Binary encoding NodeIds (namespace 0) of the messages we exchange.
local ID = {
  ServiceFault                 = 397,
  OpenSecureChannelRequest     = 446,
  OpenSecureChannelResponse    = 449,
  CloseSecureChannelRequest    = 452,
  FindServersRequest           = 422,
  FindServersResponse          = 425,
  FindServersOnNetworkRequest  = 12208,
  FindServersOnNetworkResponse = 12209,
  GetEndpointsRequest          = 428,
  GetEndpointsResponse         = 431,
  CreateSessionRequest         = 461,
  CreateSessionResponse        = 464,
  ActivateSessionRequest       = 467,
  ActivateSessionResponse      = 470,
  CloseSessionRequest          = 473,
  CloseSessionResponse         = 476,
  ReadRequest                  = 631,
  ReadResponse                 = 634,
  BrowseRequest                = 527,
  BrowseResponse               = 530,
  AnonymousIdentityToken       = 321,
  UserNameIdentityToken        = 324,
  ServerStatusDataType         = 864,
  BuildInfo                    = 340,
  ServerDiagnosticsSummaryDataType = 861,
}
NODEID = ID

--- Well-known NodeIds in the standard address space.
NODE = {
  Root                  = 84,
  Objects               = 85,
  Server                = 2253,
  ServerArray           = 2254,
  NamespaceArray        = 2255,
  ServerStatus          = 2256,
  ServerStatus_StartTime= 2257,
  ServerStatus_CurrentTime = 2258,
  ServerStatus_State    = 2259,
  BuildInfo             = 2260,
  BuildInfo_ProductUri  = 2262,
  BuildInfo_ManufacturerName = 2263,
  BuildInfo_ProductName = 2261,
  BuildInfo_SoftwareVersion = 2264,
  BuildInfo_BuildNumber = 2265,
  BuildInfo_BuildDate   = 2266,
  ServiceLevel          = 2267,
  ServerDiagnostics     = 2274,
  ServerDiagnosticsSummary = 2275,
  DiagnosticsEnabledFlag = 2294,
  ServerCapabilities    = 2268,
  ServerProfileArray    = 2269,
  LocaleIdArray         = 2271,
  Auditing              = 2994,
  RoleSet               = 15606,
  MaxSessions           = 24098,
}

--- Attribute identifiers (OPC 10000-6, A.1).
ATTR = {
  NodeId = 1, NodeClass = 2, BrowseName = 3, DisplayName = 4, Description = 5,
  WriteMask = 6, UserWriteMask = 7, Value = 13, DataType = 14, ValueRank = 15,
  AccessLevel = 17, UserAccessLevel = 18, Historizing = 20, Executable = 21,
  UserExecutable = 22,
}

SECURITY_MODE = {[0] = "Invalid", [1] = "None", [2] = "Sign", [3] = "SignAndEncrypt"}

USER_TOKEN_TYPE = {[0] = "Anonymous", [1] = "UserName", [2] = "Certificate",
                   [3] = "IssuedToken"}

APPLICATION_TYPE = {[0] = "Server", [1] = "Client", [2] = "ClientAndServer",
                    [3] = "DiscoveryServer"}

NODE_CLASS = {[1] = "Object", [2] = "Variable", [4] = "Method",
              [8] = "ObjectType", [16] = "VariableType", [32] = "ReferenceType",
              [64] = "DataType", [128] = "View"}

SERVER_STATE = {[0] = "Running", [1] = "Failed", [2] = "NoConfiguration",
                [3] = "Suspended", [4] = "Shutdown", [5] = "Test",
                [6] = "CommunicationFault", [7] = "Unknown"}

--- StatusCodes, generated from the OPC Foundation's StatusCode.csv
-- (UA-Nodeset/Schema/StatusCode.csv). Hand-maintained tables drift:
-- an earlier one had 0x80250000 as a certificate error when it is in
-- fact Bad_SessionIdInvalid, which turned a plain session problem into
-- a misleading report.
STATUS_CODES = {
  [0x00000000] = "Good",
  [0x002D0000] = "Good_SubscriptionTransferred",
  [0x002E0000] = "Good_CompletesAsynchronously",
  [0x002F0000] = "Good_Overload",
  [0x00300000] = "Good_Clamped",
  [0x00960000] = "Good_LocalOverride",
  [0x00A20000] = "Good_EntryInserted",
  [0x00A30000] = "Good_EntryReplaced",
  [0x00A50000] = "Good_NoData",
  [0x00A60000] = "Good_MoreData",
  [0x00A70000] = "Good_CommunicationEvent",
  [0x00A80000] = "Good_ShutdownEvent",
  [0x00A90000] = "Good_CallAgain",
  [0x00AA0000] = "Good_NonCriticalTimeout",
  [0x00BA0000] = "Good_ResultsMayBeIncomplete",
  [0x00D90000] = "Good_DataIgnored",
  [0x00DC0000] = "Good_Edited",
  [0x00DD0000] = "Good_PostActionFailed",
  [0x00DF0000] = "Good_RetransmissionQueueNotSupported",
  [0x00E00000] = "Good_DependentValueChanged",
  [0x00EB0000] = "Good_SubNormal",
  [0x00EF0000] = "Good_PasswordChangeRequired",
  [0x01160000] = "Good_Edited_DependentValueChanged",
  [0x01170000] = "Good_Edited_DominantValueChanged",
  [0x01180000] = "Good_Edited_DominantValueChanged_DependentValueChanged",
  [0x04010000] = "Good_CascadeInitializationAcknowledged",
  [0x04020000] = "Good_CascadeInitializationRequest",
  [0x04030000] = "Good_CascadeNotInvited",
  [0x04040000] = "Good_CascadeNotSelected",
  [0x04070000] = "Good_FaultStateActive",
  [0x04080000] = "Good_InitiateFaultState",
  [0x04090000] = "Good_Cascade",
  [0x40000000] = "Uncertain",
  [0x406C0000] = "Uncertain_ReferenceOutOfServer",
  [0x408F0000] = "Uncertain_NoCommunicationLastUsableValue",
  [0x40900000] = "Uncertain_LastUsableValue",
  [0x40910000] = "Uncertain_SubstituteValue",
  [0x40920000] = "Uncertain_InitialValue",
  [0x40930000] = "Uncertain_SensorNotAccurate",
  [0x40940000] = "Uncertain_EngineeringUnitsExceeded",
  [0x40950000] = "Uncertain_SubNormal",
  [0x40A40000] = "Uncertain_DataSubNormal",
  [0x40BC0000] = "Uncertain_ReferenceNotDeleted",
  [0x40C00000] = "Uncertain_NotAllNodesAvailable",
  [0x40DE0000] = "Uncertain_DominantValueChanged",
  [0x40E20000] = "Uncertain_DependentValueChanged",
  [0x40F20000] = "Uncertain_OverRange",
  [0x40F30000] = "Uncertain_UnderRange",
  [0x42080000] = "Uncertain_TransducerInManual",
  [0x42090000] = "Uncertain_SimulatedValue",
  [0x420A0000] = "Uncertain_SensorCalibration",
  [0x420F0000] = "Uncertain_ConfigurationError",
  [0x80000000] = "Bad",
  [0x80010000] = "Bad_UnexpectedError",
  [0x80020000] = "Bad_InternalError",
  [0x80030000] = "Bad_OutOfMemory",
  [0x80040000] = "Bad_ResourceUnavailable",
  [0x80050000] = "Bad_CommunicationError",
  [0x80060000] = "Bad_EncodingError",
  [0x80070000] = "Bad_DecodingError",
  [0x80080000] = "Bad_EncodingLimitsExceeded",
  [0x80090000] = "Bad_UnknownResponse",
  [0x800A0000] = "Bad_Timeout",
  [0x800B0000] = "Bad_ServiceUnsupported",
  [0x800C0000] = "Bad_Shutdown",
  [0x800D0000] = "Bad_ServerNotConnected",
  [0x800E0000] = "Bad_ServerHalted",
  [0x800F0000] = "Bad_NothingToDo",
  [0x80100000] = "Bad_TooManyOperations",
  [0x80110000] = "Bad_DataTypeIdUnknown",
  [0x80120000] = "Bad_CertificateInvalid",
  [0x80130000] = "Bad_SecurityChecksFailed",
  [0x80140000] = "Bad_CertificateTimeInvalid",
  [0x80150000] = "Bad_CertificateIssuerTimeInvalid",
  [0x80160000] = "Bad_CertificateHostNameInvalid",
  [0x80170000] = "Bad_CertificateUriInvalid",
  [0x80180000] = "Bad_CertificateUseNotAllowed",
  [0x80190000] = "Bad_CertificateIssuerUseNotAllowed",
  [0x801A0000] = "Bad_CertificateUntrusted",
  [0x801B0000] = "Bad_CertificateRevocationUnknown",
  [0x801C0000] = "Bad_CertificateIssuerRevocationUnknown",
  [0x801D0000] = "Bad_CertificateRevoked",
  [0x801E0000] = "Bad_CertificateIssuerRevoked",
  [0x801F0000] = "Bad_UserAccessDenied",
  [0x80200000] = "Bad_IdentityTokenInvalid",
  [0x80210000] = "Bad_IdentityTokenRejected",
  [0x80220000] = "Bad_SecureChannelIdInvalid",
  [0x80230000] = "Bad_InvalidTimestamp",
  [0x80240000] = "Bad_NonceInvalid",
  [0x80250000] = "Bad_SessionIdInvalid",
  [0x80260000] = "Bad_SessionClosed",
  [0x80270000] = "Bad_SessionNotActivated",
  [0x80280000] = "Bad_SubscriptionIdInvalid",
  [0x802A0000] = "Bad_RequestHeaderInvalid",
  [0x802B0000] = "Bad_TimestampsToReturnInvalid",
  [0x802C0000] = "Bad_RequestCancelledByClient",
  [0x80310000] = "Bad_NoCommunication",
  [0x80320000] = "Bad_WaitingForInitialData",
  [0x80330000] = "Bad_NodeIdInvalid",
  [0x80340000] = "Bad_NodeIdUnknown",
  [0x80350000] = "Bad_AttributeIdInvalid",
  [0x80360000] = "Bad_IndexRangeInvalid",
  [0x80370000] = "Bad_IndexRangeNoData",
  [0x80380000] = "Bad_DataEncodingInvalid",
  [0x80390000] = "Bad_DataEncodingUnsupported",
  [0x803A0000] = "Bad_NotReadable",
  [0x803B0000] = "Bad_NotWritable",
  [0x803C0000] = "Bad_OutOfRange",
  [0x803D0000] = "Bad_NotSupported",
  [0x803E0000] = "Bad_NotFound",
  [0x803F0000] = "Bad_ObjectDeleted",
  [0x80400000] = "Bad_NotImplemented",
  [0x80410000] = "Bad_MonitoringModeInvalid",
  [0x80420000] = "Bad_MonitoredItemIdInvalid",
  [0x80430000] = "Bad_MonitoredItemFilterInvalid",
  [0x80440000] = "Bad_MonitoredItemFilterUnsupported",
  [0x80450000] = "Bad_FilterNotAllowed",
  [0x80460000] = "Bad_StructureMissing",
  [0x80470000] = "Bad_EventFilterInvalid",
  [0x80480000] = "Bad_ContentFilterInvalid",
  [0x80490000] = "Bad_FilterOperandInvalid",
  [0x804A0000] = "Bad_ContinuationPointInvalid",
  [0x804B0000] = "Bad_NoContinuationPoints",
  [0x804C0000] = "Bad_ReferenceTypeIdInvalid",
  [0x804D0000] = "Bad_BrowseDirectionInvalid",
  [0x804E0000] = "Bad_NodeNotInView",
  [0x804F0000] = "Bad_ServerUriInvalid",
  [0x80500000] = "Bad_ServerNameMissing",
  [0x80510000] = "Bad_DiscoveryUrlMissing",
  [0x80520000] = "Bad_SemaphoreFileMissing",
  [0x80530000] = "Bad_RequestTypeInvalid",
  [0x80540000] = "Bad_SecurityModeRejected",
  [0x80550000] = "Bad_SecurityPolicyRejected",
  [0x80560000] = "Bad_TooManySessions",
  [0x80570000] = "Bad_UserSignatureInvalid",
  [0x80580000] = "Bad_ApplicationSignatureInvalid",
  [0x80590000] = "Bad_NoValidCertificates",
  [0x805A0000] = "Bad_RequestCancelledByRequest",
  [0x805B0000] = "Bad_ParentNodeIdInvalid",
  [0x805C0000] = "Bad_ReferenceNotAllowed",
  [0x805D0000] = "Bad_NodeIdRejected",
  [0x805E0000] = "Bad_NodeIdExists",
  [0x805F0000] = "Bad_NodeClassInvalid",
  [0x80600000] = "Bad_BrowseNameInvalid",
  [0x80610000] = "Bad_BrowseNameDuplicated",
  [0x80620000] = "Bad_NodeAttributesInvalid",
  [0x80630000] = "Bad_TypeDefinitionInvalid",
  [0x80640000] = "Bad_SourceNodeIdInvalid",
  [0x80650000] = "Bad_TargetNodeIdInvalid",
  [0x80660000] = "Bad_DuplicateReferenceNotAllowed",
  [0x80670000] = "Bad_InvalidSelfReference",
  [0x80680000] = "Bad_ReferenceLocalOnly",
  [0x80690000] = "Bad_NoDeleteRights",
  [0x806A0000] = "Bad_ServerIndexInvalid",
  [0x806B0000] = "Bad_ViewIdUnknown",
  [0x806D0000] = "Bad_TooManyMatches",
  [0x806E0000] = "Bad_QueryTooComplex",
  [0x806F0000] = "Bad_NoMatch",
  [0x80700000] = "Bad_MaxAgeInvalid",
  [0x80710000] = "Bad_HistoryOperationInvalid",
  [0x80720000] = "Bad_HistoryOperationUnsupported",
  [0x80730000] = "Bad_WriteNotSupported",
  [0x80740000] = "Bad_TypeMismatch",
  [0x80750000] = "Bad_MethodInvalid",
  [0x80760000] = "Bad_ArgumentsMissing",
  [0x80770000] = "Bad_TooManySubscriptions",
  [0x80780000] = "Bad_TooManyPublishRequests",
  [0x80790000] = "Bad_NoSubscription",
  [0x807A0000] = "Bad_SequenceNumberUnknown",
  [0x807B0000] = "Bad_MessageNotAvailable",
  [0x807C0000] = "Bad_InsufficientClientProfile",
  [0x807D0000] = "Bad_TcpServerTooBusy",
  [0x807E0000] = "Bad_TcpMessageTypeInvalid",
  [0x807F0000] = "Bad_TcpSecureChannelUnknown",
  [0x80800000] = "Bad_TcpMessageTooLarge",
  [0x80810000] = "Bad_TcpNotEnoughResources",
  [0x80820000] = "Bad_TcpInternalError",
  [0x80830000] = "Bad_TcpEndpointUrlInvalid",
  [0x80840000] = "Bad_RequestInterrupted",
  [0x80850000] = "Bad_RequestTimeout",
  [0x80860000] = "Bad_SecureChannelClosed",
  [0x80870000] = "Bad_SecureChannelTokenUnknown",
  [0x80880000] = "Bad_SequenceNumberInvalid",
  [0x80890000] = "Bad_ConfigurationError",
  [0x808A0000] = "Bad_NotConnected",
  [0x808B0000] = "Bad_DeviceFailure",
  [0x808C0000] = "Bad_SensorFailure",
  [0x808D0000] = "Bad_OutOfService",
  [0x808E0000] = "Bad_DeadbandFilterInvalid",
  [0x80970000] = "Bad_RefreshInProgress",
  [0x80980000] = "Bad_ConditionAlreadyDisabled",
  [0x80990000] = "Bad_ConditionDisabled",
  [0x809A0000] = "Bad_EventIdUnknown",
  [0x809B0000] = "Bad_NoData",
  [0x809D0000] = "Bad_DataLost",
  [0x809E0000] = "Bad_DataUnavailable",
  [0x809F0000] = "Bad_EntryExists",
  [0x80A00000] = "Bad_NoEntryExists",
  [0x80A10000] = "Bad_TimestampNotSupported",
  [0x80AB0000] = "Bad_InvalidArgument",
  [0x80AC0000] = "Bad_ConnectionRejected",
  [0x80AD0000] = "Bad_Disconnect",
  [0x80AE0000] = "Bad_ConnectionClosed",
  [0x80AF0000] = "Bad_InvalidState",
  [0x80B00000] = "Bad_EndOfStream",
  [0x80B10000] = "Bad_NoDataAvailable",
  [0x80B20000] = "Bad_WaitingForResponse",
  [0x80B30000] = "Bad_OperationAbandoned",
  [0x80B40000] = "Bad_ExpectedStreamToBlock",
  [0x80B50000] = "Bad_WouldBlock",
  [0x80B60000] = "Bad_SyntaxError",
  [0x80B70000] = "Bad_MaxConnectionsReached",
  [0x80B80000] = "Bad_RequestTooLarge",
  [0x80B90000] = "Bad_ResponseTooLarge",
  [0x80BB0000] = "Bad_EventNotAcknowledgeable",
  [0x80BD0000] = "Bad_InvalidTimestampArgument",
  [0x80BE0000] = "Bad_ProtocolVersionUnsupported",
  [0x80BF0000] = "Bad_StateNotActive",
  [0x80C10000] = "Bad_FilterOperatorInvalid",
  [0x80C20000] = "Bad_FilterOperatorUnsupported",
  [0x80C30000] = "Bad_FilterOperandCountMismatch",
  [0x80C40000] = "Bad_FilterElementInvalid",
  [0x80C50000] = "Bad_FilterLiteralInvalid",
  [0x80C60000] = "Bad_IdentityChangeNotSupported",
  [0x80C80000] = "Bad_NotTypeDefinition",
  [0x80C90000] = "Bad_ViewTimestampInvalid",
  [0x80CA0000] = "Bad_ViewParameterMismatch",
  [0x80CB0000] = "Bad_ViewVersionInvalid",
  [0x80CC0000] = "Bad_ConditionAlreadyEnabled",
  [0x80CD0000] = "Bad_DialogNotActive",
  [0x80CE0000] = "Bad_DialogResponseInvalid",
  [0x80CF0000] = "Bad_ConditionBranchAlreadyAcked",
  [0x80D00000] = "Bad_ConditionBranchAlreadyConfirmed",
  [0x80D10000] = "Bad_ConditionAlreadyShelved",
  [0x80D20000] = "Bad_ConditionNotShelved",
  [0x80D30000] = "Bad_ShelvingTimeOutOfRange",
  [0x80D40000] = "Bad_AggregateListMismatch",
  [0x80D50000] = "Bad_AggregateNotSupported",
  [0x80D60000] = "Bad_AggregateInvalidInputs",
  [0x80D70000] = "Bad_BoundNotFound",
  [0x80D80000] = "Bad_BoundNotSupported",
  [0x80DA0000] = "Bad_AggregateConfigurationRejected",
  [0x80DB0000] = "Bad_TooManyMonitoredItems",
  [0x80E10000] = "Bad_DominantValueChanged",
  [0x80E30000] = "Bad_DependentValueChanged",
  [0x80E40000] = "Bad_RequestNotAllowed",
  [0x80E50000] = "Bad_TooManyArguments",
  [0x80E60000] = "Bad_SecurityModeInsufficient",
  [0x80E70000] = "Bad_DataSetIdInvalid",
  [0x80E80000] = "Bad_TransactionPending",
  [0x80E90000] = "Bad_Locked",
  [0x80EA0000] = "Bad_IndexRangeDataMismatch",
  [0x80EC0000] = "Bad_RequiresLock",
  [0x80ED0000] = "Bad_LocaleNotSupported",
  [0x80EE0000] = "Bad_ServerTooBusy",
  [0x80F00000] = "Bad_NoValue",
  [0x80F10000] = "Bad_TransactionFailed",
  [0x810D0000] = "Bad_CertificateChainIncomplete",
  [0x810E0000] = "Bad_LicenseExpired",
  [0x810F0000] = "Bad_LicenseLimitsExceeded",
  [0x81100000] = "Bad_LicenseNotAvailable",
  [0x81110000] = "Bad_NotExecutable",
  [0x81120000] = "Bad_NumericOverflow",
  [0x81130000] = "Bad_RequestNotComplete",
  [0x81140000] = "Bad_CertificatePolicyCheckFailed",
  [0x81150000] = "Bad_AlreadyExists",
  [0x81190000] = "Bad_Edited_OutOfRange",
  [0x811A0000] = "Bad_InitialValue_OutOfRange",
  [0x811B0000] = "Bad_OutOfRange_DominantValueChanged",
  [0x811C0000] = "Bad_Edited_OutOfRange_DominantValueChanged",
  [0x811D0000] = "Bad_OutOfRange_DominantValueChanged_DependentValueChanged",
  [0x811E0000] = "Bad_Edited_OutOfRange_DominantValueChanged_DependentValueChanged",
  [0x811F0000] = "Bad_TicketRequired",
  [0x81200000] = "Bad_TicketInvalid",
}

--- Renders a StatusCode as "Name (0xXXXXXXXX)" or just the hex value.
-- @param code number StatusCode.
-- @return string human readable representation.
function status_string(code)
  if not code then return "unknown" end
  local name = STATUS_CODES[code]
  -- Severity lives in the top two bits; anything else in the low 16 bits is
  -- an info field that does not change the meaning of the code.
  if not name then
    name = STATUS_CODES[code & 0xFFFF0000]
  end
  if name then
    return string.format("%s (0x%08X)", name, code)
  end
  return string.format("0x%08X", code)
end

--- True if a StatusCode indicates success (severity Good).
function is_good(code)
  return code ~= nil and (code & 0xC0000000) == 0
end

-- ---------------------------------------------------------------------------
-- Reader: cursor over an OPC UA binary encoded buffer
-- ---------------------------------------------------------------------------

--- Raised by Reader methods; caught at the service boundary.
local function decode_error(fmt, ...)
  error({opcua_decode = true, msg = string.format(fmt, ...)}, 0)
end

Reader = {}
Reader.__index = Reader

--- Creates a cursor over <code>data</code>, starting at <code>pos</code> (1-based).
function Reader:new(data, pos)
  return setmetatable({data = data, pos = pos or 1}, Reader)
end

function Reader:remaining()
  return #self.data - self.pos + 1
end

function Reader:need(n)
  if self:remaining() < n then
    decode_error("need %d bytes at offset %d, only %d left", n, self.pos, self:remaining())
  end
end

function Reader:raw(n)
  self:need(n)
  local s = self.data:sub(self.pos, self.pos + n - 1)
  self.pos = self.pos + n
  return s
end

function Reader:skip(n)
  self:need(n)
  self.pos = self.pos + n
end

local function unpacker(fmt, size)
  return function(self)
    self:need(size)
    local v, np = string.unpack(fmt, self.data, self.pos)
    self.pos = np
    return v
  end
end

Reader.u8  = unpacker("<I1", 1)
Reader.i8  = unpacker("<i1", 1)
Reader.u16 = unpacker("<I2", 2)
Reader.i16 = unpacker("<i2", 2)
Reader.u32 = unpacker("<I4", 4)
Reader.i32 = unpacker("<i4", 4)
Reader.u64 = unpacker("<I8", 8)
Reader.i64 = unpacker("<i8", 8)
Reader.f32 = unpacker("<f", 4)
Reader.f64 = unpacker("<d", 8)

function Reader:bool()
  return self:u8() ~= 0
end

Reader.statuscode = Reader.u32

--- Reads a String or ByteString: int32 length, -1 meaning null.
-- Only -1 is null; any other negative length is a peer sending nonsense, and
-- saying so beats silently returning an empty value.
function Reader:str()
  local len = self:i32()
  if len == -1 then return nil end
  if len < 0 then
    decode_error("invalid string length %d at offset %d", len, self.pos - 4)
  end
  if len == 0 then return "" end
  return self:raw(len)
end

Reader.bytestring = Reader.str
Reader.xmlelement = Reader.str

--- Reads a DateTime (100ns ticks since 1601-01-01 UTC).
-- @return number Unix timestamp in seconds, or nil for the null date.
function Reader:datetime()
  local ticks = self:u64()
  if ticks == 0 then return nil end
  -- 11644473600 seconds between 1601-01-01 and 1970-01-01.
  return math.floor(ticks / 10000000) - 11644473600
end

function Reader:guid()
  local d1 = self:u32()
  local d2 = self:u16()
  local d3 = self:u16()
  local d4 = self:raw(8)
  return string.format("%08X-%04X-%04X-%s-%s", d1, d2, d3,
    stdnse.tohex(d4:sub(1, 2)):upper(), stdnse.tohex(d4:sub(3, 8)):upper())
end

--- Reads a NodeId in any of the five encodings.
-- @return table {ns=namespace index, type="numeric"|"string"|"guid"|"opaque", id=value}
function Reader:nodeid()
  local enc = self:u8()
  local kind = enc & 0x0F
  local node
  if kind == 0x00 then      -- TwoByte
    node = {ns = 0, type = "numeric", id = self:u8()}
  elseif kind == 0x01 then  -- FourByte
    local ns = self:u8()
    node = {ns = ns, type = "numeric", id = self:u16()}
  elseif kind == 0x02 then  -- Numeric
    local ns = self:u16()
    node = {ns = ns, type = "numeric", id = self:u32()}
  elseif kind == 0x03 then  -- String
    local ns = self:u16()
    node = {ns = ns, type = "string", id = self:str()}
  elseif kind == 0x04 then  -- Guid
    local ns = self:u16()
    local start = self.pos
    node = {ns = ns, type = "guid", id = self:guid(),
            raw = self.data:sub(start, start + 15)}
  elseif kind == 0x05 then  -- ByteString
    local ns = self:u16()
    node = {ns = ns, type = "opaque", id = self:bytestring()}
  else
    decode_error("unknown NodeId encoding 0x%02X at offset %d", enc, self.pos - 1)
  end
  node.encoding = enc
  return node
end

--- Reads an ExpandedNodeId (NodeId plus optional namespace/server URI).
function Reader:expandednodeid()
  local start = self.pos
  local enc = self.data:byte(start)
  local node = self:nodeid()
  if enc & 0x80 ~= 0 then
    node.namespace_uri = self:str()
  end
  if enc & 0x40 ~= 0 then
    node.server_index = self:u32()
  end
  return node
end

function Reader:qualifiedname()
  local ns = self:u16()
  return {ns = ns, name = self:str()}
end

--- Reads a LocalizedText, returning the text (locale is dropped).
function Reader:localizedtext()
  local mask = self:u8()
  local locale, text
  if mask & 0x01 ~= 0 then locale = self:str() end
  if mask & 0x02 ~= 0 then text = self:str() end
  return text, locale
end

--- Reads an ExtensionObject.
-- @return table {type_id=NodeId, encoding=number, body=string|nil}
function Reader:extensionobject()
  local type_id = self:nodeid()
  local encoding = self:u8()
  local body
  if encoding == 1 then       -- ByteString body
    body = self:bytestring()
  elseif encoding == 2 then   -- XmlElement body
    body = self:xmlelement()
  end
  return {type_id = type_id, encoding = encoding, body = body}
end

--- Reads a DiagnosticInfo (recursively).
function Reader:diagnosticinfo()
  local mask = self:u8()
  local info = {}
  if mask & 0x01 ~= 0 then info.symbolic_id = self:i32() end
  if mask & 0x02 ~= 0 then info.namespace_uri = self:i32() end
  if mask & 0x04 ~= 0 then info.localized_text = self:i32() end
  if mask & 0x08 ~= 0 then info.locale = self:i32() end
  if mask & 0x10 ~= 0 then info.additional_info = self:str() end
  if mask & 0x20 ~= 0 then info.inner_status = self:statuscode() end
  if mask & 0x40 ~= 0 then info.inner_diagnostic = self:diagnosticinfo() end
  return info
end

local VARIANT_BUILTIN = {
  [1] = "bool", [2] = "i8", [3] = "u8", [4] = "i16", [5] = "u16",
  [6] = "i32", [7] = "u32", [8] = "i64", [9] = "u64", [10] = "f32",
  [11] = "f64", [12] = "str", [13] = "datetime", [14] = "guid",
  [15] = "bytestring", [16] = "xmlelement", [17] = "nodeid",
  [18] = "expandednodeid", [19] = "statuscode", [20] = "qualifiedname",
  [21] = "localizedtext", [22] = "extensionobject", [23] = "datavalue",
  [24] = "variant", [25] = "diagnosticinfo",
}

--- Reads an array with an int32 length prefix (-1 = null).
-- @param fn function|string decoder method name or function.
-- @param max number optional sanity limit on the element count.
function Reader:array(fn, max)
  local n = self:i32()
  if n == -1 then return nil end
  -- A length of 0xFFFFFFFA arrives here as -6: not the null marker, but a peer
  -- claiming four billion elements. Reporting that as an empty array would
  -- hide the lie behind a plausible looking result.
  if n < 0 then
    decode_error("invalid array length %d at offset %d", n, self.pos - 4)
  end
  if n > (max or 65535) then
    decode_error("array length %d exceeds the limit of %d at offset %d",
                 n, max or 65535, self.pos - 4)
  end
  local method = type(fn) == "string" and Reader[fn] or fn
  local out = {}
  for i = 1, n do
    out[i] = method(self)
  end
  return out
end

--- Reads a Variant.
-- @return any the decoded value (array as a table), or nil for a null Variant.
function Reader:variant()
  local enc = self:u8()
  local builtin = enc & 0x3F
  if builtin == 0 then return nil end
  local name = VARIANT_BUILTIN[builtin]
  if not name then
    decode_error("unknown Variant type %d at offset %d", builtin, self.pos - 1)
  end
  local value
  if enc & 0x80 ~= 0 then
    value = self:array(name)
  else
    value = Reader[name](self)
  end
  if enc & 0x40 ~= 0 then
    -- Multidimensional: dimensions follow the flattened value array.
    local dims = self:array("i32")
    value = {value = value, dimensions = dims}
  end
  return value
end

--- Reads a DataValue.
function Reader:datavalue()
  local mask = self:u8()
  local dv = {}
  if mask & 0x01 ~= 0 then dv.value = self:variant() end
  if mask & 0x02 ~= 0 then dv.status = self:statuscode() end
  if mask & 0x04 ~= 0 then dv.source_timestamp = self:datetime() end
  if mask & 0x08 ~= 0 then dv.source_picoseconds = self:u16() end
  if mask & 0x10 ~= 0 then dv.server_timestamp = self:datetime() end
  if mask & 0x20 ~= 0 then dv.server_picoseconds = self:u16() end
  return dv
end

--- Reads a ResponseHeader (OPC 10000-4, 7.29).
function Reader:responseheader()
  local h = {}
  h.timestamp = self:datetime()
  h.request_handle = self:u32()
  h.service_result = self:statuscode()
  h.service_diagnostics = self:diagnosticinfo()
  h.string_table = self:array("str")
  h.additional_header = self:extensionobject()
  return h
end

-- ---------------------------------------------------------------------------
-- Writer: builds an OPC UA binary encoded buffer
-- ---------------------------------------------------------------------------

Writer = {}
Writer.__index = Writer

function Writer:new()
  return setmetatable({parts = {}}, Writer)
end

function Writer:raw(s)
  self.parts[#self.parts + 1] = s
  return self
end

function Writer:u8(v)  return self:raw(string.pack("<I1", v)) end
function Writer:u16(v) return self:raw(string.pack("<I2", v)) end
function Writer:u32(v) return self:raw(string.pack("<I4", v)) end
function Writer:i32(v) return self:raw(string.pack("<i4", v)) end
function Writer:u64(v) return self:raw(string.pack("<I8", v)) end
function Writer:f64(v) return self:raw(string.pack("<d", v)) end
function Writer:bool(v) return self:u8(v and 1 or 0) end

--- Writes a String or ByteString; nil is encoded as null (-1).
function Writer:str(s)
  if s == nil then return self:i32(-1) end
  return self:i32(#s):raw(s)
end

Writer.bytestring = Writer.str

--- Writes a null array (-1).
function Writer:null_array()
  return self:i32(-1)
end

--- Writes an array of strings.
function Writer:str_array(t)
  if not t then return self:null_array() end
  self:i32(#t)
  for _, s in ipairs(t) do self:str(s) end
  return self
end

function Writer:datetime(unix)
  if not unix then return self:u64(0) end
  return self:u64((unix + 11644473600) * 10000000)
end

--- Writes a numeric NodeId in namespace 0 using the most compact encoding.
function Writer:nodeid_numeric(id, ns)
  ns = ns or 0
  if ns == 0 and id <= 0xFF then
    return self:u8(0x00):u8(id)
  elseif ns <= 0xFF and id <= 0xFFFF then
    return self:u8(0x01):u8(ns):u16(id)
  end
  return self:u8(0x02):u16(ns):u32(id)
end

--- Writes a NodeId from a table as produced by Reader:nodeid().
function Writer:nodeid(node)
  if not node then return self:u8(0x00):u8(0) end
  if node.type == "numeric" then
    return self:nodeid_numeric(node.id, node.ns)
  elseif node.type == "string" then
    return self:u8(0x03):u16(node.ns):str(node.id)
  elseif node.type == "opaque" then
    return self:u8(0x05):u16(node.ns):bytestring(node.id)
  elseif node.type == "guid" then
    -- Written back from the bytes as received; a GUID AuthenticationToken has
    -- to come back byte for byte or the server loses the session.
    if node.raw and #node.raw == 16 then
      return self:u8(0x04):u16(node.ns):raw(node.raw)
    end
    local a, b, c, d, e = tostring(node.id):match(
      "^(%x+)%-(%x+)%-(%x+)%-(%x+)%-(%x+)$")
    if a then
      return self:u8(0x04):u16(node.ns)
        :u32(tonumber(a, 16)):u16(tonumber(b, 16)):u16(tonumber(c, 16))
        :raw(stdnse.fromhex(d .. e))
    end
  end
  return self:u8(0x00):u8(0)
end

--- Writes a null ExtensionObject.
function Writer:null_extensionobject()
  return self:u8(0x00):u8(0):u8(0x00)
end

--- Writes a null LocalizedText.
function Writer:null_localizedtext()
  return self:u8(0x00)
end

--- Writes a LocalizedText with text only.
function Writer:localizedtext(text)
  if not text then return self:u8(0x00) end
  return self:u8(0x02):str(text)
end

function Writer:build()
  return table.concat(self.parts)
end

--- Builds a RequestHeader (OPC 10000-4, 7.28).
-- @param auth_token table|nil AuthenticationToken NodeId from CreateSession.
-- @param handle number RequestHandle.
-- @param timeout_hint number TimeoutHint in milliseconds.
local function request_header(auth_token, handle, timeout_hint)
  local w = Writer:new()
  w:nodeid(auth_token)
  w:datetime(os.time())
  w:u32(handle)
  w:u32(0)              -- ReturnDiagnostics
  w:str(nil)            -- AuditEntryId
  w:u32(timeout_hint or 10000)
  w:null_extensionobject()
  return w:build()
end

-- ---------------------------------------------------------------------------
-- Connection: UACP transport and secure channel
-- ---------------------------------------------------------------------------

-- Hard caps against a peer that answers with more than it should. A real
-- GetEndpoints reply is a few tens of kilobytes; a Browse of a large address
-- space stays well inside these.
local MAX_MESSAGE_SIZE = 8 * 1024 * 1024   -- per chunk and per reassembled message
local MAX_CHUNKS = 512                     -- chunks per message
local DEFAULT_BUFFER = 65535

Connection = {}
Connection.__index = Connection

--- Creates a new connection object.
-- @param host table|string nmap host table or address.
-- @param port table|number nmap port table or number.
-- @param options table optional {timeout=ms, endpoint_url=string}
function Connection:new(host, port, options)
  options = options or {}
  local o = {
    host = host,
    port = port,
    ip = type(host) == "table" and host.ip or tostring(host),
    portnum = type(port) == "table" and port.number or tonumber(port),
    timeout = options.timeout,
    endpoint_url = options.endpoint_url,
    buf_parts = {},
    buf_len = 0,
    request_id = 0,
    sequence_number = 0,
    channel_id = 0,
    token_id = 0,
    recv_buffer = DEFAULT_BUFFER,
    send_buffer = DEFAULT_BUFFER,
    -- What we advertise in HEL; the server chunks its replies to this size.
    -- The specification requires at least 8192 bytes.
    advertised_buffer = math.max(8192, tonumber(options.recv_buffer) or DEFAULT_BUFFER),
    max_message_size = 0,
    max_chunk_count = 0,
  }
  if not o.timeout and type(host) == "table" then
    -- Follow the -T timing template and measured RTT.
    o.timeout = math.max(5000, stdnse.get_timeout(host) * 3)
  end
  o.timeout = o.timeout or 5000
  return setmetatable(o, Connection)
end

--- Returns the endpoint URL used for the handshake.
function Connection:url()
  if self.endpoint_url then return self.endpoint_url end
  local ip = self.ip
  if ip:find(":", 1, true) then ip = "[" .. ip .. "]" end
  return string.format("opc.tcp://%s:%d", ip, self.portnum)
end

function Connection:log(fmt, ...)
  stdnse.debug2("opcua %s:%d " .. fmt, self.ip, self.portnum, ...)
end

--- Opens the TCP connection and performs the HEL/ACK handshake.
-- @return boolean status, string error message on failure.
function Connection:connect()
  self.socket = nmap.new_socket()
  self.socket:set_timeout(self.timeout)
  local status, err = self.socket:connect(self.host, self.port)
  if not status then
    return false, "connect failed: " .. tostring(err)
  end
  return self:hello()
end

--- Sends HEL and parses the ACK, storing the negotiated limits.
function Connection:hello(url)
  url = url or self:url()
  local body = Writer:new()
    :u32(0)                          -- ProtocolVersion
    :u32(self.advertised_buffer)     -- ReceiveBufferSize
    :u32(self.advertised_buffer)     -- SendBufferSize
    :u32(0)                 -- MaxMessageSize (0 = no limit)
    :u32(0)                 -- MaxChunkCount (0 = no limit)
    :str(url)
    :build()

  local msg = "HELF" .. string.pack("<I4", 8 + #body) .. body
  local status, err = self.socket:send(msg)
  if not status then
    return false, "failed to send HEL: " .. tostring(err)
  end

  local header, payload, herr = self:recv_chunk()
  if not header then
    return false, herr
  end

  if header.type == "ERR" then
    local r = Reader:new(payload)
    local ok, code = pcall(r.statuscode, r)
    local reason = ok and select(2, pcall(r.str, r)) or nil
    self.hello_error = {code = ok and code or nil, reason = reason}
    -- An ERR still proves the peer speaks OPC UA.
    return false, string.format("server rejected HEL: %s%s",
      ok and status_string(code) or "unparsable error",
      (type(reason) == "string" and #reason > 0) and (" - " .. reason) or "")
  end

  if header.type ~= "ACK" then
    return false, "unexpected message type: " .. tostring(header.type)
  end

  local r = Reader:new(payload)
  local ok, res = pcall(function()
    return {
      protocol_version = r:u32(),
      recv_buffer = r:u32(),
      send_buffer = r:u32(),
      max_message_size = r:u32(),
      max_chunk_count = r:u32(),
    }
  end)
  if not ok then
    return false, "malformed ACK"
  end

  self.ack = res
  self.protocol_version = res.protocol_version
  -- The server's ReceiveBufferSize caps what we may send in one chunk.
  self.send_buffer = math.min(res.recv_buffer > 0 and res.recv_buffer or DEFAULT_BUFFER,
                              self.advertised_buffer)
  self.recv_buffer = res.send_buffer > 0 and res.send_buffer or DEFAULT_BUFFER
  self.max_message_size = res.max_message_size
  self.max_chunk_count = res.max_chunk_count
  self:log("ACK: proto=%d recv=%d send=%d maxmsg=%d maxchunk=%d",
    res.protocol_version, res.recv_buffer, res.send_buffer,
    res.max_message_size, res.max_chunk_count)
  return true
end

--- Reads exactly <code>n</code> bytes, buffering whatever the socket delivers
-- on top so the surplus stays available for the next chunk.
function Connection:read_exact(n)
  -- Fragments are concatenated once per call rather than on every receive:
  -- appending to a string each time is quadratic, which a peer that dribbles
  -- out a large message can exploit.
  while self.buf_len < n do
    local status, data = self.socket:receive()
    if not status then
      return nil, tostring(data)
    end
    self.buf_parts[#self.buf_parts + 1] = data
    self.buf_len = self.buf_len + #data
  end

  local buffered = table.concat(self.buf_parts)
  local out = buffered:sub(1, n)
  local rest = buffered:sub(n + 1)
  self.buf_parts = (#rest > 0) and {rest} or {}
  self.buf_len = #rest
  return out
end

--- Receives exactly one chunk.
-- @return table header {type=string, chunk=string, size=number}, string body,
--         or nil plus an error message.
function Connection:recv_chunk()
  local head, err = self:read_exact(8)
  if not head then
    return nil, nil, "receive failed: " .. tostring(err)
  end

  local msg_type = head:sub(1, 3)
  local chunk_type = head:sub(4, 4)
  local size = string.unpack("<I4", head, 5)
  if size < 8 or size > MAX_MESSAGE_SIZE then
    return nil, nil, string.format("invalid chunk size %d", size)
  end

  local body = ""
  if size > 8 then
    body, err = self:read_exact(size - 8)
    if not body then
      return nil, nil, "receive failed: " .. tostring(err)
    end
  end

  self:log("<- %s%s %d bytes", msg_type, chunk_type, size)
  return {type = msg_type, chunk = chunk_type, size = size}, body, nil
end

--- Receives a full message, reassembling C/F chunks.
-- @param expect string|nil expected message type ("MSG" or "OPN").
-- @return string body (after the security and sequence headers), or nil + error.
function Connection:recv_message(expect)
  local parts = {}
  local count = 0
  local total = 0
  while true do
    local header, payload, err = self:recv_chunk()
    if not header then return nil, err end
    count = count + 1
    if count > MAX_CHUNKS then
      return nil, string.format(
        "aborted after %d chunks without a final one; the peer is not answering in good faith",
        MAX_CHUNKS)
    end

    if header.type == "ERR" then
      local r = Reader:new(payload)
      local ok, code = pcall(r.statuscode, r)
      local reason
      if ok then
        local ok2, s = pcall(r.str, r)
        reason = ok2 and s or nil
      end
      return nil, string.format("server sent ERR: %s%s",
        ok and status_string(code) or "unparsable",
        (type(reason) == "string" and #reason > 0) and (" - " .. reason) or "")
    end

    if expect and header.type ~= expect then
      return nil, string.format("expected %s, got %s", expect, header.type)
    end

    local r = Reader:new(payload)
    local ok, err2 = pcall(function()
      r:u32()                       -- SecureChannelId
      if header.type == "OPN" then
        r:str()                     -- SecurityPolicyUri
        r:bytestring()              -- SenderCertificate
        r:bytestring()              -- ReceiverCertificateThumbprint
      else
        r:u32()                     -- TokenId (SymmetricAlgorithmSecurityHeader)
      end
      r:u32()                       -- SequenceNumber
      r:u32()                       -- RequestId
    end)
    if not ok then
      return nil, "malformed security header: " .. tostring(type(err2) == "table" and err2.msg or err2)
    end

    local body = payload:sub(r.pos)

    if header.chunk == "A" then
      -- Abort chunk: the body is an error code plus reason.
      local ar = Reader:new(body)
      local ok3, code = pcall(ar.statuscode, ar)
      return nil, "server aborted message: " ..
        (ok3 and status_string(code) or "unknown reason")
    end

    total = total + #body
    if total > MAX_MESSAGE_SIZE then
      return nil, string.format(
        "aborted after %d bytes; the reassembled message exceeds the %d byte limit",
        total, MAX_MESSAGE_SIZE)
    end

    parts[#parts + 1] = body
    self.chunks_received = (self.chunks_received or 0) + 1

    if header.chunk == "F" then
      self.last_message_chunks = #parts
      return table.concat(parts)
    elseif header.chunk ~= "C" then
      return nil, "unknown chunk type: " .. tostring(header.chunk)
    end
  end
end

--- Opens a secure channel with SecurityPolicy None.
function Connection:open_secure_channel()
  self.request_id = self.request_id + 1
  self.sequence_number = self.sequence_number + 1

  local body = Writer:new()
  body:nodeid_numeric(ID.OpenSecureChannelRequest)
  body:raw(request_header(nil, self.request_id, 10000))
  body:u32(0)          -- ClientProtocolVersion
  body:u32(0)          -- RequestType: ISSUE
  body:u32(1)          -- SecurityMode: None
  body:bytestring(nil) -- ClientNonce
  body:u32(3600000)    -- RequestedLifetime
  local payload = body:build()

  local header = Writer:new()
  header:u32(0)                            -- SecureChannelId (0 = new)
  header:str(SECURITY_POLICY_NONE)
  header:bytestring(nil)                   -- SenderCertificate
  header:bytestring(nil)                   -- ReceiverCertificateThumbprint
  header:u32(self.sequence_number)
  header:u32(self.request_id)
  local head = header:build()

  local msg = "OPNF" .. string.pack("<I4", 8 + #head + #payload) .. head .. payload
  local status, err = self.socket:send(msg)
  if not status then
    return false, "failed to send OpenSecureChannel: " .. tostring(err)
  end

  local resp, rerr = self:recv_message("OPN")
  if not resp then
    return false, rerr
  end

  local ok, result = pcall(function()
    local r = Reader:new(resp)
    local type_id = r:nodeid()
    local rh = r:responseheader()
    if type_id.id == ID.ServiceFault or not is_good(rh.service_result) then
      return {fault = rh.service_result}
    end
    if type_id.id ~= ID.OpenSecureChannelResponse then
      return {fault = nil, unexpected = type_id.id}
    end
    r:u32()                       -- ServerProtocolVersion
    local channel_id = r:u32()    -- SecurityToken.ChannelId
    local token_id = r:u32()      -- SecurityToken.TokenId
    r:datetime()                  -- CreatedAt
    local lifetime = r:u32()      -- RevisedLifetime
    return {channel_id = channel_id, token_id = token_id, lifetime = lifetime}
  end)

  if not ok then
    return false, "failed to parse OpenSecureChannelResponse: " ..
      tostring(type(result) == "table" and result.msg or result)
  end
  if result.fault then
    return false, "OpenSecureChannel rejected: " .. status_string(result.fault)
  end
  if result.unexpected then
    return false, string.format("unexpected response type %d", result.unexpected)
  end

  self.channel_id = result.channel_id
  self.token_id = result.token_id
  self:log("secure channel %d, token %d, lifetime %dms",
    result.channel_id, result.token_id, result.lifetime or 0)
  return true
end

--- Sends a service request on the open secure channel and returns the response
-- body, positioned at the TypeId.
-- @param type_id number binary encoding NodeId of the request.
-- @param body string encoded request (without the TypeId).
-- @param timeout_hint number|nil TimeoutHint for the RequestHeader.
-- @return string response body, or nil plus an error message.
function Connection:request(type_id, body, timeout_hint)
  self.request_id = self.request_id + 1
  local handle = self.request_id

  local payload = Writer:new()
    :nodeid_numeric(type_id)
    :raw(request_header(self.auth_token, handle, timeout_hint))
    :raw(body)
    :build()

  -- Each chunk carries a 24 byte header (message header, symmetric security
  -- header, sequence header); the rest of the buffer is available for payload.
  local max_body = self.send_buffer - 24
  if max_body < 1024 then max_body = 1024 end

  local offset = 1
  local total = #payload
  while offset <= total do
    local slice = payload:sub(offset, offset + max_body - 1)
    offset = offset + #slice
    local final = (offset > total) and "F" or "C"
    self.sequence_number = self.sequence_number + 1
    local chunk = Writer:new()
      :u32(self.channel_id)
      :u32(self.token_id)
      :u32(self.sequence_number)
      :u32(handle)
      :raw(slice)
      :build()
    local msg = "MSG" .. final .. string.pack("<I4", 8 + #chunk) .. chunk
    self:log("-> MSG%s %d bytes", final, #msg)
    local status, err = self.socket:send(msg)
    if not status then
      return nil, "failed to send request: " .. tostring(err)
    end
  end

  return self:recv_message("MSG")
end

--- Sends a request and decodes the response header, checking the service result.
-- @return table Reader positioned after the ResponseHeader, or nil + error.
function Connection:service(type_id, expected_response, body, timeout_hint)
  local resp, err = self:request(type_id, body, timeout_hint)
  if not resp then return nil, err end

  local ok, result = pcall(function()
    local r = Reader:new(resp)
    local tid = r:nodeid()
    local rh = r:responseheader()
    return {reader = r, type_id = tid, header = rh}
  end)
  if not ok then
    return nil, "failed to parse response header: " ..
      tostring(type(result) == "table" and result.msg or result)
  end

  if result.type_id.id == ID.ServiceFault then
    return nil, "service fault: " .. status_string(result.header.service_result)
  end
  if not is_good(result.header.service_result) then
    return nil, "service returned " .. status_string(result.header.service_result)
  end
  if result.type_id.id ~= expected_response then
    return nil, string.format("unexpected response type %s",
      tostring(result.type_id.id))
  end
  return result.reader
end

--- Closes the secure channel (best effort) and the socket.
function Connection:close()
  if self.socket then
    if self.channel_id and self.channel_id ~= 0 then
      pcall(function()
        self.request_id = self.request_id + 1
        self.sequence_number = self.sequence_number + 1
        local payload = Writer:new()
          :nodeid_numeric(ID.CloseSecureChannelRequest)
          :raw(request_header(self.auth_token, self.request_id, 5000))
          :build()
        local chunk = Writer:new()
          :u32(self.channel_id):u32(self.token_id)
          :u32(self.sequence_number):u32(self.request_id)
          :raw(payload):build()
        self.socket:send("CLOF" .. string.pack("<I4", 8 + #chunk) .. chunk)
      end)
    end
    self.socket:close()
    self.socket = nil
  end
end

-- ---------------------------------------------------------------------------
-- Structure decoders
-- ---------------------------------------------------------------------------

--- Reads an ApplicationDescription (OPC 10000-4, 7.1).
function Reader:applicationdescription()
  local a = {}
  a.application_uri = self:str()
  a.product_uri = self:str()
  a.application_name = self:localizedtext()
  local t = self:u32()
  a.application_type_id = t
  a.application_type = APPLICATION_TYPE[t] or tostring(t)
  a.gateway_server_uri = self:str()
  a.discovery_profile_uri = self:str()
  a.discovery_urls = self:array("str", 256)
  return a
end

--- Reads a UserTokenPolicy (OPC 10000-4, 7.37).
function Reader:usertokenpolicy()
  local p = {}
  p.policy_id = self:str()
  local t = self:u32()
  p.token_type_id = t
  p.token_type = USER_TOKEN_TYPE[t] or tostring(t)
  p.issued_token_type = self:str()
  p.issuer_endpoint_url = self:str()
  p.security_policy_uri = self:str()
  return p
end

--- Reads an EndpointDescription (OPC 10000-4, 7.10).
function Reader:endpointdescription()
  local e = {}
  e.endpoint_url = self:str()
  e.server = self:applicationdescription()
  e.server_certificate = self:bytestring()
  local mode = self:u32()
  e.security_mode_id = mode
  e.security_mode = SECURITY_MODE[mode] or tostring(mode)
  e.security_policy_uri = self:str()
  e.user_identity_tokens = self:array("usertokenpolicy", 64)
  e.transport_profile_uri = self:str()
  e.security_level = self:u8()
  return e
end

--- Reads a ServerOnNetwork (OPC 10000-4, 7.34).
function Reader:serveronnetwork()
  local s = {}
  s.record_id = self:u32()
  s.server_name = self:str()
  s.discovery_url = self:str()
  s.server_capabilities = self:array("str", 64)
  return s
end

--- Reads a ReferenceDescription (OPC 10000-4, 7.30).
function Reader:referencedescription()
  local r = {}
  r.reference_type_id = self:nodeid()
  r.is_forward = self:bool()
  r.node_id = self:expandednodeid()
  r.browse_name = self:qualifiedname()
  r.display_name = self:localizedtext()
  local nc = self:u32()
  r.node_class_id = nc
  r.node_class = NODE_CLASS[nc] or tostring(nc)
  r.type_definition = self:expandednodeid()
  return r
end

-- ---------------------------------------------------------------------------
-- Discovery services (no session required)
-- ---------------------------------------------------------------------------

--- Calls GetEndpoints.
-- @param url string|nil endpoint URL to ask for (defaults to the connection URL).
-- @return table array of EndpointDescription, or nil plus an error message.
function Connection:get_endpoints(url)
  local body = Writer:new()
    :str(url or self:url())
    :null_array()          -- LocaleIds
    :null_array()          -- ProfileUris
    :build()

  local r, err = self:service(ID.GetEndpointsRequest, ID.GetEndpointsResponse, body)
  if not r then return nil, err end

  local ok, endpoints = pcall(r.array, r, "endpointdescription", 128)
  if not ok then
    return nil, "failed to parse endpoints: " ..
      tostring(type(endpoints) == "table" and endpoints.msg or endpoints)
  end
  return endpoints or {}
end

--- Calls FindServers.
-- @return table array of ApplicationDescription, or nil plus an error message.
function Connection:find_servers(url)
  local body = Writer:new()
    :str(url or self:url())
    :null_array()          -- LocaleIds
    :null_array()          -- ServerUris
    :build()

  local r, err = self:service(ID.FindServersRequest, ID.FindServersResponse, body)
  if not r then return nil, err end

  local ok, servers = pcall(r.array, r, "applicationdescription", 256)
  if not ok then
    return nil, "failed to parse servers: " ..
      tostring(type(servers) == "table" and servers.msg or servers)
  end
  return servers or {}
end

--- Calls FindServersOnNetwork; only a Local Discovery Server with the
-- multicast extension supports it.
-- @return table array of ServerOnNetwork, or nil plus an error message.
function Connection:find_servers_on_network()
  local body = Writer:new()
    :u32(0)                -- StartingRecordId
    :u32(0)                -- MaxRecordsToReturn (0 = all)
    :null_array()          -- ServerCapabilityFilter
    :build()

  local r, err = self:service(ID.FindServersOnNetworkRequest,
                              ID.FindServersOnNetworkResponse, body)
  if not r then return nil, err end

  local ok, servers = pcall(function()
    r:datetime()           -- LastCounterResetTime
    return r:array("serveronnetwork", 256)
  end)
  if not ok then
    return nil, "failed to parse network servers: " ..
      tostring(type(servers) == "table" and servers.msg or servers)
  end
  return servers or {}
end

-- ---------------------------------------------------------------------------
-- Session services
-- ---------------------------------------------------------------------------

--- Creates and activates a session.
-- @param options table {username=string, password=string, policy_id=string,
--                       session_name=string, endpoint_url=string}
--   Without credentials an anonymous token is used.
-- @return boolean status, string error message on failure.
function Connection:create_session(options)
  options = options or {}
  local url = options.endpoint_url or self:url()

  local client = Writer:new()
    :str("urn:nmap:opcua-nse:client")   -- ApplicationUri
    :str("https://nmap.org")            -- ProductUri
    :localizedtext("Nmap NSE")          -- ApplicationName
    :u32(1)                             -- ApplicationType: Client
    :str(nil)                           -- GatewayServerUri
    :str(nil)                           -- DiscoveryProfileUri
    :null_array()                       -- DiscoveryUrls
    :build()

  local nonce = rand.random_string(32)
  local body = Writer:new()
    :raw(client)
    :str(nil)                           -- ServerUri
    :str(url)                           -- EndpointUrl
    :str(options.session_name or "nmap-opcua")
    :bytestring(nonce)                  -- ClientNonce
    :bytestring(nil)                    -- ClientCertificate
    :f64(60000)                         -- RequestedSessionTimeout
    :u32(MAX_MESSAGE_SIZE)              -- MaxResponseMessageSize
    :build()

  local r, err = self:service(ID.CreateSessionRequest, ID.CreateSessionResponse, body)
  if not r then return false, err end

  local ok, res = pcall(function()
    local session_id = r:nodeid()
    local auth_token = r:nodeid()
    local timeout = r:f64()
    local server_nonce = r:bytestring()
    local server_cert = r:bytestring()
    local endpoints = r:array("endpointdescription", 128)
    return {session_id = session_id, auth_token = auth_token,
            timeout = timeout, server_nonce = server_nonce,
            server_certificate = server_cert, endpoints = endpoints}
  end)
  if not ok then
    return false, "failed to parse CreateSessionResponse: " ..
      tostring(type(res) == "table" and res.msg or res)
  end

  self.session_id = res.session_id
  self.auth_token = res.auth_token
  self.session_endpoints = res.endpoints
  self.server_certificate = res.server_certificate

  return self:activate_session(options)
end

--- Activates the current session with an identity token.
function Connection:activate_session(options)
  options = options or {}

  local token = Writer:new()
  if options.username then
    local inner = Writer:new()
      :str(options.policy_id or "username")
      :str(options.username)
      :bytestring(options.password or "")   -- plaintext: only valid with policy None
      :str(nil)                             -- EncryptionAlgorithm
      :build()
    token:nodeid_numeric(ID.UserNameIdentityToken)
    token:u8(0x01)                          -- body is a ByteString
    token:bytestring(inner)
  else
    local inner = Writer:new():str(options.policy_id or "anonymous"):build()
    token:nodeid_numeric(ID.AnonymousIdentityToken)
    token:u8(0x01)
    token:bytestring(inner)
  end

  local body = Writer:new()
    :str(nil):bytestring(nil)   -- ClientSignature (algorithm, signature)
    :null_array()               -- ClientSoftwareCertificates
    :null_array()               -- LocaleIds
    :raw(token:build())         -- UserIdentityToken
    :str(nil):bytestring(nil)   -- UserTokenSignature
    :build()

  local r, err = self:service(ID.ActivateSessionRequest, ID.ActivateSessionResponse, body)
  if not r then return false, err end

  local ok, res = pcall(function()
    r:bytestring()              -- ServerNonce
    local results = r:array("statuscode", 64)
    return results
  end)
  if not ok then
    return false, "failed to parse ActivateSessionResponse"
  end
  if res then
    for _, code in ipairs(res) do
      if not is_good(code) then
        return false, "identity token rejected: " .. status_string(code)
      end
    end
  end

  self.session_active = true
  return true
end

--- Reads attributes from the address space.
-- @param nodes table array of {node=nodeid table or numeric id, attr=number}
-- @return table array of DataValue, or nil plus an error message.
function Connection:read(nodes)
  local w = Writer:new()
    :f64(0)      -- MaxAge
    :u32(0)      -- TimestampsToReturn: Source
    :i32(#nodes)
  for _, n in ipairs(nodes) do
    if type(n.node) == "number" then
      w:nodeid_numeric(n.node)
    else
      w:nodeid(n.node)
    end
    w:u32(n.attr or ATTR.Value)
    w:str(nil)          -- IndexRange
    w:u16(0):str(nil)   -- DataEncoding (QualifiedName)
  end

  local r, err = self:service(ID.ReadRequest, ID.ReadResponse, w:build())
  if not r then return nil, err end

  local ok, values = pcall(r.array, r, "datavalue", 1024)
  if not ok then
    return nil, "failed to parse ReadResponse: " ..
      tostring(type(values) == "table" and values.msg or values)
  end
  return values or {}
end

--- Browses the references of a node.
-- @param node number|table NodeId to browse.
-- @param options table {max_refs=number, node_class_mask=number}
-- @return table array of ReferenceDescription, or nil plus an error message.
function Connection:browse(node, options)
  options = options or {}
  local w = Writer:new()
    :u8(0x00):u8(0)          -- View.ViewId (null NodeId)
    :datetime(nil)           -- View.Timestamp
    :u32(0)                  -- View.ViewVersion
    :u32(options.max_refs or 0)
    :i32(1)                  -- one BrowseDescription
  if type(node) == "number" then
    w:nodeid_numeric(node)
  else
    w:nodeid(node)
  end
  w:u32(0)                            -- BrowseDirection: Forward
  w:nodeid_numeric(33)                -- ReferenceTypeId: HierarchicalReferences
  w:bool(true)                        -- IncludeSubtypes
  w:u32(options.node_class_mask or 0) -- NodeClassMask: all
  w:u32(0x3F)                         -- ResultMask: all

  local r, err = self:service(ID.BrowseRequest, ID.BrowseResponse, w:build())
  if not r then return nil, err end

  local ok, res = pcall(function()
    local n = r:i32()
    if n < 1 then return {} end
    local status = r:statuscode()
    r:bytestring()             -- ContinuationPoint
    local refs = r:array("referencedescription", 4096)
    return {status = status, references = refs or {}}
  end)
  if not ok then
    return nil, "failed to parse BrowseResponse: " ..
      tostring(type(res) == "table" and res.msg or res)
  end
  if res.status and not is_good(res.status) then
    return nil, "browse failed: " .. status_string(res.status)
  end
  return res.references
end

-- ---------------------------------------------------------------------------
-- Security assessment helpers
-- ---------------------------------------------------------------------------

--- Security policies and how they are rated.
-- Basic128Rsa15 and Basic256 were deprecated in OPC UA 1.04 because they
-- rely on SHA-1; None provides no protection at all.
POLICY_RATING = {
  ["None"]                  = {rating = "insecure",   note = "no signing or encryption"},
  ["Basic128Rsa15"]         = {rating = "deprecated", note = "SHA-1, deprecated since 1.04"},
  ["Basic256"]              = {rating = "deprecated", note = "SHA-1, deprecated since 1.04"},
  ["Basic256Sha256"]        = {rating = "acceptable", note = ""},
  ["Aes128_Sha256_RsaOaep"] = {rating = "recommended", note = ""},
  ["Aes256_Sha256_RsaPss"]  = {rating = "recommended", note = ""},
}

--- Strips the namespace prefix from a SecurityPolicy URI.
function policy_name(uri)
  if not uri or uri == "" then return "unknown" end
  return uri:match("#([^#]+)$") or uri
end

--- Rating table entry for a policy URI.
function policy_rating(uri)
  return POLICY_RATING[policy_name(uri)] or {rating = "unknown", note = ""}
end

--- Formats a certificate validity field, which may be a table or a string.
local function cert_time_string(t)
  if type(t) == "string" then return t end
  if type(t) == "table" then
    return string.format("%04d-%02d-%02d %02d:%02d:%02d UTC",
      t.year or 0, t.month or 0, t.day or 0, t.hour or 0, t.min or 0, t.sec or 0)
  end
  return "unknown"
end

--- Converts a certificate validity field to a Unix timestamp, if possible.
local function cert_time_stamp(t)
  if type(t) == "table" and t.year then
    return os.time({year = t.year, month = t.month or 1, day = t.day or 1,
                    hour = t.hour or 0, min = t.min or 0, sec = t.sec or 0})
  end
  return nil
end

--- Renders a certificate name table (subject or issuer) as a short string.
local function name_string(name)
  if type(name) ~= "table" then return tostring(name) end
  local parts = {}
  for _, k in ipairs({"commonName", "organizationName", "countryName"}) do
    if name[k] then parts[#parts + 1] = name[k] end
  end
  if #parts == 0 then
    for k, v in pairs(name) do
      parts[#parts + 1] = string.format("%s=%s", k, tostring(v))
    end
  end
  return table.concat(parts, ", ")
end

--- Parses and evaluates a DER encoded OPC UA application certificate.
-- @param der string raw certificate as sent in an EndpointDescription.
-- @param application_uri string|nil the ApplicationUri the certificate must match.
-- @return table certificate details plus a list of issues, or nil plus an error.
function analyze_certificate(der, application_uri)
  if not der or #der == 0 then
    return nil, "no certificate"
  end

  local ok, cert = pcall(sslcert.parse_ssl_certificate, der)
  if not ok or not cert then
    return nil, "unparsable certificate"
  end

  local info = {issues = {}}
  info.subject = name_string(cert.subject)
  info.issuer = name_string(cert.issuer)
  info.valid_from = cert_time_string(cert.validity and cert.validity.notBefore)
  info.valid_to = cert_time_string(cert.validity and cert.validity.notAfter)
  info.sig_algorithm = cert.sig_algorithm
  if cert.pubkey then
    info.key_type = cert.pubkey.type
    info.key_bits = cert.pubkey.bits
  end

  -- SubjectAltName carries the ApplicationUri that OPC 10000-4 requires to
  -- match the ApplicationUri announced in the EndpointDescription.
  for _, ext in ipairs(cert.extensions or {}) do
    if ext.name == "X509v3 Subject Alternative Name" then
      info.subject_alt_name = ext.value
      info.san_uri = ext.value:match("URI:([^,]+)")
    elseif ext.name == "X509v3 Basic Constraints" then
      info.basic_constraints = ext.value
    end
  end

  local openssl_ok, openssl = pcall(require, "openssl")
  if openssl_ok and openssl and openssl.digest then
    local dok, digest = pcall(openssl.digest, "sha256", der)
    if dok and digest then
      info.fingerprint_sha256 = stdnse.tohex(digest):upper()
    end
  end

  local function issue(severity, text)
    info.issues[#info.issues + 1] = {severity = severity, text = text}
  end

  if info.subject == info.issuer then
    info.self_signed = true
    issue("low", "certificate is self-signed")
  end

  local now = os.time()
  local not_after = cert_time_stamp(cert.validity and cert.validity.notAfter)
  local not_before = cert_time_stamp(cert.validity and cert.validity.notBefore)
  if not_after and not_after < now then
    info.expired = true
    issue("high", string.format("certificate expired on %s", info.valid_to))
  end
  if not_before and not_before > now then
    info.not_yet_valid = true
    issue("high", string.format("certificate not valid before %s", info.valid_from))
  end

  if info.key_bits and info.key_type == "rsa" and info.key_bits < 2048 then
    issue("high", string.format("weak %d bit RSA key", info.key_bits))
  end

  local sig = (info.sig_algorithm or ""):lower()
  if sig:find("md5") or sig:find("sha1") or sig:find("sha-1") then
    issue("high", string.format("weak certificate signature algorithm: %s",
      info.sig_algorithm))
  end

  if application_uri and application_uri ~= "" then
    if not info.san_uri then
      issue("medium", "certificate has no URI in subjectAltName (required by OPC 10000-4)")
    elseif info.san_uri ~= application_uri then
      issue("medium", string.format(
        "certificate URI does not match ApplicationUri (%s vs %s)",
        info.san_uri, application_uri))
    end
  end

  table.sort(info.issues, function(a, b)
    local order = {critical = 1, high = 2, medium = 3, low = 4, info = 5}
    return (order[a.severity] or 9) < (order[b.severity] or 9)
  end)

  return info
end

local SEVERITY_ORDER = {critical = 1, high = 2, medium = 3, low = 4, info = 5}

--- Sorts findings in place, most severe first.
function sort_findings(findings)
  table.sort(findings, function(a, b)
    local sa = SEVERITY_ORDER[a.severity] or 9
    local sb = SEVERITY_ORDER[b.severity] or 9
    if sa ~= sb then return sa < sb end
    return (a.title or "") < (b.title or "")
  end)
  return findings
end

--- Evaluates a list of endpoints and returns security findings.
-- @param endpoints table array of EndpointDescription.
-- @return table array of {severity=, title=, detail=, endpoints={numbers}}
function assess_endpoints(endpoints)
  local findings = {}
  local by_key = {}

  local function add(severity, key, title, detail, index)
    local f = by_key[key]
    if not f then
      f = {severity = severity, title = title, detail = detail, endpoints = {}}
      by_key[key] = f
      findings[#findings + 1] = f
    end
    -- A server may offer the same token type several times on one endpoint
    -- (open62541 does), which must not list that endpoint twice.
    if index and f.endpoints[#f.endpoints] ~= index then
      f.endpoints[#f.endpoints + 1] = index
    end
  end

  local has_secure_endpoint = false
  local anonymous_on_unencrypted = false

  for i, ep in ipairs(endpoints) do
    local policy = policy_name(ep.security_policy_uri)
    local rating = policy_rating(ep.security_policy_uri)

    if ep.security_mode == "None" then
      add("high", "mode-none", "SecurityMode None",
        "Endpoint accepts unsigned, unencrypted communication; traffic can be read and modified in transit.", i)
    elseif ep.security_mode == "Sign" then
      add("low", "mode-sign", "SecurityMode Sign only",
        "Messages are authenticated but transmitted in the clear.", i)
    elseif ep.security_mode == "SignAndEncrypt" then
      if rating.rating == "acceptable" or rating.rating == "recommended" then
        has_secure_endpoint = true
      end
    end

    if policy == "None" then
      add("high", "policy-none", "SecurityPolicy None",
        "No cryptographic protection is applied on this endpoint.", i)
    elseif rating.rating == "deprecated" then
      add("medium", "policy-" .. policy, "Deprecated SecurityPolicy " .. policy,
        string.format("%s (%s). OPC UA 1.04 deprecated this policy; BSI advises against SHA-1.",
          policy, rating.note), i)
    end

    if ep.security_level == 0 then
      add("low", "level-zero", "SecurityLevel 0",
        "The server itself rates this endpoint as offering no security.", i)
    end

    for _, tok in ipairs(ep.user_identity_tokens or {}) do
      local tok_policy = tok.security_policy_uri and policy_name(tok.security_policy_uri)
                         or policy
      if tok.token_type == "Anonymous" then
        add("high", "anonymous", "Anonymous access allowed",
          "The endpoint accepts anonymous sessions, so no user authentication is enforced.", i)
        if ep.security_mode ~= "SignAndEncrypt" then
          anonymous_on_unencrypted = true
        end
      elseif tok.token_type == "UserName" then
        if tok_policy == "None" and ep.security_mode ~= "SignAndEncrypt" then
          add("critical", "cleartext-credentials", "Credentials sent in cleartext",
            string.format("UserName token with SecurityPolicy %s on a %s endpoint: passwords are transmitted unprotected.",
              tok_policy, ep.security_mode), i)
        end
      end
    end

    -- Announced protection versus the certificate that would carry it.
    if ep.security_mode ~= "None" and ep.server_certificate then
      local cert = analyze_certificate(ep.server_certificate,
                                       ep.server and ep.server.application_uri)
      if cert then
        ep.certificate = cert
        for _, iss in ipairs(cert.issues) do
          if iss.severity == "high" then
            add("medium", "cert-" .. iss.text, "Certificate weakness on a secured endpoint",
              string.format("%s, on an endpoint that advertises signing or encryption.",
                iss.text), i)
          end
        end
      end
    end
  end

  if #endpoints > 0 and not has_secure_endpoint then
    add("high", "no-secure-endpoint", "No securely configured endpoint",
      "The server offers no endpoint combining SignAndEncrypt with a current SecurityPolicy.")
  end

  if anonymous_on_unencrypted then
    add("high", "anonymous-unencrypted", "Anonymous access without encryption",
      "Anonymous sessions are accepted on an endpoint that does not encrypt traffic.")
  end

  return sort_findings(findings)
end

--- Decodes a ServerStatusDataType carried in an ExtensionObject.
-- @param ext table as returned by Reader:extensionobject().
-- @return table {start_time, current_time, state, build_info}, or nil.
function decode_server_status(ext)
  if not ext or not ext.body or ext.type_id.id ~= ID.ServerStatusDataType then
    return nil
  end
  local ok, status = pcall(function()
    local r = Reader:new(ext.body)
    local s = {}
    s.start_time = r:datetime()
    s.current_time = r:datetime()
    local state = r:u32()
    s.state_id = state
    s.state = SERVER_STATE[state] or tostring(state)
    s.build_info = {
      product_uri = r:str(),
      manufacturer_name = r:str(),
      product_name = r:str(),
      software_version = r:str(),
      build_number = r:str(),
      build_date = r:datetime(),
    }
    s.seconds_till_shutdown = r:u32()
    s.shutdown_reason = r:localizedtext()
    return s
  end)
  if not ok then return nil end
  return status
end

--- Decodes a ServerDiagnosticsSummaryDataType from an ExtensionObject.
-- Twelve counters, in the order given by OPC 10000-5. The session counters are
-- the interesting ones for an assessment: they say whether anyone else has
-- been here, and whether the server has been turning people away.
-- @param ext table as returned by Reader:extensionobject().
-- @return table of counters, or nil.
function decode_server_diagnostics(ext)
  if not ext or not ext.body or
     ext.type_id.id ~= ID.ServerDiagnosticsSummaryDataType then
    return nil
  end
  local ok, summary = pcall(function()
    local r = Reader:new(ext.body)
    return {
      server_view_count = r:u32(),
      current_session_count = r:u32(),
      cumulated_session_count = r:u32(),
      security_rejected_session_count = r:u32(),
      rejected_session_count = r:u32(),
      session_timeout_count = r:u32(),
      session_abort_count = r:u32(),
      publishing_interval_count = r:u32(),
      current_subscription_count = r:u32(),
      cumulated_subscription_count = r:u32(),
      security_rejected_requests_count = r:u32(),
      rejected_requests_count = r:u32(),
    }
  end)
  if not ok then return nil end
  return summary
end

--- Picks the endpoint best suited for an unencrypted session: SecurityMode
-- None, preferring one that accepts the requested token type.
-- @param endpoints table array of EndpointDescription.
-- @param token_type string "Anonymous" or "UserName".
-- @return table endpoint, table token policy, or nil.
function pick_session_endpoint(endpoints, token_type)
  token_type = token_type or "Anonymous"
  local fallback, fallback_token
  for _, ep in ipairs(endpoints or {}) do
    if ep.security_mode == "None" then
      for _, tok in ipairs(ep.user_identity_tokens or {}) do
        if tok.token_type == token_type then
          local policy = tok.security_policy_uri and policy_name(tok.security_policy_uri)
          -- A token policy of None means we can send the token as is.
          if not policy or policy == "None" or policy == "unknown" then
            return ep, tok
          end
          fallback, fallback_token = fallback or ep, fallback_token or tok
        end
      end
    end
  end
  return fallback, fallback_token
end

--- Renders an AccessLevel bit mask.
function access_level_string(mask)
  if not mask then return nil end
  local bits = {}
  if mask & 0x01 ~= 0 then bits[#bits + 1] = "read" end
  if mask & 0x02 ~= 0 then bits[#bits + 1] = "write" end
  if mask & 0x04 ~= 0 then bits[#bits + 1] = "history-read" end
  if mask & 0x08 ~= 0 then bits[#bits + 1] = "history-write" end
  if mask & 0x20 ~= 0 then bits[#bits + 1] = "status-write" end
  if mask & 0x40 ~= 0 then bits[#bits + 1] = "timestamp-write" end
  if #bits == 0 then return "none" end
  return table.concat(bits, "+")
end

--- Formats a NodeId the way OPC UA tools display it (ns=1;i=42).
function nodeid_string(node)
  if not node then return nil end
  -- Callers may pass a plain identifier for a namespace 0 numeric NodeId.
  if type(node) == "number" then
    return string.format("i=%d", node)
  end
  local prefix = (node.ns and node.ns ~= 0) and string.format("ns=%d;", node.ns) or ""
  if node.type == "numeric" then
    return string.format("%si=%s", prefix, tostring(node.id))
  elseif node.type == "string" then
    return string.format("%ss=%s", prefix, tostring(node.id))
  elseif node.type == "guid" then
    return string.format("%sg=%s", prefix, tostring(node.id))
  elseif node.type == "opaque" then
    return string.format("%sb=%s", prefix, stdnse.tohex(node.id or ""))
  end
  return prefix .. "?"
end

--- Extracts the host part of a discovery URL.
-- Handles opc.tcp, opc.https and opc.wss URLs with or without a port, and
-- bracketed IPv6 literals.
-- @param url string discovery URL.
-- @return string host, or nil if the URL cannot be parsed.
function discovery_url_host(url)
  if type(url) ~= "string" then return nil end
  local rest = url:match("^opc%.[%w]+://(.+)$") or url:match("^https?://(.+)$")
  if not rest then return nil end
  local bracketed = rest:match("^%[([^%]]+)%]")
  if bracketed then return bracketed end
  local host = rest:match("^([^:/]+)")
  if host == "" then return nil end
  return host
end

--- Formats an OPC UA timestamp for output.
function time_string(unix)
  if not unix then return nil end
  return os.date("!%Y-%m-%d %H:%M:%SZ", unix)
end

--- Convenience wrapper: connect, open a secure channel, fetch the endpoints.
-- @param host table nmap host table.
-- @param port table nmap port table.
-- @param options table optional {timeout=ms, endpoint_url=string}
-- @return table connection, table endpoints, string error
function discover(host, port, options)
  local conn = Connection:new(host, port, options)
  local status, err = conn:connect()
  if not status then
    return conn, nil, err
  end
  status, err = conn:open_secure_channel()
  if not status then
    return conn, nil, err
  end
  local endpoints, eerr = conn:get_endpoints(options and options.endpoint_url)
  if not endpoints then
    return conn, nil, eerr
  end
  return conn, endpoints, nil
end

-- ---------------------------------------------------------------------------
-- Unit tests
--
-- Run without a target:  nmap --script unittest --script-args unittest.run
-- The fixtures below are real bytes captured from an OPC UA server, so a
-- regression in the decoder fails here instead of in the field.
-- ---------------------------------------------------------------------------

local unittest = require "unittest"
if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

local function decode(fixture, method)
  local r = Reader:new(fixture)
  return r[method](r)
end

-- Primitives ---------------------------------------------------------------

test_suite:add_test(unittest.equal(
  decode("\x2a\x00\x00\x00", "u32"), 42), "u32 little endian")

test_suite:add_test(unittest.equal(
  decode("\x05\x00\x00\x00hallo", "str"), "hallo"), "String with length prefix")

test_suite:add_test(unittest.is_nil(
  decode("\xff\xff\xff\xff", "str")), "null String decodes to nil")

test_suite:add_test(unittest.equal(
  decode("\x00\x00\x00\x00", "str"), ""), "empty String is not null")

-- DateTime: 1601-01-01 plus 13 000 000 000 seconds is 2012-01-13 08:26:40 UTC.
test_suite:add_test(unittest.equal(
  decode(string.pack("<I8", 13000000000 * 10000000), "datetime"),
  13000000000 - 11644473600), "DateTime converts FILETIME ticks to Unix time")

test_suite:add_test(unittest.is_nil(
  decode(string.pack("<I8", 0), "datetime")), "null DateTime decodes to nil")

-- NodeId encodings ---------------------------------------------------------

local two_byte = decode("\x00\x55", "nodeid")
test_suite:add_test(unittest.equal(two_byte.id, 0x55), "TwoByte NodeId identifier")
test_suite:add_test(unittest.equal(two_byte.ns, 0), "TwoByte NodeId namespace")

local four_byte = decode("\x01\x00\xac\x01", "nodeid")
test_suite:add_test(unittest.equal(four_byte.id, 428), "FourByte NodeId identifier")

local numeric = decode("\x02\x02\x00\x39\x30\x00\x00", "nodeid")
test_suite:add_test(unittest.equal(numeric.id, 12345), "Numeric NodeId identifier")
test_suite:add_test(unittest.equal(numeric.ns, 2), "Numeric NodeId namespace")

local string_node = decode("\x03\x01\x00\x03\x00\x00\x00abc", "nodeid")
test_suite:add_test(unittest.equal(string_node.id, "abc"), "String NodeId identifier")
test_suite:add_test(unittest.equal(nodeid_string(string_node), "ns=1;s=abc"),
  "String NodeId renders as ns=1;s=abc")

test_suite:add_test(unittest.equal(nodeid_string(four_byte), "i=428"),
  "namespace 0 NodeId renders without prefix")

test_suite:add_test(unittest.equal(nodeid_string(85), "i=85"),
  "a plain number renders as a namespace 0 NodeId")

-- Round trip through the writer --------------------------------------------

local encoded = Writer:new():nodeid_numeric(2256):build()
test_suite:add_test(unittest.equal(decode(encoded, "nodeid").id, 2256),
  "NodeId survives a writer/reader round trip")

test_suite:add_test(unittest.equal(#Writer:new():nodeid_numeric(85):build(), 2),
  "small numeric NodeIds use the two byte encoding")

test_suite:add_test(unittest.equal(
  Reader:new(Writer:new():str(nil):build()):str(), nil),
  "null String survives a writer/reader round trip")

-- LocalizedText and QualifiedName ------------------------------------------

test_suite:add_test(unittest.equal(
  decode("\x02\x04\x00\x00\x00Name", "localizedtext"), "Name"),
  "LocalizedText with text only")

test_suite:add_test(unittest.equal(
  decode("\x03\x02\x00\x00\x00de\x04\x00\x00\x00Name", "localizedtext"), "Name"),
  "LocalizedText with locale and text")

test_suite:add_test(unittest.equal(
  decode("\x01\x00\x03\x00\x00\x00abc", "qualifiedname").name, "abc"),
  "QualifiedName")

-- Variants -----------------------------------------------------------------

test_suite:add_test(unittest.is_nil(decode("\x00", "variant")),
  "null Variant decodes to nil")

test_suite:add_test(unittest.equal(
  decode("\x06\x2a\x00\x00\x00", "variant"), 42), "Int32 Variant")

local array_variant = decode(
  "\x8c\x02\x00\x00\x00\x01\x00\x00\x00a\x01\x00\x00\x00b", "variant")
test_suite:add_test(unittest.equal(#array_variant, 2), "String array Variant length")
test_suite:add_test(unittest.equal(array_variant[2], "b"), "String array Variant content")

-- DataValue ----------------------------------------------------------------

local dv = decode("\x03\x06\x2a\x00\x00\x00\x00\x00\x00\x00", "datavalue")
test_suite:add_test(unittest.equal(dv.value, 42), "DataValue carries the value")
test_suite:add_test(unittest.equal(dv.status, 0), "DataValue carries the status code")

-- StatusCodes --------------------------------------------------------------

test_suite:add_test(unittest.is_true(is_good(0x00000000)), "Good is good")
test_suite:add_test(unittest.is_false(is_good(0x80340000)), "Bad_ is not good")
test_suite:add_test(unittest.equal(status_string(0x80830000),
  "Bad_TcpEndpointUrlInvalid (0x80830000)"), "StatusCode name lookup")
test_suite:add_test(unittest.equal(status_string(0x80250000),
  "Bad_SessionIdInvalid (0x80250000)"), "session status code, not a certificate one")
test_suite:add_test(unittest.equal(status_string(0x80830001),
  "Bad_TcpEndpointUrlInvalid (0x80830001)"), "StatusCode ignores the info bits")
test_suite:add_test(unittest.equal(status_string(0x00000000), "Good (0x00000000)"),
  "Good has a name too")

-- Policy rating ------------------------------------------------------------

test_suite:add_test(unittest.equal(
  policy_name("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"),
  "Basic256Sha256"), "policy_name strips the URI prefix")

test_suite:add_test(unittest.equal(
  policy_rating(SECURITY_POLICY_NONE).rating, "insecure"), "None is rated insecure")

test_suite:add_test(unittest.equal(
  policy_rating(SECURITY_POLICY_BASE .. "Basic128Rsa15").rating, "deprecated"),
  "Basic128Rsa15 is rated deprecated")

test_suite:add_test(unittest.equal(
  policy_rating(SECURITY_POLICY_BASE .. "Aes256_Sha256_RsaPss").rating,
  "recommended"), "Aes256_Sha256_RsaPss is rated recommended")

-- Access levels ------------------------------------------------------------

test_suite:add_test(unittest.equal(access_level_string(0x03), "read+write"),
  "AccessLevel read and write")
test_suite:add_test(unittest.equal(access_level_string(0x01), "read"),
  "AccessLevel read only")
test_suite:add_test(unittest.equal(access_level_string(0x00), "none"),
  "AccessLevel none")

-- Endpoint assessment ------------------------------------------------------

local insecure_endpoint = {
  endpoint_url = "opc.tcp://192.0.2.1:4840/",
  security_mode = "None",
  security_policy_uri = SECURITY_POLICY_NONE,
  security_level = 0,
  user_identity_tokens = {
    {token_type = "Anonymous", security_policy_uri = SECURITY_POLICY_NONE},
    {token_type = "UserName", security_policy_uri = SECURITY_POLICY_NONE},
  },
}

local findings = assess_endpoints({insecure_endpoint})
local titles = {}
for _, f in ipairs(findings) do titles[f.title] = f.severity end

test_suite:add_test(unittest.equal(titles["SecurityMode None"], "high"),
  "SecurityMode None is a high finding")
test_suite:add_test(unittest.equal(titles["Credentials sent in cleartext"], "critical"),
  "UserName over policy None is critical")
test_suite:add_test(unittest.equal(titles["Anonymous access allowed"], "high"),
  "anonymous access is a high finding")
test_suite:add_test(unittest.equal(findings[1].severity, "critical"),
  "findings are sorted most severe first")

local secure_endpoint = {
  endpoint_url = "opc.tcp://192.0.2.1:4840/",
  security_mode = "SignAndEncrypt",
  security_policy_uri = SECURITY_POLICY_BASE .. "Aes256_Sha256_RsaPss",
  security_level = 80,
  user_identity_tokens = {
    {token_type = "UserName",
     security_policy_uri = SECURITY_POLICY_BASE .. "Aes256_Sha256_RsaPss"},
  },
}

test_suite:add_test(unittest.equal(#assess_endpoints({secure_endpoint}), 0),
  "a properly configured endpoint produces no findings")

-- Hostile input -----------------------------------------------------------
-- A peer can answer with anything; these lengths must be rejected rather than
-- believed or silently turned into an empty result.

local function decodes(fixture, method, ...)
  local r = Reader:new(fixture)
  return pcall(r[method], r, ...)
end

test_suite:add_test(unittest.is_false(
  (decodes("\xfa\xff\xff\xff", "array", "str"))),
  "an array length of -6 is rejected, not treated as null")

test_suite:add_test(unittest.is_nil(
  select(2, decodes("\xff\xff\xff\xff", "array", "str"))),
  "an array length of -1 is the null marker")

test_suite:add_test(unittest.is_false(
  (decodes("\xfe\xff\xff\xff", "str"))),
  "a string length of -2 is rejected")

test_suite:add_test(unittest.is_false(
  (decodes("\x10\x00\x00\x00", "array", "str", 4))),
  "an array longer than the caller's limit is rejected")

test_suite:add_test(unittest.is_false(
  (decodes("\xff\xff\xff\x7f", "str"))),
  "a string claiming 2 GB is rejected against the available data")

-- Discovery URL parsing ----------------------------------------------------

test_suite:add_test(unittest.equal(
  discovery_url_host("opc.tcp://192.0.2.10:4840/UA/Server"), "192.0.2.10"),
  "discovery URL with address, port and path")

test_suite:add_test(unittest.equal(
  discovery_url_host("opc.tcp://plc-01:4840"), "plc-01"),
  "discovery URL with a host name")

test_suite:add_test(unittest.equal(
  discovery_url_host("opc.tcp://[2001:db8::1]:4840/"), "2001:db8::1"),
  "discovery URL with a bracketed IPv6 literal")

test_suite:add_test(unittest.equal(
  discovery_url_host("opc.tcp://gateway.example.com/discovery"),
  "gateway.example.com"), "discovery URL without a port")

test_suite:add_test(unittest.equal(
  discovery_url_host("opc.https://192.0.2.11:443/"), "192.0.2.11"),
  "opc.https discovery URL")

test_suite:add_test(unittest.is_nil(discovery_url_host("not a url")),
  "unparsable discovery URL yields nil")

-- Session endpoint selection -----------------------------------------------

local chosen = pick_session_endpoint({secure_endpoint, insecure_endpoint}, "Anonymous")
test_suite:add_test(unittest.equal(chosen, insecure_endpoint),
  "session endpoint selection prefers SecurityMode None")

return _ENV
