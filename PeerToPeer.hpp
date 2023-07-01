#pragma once
#include <Utility/CppUtility.hpp>
#include <Utility/Socket.hpp>
#include <span>

enum class PTPCommandType : uint16_t
{
	// All Responses to Query Commands end with '\r\n'
	// Returns a string containing version
	// Example CMD0_
	CmdQueryVersion = 0,
	// Returns a list of all members, example: 127.0.0.1,152.24.23.22
	// Example CMD1_
	CmdQueryMembers,
	// Example command CMD2_152.24.23.22,n.n.n.n the following bytes are considered to be the payload
	CmdSendToMembers,
	// Response Codes are any code higher than 0x7FA6
	ResponseCodeBoundary = 0x7FA6,
	ResponseToQuery,
	ResponseMailbox,
	ResponseMalformedCommand,
	Unknown = 0xFFFF
};

enum class PTParseCode : uint16_t {
	Success = 0,
	SuccessHttp = 1,
	InvalidPrefix = 2,
	UnknownPrefix = 3,
	InvalidCommandId = 4,
	SendToMemberMalformed = 5,
	MalformedIPAddress = 6,
	NotParsed = 7,
	GeneralFailure = 255
};

class PTPCommunicationBuilder
{
public:
	PTPCommunicationBuilder() = default;
	PTPCommunicationBuilder(PTPCommandType type) : Type(type) {}
	PTPCommunicationBuilder(std::vector<int8_t>& stream) : PTPCommunicationBuilder(std::span(stream)) {}
	PTPCommunicationBuilder(const std::span<int8_t>& stream)
	{

		const int streamSize = int(stream.size_bytes());
		if (streamSize <= 3) {
			m_ParseCode = PTParseCode::InvalidPrefix;
			return;
		}

		auto extractCommandType = [&](int start) -> int {
			int maxLength = std::min(start + 6, streamSize);
			int j;
			for (j = start; j <= maxLength; j++) {
				if (j == maxLength) {
					m_ParseCode = PTParseCode::InvalidCommandId;
					return -1;
				}
				if (stream[j] == '_') {
					break;
				}
			}
			std::span<const int8_t> commandTypeAsString(stream.begin() + start, stream.begin() + j);
			size_t cmdTypeU64;
			if (!cpp::TryToInt64((char*)commandTypeAsString.data(), cmdTypeU64)) {
				m_ParseCode = PTParseCode::InvalidCommandId;
				return -1;
			}
			Type = PTPCommandType(cmdTypeU64);
			return j;
		};

		auto extractAddressList = [&](int streamOffset) -> bool {
			constexpr int maxAddressLen = 16;
			char address[maxAddressLen]{};
			int length = 0;
			int k;

			for (k = streamOffset + 1; k < streamSize; k++)
			{
				if (length > maxAddressLen) {
					// malformed address
					return false;
				}
				if ((stream[k] >= '0' && stream[k] <= '9') || stream[k] == '.') {
					address[length++] = stream[k];
					continue;
				}
				if (stream[k] == ',' || stream[k] == '_') {
					uint32_t addr32 = sw::ParseIPv4Address(address);
					if (addr32 == 0) {
						// malformed address
						return false;
					}
					m_AddressList.push_back(addr32);
					if (stream[k] == '_') {
						k++;
						break;
					}
					memset(address, 0, sizeof(address));
					length = 0;
					continue;
				}
				// malformed address
				return false;
			}

			// Extract Content
			m_Content = std::span(stream.begin() + k, stream.end());
			m_ParseCode = PTParseCode::Success;
			return true;
		};

		if (
			strncmp((char*)stream.data(), "CMD", 3) == 0 ||
			strncmp((char*)stream.data(), "RES", 3) == 0) {

			// 1) Extract PTPCommandType
			int streamOffset = extractCommandType(3);
			if (streamOffset == -1) {
				m_ParseCode = PTParseCode::InvalidCommandId;
				return;
			}

			if (Type == PTPCommandType::CmdSendToMembers) {

				if (streamSize <= streamOffset) {
					Type = PTPCommandType::ResponseMalformedCommand;
					m_ParseCode = PTParseCode::SendToMemberMalformed;
					return;
				}

				// Extract IP Address List
				if (!extractAddressList(streamOffset)) {
					m_ParseCode = PTParseCode::MalformedIPAddress;
					return;
				}

			}

			m_ParseCode = PTParseCode::Success;
		}
		else if (strncmp((char*)stream.data(), "GET", 3) == 0)
		{
			m_ParseCode = PTParseCode::SuccessHttp;
		}
		else {
			m_ParseCode = PTParseCode::UnknownPrefix;
		}
	}

	void AddAddress(uint32_t address)
	{
		m_AddressList.push_back(address);
	}

	void AddAddress(const sw::Socket& socket)
	{
		if (socket.GetEndpoint().IPv4 == 0) {
			throw std::runtime_error("Socket contains invalid IPv4 address");
		}
		m_AddressList.push_back(socket.GetEndpoint().IPv4);
	}

	void AddAddress(std::string_view address)
	{
		uint32_t adder32 = sw::ParseIPv4Address(address.data());
		if (adder32 == 0) {
			throw std::runtime_error("Invalid Address");
		}
	}

	void SetContent(const std::span<int8_t>& content, bool copyContent)
	{
		if (copyContent) {
			m_ContentOwnership.resize(content.size());
			memcpy(m_ContentOwnership.data(), content.data(), content.size_bytes());
			m_Content = m_ContentOwnership;
		}
		else {
			m_Content = content;
		}
	}

	std::vector<int8_t> GenerateStream() const {
		bool isCmd = Type < PTPCommandType::ResponseCodeBoundary;

		std::vector<int8_t> stream;
		constexpr uint32_t maxAddressLength = 16;
		// CMD65535_255.255.255.255,...,127.0.0.1_Content...
		uint32_t streamSize = 9u + ((uint32_t)m_AddressList.size() * maxAddressLength) + 1u + uint32_t(m_Content.size_bytes());
		stream.resize(streamSize);

		uint32_t offset = 0;

		if (isCmd)
			memcpy(stream.data(), "CMD", 3);
		else
			memcpy(stream.data(), "RES", 3);

		offset += 3;

		auto type = std::to_string(uint16_t(Type));
		memcpy(stream.data() + offset, type.data(), type.size());
		offset += uint32_t(type.size());

		memcpy(stream.data() + offset, "_", 1);
		offset += 1;

		for (int i = 0; i < m_AddressList.size(); i++) {
			auto adder32 = m_AddressList[i];
			auto address = sw::IPv4AddressAsString(adder32);
			memcpy(stream.data() + offset, address.data(), address.size());
			offset += (uint32_t)address.size();
			char delimeter = (i != m_AddressList.size() - 1) ? ',' : '_';
			memcpy(stream.data() + offset, &delimeter, 1);
			offset += 1;
		}

		if (m_Content.size() > 0) {
			memcpy(stream.data() + offset, m_Content.data(), m_Content.size_bytes());
			offset += uint32_t(m_Content.size_bytes());
		}

		if (Type == PTPCommandType::ResponseToQuery) {
			stream.resize(offset + 2);
			stream[stream.size() - 2] = '\r';
			stream[stream.size() - 1] = '\n';
		}
		else {
			stream.resize(offset);
		}

		return stream;
	}


public:
	PTPCommandType Type = PTPCommandType::Unknown;

public:
	inline PTParseCode GetParseCode() const { return m_ParseCode; }
	inline const std::vector<uint32_t>& GetAddressList() const { return m_AddressList; }
	inline std::span<int8_t> GetContent() const { return m_Content; }

private:
	std::vector<uint32_t> m_AddressList;
	std::span<int8_t> m_Content;
	std::vector<int8_t> m_ContentOwnership;
	PTParseCode m_ParseCode = PTParseCode::NotParsed;
};
