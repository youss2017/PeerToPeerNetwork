#pragma once
#include "PeerToPeer.hpp"
#include <ranges>

class ClientMessageRouter
{
public:
	ClientMessageRouter(int port = 80) {
		m_Router = sw::Socket(sw::SocketType::TCP);
		m_Router
			.Bind(sw::SocketInterface::Any, port)
			.Listen(100)
			.SetBlockingMode(false);
		m_RequestBuffer.resize(std::numeric_limits<uint16_t>::max());
	}

	void Run() {
		while (true) {
			auto client = m_Router.Accept();
			if (!client.IsValid()) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
				_ProcessClientQueue();
				continue;
			}

			client.SetBlockingMode(false);
			LOG(INFO, "{} connected.", client.GetEndpoint().ToString());
			m_Queue.emplace_back(std::move(client));
			_ProcessClientQueue();
		}
	}

private:
	void _ProcessClientQueue()
	{
		std::erase_if(m_Queue, [](const sw::Socket& client) -> bool {
			if (!client.IsConnected()) {
				LOG(INFO, "{} disconnected.", client.GetEndpoint().ToString());
				return true;
			}
			return false;
			});
		for (auto& client : m_Queue) {
			int32_t recvBytes = client.Recv(m_RequestBuffer.data(), int32_t(m_RequestBuffer.size()), false);
			if (recvBytes <= 0) continue;
			_RedirectClientIO(client, recvBytes);
		}
	}

	void _RedirectClientIO(sw::Socket& client, int32_t recvBytes)
	{
		auto command = PTPCommunicationBuilder({ m_RequestBuffer.begin(), m_RequestBuffer.begin() + recvBytes});
		if(command.GetParseCode() == PTParseCode::SuccessHttp) {
			client.Send(_GenerateReportHTML());
			return;
		}

		PTPCommunicationBuilder response;
		if(command.GetParseCode() == PTParseCode::Success) {
			auto type = command.Type;
			if (type == PTPCommandType::CmdQueryVersion) {
				response.Type = PTPCommandType::ResponseToQuery;
				response.SetContent({ (int8_t*)RouterVersion, strlen(RouterVersion) }, false);
			}
			else if (type == PTPCommandType::CmdQueryMembers) {
				response.Type = PTPCommandType::ResponseToQuery;
				for (auto& c : m_Queue) {
					response.AddAddress(c.GetEndpoint().IPv4);
				}
			}
			else if (type == PTPCommandType::CmdSendToMembers)
			{
				response.Type = PTPCommandType::ResponseMailbox;
				auto& addressList = command.GetAddressList();
				auto targets = m_Queue | std::views::filter([&](sw::Socket& c) -> bool {
					uint32_t ip = c.GetEndpoint().IPv4;
					return std::ranges::any_of(addressList, [ip](uint32_t adder32) { return adder32 == ip; });
				});
				response.AddAddress(client.GetEndpoint().IPv4);
				response.SetContent(command.GetContent(), false);
				auto stream = response.GenerateStream();
				for (auto& item : targets) {
					item.Send(stream.data(), int32_t(stream.size()));
				}
				return;
			}
			else {
				response = PTPCommunicationBuilder(PTPCommandType::Unknown);
				int8_t msg[] = "Unknown Command, cannot process.";
				response.SetContent(msg, true);
			}
		}
		else {
			response = PTPCommunicationBuilder(PTPCommandType::ResponseMalformedCommand);
			std::string msg = "Could not parse request, error code: ";
			switch (command.GetParseCode()) {
				case PTParseCode::InvalidPrefix: msg += "Invalid Prefix"; break;
				case PTParseCode::UnknownPrefix: msg += "Unknown Prefix"; break;
				case PTParseCode::InvalidCommandId: msg += "Invalid Command Id"; break;
				case PTParseCode::SendToMemberMalformed: msg += "SendToMember Malformed."; break;
				case PTParseCode::MalformedIPAddress: msg += "Malformed IP Address"; break;
				default:
					msg += "General Failure";
			}
			msg += "\r\n";
			response.SetContent(std::span((int8_t*)msg.data(), msg.size()), true);
		}
		
		auto stream = response.GenerateStream();
		client.Send(stream.data(), int32_t(stream.size()));
	}

	std::string _GenerateReportHTML() {
		uint64_t now = time(nullptr);
		std::string tableEntries;
		for (auto& client : m_Queue) {
			const auto& ep = client.GetEndpoint();
			time_t timestamp = client.ConnectedTimestamp();
			tm* timepoint = localtime(&timestamp);

			char date[256];
			strftime(date, sizeof(date), "%Y %B %d, %A %I:%M:%S %p %Z", timepoint);
			double timeConnected = (now - timestamp) / 60.0;
			tableEntries += cpp::Format("<tr><td>{}</td><td>{}</td><td>{}</td><td>{:%.3lf} min</td></tr>\n", ep.Address, ep.Port, date, timeConnected);
		}

		std::string document =
			cpp::Format(R"(
				<!DOCTYPE html>
				<html>
					<head>
						<title>Peer to Peer Router - {}</title>
						<link rel="preconnect" href="https://fonts.googleapis.com">
						<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
						<link href="https://fonts.googleapis.com/css2?family=Mukta:wght@300&display=swap" rel="stylesheet">
						<style>
							* {{ font-family: 'Mukta', sans-serif; }}
							table tbody td {{
								border: solid 0.2em #7EBC89;
								text-align: center;
								padding: 0.1em;
							}}
							table tbody tr:nth-child(odd) {{
								background-color: #FAEDCA;
							}}
							table tbody tr:nth-child(even) {{
								background-color: #F2C078;
							}}
							table thead th {{
								background-color: #7EBC89;
								padding: 0.5em;
							}}
							table tbody tr:hover {{
								background-color: #C1DBB3;
							}}
							body {{
								background-color: #476A6F;
							}}
						</style>
					</head>
					<body>
						<table style='margin: auto auto auto auto;'>
							<thead>
								<tr>
									<th>Client Address</th>
									<th>Client Port</th>
									<th>Client Time Stamp</th>
									<th>Time Connected</th>
								</tr>
							</thead>
							<tbody>
								{}
							</tbody>
						</table>
					</body>
				</html>
			)", m_Queue.size(), tableEntries);

		return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + std::to_string(document.size()) + "\r\n\r\n" + document;
	}

private:
	sw::Socket m_Router;
	std::vector<int8_t> m_RequestBuffer;
	std::vector<sw::Socket> m_Queue;
	static const char* RouterVersion;
};

const char* ClientMessageRouter::RouterVersion = "Peer To Peer Network 1.0.0.0\r\n";
