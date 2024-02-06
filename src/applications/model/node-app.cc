#include "node-app.h"

#include "sha-256.h"
#include "stdlib.h"

#include "ns3/address-utils.h"
#include "ns3/address.h"
#include "ns3/double.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/ipv4.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/socket.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-socket.h"
#include "ns3/uinteger.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <openssl/sha.h>

// #include "sha-256.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("NodeApp");

NS_OBJECT_ENSURE_REGISTERED(NodeApp);

TypeId
NodeApp::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::NodeApp")
                            .SetParent<Application>()
                            .SetGroupName("Applications")
                            .AddConstructor<NodeApp>();

    return tid;
}

NodeApp::NodeApp(void)
{
}

NodeApp::~NodeApp(void)
{
    NS_LOG_FUNCTION(this);
}

float
getRandomDelay()
{
    return (rand() % 3) * 1.0 / 1000;
}

void
NodeApp::StartApplication()
{
    // Initialize socket
    if (!m_socket)
    {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        m_socket = Socket::CreateSocket(GetNode(), tid);

        // Note: This is equivalent to monitoring all network card IP addresses.
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 7071);
        m_socket->Bind(local); // Bind the local IP and port
        m_socket->Listen();
    }
    m_socket->SetRecvCallback(MakeCallback(&NodeApp::HandleRead, this));
    m_socket->SetAllowBroadcast(true);

    std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();
    // Establish connections to all nodes
    NS_LOG_INFO("node" << m_id << " start");
    while (iter != m_peersAddresses.end())
    {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> socketClient = Socket::CreateSocket(GetNode(), tid);
        socketClient->Connect(InetSocketAddress(*iter, 7071));
        m_peersSockets[*iter] = socketClient;
        iter++;
    }

    if (is_leader == 1)
    // if(1)
    {
        Simulator::Schedule(Seconds(getRandomDelay()), &NodeApp::sendMessage, this);
    }
}

void
NodeApp::sendMessage(void)
{
    // Create a sample message
    memset(target, 0, sizeof(target));
    /* too hard?: try target[2] = 0xFF
       too easy?: try target[2] = 0x01 */
    target[2] = 0;
    std::string myString = "Hello Blockchain" + std::to_string(GetNode()->GetId());
    std::vector<uint8_t> myVector(myString.begin(), myString.end());
    uint8_t* data = &myVector[0];

    // Get the last block in the ledger (if available)
    block_header_t* previousBlock = nullptr;
    if (!ledger.empty())
    {
        previousBlock = &ledger.back();
    }

    // Build a new block using the last block in the ledger as the previous block
    block_header_t newBlock =
        build_block(previousBlock, reinterpret_cast<const char*>(data), myString.size());

    newBlock.block_number = static_cast<uint32_t>(ledger.size());
    ;

    mine_block(&newBlock, target);

    // Add the new block to the ledger
    ledger.push_back(newBlock);
    std::string blocString = blockToString(newBlock);

    // NS_LOG_INFO("Node " << GetNode ()->GetId () <<  "blocToString :" << blocString);
    std::vector<uint8_t> myVector2(blocString.begin(), blocString.end());
    uint8_t* data2 = &myVector2[0];

    // NS_LOG_INFO("Node " << GetNode ()->GetId () << "  Contents Hash: " );

    NodeApp::SendTX(data2, sizeof(blocString) * 8);
}

void
NodeApp::fprint_hash_for_log(uint8_t* hash)
{
    std::ostringstream hashStream;
    hashStream << "0x";
    for (int i = 0; i < 32; ++i)
        hashStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);

    NS_LOG_INFO(hashStream.str());
}

block_header_t
NodeApp::build_block(const block_header_t* previous, const char* contents, uint64_t length)
{
    block_header_t header;
    header.contents_length = length;

    if (previous)
    {
        /* calculate previous block header hash */
        calc_sha_256(header.previous_hash,
                     blockToString(*previous).data(),
                     blockToString(*previous).length());
        // calc_sha_256(header.previous_hash, previous, sizeof(block_header_t));
    }
    else
    {
        /* genesis has no previous. just use zeroed hash */
        memset(header.previous_hash, 0, sizeof(header.previous_hash));
    }

    /* add data hash */
    calc_sha_256(header.contents_hash, contents, length);
    return header;
}

bool
hasZeroByte(const uint8_t* array, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        if (array[i] == 0x00)
        {
            return true; // Found a zero byte
        }
    }
    return false; // No zero byte found
}

void
NodeApp::mine_block(block_header_t* header, const uint8_t* target)
{
    while (1)
    {
        /* MINING: start of the mining round */
        header->timestamp = (uint64_t)time(NULL);

        uint8_t block_hash[32];

        for (uint32_t i = 0; i < UINT32_MAX; ++i)
        {
            header->nonce = i;
            calc_sha_256(block_hash,
                         blockToString(*header).data(),
                         blockToString(*header).length());

            if (hasZeroByte(block_hash, sizeof(block_hash)))
            {
                NS_LOG_INFO("\n");
                NS_LOG_INFO("*******************Node " << GetNode()->GetId()
                                                       << " Block Mined************ ");
                NS_LOG_INFO(blockToString(*header));
                NS_LOG_INFO(blockToString(*header).length());
                fprint_hash_for_log(block_hash);
                NS_LOG_INFO(header->nonce);
                NS_LOG_INFO("\n");
                return;
            }
            /* we found a good hash */
        }

        /* The uint32 expired without finding a valid hash.
           Restart the time, and hope that this time + nonce combo works. */
    }

    /* this should never happen */
    // assert(0);
}

bool
NodeApp::check_validation(block_header_t* header, const uint8_t* target)
{
    uint8_t block_hash[32];
    calc_sha_256(block_hash, blockToString(*header).data(), blockToString(*header).length());

    NS_LOG_INFO("\n");
    NS_LOG_INFO("*******************Node " << GetNode()->GetId()
                                           << " CHECK BLOCK VALIDATION ************ ");
    NS_LOG_INFO(blockToString(*header));
    NS_LOG_INFO(header->nonce);
    fprint_hash_for_log(block_hash);
    NS_LOG_INFO("\n");
    if (hasZeroByte(block_hash, sizeof(block_hash)))
    {
        return true;
    }
    else
    {
        return false;
    }
}

std::string
NodeApp::blockToString(const block_header_t& block)
{
    std::ostringstream oss;
    oss << block.contents_length << "@@" << std::hex;
    for (int i = 0; i < 32; ++i)
    {
        oss << static_cast<int>(block.contents_hash[i]);
        if (i < 31)
            oss << ":";
    }
    oss << "@@";
    for (int i = 0; i < 32; ++i)
    {
        oss << static_cast<int>(block.previous_hash[i]);
        if (i < 31)
            oss << ":";
    }
    // for (int i = 0; i < 32; ++i) {
    // oss << static_cast<int>(block.contents_hash[i]);
    // }
    // oss << "@@";
    // // Previous hash
    // for (int i = 0; i < 32; ++i) {
    //     oss<< static_cast<int>(block.previous_hash[i]);
    // }
    oss << "@@" << block.timestamp << "@@" << block.nonce << "@@" << block.block_number;
    return oss.str();
}

std::vector<std::string>
splitString(const std::string& input, const std::string& delimiter)
{
    std::vector<std::string> parts;
    size_t pos = 0;
    size_t found;

    while ((found = input.find(delimiter, pos)) != std::string::npos)
    {
        parts.push_back(input.substr(pos, found - pos));
        pos = found + delimiter.length();
    }

    parts.push_back(input.substr(pos));
    return parts;
}

// void NodeApp::hexStringToByteArray(const std::string& hex, uint8_t* result, size_t length) {
//     for (size_t i = 0; i < length; i++) {
//         std::string byteString = hex.substr(2 * i, 2);
//         result[i] = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
//     }
// }

void
NodeApp::hexStringToByteArray(const std::string& hex, uint8_t* result, size_t length)
{
    std::istringstream ss(hex);
    std::string byte;

    for (size_t i = 0; i < length; ++i)
    {
        std::getline(ss, byte, ':');
        // NS_LOG_INFO("byte"<<byte);
        result[i] = static_cast<uint8_t>(std::stoi(byte, nullptr, 16));
    }
}

block_header_t
NodeApp::stringToBlock(const std::string& str)
{
    block_header_t block;

    // Split the string by @@
    std::vector<std::string> parts = splitString(str, "@@");
    // for (size_t i = 0; i < parts.size(); i++)

    // {NS_LOG_INFO("Node " << GetNode ()->GetId () << " bloc added: " << parts[i]);

    //     /* code */
    // }

    // Check if the string is properly formatted
    if (parts.size() != 6)
    {
        throw std::invalid_argument("Invalid block format");
    }

    // Parse the contents_length
    block.contents_length = std::stoi(parts[0]);

    // Parse the contents_hash
    hexStringToByteArray(parts[1], block.contents_hash, 32);

    // Parse the previous_hash
    hexStringToByteArray(parts[2], block.previous_hash, 32);

    // Parse the timestamp
    block.timestamp = std::stoul(parts[3], nullptr, 16);
    // Parse the nonce
    block.nonce = std::stoul(parts[4], nullptr, 16);

    // Parse the block_number
    block.block_number = std::stoul(parts[5]);
    //  NS_LOG_INFO(blockToString(block));
 
    return block;
}

void
NodeApp::StopApplication()
{
    if (is_leader == 1)
    {
        NS_LOG_INFO("At time " << Simulator::Now().GetSeconds() << " Stop");
    }
}

bool
NodeApp::isEqual(const uint8_t arr1[32], const uint8_t arr2[32])
{
    for (int i = 0; i < 32; ++i)
    {
        if (arr1[i] != arr2[i])
        {
            return false;
        }
    }
    return true;
}

bool
NodeApp::isPrevious(const block_header_t& ledgerBlock, const block_header_t& newBloc)
{
    uint8_t prev_hash[32];
    calc_sha_256(prev_hash, blockToString(ledgerBlock).data(), blockToString(ledgerBlock).length());
    return isEqual(prev_hash, newBloc.previous_hash);
}

void
NodeApp::HandleRead(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address from;
    Address localAddress;

    while ((packet = socket->RecvFrom(from)))
    {
        socket->SendTo(packet, 0, from);
        if (packet->GetSize() == 0)
        {
            break;
        }
        if (InetSocketAddress::IsMatchingType(from))
        {
            std::string msg = getPacketContent(packet, from);

            block_header_t newBloc = stringToBlock(msg);
            uint8_t prev_hash[32];

            if (check_validation(&newBloc, target))
            {
                if (ledger.size() == 0)
                {
                    memset(prev_hash, 0, sizeof(prev_hash));

                    if (isEqual(prev_hash, newBloc.previous_hash))
                    {
                        ledger.push_back(newBloc);
                        NS_LOG_INFO("Node " << GetNode()->GetId() << " bloc added2: ");
                    }
                    else
                    {
                        NS_LOG_INFO("Node " << GetNode()->GetId() << " wrong Pervious Block hash ");
                    }
                }
                else
                {
                    if (isPrevious(ledger.back(), newBloc))
                    {
                        ledger.push_back(newBloc);
                        NS_LOG_INFO(
                            "Node "
                            << GetNode()->GetId()
                            << " bloc added2:  with proper Pervious Block hash in main ledger");
                    }
                    else
                    {
                        std::list<block_header_t> tempLedger;
                        int flag = 0;
                        // Iterate over each block in the ledger
                        for (const auto& block_header : ledger)
                        {
                            if (!flag)
                                tempLedger.push_back(block_header);
                            if (isPrevious(block_header, newBloc))
                            {
                                // std::list<block_header_t> new_list(
                                //     ledger.begin(),
                                //     std::find(ledger.begin(), ledger.end(), block_header));

                                // Add the new list to list_of_ledgers
                                list_of_ledgers.push_back(tempLedger);
                                flag = 1;
                                // Stop iterating over the current ledger
                                break;
                            }
                        }

                        if (!list_of_ledgers.empty())
                        {
                            for (auto& ledger2 : list_of_ledgers)
                            {
                                if (isPrevious(ledger2.back(), newBloc))
                                {
                                    ledger2.push_back(newBloc);
                                }
                            }
                        }
                        // Find the longest list in list_of_ledgers
                        auto longest_iter =
                            std::max_element(list_of_ledgers.begin(),
                                             list_of_ledgers.end(),
                                             [](const std::list<block_header_t>& lhs,
                                                const std::list<block_header_t>& rhs) {
                                                 return lhs.size() < rhs.size();
                                             });

                        // If the longest list is longer than ledger, swap its contents with
                        // ledger
                        if (longest_iter != list_of_ledgers.end() &&
                            longest_iter->size() > ledger.size())
                        {
                            ledger.clear(); // Clear the contents of ledger

                            // Copy elements from the longest list to ledger
                            for (const auto& elem : *longest_iter)
                            {
                                ledger.push_back(elem);
                            }

                            // Clear the longest list
                            longest_iter->clear();
                        }
                    }
                }
            }
            else
            {
                NS_LOG_INFO("Node " << GetNode()->GetId() << "wrong sha");
            }

            // else
            // {
            //     calc_sha_256(prev_hash,
            //                  blockToString(ledger.back()).data(),
            //                  blockToString(ledger.back()).length());
            // }

            // NS_LOG_INFO("Node " << GetNode()->GetId() << " bloc ledger lentgh: " <<
            // ledger.size());
        }
        socket->GetSockName(localAddress);
    }
}

std::string
NodeApp::getPacketContent(Ptr<Packet> packet, Address from)
{
    char* packetInfo = new char[packet->GetSize() + 1];
    std::ostringstream totalStream;
    packet->CopyData(reinterpret_cast<uint8_t*>(packetInfo), packet->GetSize());
    packetInfo[packet->GetSize()] = '\0';
    totalStream << m_bufferedData[from] << packetInfo;
    std::string totalReceivedData(totalStream.str());
    return totalReceivedData;
}

void
SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p)
{
    socketClient->Send(p);
}

void
NodeApp::SendTX(uint8_t data[], int size)
{
    NS_LOG_INFO("broadcast message at time: " << Simulator::Now().GetSeconds() << " s");

    Ptr<Packet> p;

    p = Create<Packet>(data, size);

    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");

    std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();

    while (iter != m_peersAddresses.end())
    {
        TypeId tId = TypeId::LookupByName("ns3::UdpSocketFactory");

        Ptr<Socket> socketClient = m_peersSockets[*iter];
        double delay = getRandomDelay();

        Simulator::Schedule(Seconds(delay), SendPacket, socketClient, p);
        iter++;
    }
}
} // namespace ns3