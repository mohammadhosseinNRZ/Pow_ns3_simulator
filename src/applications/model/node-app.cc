#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "node-app.h"
#include "stdlib.h"
#include "ns3/ipv4.h"
#include <map>
#include "sha-256.h"
#include <iomanip>
#include <openssl/sha.h>

// #include "sha-256.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("NodeApp");

NS_OBJECT_ENSURE_REGISTERED (NodeApp);


TypeId NodeApp::GetTypeId (void)
{
    static TypeId tid = TypeId ("ns3::NodeApp")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<NodeApp> ()
    ;

    return tid;
}

NodeApp::NodeApp(void) {

}

NodeApp::~NodeApp(void) {
    NS_LOG_FUNCTION (this);
}

float getRandomDelay() {
  return (rand() % 3) * 1.0 / 1000;
}

void NodeApp::StartApplication () {

    
    // Initialize socket
    if (!m_socket)
    {
        TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
        m_socket = Socket::CreateSocket (GetNode (), tid);

        // Note: This is equivalent to monitoring all network card IP addresses.
        InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 7071);
        m_socket->Bind (local);           // Bind the local IP and port
        m_socket->Listen ();
    }
    m_socket->SetRecvCallback (MakeCallback (&NodeApp::HandleRead, this));
    m_socket->SetAllowBroadcast (true);

    std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();
    // Establish connections to all nodes
    NS_LOG_INFO("node"<< m_id << " start");
    while(iter != m_peersAddresses.end()) {
        TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
        Ptr<Socket> socketClient = Socket::CreateSocket (GetNode (), tid);
        socketClient->Connect (InetSocketAddress(*iter, 7071));
        m_peersSockets[*iter] = socketClient;
        iter++;
    }

    // if (is_leader == 1) {
        Simulator::Schedule (Seconds(getRandomDelay()), &NodeApp::sendMessage, this);
    // }

}

void NodeApp::sendMessage(void) {
      // Create a sample message
    memset(target, 0, sizeof(target));
    /* too hard?: try target[2] = 0xFF
       too easy?: try target[2] = 0x01 */
    target[2] = 0x0F;
    std::string myString = "Hello Blockchain"  + std::to_string(GetNode ()->GetId ());
    std::vector<uint8_t> myVector(myString.begin(), myString.end());
    uint8_t *data = &myVector[0];

    // Get the last block in the ledger (if available)
     block_header_t* previousBlock = nullptr;
    if (!ledger.empty()) {
        previousBlock = &ledger.back();
    }

    // Build a new block using the last block in the ledger as the previous block
    block_header_t newBlock = build_block(previousBlock, reinterpret_cast<const char*>(data), myString.size());
    newBlock.block_number = static_cast<uint32_t>(ledger.size());;
    mine_block(&newBlock, target);
    // Add the new block to the ledger
    ledger.push_back(newBlock);
    std::string blocString = blockToString(newBlock);

    NS_LOG_INFO("Node " << GetNode ()->GetId () <<  "blocToString :" << blocString);
    std::vector<uint8_t> myVector2(blocString.begin(), blocString.end());
    uint8_t *data2 = &myVector2[0];
    // const uint8_t* dataArray = reinterpret_cast<const uint8_t*>(blocString.c_str());
    // int dataSize = blocString.size();
    // Print information about the new block (you can modify this part)
    // NS_LOG_INFO( "Node " << GetNode ()->GetId () <<  "New Block Mined:");
    // NS_LOG_INFO("Node " << GetNode ()->GetId () << "  Contents Length: " << newBlock.contents_length);
    // NS_LOG_INFO("Node " << GetNode ()->GetId () << "  Previous Hash: " );
    // fprint_hash_for_log(newBlock.previous_hash);
    // // fprint_hash(stdout, newBlock.previous_hash);
    NS_LOG_INFO("Node " << GetNode ()->GetId () << "  Contents Hash: " );
    // fprint_hash_for_log(newBlock.contents_hash);
    // // fprint_hash(stdout, newBlock.contents_hash);
    // NS_LOG_INFO("Node " << GetNode ()->GetId () << "  Timestamp: " << newBlock.timestamp);
    // NS_LOG_INFO("Node " << GetNode ()->GetId () << "  Nonce: " << newBlock.nonce);

    // Now you can proceed to send the transaction to neighbors
    // NS_LOG_INFO("size of blocScreen"<<sizeof(blocString) );
    NodeApp::SendTX(data2, sizeof(blocString)*8);
  // std::string myString = "Hello Blockchain";
  // std::vector<uint8_t> myVector(myString.begin(), myString.end());
  // uint8_t *data = &myVector[0];
  // NodeApp::SendTX(data, sizeof(myString));
}

std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::string hashStr;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashStr += hash[i];
    }
    return hashStr;
}
void NodeApp::fprint_hash_for_log(uint8_t* hash)
{
    std::ostringstream hashStream;
    hashStream << "0x";
    for (int i = 0; i < 32; ++i)
        hashStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);

    NS_LOG_INFO(hashStream.str());    

}
block_header_t NodeApp::build_block(const block_header_t* previous, const char* contents, uint64_t length)
{
    block_header_t header;
    header.contents_length = length;

    if (previous)
    {
        /* calculate previous block header hash */
        calc_sha_256(header.previous_hash, previous, sizeof(block_header_t));
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
void NodeApp::mine_block(block_header_t* header, const uint8_t* target)
{
    while (1)
    {
        /* MINING: start of the mining round */
        header->timestamp = (uint64_t)time(NULL); 

       uint8_t block_hash[32];

for (uint32_t i = 0; i < UINT32_MAX; ++i)
{
    header->nonce = i;
    calc_sha_256(block_hash, header, sizeof(block_header_t));

    if (memcmp(block_hash, target, sizeof(block_hash)) < 0){

    NS_LOG_INFO("checked hash:");
    fprint_hash_for_log(block_hash);
    NS_LOG_INFO(blockToString(*header));
   
    // block_header_t newBloc = stringToBlock(blockToString(*header));
    block_header_t* newBloc= new block_header_t;
    newBloc->block_number = header->block_number;
    memcpy(newBloc->contents_hash, header->contents_hash, sizeof(header->contents_hash));
    memcpy(newBloc->previous_hash, header->previous_hash, sizeof(header->previous_hash));
    newBloc->contents_length = header->contents_length;
    newBloc->nonce = header->nonce;
    newBloc->timestamp = header->timestamp;
    NS_LOG_INFO(blockToString(*newBloc));
    NS_LOG_INFO(check_validiation(newBloc,target));


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
bool NodeApp::check_validiation(block_header_t* header, const uint8_t* target){
uint8_t block_hash[32];
calc_sha_256(block_hash, header, sizeof(block_header_t));
    NS_LOG_INFO("checked hash2:");
    fprint_hash_for_log(block_hash);
if (memcmp(block_hash, target, sizeof(block_hash)) < 0){
    return true;
}
else {
    return false;
}
}
void NodeApp::fprint_hash(FILE* f, uint8_t* hash)
{
    fprintf(f, "0x");
    for (int i = 0; i < 32; ++i)
        fprintf(f, "%02x", hash[i]);
}
std::string NodeApp::blockToString(const block_header_t &block)
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
std::vector<std::string> splitString(const std::string& input, const std::string& delimiter) {
    std::vector<std::string> parts;
    size_t pos = 0;
    size_t found;

    while ((found = input.find(delimiter, pos)) != std::string::npos) {
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

void NodeApp::hexStringToByteArray(const std::string& hex, uint8_t* result, size_t length) {
    std::istringstream ss(hex);
    std::string byte;

    for (size_t i = 0; i < length; ++i) {
        std::getline(ss, byte, ':');
        // NS_LOG_INFO("byte"<<byte);
        result[i] = static_cast<uint8_t>(std::stoi(byte, nullptr, 16));
    }
}
block_header_t NodeApp::stringToBlock(const std::string& str) {
    block_header_t block;

    // Split the string by @@
    std::vector<std::string> parts = splitString(str, "@@");
    // for (size_t i = 0; i < parts.size(); i++)

    // {NS_LOG_INFO("Node " << GetNode ()->GetId () << " bloc added: " << parts[i]);

    //     /* code */
    // }
    
    // Check if the string is properly formatted
    if (parts.size() != 6) {
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
    // Check block number
//     if (block.block_number < 0) {
//         throw std::invalid_argument("Invalid block number");
//     }
// //    NS_LOG_INFO("got here");
//     // Check block timestamp
//     if (block.timestamp < 0) {
//         throw std::invalid_argument("Invalid block timestamp");
//     }

//     // Check block nonce
//     if (block.nonce < 0) {
//         throw std::invalid_argument("Invalid block nonce");
//     }

//     // // Check block contents_length
//     if (block.contents_length > 0 && parts.size() - 6 != block.contents_length) {
//         throw std::invalid_argument("Length of contents does not match length from string");
//     }

    // // Check block contents hash
    // if (block.contents_length > 0) {
    //     std::string contents = parts[6];
    //     // for (int i = 0; i < block.contents_length; ++i) {
    //     //     if (parts[6 + i] != contents[i]) {
    //     //         throw std::invalid_argument("contents hash does not match contents from string");
    //     //     }
    //     // }
    // }
    return block;
}
void NodeApp::StopApplication ()
{
  if (is_leader == 1) {
    NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << " Stop");
  }
}

void NodeApp::HandleRead (Ptr<Socket> socket)
{ 
    Ptr<Packet> packet;
    Address from;
    Address localAddress;

    while ((packet = socket->RecvFrom (from)))
    {
        socket->SendTo(packet, 0, from);
        if (packet->GetSize () == 0)
        {
            break;
        }
        if (InetSocketAddress::IsMatchingType (from))
        {
            std::string msg = getPacketContent(packet, from);
            
// NS_LOG_INFO(packet->GetSize ());
            // NS_LOG_INFO("Node " << GetNode ()->GetId () << " Received Message:" << msg);
            block_header_t newBloc = stringToBlock(msg);
        // NS_LOG_INFO("Node " << GetNode ()->GetId () <<  "blocToString     :" << blockToString(newBloc));

            if(check_validiation(&newBloc, target)){

            ledger.push_back(newBloc);

NS_LOG_INFO("Node " << GetNode ()->GetId () << " bloc added2: " );
            }else{
NS_LOG_INFO("Node " << GetNode ()->GetId () << "wrong sha" );



            }

        }
        socket->GetSockName (localAddress);
    }
}

std::string NodeApp::getPacketContent(Ptr<Packet> packet, Address from)
{ 
    char *packetInfo = new char[packet->GetSize () + 1];
    std::ostringstream totalStream;
    packet->CopyData (reinterpret_cast<uint8_t*>(packetInfo), packet->GetSize ());
    packetInfo[packet->GetSize ()] = '\0';
    totalStream << m_bufferedData[from] << packetInfo; 
    std::string totalReceivedData(totalStream.str());
    return totalReceivedData;
}  

void SendPacket(Ptr<Socket> socketClient,Ptr<Packet> p) {
    socketClient->Send(p);
}

void NodeApp::SendTX (uint8_t data[], int size) {
  NS_LOG_INFO("broadcast message at time: " << Simulator::Now ().GetSeconds () << " s");

  Ptr<Packet> p;

  p = Create<Packet> (data, size);

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");


  std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();

  while(iter != m_peersAddresses.end()) {
    TypeId tId = TypeId::LookupByName ("ns3::UdpSocketFactory");

    Ptr<Socket> socketClient = m_peersSockets[*iter];
    double delay = getRandomDelay();

    Simulator::Schedule(Seconds(delay), SendPacket, socketClient, p);
    iter++;
  }
}
}