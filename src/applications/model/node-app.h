#ifndef NODE_APP_H
#define NODE_APP_H

#include <algorithm>
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "ns3/boolean.h"
// #include "sha-256.h"
#include <map>
#include <list>
namespace ns3 {
typedef struct
{
    uint32_t contents_length;
    uint8_t contents_hash[32];
    uint8_t previous_hash[32];

    /* when this block started being mined */
    uint64_t timestamp; 

    /* This is adjusted to make the hash of this header fall in the valid range. */
    uint32_t nonce;
    uint32_t block_number;


    
} block_header_t;
class Address;
class Socket;
class Packet;

class NodeApp : public Application
{
  public:
    static TypeId GetTypeId (void);

    NodeApp (void);

    virtual ~NodeApp (void);

    uint32_t        m_id;                               // node id
    Ptr<Socket>     m_socket;                           // Listening socket
    std::map<Ipv4Address, Ptr<Socket>>      m_peersSockets;            // Socket list of neighbor nodes
    std::map<Address, std::string>          m_bufferedData;            // map holding the buffered data from previous handleRead events
    Address         m_local;                            // Address of this node
    std::vector<Ipv4Address>  m_peersAddresses;         // Neighbor list

    int             N;                                  // Total number of nodes
    int             is_leader;                          // Are you a leader?

    virtual void StartApplication (void);
    virtual void StopApplication (void); 
    block_header_t build_block(const block_header_t* previous, const char* contents, uint64_t length);
    void mine_block(block_header_t* header, const uint8_t* target);
    std::string blockToString(const block_header_t &block);
    // block_header_t stringToBlock(const std::string &str);
    void HandleRead (Ptr<Socket> socket);
    void fprint_hash(FILE* f, uint8_t* hash);
    void fprint_hash_for_log(uint8_t* hash);
    void hexStringToByteArray(const std::string& hex, uint8_t* result, size_t length);
    block_header_t stringToBlock(const std::string& str);
    bool check_validation(block_header_t* header, const uint8_t* target);
    std::string getPacketContent(Ptr<Packet> packet, Address from); 

    void SendTX(uint8_t data[], int num);
   
    void sendMessage(void);
  private:
    std::list<block_header_t> ledger; 
    uint8_t target[32];
};
}
#endif