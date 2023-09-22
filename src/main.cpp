#include <string>
#include <iostream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define DNS_PORT 53

// https://www.rfc-editor.org/rfc/rfc1035#section-4
struct Message {
    // Header start
    uint16_t ID;
    uint16_t parameters;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
    // Question
    char QNAME[18];
    uint16_t QCLASS;
    uint16_t QTYPE;
    // Answer
    uint16_t NAME;
    uint16_t TYPE;
    uint16_t CLASS;
    uint32_t TTL;
    uint16_t RDLENGTH;
    uint16_t RDATA[2];

};

std::ostream& operator<<(std::ostream& out, const Message& msg) {
    out << "Message: "
        << msg.ID << ", "
        << msg.QNAME
        << std::endl;
    return out;
}


std::string ip_itoa(uint ip) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    return inet_ntoa(ip_addr);
}

std::string getIpv4ByHostname(const char* domain) {
    struct hostent *host;
    if ((host=gethostbyname(domain)) == nullptr) {
        std::cerr << 
            "\nInvalid address/ Address not supported \n";
        return "";
    }
    return inet_ntoa(*(struct in_addr*)host->h_addr_list[0]);
}

void transform_domain_to_labels(std::string& domain) {
    size_t found = domain.find_last_of('.');
    size_t index = domain.length();
    while (found != std::string::npos) {
        domain[found]=index-found-1;
        index=found;
        found=domain.find_last_of('.', found-1);
    }
    domain.insert(domain.begin(), index);
    domain.push_back('\0');
}

int main(void) {
    srand(time(NULL));
    
    // transform domain to label form 
    std::string domain = "myip.opendns.com";
    transform_domain_to_labels(domain);

    Message message {
        .ID=htons(0x8088),
        .parameters=htons(0b0000000100000000),
        .QDCOUNT=htons(1),
        .ANCOUNT=0,
        .NSCOUNT=0,
        .ARCOUNT=0,
        .QCLASS=htons(1),
        .QTYPE=htons(1)
    };
    memcpy(message.QNAME, domain.data(), domain.size());

    // create socket
    int client_fd;
    if ((client_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        std::cerr << "FAIL: create socket" << std::endl;
        exit(EXIT_FAILURE);
    }
    
    // connect 
    auto resolver = "resolver2.opendns.com";
    auto ip = getIpv4ByHostname(resolver);

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(DNS_PORT);
    inet_aton(ip.data(), &serv_addr.sin_addr); 

    if ((connect(client_fd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr))) < 0) {
        std::cerr << "FAIL: could not connect" << std::endl;
    } else {
        // Connected? (not really as it's udp)
        auto sent = sendto(client_fd,
               &message,
               sizeof(struct Message),
               0,
               (struct sockaddr*) &serv_addr,
               sizeof(struct sockaddr));
        
        uint addrlen = sizeof(struct sockaddr);
        int received = -1;
        Message answer{0};
        received = recvfrom(client_fd,
                 &answer,
                 sizeof(struct Message),
                 0,
                 (struct sockaddr*) &serv_addr,
                 &addrlen);
        if (received == -1) {
            std::cerr << strerror(errno) << std::endl;
        }

#ifdef DEBUG
        std::cout << "Received " << received << " bytes, out of " << sizeof(struct Message) << std::endl;
        std::cout << answer << std::endl;
#endif
        uint32_t data = htons(answer.RDATA[0]) << 16;
        data = data | htons(answer.RDATA[1]);

        std::cout << ip_itoa(ntohl(data)) << std::endl;
    }

    // close
    close(client_fd);

    return EXIT_SUCCESS;
}
