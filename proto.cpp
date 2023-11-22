#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include <iostream>
#include <memory>
#include <chrono>
#include <string>
#include <array>
#include <vector>
#include <regex>
#include <utility>
#include <iterator>
#include <algorithm>
#include <cassert>

uint16_t checksum16(const uint8_t* buf, uint32_t len) {
  uint32_t sum = 0;
  for (uint32_t j=0; j<len-1; j+=2) {
    sum += *((uint16_t*)(&buf[j]));
  }
  if ((len & 1) != 0) {
    sum += buf[len-1];
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum = (sum >> 16) + (sum & 0xFFFF);
  return uint16_t(~sum);
}

enum class STATES {
  START = 0,
    LOGIN_SENT = 1,
    LOGIN_ACKED = 2,
    SUBMISSION_SENT = 3,
    SUBMISSION_ACKED = 4,
    LOGOUT_SENT = 5,
    LOGGED_OUT = 6,
    END = 7,
    NUMSTATES
    };
enum class EVENTS {
  L = 0,
    E = 1,
    O = 2,
    G = 3,
    S = 4,
    R = 5,
    NUMEVENTS
    };

std::ostream& operator<<(std::ostream& os, STATES s) {
  os << "CURRENT STATE: ";
  switch (s) {
  case (STATES::START):
    os << "START";
    break;
  case (STATES::LOGIN_SENT):
    os << "LOGIN_SENT";
    break;
  case (STATES::LOGIN_ACKED):
    os << "LOGIN_ACKED";
    break;
  case (STATES::SUBMISSION_SENT):
    os << "SUBMISSION_SENT";
    break;
  case (STATES::SUBMISSION_ACKED):
    os << "SUBMISSION_ACKED";
    break;
  case (STATES::LOGOUT_SENT):
    os << "LOGOUT_SENT";
    break;
  case (STATES::LOGGED_OUT):
    os << "LOGGED_OUT";
    break;
  case (STATES::END):
    os << "END";
    break;
  default:
    break;
  }
  return os;
}

typedef struct __attribute__((packed)) {
  char MsgType;			//  1
  uint16_t MsgLen;		// +2
  unsigned long Timestamp;	// +8
  uint16_t ChkSum;		// +2 = 13
} header;

typedef struct __attribute__((packed)) {
  header Header{};		//  13
  char User[64];		// +64
  char Password[32];		// +32 = 109
} login_request;

typedef struct __attribute__((packed)) {
  header Header{};		//  13
  char Code;			//  +1
  char Reason[32];		// +32 = 46
} login_response;

typedef struct __attribute__((packed)) {
  header Header{};		//  13
  char Name[64];		// +64
  char Email[64];		// +64
  char Repo[64];		// +64 = 205
} submission_request;

typedef struct __attribute__((packed)) {
  header Header{};		//  13
  char Token[32];		// +32 = 45
} submission_response;

typedef struct __attribute__((packed)) {
  header Header{};		// 13 = 13
} logout_request;

typedef struct __attribute__((packed)) {
  header Header{};		//  13
  char Reason[32];		// +32 = 45
} logout_response;

template<typename T>
class FSM {
public:
  
  // Virtual base class for CRTP state machine

  FSM() : current_state_{STATES::START} {}
  virtual ~FSM() = default;
  
  void transition(EVENTS ev) {
    static_cast<T*>(this)->transition_(ev);
  }

  STATES get_current_state() const { return current_state_; }
  void set_current_state(STATES s) { current_state_ = s; }
  void assert_current_state(STATES s) const { assert(current_state_ == s); }

  void set_state_and_transition(STATES s, EVENTS e) {
    set_current_state(s);
    transition(e);
  }

private:
  STATES current_state_;

  virtual void transition_(EVENTS) = 0;

};

class Session : public FSM<Session> {
public:
  Session(char* hostname, int port) : hostname_{hostname}, port_{port} { init(); }

  void send_login(STATES, EVENTS) {
    assert_current_state(STATES::START);

    std::cout << "LOGGING IN\n";

    auto login = create_login();

    char msg_flat[109];
    memset(msg_flat, '\0', sizeof(msg_flat));
    memcpy(msg_flat, &login, sizeof(msg_flat));
    send(sockfd_, msg_flat, sizeof(msg_flat), 0);
    std::cout << "Sent login...\n";
    
    set_state_and_transition(STATES::LOGIN_SENT, EVENTS::E);

  };

  void login_acked(STATES, EVENTS) {

    assert_current_state(STATES::LOGIN_SENT);

    char response[46];
    memset(response, '\0', sizeof(response));
    int result = read(sockfd_, response, 46);

    printf("\nresponse in hex: %x\n", response);
    
    login_response lr;
    memcpy(&lr, response, sizeof(lr));

    std::cout << "Code: " << lr.Code << std::endl;
    printf("Reason: %x\n", *(lr.Reason));    

    set_state_and_transition(STATES::LOGIN_ACKED, EVENTS::E);
    
  }

  void send_submission(STATES, EVENTS) {
    
    assert_current_state(STATES::LOGIN_ACKED);

    auto submission = create_submission();
    
    char msg_flat[205];
    memset(msg_flat, '\0', sizeof(msg_flat));
    memcpy(msg_flat, &submission, sizeof(msg_flat));
    send(sockfd_, msg_flat, sizeof(msg_flat), 0);
    std::cout << "Sent submission...\n";

    set_state_and_transition(STATES::SUBMISSION_SENT, EVENTS::S);

  };

  void submission_acked(STATES, EVENTS) {
    
    std::cout << "SUBMISSION_ACKED\n";

    assert_current_state(STATES::SUBMISSION_SENT);

    char response[45];
    memset(response, '\0', sizeof(response));
    int result = read(sockfd_, response, 45);

    submission_response sr;
    memcpy(&sr, response, sizeof(sr));

    std::cout << "token: " << sr.Token << std::endl;

    set_state_and_transition(STATES::SUBMISSION_ACKED, EVENTS::O);
  
  }

  void send_logout(STATES, EVENTS) {
    
    assert_current_state(STATES::SUBMISSION_ACKED);

    logout_request logout = create_logout();

    char msg_flat[13];
    memset(msg_flat, '\0', sizeof(msg_flat));
    memcpy(msg_flat, &logout, sizeof(msg_flat));
    send(sockfd_, msg_flat, sizeof(msg_flat), 0);
    std::cout << "Sent logout...\n";

    set_state_and_transition(STATES::LOGOUT_SENT, EVENTS::O);
    
  };

  void logout_acked(STATES, EVENTS) {
    
    assert_current_state(STATES::LOGOUT_SENT);

    char response[45];
    memset(response, '\0', sizeof(response));
    int result = read(sockfd_, response, 45);

    logout_response lr;
    memcpy(&lr, response, sizeof(lr));

    std::cout << "Logout reason: " << lr.Reason << std::endl;

    set_state_and_transition(STATES::LOGGED_OUT, EVENTS::G);


  }

  void end(STATES, EVENTS) { std::cout << "THIS IS ONLY THE END...\n"; }; 

  void transition_(EVENTS e) override {
    auto state = static_cast<std::underlying_type_t<STATES>>(get_current_state());
    auto event = static_cast<std::underlying_type_t<EVENTS>>(e);
    (*this.*M[state][event])(get_current_state(), e);
  }

private:

  std::string hostname_;
  int port_;
  std::string IP_addr_;
  int sockfd_;

  int init() {

    host_lookup(hostname_.c_str());
  
    int n=0;
    struct sockaddr_in serv_addr;
    
    if((sockfd_ = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      {
	printf("\n Error : Could not create socket \n");
	return 1;
      } 
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port_);
    
    std::cerr << IP_addr_.c_str() << std::endl;
    std::cerr << port_ << std::endl;

    if(inet_pton(AF_INET, IP_addr_.c_str(), &serv_addr.sin_addr)<=0)
      {
	printf("\n inet_pton error occured\n");
	return 1;
      } 
    
    if( connect(sockfd_, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
      {
	printf("\n Error : Connect Failed \n");
	return 1;
      } 
    
    printf("\nSuccessful handshake...\n");

    set_state_and_transition(STATES::START, EVENTS::L);

    return 0;

  }

  int host_lookup(const char* hostname) {
    struct addrinfo hints, *res, *result;
    int errcode;
    char addrstr[100];
    void *ptr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo(hostname, NULL, &hints, &result);
    if (errcode != 0) {
      perror("getaddrinfo");
      return -1;
    }

    res = result;

    while (res) {
      inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);
      switch (res->ai_family) 
	{
	case AF_INET:
	  ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	  inet_ntop(res->ai_family, ptr, addrstr, 100);
	  break;
	case AF_INET6:
	  break;
      }

      char* token = strtok(addrstr, ".");
      if (strcmp(token, "192") && strcmp(token, "127")) {
	inet_ntop(res->ai_family, ptr, addrstr, 100);
	IP_addr_ = std::string(addrstr);
      }

      res = res->ai_next;
    }

    freeaddrinfo(result);

    return 0;
    
  }

  unsigned long get_timestamp() {
    auto now = std::chrono::system_clock::now();
    unsigned long UTC = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    return UTC;
  }

  void err(STATES, EVENTS) {};

  typedef void (Session::*memfn)(STATES, EVENTS);

#define sl &Session::send_login
#define la &Session::login_acked
#define ss &Session::send_submission
#define sa &Session::submission_acked
#define so &Session::send_logout
#define oa &Session::logout_acked
#define ee &Session::end
#define er &Session::err
 
  std::vector<std::vector<memfn>> M =
    // EVENTS					
    // ======
    // L ~ LOGIN REQUEST
    // E ~ LOGIN RESPONSE
    // O ~ LOGOUT REQUEST
    // G ~ LOGOUT RESPONSE
    // S ~ SUBMISSION REQUEST
    // R ~ SUBMISSION RESPONSE
				     // STATES
    //   L   E   O   G   S   R       // ======
    { { sl, er, sl, sl, sl, sl },    // 0 ~ START
      { er, la, la, la, la, la },    // 1 ~ LOGIN_SENT
      { er, ss, ss, ss, ss, ss },    // 2 ~ LOGIN_ACKED
      { er, er, sa, sa, sa, sa },    // 3 ~ SUBMISSION_SENT
      { er, er, so, so, so, so },    // 4 ~ SUBMISSION_ACKED
      { er, er, oa, oa, oa, oa },    // 5 ~ LOGOUT_SENT
      { er, er, ee, ee, ee, ee },    // 6 ~ LOGGED_OUT
      { er, er, er, er, er, er } };  // 7 ~ END

#undef sl
#undef la
#undef ss
#undef sa
#undef so
#undef oa
#undef ee
#undef er


  login_request create_login() {

    header header_;
    login_request login_;

    char User[64], Password[32];
    strcpy(User, "pehlivaniancharles@gmail.com");
    strcpy(Password, "pwd123");

    header_.MsgType = 'L';
    header_.MsgLen = 109;  
    header_.ChkSum = 0;
    header_.Timestamp = get_timestamp();
  
    login_.Header = header_;
    memset(login_.User, '\0', sizeof(login_.User));
    memset(login_.Password, '\0', sizeof(login_.Password));
    strcpy(login_.User, User);
    strcpy(login_.Password, Password);

    uint16_t checksum = checksum16((uint8_t *)&login_, sizeof(login_));  
    login_.Header.ChkSum = checksum;

    return login_;
  }
  
  submission_request create_submission() {

    header header_;
    submission_request submission_;

    char Name[64], Email[64], Repo[64];
    strcpy(Name, "Aphelia Nirvana");
    strcpy(Email, "nyc417.protonmail.com");
    strcpy(Repo, "https://github.com/Nowhere");
    
    header_.MsgType = 'S';
    header_.MsgLen = 205;
    header_.ChkSum = 0;
    header_.Timestamp = get_timestamp();

    submission_.Header = header_;
    memset(submission_.Name, '\0', sizeof(submission_.Name));
    memset(submission_.Email, '\0', sizeof(submission_.Email));
    memset(submission_.Repo, '\0', sizeof(submission_.Repo));
    strcpy(submission_.Name, Name);
    strcpy(submission_.Email, Email);
    strcpy(submission_.Repo, Repo);

    uint16_t checksum = checksum16((uint8_t *)&submission_, sizeof(submission_));
    submission_.Header.ChkSum = checksum;

    return submission_;
    
  }

  logout_request create_logout() {
    logout_request msg;
  
    msg.Header.MsgType = 'O';
    msg.Header.MsgLen = 46;

    msg.Header.Timestamp = get_timestamp();

    msg.Header.ChkSum = 0;
    msg.Header.ChkSum = checksum16((uint8_t *)&msg, 109);
  
    return msg;

  }

};

auto main(int argc, char **argv) -> int{

  auto S = new Session{"challenge1.vitorian.com", 9009};

  return 0;
}
