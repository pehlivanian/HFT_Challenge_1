#ifndef __SESSION_HPP__
#define __SESSION_HPP__
 
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

namespace {
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
      os << "UNKNOWN STATE";
      break;
    }
    return os;
  }

  std::ostream& operator<<(std::ostream& os, EVENTS e) {
    switch (e) {
    case (EVENTS::L):
      os << "LOGIN_REQUEST";
      break;
    case (EVENTS::E):
      os << "LOGIN_RESPONSE";
      break;
    case (EVENTS::O):
      os << "LOGOUT_REQUEST";
      break;
    case (EVENTS::G):
      os << "LOGOUT_RESPONSE";
      break;
    case (EVENTS::S):
      os << "SUBMISSION_REQUEST";
      break;
    case (EVENTS::R):
      os << "SUBMISSION_RESPONSE";
      break;
    default:
      os << "UNKNOWN EVENT";
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

} // namespace

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

    auto login = create_login();

    send_(login);

    set_state_and_transition(STATES::LOGIN_SENT, EVENTS::E);

  };

  void login_acked(STATES, EVENTS) {

    assert_current_state(STATES::LOGIN_SENT);

    login_response lr;
    receive_(lr);

    set_state_and_transition(STATES::LOGIN_ACKED, EVENTS::E);
    
  }

  void send_submission(STATES, EVENTS) {
    
    assert_current_state(STATES::LOGIN_ACKED);

    auto submission = create_submission();
    
    send_(submission);

    set_state_and_transition(STATES::SUBMISSION_SENT, EVENTS::S);

  };

  void submission_acked(STATES, EVENTS) {
    
    assert_current_state(STATES::SUBMISSION_SENT);

    submission_response sr;
    receive_(sr);

    token_ = std::string(sr.Token);

    set_state_and_transition(STATES::SUBMISSION_ACKED, EVENTS::O);
  
  }

  void send_logout(STATES, EVENTS) {
    
    assert_current_state(STATES::SUBMISSION_ACKED);

    logout_request logout = create_logout();

    send_(logout);

    set_state_and_transition(STATES::LOGOUT_SENT, EVENTS::O);
    
  };

  void logout_acked(STATES, EVENTS) {
    
    assert_current_state(STATES::LOGOUT_SENT);

    logout_response lr;
    receive_(lr);

    set_state_and_transition(STATES::LOGGED_OUT, EVENTS::G);

  }

  void end(STATES, EVENTS) { 
    assert_current_state(STATES::LOGGED_OUT);

    std::cout << "Session complete.\nYour token is: " << token_ << std::endl;
  }; 

  void transition_(EVENTS e) override {
    auto s = get_current_state();
    auto state = static_cast<std::underlying_type_t<STATES>>(s);
    auto event = static_cast<std::underlying_type_t<EVENTS>>(e);
    (*this.*M[state][event])(s, e);
  }

private:

  std::string hostname_;
  int port_;
  std::string IP_addr_;
  int sockfd_;
  std::string token_;

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
      // There is probably a better way to do this; 
      // reverse lookup by IP does not work so we just 
      // filter out gateways
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

  void err(STATES s, EVENTS e) {
    std::stringstream r;
    r << "Error: received event [";
    r << e; r << "] while in state [";
    r << s; r << "]";
    throw std::runtime_error(r.str());
  };

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
    { { sl, er, er, er, er, er },    // 0 ~ START
      { er, la, la, la, la, la },    // 1 ~ LOGIN_SENT
      { er, ss, so, er, er, er },    // 2 ~ LOGIN_ACKED
      { er, er, er, er, sa, sa },    // 3 ~ SUBMISSION_SENT
      { er, er, so, er, so, so },    // 4 ~ SUBMISSION_ACKED
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

  header create_header(char msgtype, uint16_t msglen) {
    header header_;
    header_.MsgType = msgtype;
    header_.MsgLen = msglen;
    header_.ChkSum = 0;
    header_.Timestamp = get_timestamp();

    return header_;
  }

  template<typename M>
  int send_(const M& m) {

    constexpr std::size_t msg_size = sizeof(m);
    char msg[msg_size];
    memset(msg, '\0', msg_size);
    memcpy(msg, &m, msg_size);
    int result = send(sockfd_, msg, msg_size, 0);
    
    return result;

  }

  template<typename M>
  int receive_(M& m) {
    
    constexpr std::size_t msg_size = sizeof(m);
    char response[msg_size];
    memset(response, '\0', msg_size);
    int result = read(sockfd_, response, msg_size);
    
    memcpy(&m, response, msg_size);
    
    return result;
    
  }

  template<typename M>
  void add_checksum(M& m) {
    uint16_t checksum = checksum16((uint8_t *)&m, sizeof(m));
    m.Header.ChkSum = checksum;
  }

  login_request create_login() {

    header header_ = create_header('L', 109);
    login_request login_;

    char User[64], Password[32];
    strcpy(User, "pehlivaniancharles@gmail.com");
    strcpy(Password, "pwd123");

    login_.Header = header_;
    bzero(login_.User, sizeof(login_.User));
    bzero(login_.Password, sizeof(login_.Password));
    strcpy(login_.User, User);
    strcpy(login_.Password, Password);

    add_checksum(login_);

    return login_;
  }
  
  submission_request create_submission() {

    header header_ = create_header('S', 205);
    submission_request submission_;

    char Name[64], Email[64], Repo[64];
    strcpy(Name, "Aphelia Nirvana");
    strcpy(Email, "nyc417.protonmail.com");
    strcpy(Repo, "https://github.com/Nowhere");
    
    submission_.Header = header_;
    bzero(submission_.Name, sizeof(submission_.Name));
    bzero(submission_.Email, sizeof(submission_.Email));
    bzero(submission_.Repo, sizeof(submission_.Repo));
    strcpy(submission_.Name, Name);
    strcpy(submission_.Email, Email);
    strcpy(submission_.Repo, Repo);

    add_checksum(submission_);

    return submission_;
    
  }

  logout_request create_logout() {
  
    header header_ = create_header('O', 46);
    logout_request logout_;
    
    logout_.Header = header_;
    
    add_checksum(logout_);
  
    return logout_;

  }

};

#endif
