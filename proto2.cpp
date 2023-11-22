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
#include <string>
#include <chrono>
#include <regex>
#include <utility>
#include <iterator>
#include <algorithm>

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

typedef struct __attribute__((packed)) {

  char MsgType;			// 1
  uint16_t MsgLen;		// 2
  unsigned long Timestamp;	// 8
  uint16_t ChkSum;		// 2 = 13

} header;

typedef struct __attribute__((packed)) {

  header Header{};	// 13
  char User[64];	// 64
  char Password[32];	// 32 = 109
  
} login;

typedef struct __attribute__((packed)) {
  header Header{};
  char Reason[32];
} login_response;

typedef struct __attribute__((packed)) {
  header Header{};		//  13
  char Token[32];		// +32 = 45
} submission_response;

login create_login() {

  login msg;

  msg.Header.MsgType = 'L';
  msg.Header.MsgLen = 109;
  
  auto now = std::chrono::system_clock::now();
  unsigned long UTC = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
  msg.Header.Timestamp = UTC;
  
  memset(msg.User, '0', sizeof(msg.User));
  memset(msg.Password, '0', sizeof(msg.Password));
  strcpy(msg.User, "pehlivaniancharles@gmail.com");
  strcpy(msg.Password, "pwd123");

  // char msg_flat[109];
  // memset(msg_flat, '0', sizeof(msg_flat));
  // memcpy(msg_flat, &msg, sizeof(msg_flat));

  msg.Header.ChkSum = checksum16((uint8_t *)&msg, 109);

  return msg;
}

void test_checksum() {
  char MsgType = 'G';
  uint16_t MsgLen = 45;
  uint16_t ChkSum = 0;
  unsigned long Timestamp = 1700098600041879169;
  char Reason[32];
  strcpy(Reason, "Checksum 10147 got 12195");

  header header_;
  login_response login_response_;

  header_.MsgType = MsgType;
  header_.MsgLen = MsgLen;
  header_.ChkSum = ChkSum;
  header_.Timestamp = Timestamp;

  login_response_.Header = header_;
  memset(login_response_.Reason, '\0', sizeof(login_response_.Reason));
  strcpy(login_response_.Reason, Reason);

  uint16_t checksum_s1 = checksum16((uint8_t *)&login_response_, sizeof(login_response_));

  uint16_t checksum_d = 16904;

  std::cout << "s1: " << checksum_s1 << std::endl;
  std::cout << "d: " << checksum_d << std::endl;

  login login_;
  header header2_;
  char User[64], Password[32];
  strcpy(User, "pehlivaniancharles@gmail.com");
  strcpy(Password, "pwd123");
  
  header2_.MsgType = 'L';
  header2_.MsgLen = 109;
  header2_.ChkSum = 0;
  header2_.Timestamp = 1700100175523627550;
  
  login_.Header = header2_;
  memset(login_.User, '\0', sizeof(login_.User));
  memset(login_.Password, '\0', sizeof(login_.Password));
  strcpy(login_.User, User);
  strcpy(login_.Password, Password);

  uint16_t checksum_s2 = checksum16((uint8_t *)&login_, sizeof(login_));
  uint16_t checksum_d1 = 41118;
  
  std::cout << "s2: " << checksum_s2 << std::endl;
  std::cout << "d1: " << checksum_d1 << std::endl;

  submission_response submission_response_;
  header header3_;
  char Token[32];
  strcpy(Token, "YUser logged in");

  header_3.MsgType = 'E';
  header_3.MsgLen = 45;
  

	 
  
}

auto main(int argc, char **argv) -> int {

  auto cl = create_login();
  test_checksum();
  
  return 0;
}
