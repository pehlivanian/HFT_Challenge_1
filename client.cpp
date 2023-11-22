#include "client.hpp"

auto main() -> int {
  
  auto S = new Session{"challenge1.vitorian.com", 9009};
  
  S->start();

  return 0;
}
