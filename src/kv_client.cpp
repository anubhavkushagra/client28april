#include "kv_client.h"

#include "discovery.grpc.pb.h"
#include "kv.grpc.pb.h"

#include <atomic>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace kv {

static constexpr int GCM_IV_LEN = 12;
static constexpr int GCM_TAG_LEN = 16;

static std::string ReadFile(const std::string &path) {
  if (path.empty())
    return "";
  std::ifstream t(path);
  if (!t.is_open())
    return "";
  return std::string((std::istreambuf_iterator<char>(t)),
                     std::istreambuf_iterator<char>());
}

static std::string aes_gcm_encrypt(const std::string &plaintext,
                                   const std::string &key) {
  if (key.length() != 32 || plaintext.empty())
    return plaintext;
  unsigned char iv[GCM_IV_LEN];
  RAND_bytes(iv, GCM_IV_LEN);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
  EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char *)key.data(), iv);
  std::vector<unsigned char> ciphertext(plaintext.length());
  int len;
  EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                    (const unsigned char *)plaintext.data(),
                    plaintext.length());
  int ciphertext_len = len;
  EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
  ciphertext_len += len;
  unsigned char tag[GCM_TAG_LEN];
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
  EVP_CIPHER_CTX_free(ctx);
  std::string result;
  result.reserve(GCM_IV_LEN + GCM_TAG_LEN + ciphertext_len);
  result.append((char *)iv, GCM_IV_LEN);
  result.append((char *)tag, GCM_TAG_LEN);
  result.append((char *)ciphertext.data(), ciphertext_len);
  std::vector<unsigned char> b64_out(((result.size() + 2) / 3) * 4 + 1);
  int b64_len = EVP_EncodeBlock(
      b64_out.data(), (const unsigned char *)result.data(), result.size());
  return std::string((char *)b64_out.data(), b64_len);
}

static std::string aes_gcm_decrypt(const std::string &b64_encrypted,
                                   const std::string &key) {
  if (key.length() != 32 || b64_encrypted.empty())
    return b64_encrypted;
  std::vector<unsigned char> raw_encrypted(b64_encrypted.size());
  int raw_len = EVP_DecodeBlock(raw_encrypted.data(),
                                (const unsigned char *)b64_encrypted.data(),
                                b64_encrypted.size());
  while (raw_len > 0 && b64_encrypted[b64_encrypted.size() - 1] == '=') {
    if (b64_encrypted.size() > 1 &&
        b64_encrypted[b64_encrypted.size() - 2] == '=')
      raw_len -= 2;
    else
      raw_len -= 1;
    break;
  }
  std::string encrypted((char *)raw_encrypted.data(), raw_len);
  if (encrypted.length() < (GCM_IV_LEN + GCM_TAG_LEN))
    return b64_encrypted;
  const unsigned char *iv = (const unsigned char *)encrypted.data();
  unsigned char tag[GCM_TAG_LEN];
  std::memcpy(tag, encrypted.data() + GCM_IV_LEN, GCM_TAG_LEN);
  const unsigned char *ciphertext =
      (const unsigned char *)encrypted.data() + GCM_IV_LEN + GCM_TAG_LEN;
  int ciphertext_len = encrypted.length() - GCM_IV_LEN - GCM_TAG_LEN;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
  EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char *)key.data(), iv);
  std::vector<unsigned char> plaintext(ciphertext_len);
  int len;
  EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len);
  int plaintext_len = len;
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);
  int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
  EVP_CIPHER_CTX_free(ctx);
  if (ret <= 0)
    return "ERROR_DECRYPTION_FAILED_OR_TAMPERED";
  plaintext_len += len;
  return std::string((char *)plaintext.data(), plaintext_len);
}

class KVClientImpl;

using StubList = const std::vector<std::shared_ptr<kv::KVService::Stub>>;

class PipelineImpl {
public:
  PipelineImpl(std::shared_ptr<StubList> stubs, std::string &jwt,
               std::shared_mutex &jwt_mu, const std::string &master_key,
               KVClientImpl *parent)
      : stubs_(stubs), jwt_ref_(jwt), jwt_mu_(jwt_mu), master_key_(master_key),
        parent_(parent) {}

  void add(kv::OpType type, const std::string &key,
           const std::string &value = "") {
    auto *req = batch_req_.add_requests();
    req->set_type(type);
    req->set_key(key);
    if (!value.empty()) {
      if (type == kv::PUT && !master_key_.empty()) {
        req->set_value(aes_gcm_encrypt(value, master_key_));
      } else {
        req->set_value(value);
      }
    }
  }

  std::vector<Result> execute();

private:
  std::shared_ptr<StubList> stubs_;
  std::string &jwt_ref_;
  std::shared_mutex &jwt_mu_;
  std::string master_key_;
  KVClientImpl *parent_;
  kv::BatchRequest batch_req_;
};

Pipeline::Pipeline(std::unique_ptr<PipelineImpl> impl)
    : pimpl_(std::move(impl)) {}
Pipeline::~Pipeline() = default;
Pipeline::Pipeline(Pipeline &&) noexcept = default;
Pipeline &Pipeline::operator=(Pipeline &&) noexcept = default;
void Pipeline::put(const std::string &key, const std::string &value) {
  pimpl_->add(kv::PUT, key, value);
}
void Pipeline::get(const std::string &key) { pimpl_->add(kv::GET, key); }
void Pipeline::del(const std::string &key) { pimpl_->add(kv::DELETE, key); }
std::vector<Result> Pipeline::execute() { return pimpl_->execute(); }

class KVClientImpl {
public:
  KVClientImpl(const ClientOptions &opts) : opts_(opts) {}

  bool connect() {
    std::string ca_cert = ReadFile(opts_.ca_cert_path);
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = ca_cert;
    if (!opts_.tls_cert_path.empty() && !opts_.tls_key_path.empty()) {
      ssl_opts.pem_cert_chain = ReadFile(opts_.tls_cert_path);
      ssl_opts.pem_private_key = ReadFile(opts_.tls_key_path);
    }
    auto channel_creds = ca_cert.empty() ? grpc::InsecureChannelCredentials()
                                         : grpc::SslCredentials(ssl_opts);
    grpc::ChannelArguments login_args;
    if (!ca_cert.empty())
      login_args.SetSslTargetNameOverride("kv-server");

    auto login_ch = grpc::CreateCustomChannel(
        "ipv4:" + opts_.server_ip + ":" + std::to_string(opts_.start_port),
        channel_creds, login_args);
    auto login_stub = kv::KVService::NewStub(login_ch);

    {
      std::unique_lock<std::shared_mutex> lock(jwt_mu_);
      if (!opts_.api_key.empty() && opts_.api_key.size() > 100)
        jwt_ = opts_.api_key;
    }

    {
      std::unique_lock<std::shared_mutex> lock(jwt_mu_);
      if (jwt_.empty()) {
        grpc::ClientContext ctx;
        kv::LoginRequest req;
        kv::LoginResponse resp;
        req.set_api_key(opts_.api_key);
        req.set_client_id("hybrid-client-v8");
        auto st = login_stub->Login(&ctx, req, &resp);
        if (!st.ok()) {
          std::cerr << "Login explicitly failed: " << st.error_message()
                    << std::endl;
          return false;
        }
        if (resp.jwt_token().empty()) {
          std::cerr << "Login returned empty JWT token." << std::endl;
          return false;
        }
        jwt_ = resp.jwt_token();
      }
    }

    if (!std::atomic_load(&stubs_)) {
      int retries = 0;
      while (!xds_loop_step() && retries++ < 30) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
      if (!std::atomic_load(&stubs_)) {
        std::cerr << "[CRITICAL] Discovery failed." << std::endl;
        return false;
      }
      xds_thread_ = std::thread([this]() {
        while (!stop_xds_) {
          xds_loop_step();
          for (int i = 0; i < 5 && !stop_xds_; i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
      });
    }
    return true;
  }

  std::string register_account(const std::string &client_id) {
    return ""; // Stubbed for brevity
  }

  Result execute_single(kv::OpType type, const std::string &key,
                        const std::string &value = "", bool is_retry = false) {
    static thread_local std::shared_ptr<StubList> local_cur_stubs;
    static thread_local int rcu_tick = 0;

    if (!local_cur_stubs || (rcu_tick++ % 500) == 0) {
      local_cur_stubs = std::atomic_load(&stubs_);
    }

    if (!local_cur_stubs || local_cur_stubs->empty())
      return {false, "NO_NODES_AVAILABLE"};

    int chan_idx = rr_channel_.fetch_add(1, std::memory_order_relaxed) %
                   local_cur_stubs->size();
    auto *stub = (*local_cur_stubs)[chan_idx].get();

    kv::SingleRequest req;
    req.set_type(type);
    req.set_key(key);
    if (!value.empty()) {
      if (type == kv::PUT && !opts_.master_encryption_key.empty())
        req.set_value(aes_gcm_encrypt(value, opts_.master_encryption_key));
      else
        req.set_value(value);
    }

    kv::SingleResponse resp;
    grpc::ClientContext ctx;

    // Optimize JWT access: load from an un-contended thread_local cache
    static thread_local std::string local_jwt;
    if (local_jwt.empty()) {
      std::shared_lock<std::shared_mutex> lock(jwt_mu_);
      local_jwt = jwt_;
    }
    ctx.AddMetadata("authorization", local_jwt);

    grpc::Status st = stub->ExecuteSingle(&ctx, req, &resp);
    if ((st.error_code() == grpc::StatusCode::UNAUTHENTICATED ||
         st.error_code() == grpc::StatusCode::UNAVAILABLE) &&
        !is_retry) {
      if (st.error_code() == grpc::StatusCode::UNAUTHENTICATED)
        connect();                                   // Refresh JWT
      return execute_single(type, key, value, true); // Retry on new subchannel
    }
    if (!st.ok())
      return {false, st.error_message()};

    std::string final_val = resp.value();
    if (resp.success() && type == kv::GET &&
        !opts_.master_encryption_key.empty() && !final_val.empty()) {
      final_val = aes_gcm_decrypt(final_val, opts_.master_encryption_key);
    }
    return {resp.success(), final_val};
  }

  Pipeline pipeline() {
    return Pipeline(
        std::make_unique<PipelineImpl>(std::atomic_load(&stubs_), jwt_, jwt_mu_,
                                       opts_.master_encryption_key, this));
  }

private:
  friend class PipelineImpl;
  ClientOptions opts_;
  std::string jwt_;
  std::shared_mutex jwt_mu_;
  std::shared_ptr<StubList> stubs_;
  std::atomic<int> rr_channel_{0};

  std::thread xds_thread_;
  std::atomic<bool> stop_xds_{false};
  std::vector<std::string> current_nodes_;

  bool xds_loop_step() {
    auto disc_ch = grpc::CreateCustomChannel(
        "ipv4:" + opts_.server_ip + ":50051",
        grpc::InsecureChannelCredentials(), grpc::ChannelArguments());
    auto disc_stub = kv::discovery::DiscoveryService::NewStub(disc_ch);
    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() +
                     std::chrono::seconds(2));
    kv::discovery::GetNodesRequest req;
    req.set_client_version("v8-client-dynamic");
    kv::discovery::GetNodesResponse resp;
    auto st = disc_stub->GetHealthyNodes(&ctx, req, &resp);

    if (st.ok() && resp.node_addresses_size() > 0) {
      std::vector<std::string> new_nodes;
      for (int i = 0; i < resp.node_addresses_size(); ++i)
        new_nodes.push_back(resp.node_addresses(i));
      std::sort(new_nodes.begin(), new_nodes.end());

      if (new_nodes != current_nodes_) {
        std::cout << "[Client] Topology change! " << new_nodes.size()
                  << " nodes available." << std::endl;
        auto new_stubs = std::make_shared<
            std::vector<std::shared_ptr<kv::KVService::Stub>>>();
        std::string ca_cert = ReadFile(opts_.ca_cert_path);
        grpc::SslCredentialsOptions ssl_opts;
        ssl_opts.pem_root_certs = ca_cert;
        auto channel_creds = ca_cert.empty()
                                 ? grpc::InsecureChannelCredentials()
                                 : grpc::SslCredentials(ssl_opts);

        for (const auto &ep : new_nodes) {
          for (int c = 0; c < opts_.channels_per_shard; ++c) {
            grpc::ChannelArguments args;
            args.SetInt(GRPC_ARG_USE_LOCAL_SUBCHANNEL_POOL, 1);
            if (!ca_cert.empty())
              args.SetSslTargetNameOverride("kv-server");
            auto ch =
                grpc::CreateCustomChannel("ipv4:" + ep, channel_creds, args);
            new_stubs->push_back(kv::KVService::NewStub(std::move(ch)));
          }
        }

        current_nodes_ = new_nodes;
        std::atomic_store(&stubs_, std::shared_ptr<StubList>(new_stubs));
      }
      return true;
    }
    return false;
  }

public:
  ~KVClientImpl() {
    stop_xds_ = true;
    if (xds_thread_.joinable())
      xds_thread_.join();
  }
};

std::vector<Result> PipelineImpl::execute() {
  bool retried = false;
retry_label:
  if (batch_req_.requests_size() == 0)
    return {};

  kv::BatchResponse batch_resp;
  grpc::ClientContext ctx;
  {
    std::shared_lock<std::shared_mutex> lock(jwt_mu_);
    ctx.AddMetadata("authorization", jwt_ref_);
  }

  if (!stubs_ || stubs_->empty())
    return {};
  static std::atomic<int> rr_channel_{0};
  int chan_idx =
      rr_channel_.fetch_add(1, std::memory_order_relaxed) % stubs_->size();
  auto *stub = (*stubs_)[chan_idx].get();

  grpc::Status s = stub->ExecuteBatch(&ctx, batch_req_, &batch_resp);

  std::vector<Result> res;
  if (s.ok()) {
    for (int j = 0; j < batch_resp.responses_size(); ++j) {
      std::string val = batch_resp.responses(j).value();
      if (batch_resp.responses(j).success() && !master_key_.empty() &&
          !val.empty()) {
        val = aes_gcm_decrypt(val, master_key_);
      }
      res.push_back({batch_resp.responses(j).success(), val});
    }
  } else {
    if ((s.error_code() == grpc::StatusCode::UNAUTHENTICATED ||
         s.error_code() == grpc::StatusCode::UNAVAILABLE) &&
        !retried && parent_) {
      if (s.error_code() == grpc::StatusCode::UNAUTHENTICATED)
        parent_->connect();
      retried = true;
      goto retry_label;
    }
    for (int j = 0; j < batch_req_.requests_size(); ++j) {
      res.push_back({false, s.error_message()});
    }
  }

  batch_req_.clear_requests();
  return res;
}

KVClient::KVClient(const ClientOptions &options)
    : pimpl_(std::make_unique<KVClientImpl>(options)) {}
KVClient::~KVClient() = default;
bool KVClient::connect() { return pimpl_->connect(); }
std::string KVClient::register_account(const std::string &client_id) {
  return pimpl_->register_account(client_id);
}
Result KVClient::put(const std::string &key, const std::string &value) {
  return pimpl_->execute_single(kv::PUT, key, value);
}
Result KVClient::get(const std::string &key) {
  return pimpl_->execute_single(kv::GET, key);
}
Result KVClient::del(const std::string &key) {
  return pimpl_->execute_single(kv::DELETE, key);
}
Pipeline KVClient::pipeline() { return pimpl_->pipeline(); }

} // namespace kv
