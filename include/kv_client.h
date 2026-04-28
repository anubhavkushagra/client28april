#pragma once

#include <string>
#include <vector>
#include <memory>

namespace kv {

struct Result {
  bool success;
  std::string value; // for GET or error msg
};

struct ClientOptions {
  std::string server_ip;
  int start_port = 50063;
  int num_shards = 8;
  int channels_per_shard = 16;
  std::string api_key;
  std::string ca_cert_path;
  std::string tls_cert_path;
  std::string tls_key_path;
  std::string master_encryption_key;
};

class PipelineImpl; // Forward declaration to hide gRPC internals

class Pipeline {
public:
  explicit Pipeline(std::unique_ptr<PipelineImpl> impl);
  ~Pipeline();
  Pipeline(Pipeline &&) noexcept;
  Pipeline &operator=(Pipeline &&) noexcept;

  void put(const std::string &key, const std::string &value);
  void get(const std::string &key);
  void del(const std::string &key);

  std::vector<Result> execute();

private:
  std::unique_ptr<PipelineImpl> pimpl_;
};

class KVClientImpl; // Forward declaration to hide gRPC internals

class KVClient {
public:
  explicit KVClient(const ClientOptions &options);
  ~KVClient();

  bool connect();
  std::string register_account(const std::string &client_id);

  Result put(const std::string &key, const std::string &value);
  Result get(const std::string &key);
  Result del(const std::string &key);

  Pipeline pipeline();

private:
  std::unique_ptr<KVClientImpl> pimpl_;
};

} // namespace kv
