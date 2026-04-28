#include "kv_client.h"
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

int main(int argc, char **argv) {
  if (argc < 4) {
    std::cout << "Usage: ./benchmark_single <THREADS> <SECONDS> <SERVER_IP>\n";
    return 0;
  }

  int num_threads = std::stoi(argv[1]);
  int duration_s = std::stoi(argv[2]);
  std::string server_ip = argv[3];

  kv::ClientOptions opts;
  opts.server_ip = server_ip;
  opts.num_shards = 8;
  opts.channels_per_shard = 16;
  opts.ca_cert_path = "ca.crt";
  opts.api_key = "initial-pass";

  std::cout
      << "Creating client with 128 connection pool... (rr_channel atomic mode)"
      << std::endl;

  kv::KVClient client(opts);
  if (!client.connect()) {
    std::cerr << "Connect failed" << std::endl;
    return 1;
  }

  std::atomic<long> total_ops{0};
  std::cout << "Starting Single benchmark for " << duration_s << "s with "
            << num_threads << " threads..." << std::endl;

  auto start = std::chrono::steady_clock::now();
  std::vector<std::thread> workers;

  for (int t = 0; t < num_threads; ++t) {
    workers.emplace_back([&, t]() {
      unsigned int seed = t;
      long local_ops = 0;
      while (true) {
        if (std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start)
                .count() >= duration_s)
          break;

        auto res =
            client.put("k_" + std::to_string(rand_r(&seed) % 1000000), "val");
        if (res.success)
          local_ops++;
      }
      total_ops += local_ops;
    });
  }

  for (auto &w : workers)
    w.join();
  auto end = std::chrono::steady_clock::now();
  double elapsed = std::chrono::duration<double>(end - start).count();

  std::cout << "--------------------------------------" << std::endl;
  std::cout << "Total Successful Ops: " << total_ops.load() << std::endl;
  std::cout << "Throughput: " << (long)(total_ops.load() / elapsed) << " TPS"
            << std::endl;
  std::cout << "--------------------------------------" << std::endl;

  return 0;
}
