cmake_minimum_required(VERSION 3.16)
project(clientsdk16aprl CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Dependencies
find_package(Threads REQUIRED)
find_package(protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# Proto Codegen
set(PROTO_DIR ${CMAKE_SOURCE_DIR}/proto)
set(PROTO_OUT ${CMAKE_BINARY_DIR}/proto_gen)
file(MAKE_DIRECTORY ${PROTO_OUT})

get_target_property(GRPC_CPP_PLUGIN gRPC::grpc_cpp_plugin IMPORTED_LOCATION_NOCONFIG)
if(NOT GRPC_CPP_PLUGIN)
  get_target_property(GRPC_CPP_PLUGIN gRPC::grpc_cpp_plugin IMPORTED_LOCATION)
endif()

find_program(PROTOC_EXE protoc REQUIRED)

add_custom_command(
  OUTPUT  ${PROTO_OUT}/kv.pb.cc ${PROTO_OUT}/kv.pb.h
          ${PROTO_OUT}/kv.grpc.pb.cc ${PROTO_OUT}/kv.grpc.pb.h
          ${PROTO_OUT}/discovery.pb.cc ${PROTO_OUT}/discovery.pb.h
          ${PROTO_OUT}/discovery.grpc.pb.cc ${PROTO_OUT}/discovery.grpc.pb.h
  COMMAND ${PROTOC_EXE}
    --proto_path=${PROTO_DIR}
    --cpp_out=${PROTO_OUT}
    --grpc_out=${PROTO_OUT}
    --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
    ${PROTO_DIR}/kv.proto ${PROTO_DIR}/discovery.proto
  DEPENDS ${PROTO_DIR}/kv.proto ${PROTO_DIR}/discovery.proto
)

add_library(kv_proto STATIC
  ${PROTO_OUT}/kv.pb.cc
  ${PROTO_OUT}/kv.grpc.pb.cc
  ${PROTO_OUT}/discovery.pb.cc
  ${PROTO_OUT}/discovery.grpc.pb.cc
)
target_include_directories(kv_proto PUBLIC ${PROTO_OUT})
target_link_libraries(kv_proto PUBLIC gRPC::grpc++ protobuf::libprotobuf)

# Client Single Request
add_executable(load_client_single load_client_single.cpp)
target_include_directories(load_client_single PRIVATE jwt-cpp/include)
target_link_libraries(load_client_single PRIVATE 
    kv_proto 
    Threads::Threads 
    gRPC::grpc++ 
    protobuf::libprotobuf 
)

# Client Batch Request
add_executable(load_client_batch load_client_batch.cpp)
target_include_directories(load_client_batch PRIVATE jwt-cpp/include)
target_link_libraries(load_client_batch PRIVATE 
    kv_proto 
    Threads::Threads 
    gRPC::grpc++ 
    protobuf::libprotobuf 
)
