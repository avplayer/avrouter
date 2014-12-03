
add_executable(avrouter ca_avimcert.cpp main.cpp http_connection.cpp http_server.cpp router_server.cpp io_service_pool.cpp connection.cpp database.cpp root_ca.cpp forward_moudle.cpp login_moudle.cpp register_moudle.cpp)

target_link_libraries(avrouter avimproto)
