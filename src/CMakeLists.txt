add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE)

# Check the third party Libraries
find_package(Libubox REQUIRED)
find_package(Libuwsc REQUIRED)

include_directories(${LIBUWSC_INCLUDE_DIR} ${LIBUBOX_INCLUDE_DIR})
set(EXTRA_LIBS ${LIBUWSC_LIBRARY} ${LIBUBOX_LIBRARY} uci blobmsg_json util)

add_executable(rttyd main.c utils.c)
target_link_libraries(rttyd ${EXTRA_LIBS})

install(
    TARGETS rttyd
    RUNTIME DESTINATION bin
)
